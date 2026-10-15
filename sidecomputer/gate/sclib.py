"""SideComputer shared library: spool, profiles, redaction, audit chain. Python stdlib only."""
import base64, contextlib, fcntl, grp, hashlib, hmac, ipaddress, json, os, pwd, re, subprocess, time, uuid

SPOOL = os.environ.get("SC_SPOOL", "/var/lib/sidecomputer")
PROFILES_DIR = os.environ.get("SC_PROFILES", "/etc/sidecomputer/profiles")
GRANTS_PATH = os.environ.get("SC_GRANTS", "/etc/sidecomputer/grants.json")
AUDIT_KEY_PATH = os.environ.get("SC_AUDIT_KEY", "/etc/sidecomputer/audit.key")

# Directories the gate or worker create. approvals/ is root-owned and is not created here.
SUBDIRS = ("queue", "running", "done", "artifacts", "private", "pending", "cancellations", "locks")
SUMMARY_MAX = 500
MAX_INPUT = 8000
GENESIS = "0" * 64
ID_RE = re.compile(r"^[0-9a-f]{12}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
REQUESTER_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.:@/+/=-]{1,200}$")
DENIED_ARTIFACTS = frozenset({"stdout.log", "stderr.log"})
BINDING_FIELDS = ("id", "profile", "kind", "input", "timeout", "requester", "key_id")
PROFILE_KEYS = {"name", "description", "allow_command", "prompt_runner", "max_timeout",
                "memory_max", "cpu_quota", "tasks_max", "artifact_max_bytes", "packages", "mcps", "env",
                "network", "egress_allow", "requires_approval"}

# DAC policy applied by bootstrap. Modes are the source of truth for tests.
# append_only files can be extended by the audit group; history cannot be rewritten.
ACTORS = {
    "root": {"groups": frozenset()},
    "sidecomputer": {"groups": frozenset({"sidecomputer"})},
    "sc-gate": {"groups": frozenset({"sc-gate", "sc-audit", "sc-ipc"})},
    "sc-worker": {"groups": frozenset({"sc-worker", "sc-audit", "sc-ipc"})},
    "sc-task": {"groups": frozenset({"sc-task"})},
}
SPOOL_POLICY = {
    "spool": {"owner": "root", "group": "root", "mode": 0o755},
    "queue": {"owner": "sc-gate", "group": "sc-worker", "mode": 0o2750},
    "running": {"owner": "sc-worker", "group": "sc-gate", "mode": 0o2750},
    "done": {"owner": "sc-worker", "group": "sc-gate", "mode": 0o2750},
    "artifacts": {"owner": "sc-worker", "group": "sc-gate", "mode": 0o2750},
    "private": {"owner": "sc-worker", "group": "sc-worker", "mode": 0o700},
    "pending": {"owner": "sc-gate", "group": "sc-worker", "mode": 0o2750},
    "cancellations": {"owner": "sc-gate", "group": "sc-worker", "mode": 0o2750},
    "locks": {"owner": "root", "group": "sc-ipc", "mode": 0o3770},
    "approvals": {"owner": "root", "group": "sc-worker", "mode": 0o2750},
    "audit.log": {"owner": "root", "group": "sc-audit", "mode": 0o660, "append_only": True},
    "audit.lock": {"owner": "root", "group": "sc-audit", "mode": 0o660},
    "artifacts.log": {"owner": "root", "group": "sc-audit", "mode": 0o660, "append_only": True},
    "worker.heartbeat": {"owner": "sc-worker", "group": "sc-worker", "mode": 0o644},
}
FILE_MODE = 0o640

def spool(*parts):
    return os.path.join(SPOOL, *parts)

def ensure_spool():
    os.makedirs(SPOOL, exist_ok=True)
    for name in SUBDIRS:
        os.makedirs(spool(name), exist_ok=True)
    for name in ("audit.log", "audit.lock", "artifacts.log", "worker.heartbeat"):
        path = spool(name)
        if not os.path.exists(path):
            try:
                fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o660)
                os.close(fd)
            except OSError:
                pass

# ---------------- profiles ----------------
class ProfileError(ValueError):
    pass

def _valid_egress(item):
    try:
        net = ipaddress.ip_network(item, strict=False)
    except (TypeError, ValueError):
        return False
    return net.prefixlen != 0

def validate_profile(raw):
    if not isinstance(raw, dict):
        raise ProfileError("profile must be an object")
    extra = set(raw) - PROFILE_KEYS
    if extra:
        raise ProfileError("unknown keys: %s" % ",".join(sorted(extra)))
    if not isinstance(raw.get("name"), str) or not NAME_RE.match(raw["name"]):
        raise ProfileError("invalid name")
    if not isinstance(raw.get("allow_command", False), bool):
        raise ProfileError("allow_command must be bool")
    runner = raw.get("prompt_runner")
    if runner is not None and (not isinstance(runner, list) or not runner or not all(isinstance(x, str) for x in runner)
                               or not any("{prompt}" in x for x in runner)):
        raise ProfileError("prompt_runner must be a non-empty argv list containing {prompt}")
    timeout = raw.get("max_timeout", 3600)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 86400:
        raise ProfileError("max_timeout must be int 1..86400")
    cap = raw.get("artifact_max_bytes", 262144)
    if not isinstance(cap, int) or isinstance(cap, bool) or not 0 <= cap <= 10 * 1024 * 1024:
        raise ProfileError("artifact_max_bytes must be int 0..10MiB")
    for key in ("packages", "mcps"):
        value = raw.get(key, [])
        if not isinstance(value, list) or not all(isinstance(x, str) and re.match(r"^[A-Za-z0-9@/._:+=-]{1,128}$", x) for x in value):
            raise ProfileError("%s must be a list of safe package specs" % key)
    env = raw.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and re.match(r"^[A-Z_][A-Z0-9_]*$", k) and isinstance(v, str) for k, v in env.items()):
        raise ProfileError("env must map UPPER_CASE names to strings")
    if "network" in raw and not isinstance(raw["network"], bool):
        raise ProfileError("network must be bool")
    if "requires_approval" in raw and not isinstance(raw["requires_approval"], bool):
        raise ProfileError("requires_approval must be bool")
    allow = raw.get("egress_allow", [])
    if not isinstance(allow, list) or not all(isinstance(x, str) and _valid_egress(x) for x in allow):
        raise ProfileError("egress_allow must be a list of non-default CIDRs")
    if not raw.get("allow_command") and not runner:
        raise ProfileError("profile allows neither command nor prompt")
    return raw

def load_profiles():
    out = {}
    if not os.path.isdir(PROFILES_DIR):
        return out
    for name in sorted(os.listdir(PROFILES_DIR)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(PROFILES_DIR, name)) as fh:
                profile = validate_profile(json.load(fh))
            out[profile["name"]] = profile
        except (OSError, ValueError):
            continue
    return out

def network_requested(profile):
    return bool(profile and (profile.get("network") or profile.get("egress_allow")))

def requires_approval(profile):
    if "requires_approval" in profile:
        return bool(profile["requires_approval"])
    return bool(profile.get("allow_command") or network_requested(profile))

# ---------------- redaction ----------------
_REDACT = [
    (re.compile(r"-----BEGIN [A-Z ]+-----.*?(-----END [A-Z ]+-----|$)", re.S), "[REDACTED_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED_JWT]"),
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|xox[abprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|hf_[A-Za-z0-9]{8,}|xai-[A-Za-z0-9]{8,})"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|auth|bearer|credential|private[_-]?key)(\s*[:=]\s*|\s+)\S+"), r"\1=[REDACTED]"),
    (re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:]+:[^\s/@]+@"), "[REDACTED_CREDS]@"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[REDACTED_HEX]"),
    (re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}"), "[REDACTED_BLOB]"),
]
_ALLOWED = re.compile(r"[^A-Za-z0-9 \t\n.,:;!?()\[\]{}<>'\"/_+=%#@&*|~^$-]")

def redact(text, limit=SUMMARY_MAX):
    if not isinstance(text, str):
        text = str(text)
    for pattern, replacement in _REDACT:
        text = pattern.sub(replacement, text)
    text = _ALLOWED.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > limit:
        text = "..." + text[-(limit - 3):]
    return text

def redact_artifact(data):
    """Redact a fetched artifact. The byte cap is applied by the gate; this does not summary-truncate."""
    if isinstance(data, str):
        text = data
    else:
        text = bytes(data).decode("utf-8", "replace")
    return redact(text, limit=max(len(text), 1)).encode("utf-8")

def summarize(stdout, stderr, exit_code):
    tail = "\n".join([line for line in stdout.splitlines() if line.strip()][-8:])
    if exit_code != 0:
        err_tail = "\n".join([line for line in stderr.splitlines() if line.strip()][-4:])
        tail = (tail + "\n[stderr]\n" + err_tail).strip()
    return redact(tail or "(no output)")

# ---------------- tasks ----------------
def new_id():
    return uuid.uuid4().hex[:12]

def write_json(path, obj, mode=FILE_MODE):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.chmod(tmp, mode)
    os.replace(tmp, path)

def read_json(path):
    with open(path) as fh:
        return json.load(fh)

def find_task(tid):
    if not ID_RE.match(tid or ""):
        return None, None
    for state in ("done", "running", "queue", "pending"):
        path = spool(state, tid + ".json")
        if os.path.exists(path):
            try:
                return state, read_json(path)
            except (OSError, ValueError):
                return state, None
    return None, None

PUBLIC = ("id", "profile", "kind", "state", "exit_code", "duration_s", "summary", "submitted_at",
          "started_at", "finished_at", "artifacts", "requester", "key_id", "approved_by")

def public_view(task):
    return {key: task[key] for key in PUBLIC if key in task}

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def task_binding(task):
    return {key: task[key] for key in BINDING_FIELDS}

def task_hash(task):
    return hashlib.sha256(canonical(task_binding(task)).encode()).hexdigest()

def approval_path(tid):
    return spool("approvals", tid + ".json")

def load_approval(tid):
    path = approval_path(tid)
    if not os.path.isfile(path):
        return None
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None

def approve_task(tid, approver="root"):
    """Host-admin approval. Not an MCP tool: the bot cannot approve its own task."""
    if os.geteuid() != 0 and os.environ.get("SC_ALLOW_APPROVE") != "1":
        raise PermissionError("approval is a host-admin action")
    if not isinstance(approver, str) or not REQUESTER_RE.match(approver):
        raise ValueError("invalid approver")
    if not ID_RE.match(tid or ""):
        raise ValueError("bad id")
    source = None
    task = None
    for folder in ("pending", "queue"):
        path = spool(folder, tid + ".json")
        if os.path.isfile(path):
            source = folder
            task = read_json(path)
            break
    if not task:
        raise ValueError("task is not awaiting approval")
    os.makedirs(spool("approvals"), exist_ok=True)
    record = {"id": tid, "task_hash": task_hash(task), "approver": approver, "ts": time.time_ns()}
    write_json(approval_path(tid), record)
    task["state"] = "queued"
    task["approved_by"] = approver
    write_json(spool("queue", tid + ".json"), task)
    if source == "pending":
        try:
            os.unlink(spool("pending", tid + ".json"))
        except FileNotFoundError:
            pass
    log("audit.log", {"op": "approve", "id": tid, "approver": approver,
                      "requester": task.get("requester", ""), "key_id": task.get("key_id", "")})
    return record

def revalidate(task, profile):
    """Re-check a queue file against the live profile. Returns an error string or None.

    Timeout above the profile max is clamped after the approval binding is checked.
    Kind, input and approval mismatches are rejected and must not run.
    """
    if not isinstance(task, dict):
        return "task is not an object"
    if not profile or task.get("profile") != profile.get("name"):
        return "profile is not declared"
    kind = task.get("kind")
    if kind not in ("command", "prompt"):
        return "kind is not allowed"
    text = task.get("input")
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_INPUT or "\x00" in text:
        return "invalid command/prompt"
    if kind == "command" and not profile.get("allow_command"):
        return "profile does not allow raw commands"
    if kind == "prompt" and not profile.get("prompt_runner"):
        return "profile has no prompt runner"
    if not isinstance(task.get("key_id"), str) or not KEY_ID_RE.match(task.get("key_id", "")):
        return "task has no key id"
    if not isinstance(task.get("requester"), str) or not REQUESTER_RE.match(task.get("requester", "")):
        return "task has no requester"
    timeout = task.get("timeout")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        return "invalid timeout"
    if requires_approval(profile):
        approval = load_approval(task.get("id"))
        if not approval or approval.get("id") != task.get("id") or approval.get("task_hash") != task_hash(task):
            return "approval missing or does not match task"
    maximum = profile.get("max_timeout", 3600)
    if timeout > maximum:
        task["timeout"] = maximum
    return None

def artifact_dir(tid, spool_root=None):
    """Resolved artifact directory for one task id, or ValueError if it escapes."""
    if not ID_RE.match(tid or ""):
        raise ValueError("bad id")
    root = os.path.realpath(os.path.join(spool_root or SPOOL, "artifacts"))
    path = os.path.realpath(os.path.join(root, tid))
    if os.path.dirname(path) != root:
        raise ValueError("artifact path escapes the spool")
    return path

# ---------------- audit chain (invariant 9) ----------------
def _audit_key():
    path = os.environ.get("SC_AUDIT_KEY", AUDIT_KEY_PATH)
    try:
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) >= 32:
            return key
    except OSError:
        key = b""
    fresh = os.urandom(32)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        with open(path, "rb") as fh:
            return fh.read()
    else:
        os.write(fd, fresh)
        os.close(fd)
        return fresh

def _audit_tail(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return GENESIS, 0
    with open(path) as fh:
        lines = [line for line in fh.read().splitlines() if line.strip()]
    if not lines:
        return GENESIS, 0
    last = json.loads(lines[-1])
    return last["hash"], int(last["seq"]) + 1

def log(name, rec):
    if name != "audit.log":
        payload = dict(rec, ts=time.time_ns())
        fd = os.open(spool(name), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o660)
        with os.fdopen(fd, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        return
    path = spool("audit.log")
    lock_path = spool("audit.lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o660)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        prev, seq = _audit_tail(path)
        body = dict(rec)
        body["ts"] = time.time_ns()
        body["seq"] = seq
        body["prev"] = prev
        digest = hashlib.sha256(canonical(body).encode()).hexdigest()
        body["hash"] = digest
        body["mac"] = hmac.new(_audit_key(), digest.encode(), hashlib.sha256).hexdigest()
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o660)
        try:
            os.write(fd, (json.dumps(body, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

def read_audit():
    path = spool("audit.log")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh.read().splitlines() if line.strip()]

def verify_audit(path=None):
    """Return (ok, reason). The chain is gapless and each record is bound to the previous hash."""
    path = path or spool("audit.log")
    key = _audit_key()
    prev = GENESIS
    if not os.path.exists(path):
        return True, "ok"
    with open(path) as fh:
        lines = [line for line in fh.read().splitlines() if line.strip()]
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except ValueError:
            return False, "invalid json at %d" % index
        mac = record.pop("mac", None)
        digest = record.pop("hash", None)
        if record.get("seq") != index:
            return False, "gap or reorder at %d" % index
        if record.get("prev") != prev:
            return False, "prev mismatch at %d" % index
        expect = hashlib.sha256(canonical(record).encode()).hexdigest()
        if digest != expect:
            return False, "hash mismatch at %d" % index
        expect_mac = hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac or "", expect_mac):
            return False, "mac mismatch at %d" % index
        prev = digest
    return True, "ok"

# ---------------- grants (invariant 2) ----------------
def fingerprint_pubkey(line):
    parts = line.strip().split()
    if len(parts) < 2:
        raise ValueError("bad pubkey")
    blob = base64.b64decode(parts[1], validate=True)
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

def load_grants(path=None):
    path = path or os.environ.get("SC_GRANTS", GRANTS_PATH)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, dict):
        return {}
    out = {}
    for key_id, spec in keys.items():
        if not isinstance(key_id, str) or not isinstance(spec, dict):
            continue
        profiles = spec.get("profiles")
        if not isinstance(profiles, list) or not all(isinstance(item, str) for item in profiles):
            continue
        out[key_id] = {"profiles": list(profiles)}
    return out

def write_grant(path, fingerprint, profiles):
    data = {"keys": {}}
    if os.path.isfile(path):
        try:
            with open(path) as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict) and isinstance(loaded.get("keys"), dict):
                data = loaded
        except (OSError, ValueError):
            data = {"keys": {}}
    data.setdefault("keys", {})[fingerprint] = {"profiles": list(profiles)}
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)

def current_key_id():
    return os.environ.get("SC_KEY_ID", "")

def granted_profiles():
    key_id = current_key_id()
    if not key_id or not KEY_ID_RE.match(key_id):
        return set()
    spec = load_grants().get(key_id)
    if not spec:
        return set()
    return set(spec["profiles"])

def task_visible(task):
    """A key sees only tasks it submitted in a profile it was granted."""
    if not task:
        return False
    if task.get("profile") not in granted_profiles():
        return False
    return task.get("key_id") == current_key_id()

# ---------------- cancellation ----------------
def cancel_marker(tid):
    return spool("cancellations", tid)

def request_cancel(tid):
    os.makedirs(spool("cancellations"), exist_ok=True)
    fd = os.open(cancel_marker(tid), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o640)
    os.close(fd)

def cancellation_requested(tid):
    return os.path.exists(cancel_marker(tid))

@contextlib.contextmanager
def locked_task(tid):
    if not ID_RE.match(tid or ""):
        raise ValueError("bad id")
    os.makedirs(spool("locks"), exist_ok=True)
    fd = os.open(spool("locks", tid + ".lock"), os.O_CREAT | os.O_RDWR, 0o660)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

def sweep_finished():
    """Drop queue/pending files the worker already finished. Ignore EACCES (gate-only unlink)."""
    for folder in ("queue", "pending"):
        directory = spool(folder)
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            if not name.endswith(".json"):
                continue
            tid = name[:-5]
            if os.path.exists(spool("done", tid + ".json")):
                try:
                    os.unlink(os.path.join(directory, name))
                except OSError:
                    pass

# ---------------- permission policy ----------------
def _class_bits(mode, which):
    shift = {"owner": 6, "group": 3, "other": 0}[which]
    return (mode >> shift) & 0o7

def can(actor, key, action):
    """Whether actor may read, append, edit, or traverse a policy path.

    edit is rewrite/truncate. Append-only logs deny edit for every non-root actor
    even when the mode bit would allow a write.
    """
    if actor not in ACTORS:
        raise KeyError(actor)
    spec = SPOOL_POLICY[key]
    if spec.get("append_only") and action in ("write", "edit") and actor != "root":
        return False
    if actor == "root":
        return True
    bit_action = "write" if action in ("write", "append", "edit") else "read" if action == "read" else "exec"
    if spec["owner"] == actor:
        bits = _class_bits(spec["mode"], "owner")
    elif spec["group"] in ACTORS[actor]["groups"]:
        bits = _class_bits(spec["mode"], "group")
    else:
        bits = _class_bits(spec["mode"], "other")
    need = {"read": 4, "write": 2, "exec": 1}[bit_action]
    return bool(bits & need)

def _try_chown(path, spec):
    try:
        uid = 0 if spec["owner"] == "root" else pwd.getpwnam(spec["owner"]).pw_uid
        gid = 0 if spec["group"] == "root" else grp.getgrnam(spec["group"]).gr_gid
    except KeyError:
        return
    os.chown(path, uid, gid)

def apply_spool_policy(spool_root, chown=True):
    """Create the spool layout and apply SPOOL_POLICY modes. chown is best-effort."""
    os.makedirs(spool_root, exist_ok=True)
    _apply_node(spool_root, SPOOL_POLICY["spool"], chown, is_dir=True)
    for name, spec in SPOOL_POLICY.items():
        if name == "spool":
            continue
        path = os.path.join(spool_root, name)
        is_dir = "." not in name
        if is_dir:
            os.makedirs(path, exist_ok=True)
        elif not os.path.exists(path):
            fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            os.close(fd)
        _apply_node(path, spec, chown, is_dir)
        if spec.get("append_only") and chown:
            _try_append_only(path)

def _apply_node(path, spec, chown, is_dir):
    mode = spec["mode"] if is_dir else (spec["mode"] & 0o777)
    os.chmod(path, mode)
    if chown:
        _try_chown(path, spec)

def _try_append_only(path):
    # chattr is best-effort: the hash chain still detects a rewrite if the flag is unavailable.
    if not os.path.exists("/usr/bin/chattr") and not os.path.exists("/bin/chattr"):
        return
    subprocess.call(["chattr", "+a", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
