"""SideComputer shared library: spool, profiles, redaction. Python stdlib only."""
import json, os, re, time, uuid

SPOOL = os.environ.get("SC_SPOOL", "/var/lib/sidecomputer")
PROFILES_DIR = os.environ.get("SC_PROFILES", "/etc/sidecomputer/profiles")
SUBDIRS = ("queue", "running", "done", "artifacts")
SUMMARY_MAX = 500
ID_RE = re.compile(r"^[0-9a-f]{12}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PROFILE_KEYS = {"name", "description", "allow_command", "prompt_runner", "max_timeout",
                "memory_max", "cpu_quota", "tasks_max", "artifact_max_bytes", "packages", "mcps", "env"}

def spool(*p):
    return os.path.join(SPOOL, *p)

def ensure_spool():
    for d in SUBDIRS:
        os.makedirs(spool(d), exist_ok=True)

# ---------------- profiles ----------------
class ProfileError(ValueError):
    pass

def validate_profile(p):
    if not isinstance(p, dict):
        raise ProfileError("profile must be an object")
    extra = set(p) - PROFILE_KEYS
    if extra:
        raise ProfileError("unknown keys: %s" % ",".join(sorted(extra)))
    if not isinstance(p.get("name"), str) or not NAME_RE.match(p["name"]):
        raise ProfileError("invalid name")
    if not isinstance(p.get("allow_command", False), bool):
        raise ProfileError("allow_command must be bool")
    pr = p.get("prompt_runner")
    if pr is not None and (not isinstance(pr, list) or not pr or not all(isinstance(x, str) for x in pr)
                           or not any("{prompt}" in x for x in pr)):
        raise ProfileError("prompt_runner must be a non-empty argv list containing {prompt}")
    mt = p.get("max_timeout", 3600)
    if not isinstance(mt, int) or isinstance(mt, bool) or not 1 <= mt <= 86400:
        raise ProfileError("max_timeout must be int 1..86400")
    am = p.get("artifact_max_bytes", 262144)
    if not isinstance(am, int) or isinstance(am, bool) or not 0 <= am <= 10 * 1024 * 1024:
        raise ProfileError("artifact_max_bytes must be int 0..10MiB")
    for k in ("packages", "mcps"):
        v = p.get(k, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and re.match(r"^[A-Za-z0-9@/._:+=-]{1,128}$", x) for x in v):
            raise ProfileError("%s must be a list of safe package specs" % k)
    env = p.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and re.match(r"^[A-Z_][A-Z0-9_]*$", k) and isinstance(v, str) for k, v in env.items()):
        raise ProfileError("env must map UPPER_CASE names to strings")
    if not p.get("allow_command") and not pr:
        raise ProfileError("profile allows neither command nor prompt")
    return p

def load_profiles():
    out = {}
    if not os.path.isdir(PROFILES_DIR):
        return out
    for f in sorted(os.listdir(PROFILES_DIR)):
        if f.endswith(".json"):
            try:
                with open(os.path.join(PROFILES_DIR, f)) as fh:
                    p = validate_profile(json.load(fh))
                out[p["name"]] = p
            except (OSError, ValueError):
                continue  # invalid profiles are ignored, never half-loaded
    return out

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
    for rx, rep in _REDACT:
        text = rx.sub(rep, text)
    text = _ALLOWED.sub("", text)            # allowlist: printable ASCII only
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > limit:
        text = "..." + text[-(limit - 3):]
    return text

def summarize(stdout, stderr, exit_code):
    tail = "\n".join([l for l in stdout.splitlines() if l.strip()][-8:])
    if exit_code != 0:
        etail = "\n".join([l for l in stderr.splitlines() if l.strip()][-4:])
        tail = (tail + "\n[stderr]\n" + etail).strip()
    return redact(tail or "(no output)")

# ---------------- tasks ----------------
def new_id():
    return uuid.uuid4().hex[:12]

def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)

def read_json(path):
    with open(path) as fh:
        return json.load(fh)

def find_task(tid):
    if not ID_RE.match(tid or ""):
        return None, None
    for st in ("done", "running", "queue"):
        p = spool(st, tid + ".json")
        if os.path.exists(p):
            try:
                return st, read_json(p)
            except (OSError, ValueError):
                return st, None
    return None, None

PUBLIC = ("id", "profile", "kind", "state", "exit_code", "duration_s", "summary", "submitted_at", "started_at", "finished_at", "artifacts")

def public_view(t):
    return {k: t[k] for k in PUBLIC if k in t}

def log(name, rec):
    rec = dict(rec, ts=time.time())
    with open(spool(name), "a") as fh:
        fh.write(json.dumps(rec) + "\n")
