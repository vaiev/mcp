import base64, io, json, os, resource, stat, subprocess, sys, tempfile, time, unittest, shutil
from unittest import mock
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
GATE = os.path.join(ROOT, "gate")
TMP = tempfile.mkdtemp(prefix="sc-test-")
os.environ["SC_SPOOL"] = os.path.join(TMP, "spool")
os.environ["SC_PROFILES"] = os.path.join(TMP, "profiles")
os.environ["SC_GRANTS"] = os.path.join(TMP, "grants.json")
os.environ["SC_AUDIT_KEY"] = os.path.join(TMP, "audit.key")
os.environ["SC_KEY_ID"] = "test-key"
os.environ["SC_ALLOW_APPROVE"] = "1"
os.environ["SC_SYSTEMD_RUN"] = "0"
os.environ["SC_TASK_SEPARATION"] = "0"
shutil.copytree(os.path.join(ROOT, "profiles"), os.environ["SC_PROFILES"])
with open(os.path.join(os.environ["SC_PROFILES"], "echo.json"), "w") as f:
    json.dump({"name": "echo", "allow_command": False, "requires_approval": False,
               "prompt_runner": ["/bin/echo", "got:{prompt}"], "max_timeout": 5, "artifact_max_bytes": 100}, f)
sys.path.insert(0, GATE); sys.path.insert(0, os.path.join(ROOT, "client"))
import sclib, gate, worker, sc_client

PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILYsC3gQWiY0VzyPiEjHzOG3ivvR/HbKhDpF/ubJmaE9 bot"

def refresh_grants(profiles=None):
    if profiles is None:
        profiles = []
        for name in os.listdir(os.environ["SC_PROFILES"]):
            if name.endswith(".json"):
                with open(os.path.join(os.environ["SC_PROFILES"], name)) as fh:
                    profiles.append(json.load(fh)["name"])
    sclib.write_grant(os.environ["SC_GRANTS"], os.environ["SC_KEY_ID"], sorted(set(profiles)))

def write_profile(spec):
    with open(os.path.join(os.environ["SC_PROFILES"], spec["name"] + ".json"), "w") as fh:
        json.dump(spec, fh)
    refresh_grants()

refresh_grants()
sclib.ensure_spool()

def call(_tool, **args):
    r = gate.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": _tool, "arguments": args}})
    res = r["result"]; return res["isError"], json.loads(res["content"][0]["text"])

class JsonRpc(unittest.TestCase):
    def test_health_artifact_redaction(self):
        error, response = call("health")
        self.assertFalse(error)
        self.assertEqual(response.get("artifact_redaction"), "all")

    def test_submit_audit_key_unreadable(self):
        for profile, payload in (("echo", {"prompt": "hello"}), ("compute", {"command": "echo hello"})):
            with self.subTest(profile=profile):
                before = {folder: set(os.listdir(sclib.spool(folder))) for folder in ("queue", "pending")}
                with mock.patch.object(sclib, "_audit_key", side_effect=PermissionError("audit key unreadable")):
                    error, response = call("submit_task", profile=profile, **payload)
                self.assertTrue(error)
                self.assertEqual(response, {"error": "internal error"})
                for folder in before:
                    self.assertEqual(set(os.listdir(sclib.spool(folder))), before[folder])

    def test_initialize_and_list(self):
        r = gate.handle({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}})
        self.assertEqual(r["id"], 7); self.assertIn("tools", r["result"]["capabilities"])
        names = {t["name"] for t in gate.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
        self.assertEqual(names, {"submit_task", "task_status", "list_tasks", "cancel_task", "list_profiles", "request_artifact", "health"})
        self.assertNotIn("rotate_bot_key", names)
        self.assertNotIn("approve_task", names)
    def test_errors(self):
        self.assertEqual(gate.handle({"id": 1, "method": "x"})["error"]["code"], -32600)
        self.assertEqual(gate.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"})["error"]["code"], -32601)
        self.assertIsNone(gate.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(gate.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "shell"}})["error"]["code"], -32602)
    def test_tool_validation(self):
        sclib.ensure_spool()
        self.assertTrue(call("submit_task", profile="nope", command="ls")[0])
        self.assertTrue(call("submit_task", profile="echo", command="ls")[0])            # command not allowed
        self.assertTrue(call("submit_task", profile="compute", command="ls", prompt="x")[0])
        self.assertTrue(call("task_status", id="../../etc/passwd")[0])
        e, out = call("submit_task", profile="echo", prompt="hi", timeout=999)
        self.assertFalse(e); self.assertEqual(out["timeout"], 5)                           # clamped

class AuditFailures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.object(sclib, "SPOOL", self.tmp.name)
        patch.start()
        self.addCleanup(patch.stop)
        sclib.ensure_spool()

    def test_approval_audit_failure_has_no_side_effects(self):
        tid = gate.t_submit({"profile": "compute", "command": "echo hello"})["id"]
        pending = sclib.read_json(sclib.spool("pending", tid + ".json"))
        with mock.patch.object(sclib, "log", side_effect=OSError("audit unavailable")):
            with self.assertRaises(OSError):
                sclib.approve_task(tid)
        self.assertIsNone(sclib.load_approval(tid))
        self.assertFalse(os.path.exists(sclib.spool("queue", tid + ".json")))
        self.assertEqual(sclib.read_json(sclib.spool("pending", tid + ".json")), pending)

    def test_enqueue_failure_is_audited_and_original_error_raised(self):
        for approve in (False, True):
            for audit_fails in (False, True):
                with self.subTest(approve=approve, audit_fails=audit_fails):
                    tid = gate.t_submit({"profile": "compute", "command": "echo hello"})["id"] if approve else sclib.new_id()
                    failure = OSError("queue unavailable")
                    write = sclib.write_json
                    log = sclib.log
                    def fail_queue(path, obj, *args, **kwargs):
                        if path == sclib.spool("queue", tid + ".json"):
                            raise failure
                        return write(path, obj, *args, **kwargs)
                    def audit(path, event):
                        if event["op"] == "enqueue_failed" and audit_fails:
                            raise OSError("audit unavailable")
                        return log(path, event)
                    with mock.patch.object(sclib, "new_id", return_value=tid), mock.patch.object(sclib, "write_json", side_effect=fail_queue), mock.patch.object(sclib, "log", side_effect=audit) as logged:
                        with self.assertRaises(OSError) as caught:
                            if approve:
                                sclib.approve_task(tid)
                            else:
                                gate.t_submit({"profile": "echo", "prompt": "hello"})
                    self.assertIs(caught.exception, failure)
                    events = [c.args[1] for c in logged.call_args_list]
                    self.assertEqual([e["op"] for e in events], ["approve" if approve else "submit", "enqueue_failed"])
                    self.assertTrue(all(e["id"] == tid for e in events))
                    self.assertFalse(os.path.exists(sclib.spool("queue", tid + ".json")))

    def test_worker_start_audit_precedes_execution(self):
        tid = gate.t_submit({"profile": "echo", "prompt": "hello", "requester": "tester"})["id"]
        prepare = worker.prepare_workdir
        def checked_prepare(task_id):
            events = [e for e in sclib.read_audit() if e.get("op") == "start" and e.get("id") == tid]
            self.assertEqual(len(events), 1)
            self.assertEqual({k: events[0][k] for k in ("profile", "kind", "requester", "key_id")},
                             {"profile": "echo", "kind": "prompt", "requester": "tester", "key_id": "test-key"})
            return prepare(task_id)
        with mock.patch.object(worker, "prepare_workdir", side_effect=checked_prepare):
            self.assertEqual(worker.once()["state"], "succeeded")

    def test_worker_audit_failure_refuses_execution(self):
        tid = gate.t_submit({"profile": "echo", "prompt": "hello"})["id"]
        with mock.patch.object(sclib, "log", side_effect=OSError("audit unavailable")), mock.patch.object(worker.subprocess, "Popen") as execute:
            try:
                worker.once()
            except OSError:
                pass
        execute.assert_not_called()
        state, task = sclib.find_task(tid)
        self.assertEqual(state, "done")
        self.assertIn(task["state"], ("failed", "rejected"))
        self.assertIn("audit", task["summary"])

class Redaction(unittest.TestCase):
    def test_secrets(self):
        s = sclib.redact("token=abc123 key sk-ABCDEFGH12345678 ip 10.1.2.3 mail a@b.io "
                         "ghp_abcdefghijklmnop https://u:p@h.com/x -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY----- "
                         + "a" * 50 + " deadbeef" * 5)
        for bad in ("abc123", "sk-ABC", "10.1.2.3", "a@b.io", "ghp_", "u:p@", "AAAA", "a" * 50, "deadbeefdeadbeef"):
            self.assertNotIn(bad, s)
    def test_cap_and_allowlist(self):
        s = sclib.redact("x\x1b[31m\u00e9" + "y " * 1000)
        self.assertLessEqual(len(s), 500); self.assertNotIn("\x1b", s); self.assertNotIn("\u00e9", s)

class Profiles(unittest.TestCase):
    def test_shipped_valid(self):
        for f in os.listdir(os.path.join(ROOT, "profiles")):
            sclib.validate_profile(json.load(open(os.path.join(ROOT, "profiles", f))))
    def test_invalid(self):
        bad = [{"name": "x y", "allow_command": True}, {"name": "a", "allow_command": True, "evil": 1},
               {"name": "a"}, {"name": "a", "prompt_runner": ["x"]}, {"name": "a", "allow_command": True, "packages": ["x; rm -rf /"]},
               {"name": "a", "allow_command": True, "max_timeout": 0}, {"name": "a", "allow_command": True, "env": {"lower": "x"}}]
        for b in bad:
            with self.assertRaises(sclib.ProfileError):
                sclib.validate_profile(b)

class EndToEnd(unittest.TestCase):
    def gate_proc(self, msgs):
        env = dict(os.environ); env.pop("SSH_ORIGINAL_COMMAND", None)
        inp = "".join(json.dumps(m) + "\n" for m in msgs)
        p = subprocess.run([sys.executable, os.path.join(GATE, "gate.py")], input=inp, capture_output=True, text=True, env=env, timeout=20)
        return [json.loads(l) for l in p.stdout.splitlines()]
    def tc(self, i, _tool, **a):
        return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": _tool, "arguments": a}}
    def txt(self, r):
        return json.loads(r["result"]["content"][0]["text"])
    def test_full_flow(self):
        rs = self.gate_proc([{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
                             {"jsonrpc": "2.0", "method": "notifications/initialized"},
                             self.tc(1, "submit_task", profile="compute", command="echo hello; echo password=hunter2; echo 192.168.0.1; echo data > out.txt"),
                             self.tc(2, "submit_task", profile="compute", command="exit 3"),
                             self.tc(3, "submit_task", profile="compute", command="sleep 30", timeout=1)])
        self.assertEqual(len(rs), 4)
        ids = [self.txt(r)["id"] for r in rs[1:]]
        for tid in ids:
            self.assertEqual(sclib.find_task(tid)[0], "pending")
            sclib.approve_task(tid, approver="tester")
        while worker.once():
            pass
        rs = self.gate_proc([self.tc(i, "task_status", id=t) for i, t in enumerate(ids)] +
                            [self.tc(9, "request_artifact", id=ids[0], name="out.txt"),
                             self.tc(10, "request_artifact", id=ids[0], name="../../../etc/passwd"),
                             self.tc(11, "list_tasks"), self.tc(12, "health"), self.tc(13, "list_profiles")])
        ok, fail, to = (self.txt(r) for r in rs[:3])
        self.assertEqual((ok["state"], ok["exit_code"]), ("succeeded", 0))
        self.assertIn("hello", ok["summary"]); self.assertNotIn("hunter2", ok["summary"]); self.assertNotIn("192.168", ok["summary"])
        self.assertNotIn("input", ok)
        self.assertEqual((fail["state"], fail["exit_code"]), ("failed", 3))
        self.assertEqual(to["state"], "timeout"); self.assertLess(to["duration_s"], 5)
        art = self.txt(rs[3])
        self.assertTrue(art["redacted"])
        self.assertEqual(base64.b64decode(art["data"]), sclib.redact_artifact(b"data\n"))
        self.assertNotIn("stdout.log", ok.get("artifacts") or [])
        denied = self.gate_proc([self.tc(14, "request_artifact", id=ids[0], name="stdout.log")])
        self.assertTrue(denied[0]["result"]["isError"])
        self.assertNotIn("hunter2", denied[0]["result"]["content"][0]["text"])
        self.assertTrue(rs[4]["result"]["isError"])
        self.assertGreaterEqual(len(self.txt(rs[5])["tasks"]), 3)
        self.assertTrue(self.txt(rs[6])["ok"])
        self.assertTrue(os.path.exists(os.path.join(os.environ["SC_SPOOL"], "artifacts.log")))
    def test_cancel_queued(self):
        r = self.gate_proc([self.tc(1, "submit_task", profile="echo", prompt="x")])
        tid = self.txt(r[0])["id"]
        r = self.gate_proc([self.tc(1, "cancel_task", id=tid), self.tc(2, "task_status", id=tid)])
        self.assertEqual(self.txt(r[1])["state"], "cancelled")
    def test_prompt_profile(self):
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="echo", prompt="hello world")])[0])["id"]
        while worker.once():
            pass
        st = self.txt(self.gate_proc([self.tc(1, "task_status", id=tid)])[0])
        self.assertEqual(st["summary"], "got:hello world")
    def test_artifact_cap(self):
        write_profile({"name": "tiny", "allow_command": True, "requires_approval": False, "network": False,
                       "max_timeout": 5, "artifact_max_bytes": 100})
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="tiny",
                                               command="python3 -c \"open('big.txt','w').write('x'*200)\"")])[0])["id"]
        while worker.once():
            pass
        r = self.gate_proc([self.tc(1, "request_artifact", id=tid, name="big.txt")])
        self.assertIn("cap", self.txt(r[0])["error"])
    def test_rejects_other_commands(self):
        env = dict(os.environ, SSH_ORIGINAL_COMMAND="cat /etc/passwd")
        p = subprocess.run([sys.executable, os.path.join(GATE, "gate.py")], input="", capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 1); self.assertEqual(p.stdout, "")
    def test_parse_error(self):
        env = dict(os.environ); env.pop("SSH_ORIGINAL_COMMAND", None)
        p = subprocess.run([sys.executable, os.path.join(GATE, "gate.py")], input="{bad\n", capture_output=True, text=True, env=env)
        self.assertEqual(json.loads(p.stdout)["error"]["code"], -32700)

class Bootstrap(unittest.TestCase):
    def test_audit_key_ownership_and_mode(self):
        with open(os.path.join(ROOT, "bootstrap.sh")) as fh:
            script = fh.read()
        self.assertIn('run chown root:sc-audit "$ETC/audit.key"', script)
        self.assertIn('chmod 0640 "$ETC/audit.key"\n', script)

    def run_bs(self, prefix, *a):
        env = dict(os.environ, SC_PREFIX=prefix, SC_DRY_RUN="1")
        p = subprocess.run(["bash", os.path.join(ROOT, "bootstrap.sh")] + list(a), capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr
    def test_idempotent_strict_and_open(self):
        pre = tempfile.mkdtemp(); key = PUBKEY
        for _ in range(2):
            rc, out, err = self.run_bs(pre, "--profile", "compute,repo-bridge", "--bot-pubkey", key, "--mode", "strict")
            self.assertEqual(rc, 0, out + err); self.assertTrue(json.loads(out)["ok"])
        ak = open(os.path.join(pre, "home/sidecomputer/.ssh/authorized_keys")).read().splitlines()
        self.assertEqual(len(ak), 1)
        self.assertIn('command="/usr/local/bin/sidecomputer-gate"', ak[0])
        self.assertIn("restrict", ak[0])
        self.assertIn(sclib.fingerprint_pubkey(key), ak[0])
        rc, out, err = self.run_bs(pre, "--profile", "compute", "--bot-pubkey", key, "--mode", "open")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("less safe", json.loads(out)["warning"])
        ak = open(os.path.join(pre, "home/sidecomputer/.ssh/authorized_keys")).read().splitlines()
        self.assertEqual(len(ak), 2)
        self.assertIn('command="/usr/local/bin/sidecomputer-gate"', ak[1])
        self.assertIn("restrict", ak[1])
        self.assertNotRegex(ak[1], r"(^|[^,])restrict,pty")
        self.assertNotEqual(self.run_bs(pre, "--profile", "nope", "--bot-pubkey", key)[0], 0)
        self.assertNotEqual(self.run_bs(pre, "--profile", "compute", "--bot-pubkey", "garbage")[0], 0)

class Client(unittest.TestCase):
    def test_normalize_pem(self):
        try:
            import paramiko
        except ImportError:
            self.skipTest("paramiko not available")
        k = paramiko.RSAKey.generate(2048)
        buf = io.StringIO(); k.write_private_key(buf); pem = buf.getvalue()
        collapsed = pem.replace("\n", " ")
        self.assertEqual(sc_client.load_key(sc_client.normalize_pem(collapsed)).get_base64(), k.get_base64())
        self.assertEqual(sc_client.load_key(sc_client.normalize_pem(pem.replace("\n", "\\n"))).get_base64(), k.get_base64())
    def test_session_against_gate(self):
        env = dict(os.environ); env.pop("SSH_ORIGINAL_COMMAND", None)
        p = subprocess.Popen([sys.executable, os.path.join(GATE, "gate.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        s = sc_client.MCPSession(p.stdout, p.stdin); s.init()
        self.assertEqual(len(s.request("tools/list")["tools"]), 7)
        p.stdin.close(); p.wait(5)

class ReviewFixes(unittest.TestCase):
    def run_until(self, tid, limit=40):
        for _ in range(limit):
            item = worker.once()
            if item is None:
                return None
            if item["id"] == tid:
                return item
        self.fail("task %s was not started" % tid)

    def gate_proc(self, msgs):
        env = dict(os.environ); env.pop("SSH_ORIGINAL_COMMAND", None)
        inp = "".join(json.dumps(m) + "\n" for m in msgs)
        p = subprocess.run([sys.executable, os.path.join(GATE, "gate.py")], input=inp, capture_output=True, text=True, env=env, timeout=20)
        return [json.loads(line) for line in p.stdout.splitlines()]
    def tc(self, i, tool, **kwargs):
        return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": kwargs}}
    def txt(self, response):
        return json.loads(response["result"]["content"][0]["text"])

    def test_redirected_artifact_is_redacted(self):
        write_profile({"name": "redirect", "allow_command": True, "requires_approval": False, "network": False,
                       "max_timeout": 5, "artifact_max_bytes": 10000})
        command = "printf 'password=hunter2\\n10.1.2.3\\nsafe-line\\n' > out.txt"
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="redirect", command=command)])[0])["id"]
        while worker.once():
            pass
        response = self.gate_proc([self.tc(1, "request_artifact", id=tid, name="out.txt")])[0]
        body = self.txt(response)
        data = base64.b64decode(body["data"])
        self.assertTrue(body["redacted"])
        self.assertNotIn(b"hunter2", data)
        self.assertNotIn(b"10.1.2.3", data)
        self.assertIn(b"safe-line", data)
        self.assertIn(b"[REDACTED", data)
        raw = open(os.path.join(os.environ["SC_SPOOL"], "private", tid, "stdout.log")).read()
        self.assertNotIn("hunter2", raw)

    def test_stdout_log_is_not_downloadable(self):
        write_profile({"name": "logs", "allow_command": True, "requires_approval": False, "network": False,
                       "max_timeout": 5, "artifact_max_bytes": 10000})
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="logs",
                                               command="echo password=hunter2; echo 10.0.0.1")])[0])["id"]
        while worker.once():
            pass
        raw_path = os.path.join(os.environ["SC_SPOOL"], "private", tid, "stdout.log")
        self.assertIn("hunter2", open(raw_path).read())
        self.assertFalse(os.path.exists(os.path.join(os.environ["SC_SPOOL"], "artifacts", tid, "stdout.log")))
        for name in ("stdout.log", "stderr.log"):
            response = self.gate_proc([self.tc(1, "request_artifact", id=tid, name=name)])[0]
            self.assertTrue(response["result"]["isError"])
            self.assertNotIn("hunter2", response["result"]["content"][0]["text"])
            self.assertNotIn("10.0.0.1", response["result"]["content"][0]["text"])
        status = self.txt(self.gate_proc([self.tc(1, "task_status", id=tid)])[0])
        self.assertNotIn("hunter2", status["summary"])
        self.assertNotIn("10.0.0.1", status["summary"])

    def test_forged_queue_entry_rejected(self):
        tid = "abc123abc123"
        sclib.write_json(sclib.spool("queue", tid + ".json"), {
            "id": tid, "profile": "echo", "kind": "command", "input": "echo PWNED > pwned.txt",
            "timeout": 5, "state": "queued", "requester": "tester", "key_id": "test-key"})
        done = self.run_until(tid)
        self.assertEqual(done["state"], "rejected")
        self.assertIn("allow", done["summary"])
        self.assertFalse(os.path.exists(sclib.spool("artifacts", tid, "pwned.txt")))
        self.assertNotIn("input", done)

    def test_timeout_is_clamped_on_recheck(self):
        tid = "def456def456"
        sclib.write_json(sclib.spool("queue", tid + ".json"), {
            "id": tid, "profile": "echo", "kind": "prompt", "input": "clamped",
            "timeout": 99999, "state": "queued", "requester": "tester", "key_id": "test-key"})
        done = self.run_until(tid)
        self.assertEqual(done["state"], "succeeded")
        self.assertEqual(done["timeout"], 5)

    def test_symlink_artifact_rejected(self):
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="echo", prompt="hello")])[0])["id"]
        while worker.once():
            pass
        adir = sclib.spool("artifacts", tid)
        os.symlink("/etc/passwd", os.path.join(adir, "link.txt"))
        response = self.gate_proc([self.tc(1, "request_artifact", id=tid, name="link.txt")])[0]
        self.assertTrue(response["result"]["isError"])
        self.assertNotIn("root:", response["result"]["content"][0]["text"])
        secret = os.path.join(os.environ["SC_SPOOL"], "private", tid, "stdout.log")
        os.symlink(secret, os.path.join(adir, "alias.txt"))
        response = self.gate_proc([self.tc(1, "request_artifact", id=tid, name="alias.txt")])[0]
        self.assertTrue(response["result"]["isError"])

    def test_host_key_policy_refuses_tofu(self):
        try:
            import paramiko
        except ImportError:
            self.skipTest("paramiko not available")
        client = paramiko.SSHClient()
        with self.assertRaises(sc_client.HostKeyError):
            sc_client.configure_host_keys(client, "/no/such/known_hosts", accept_new=False)
        with self.assertRaises(sc_client.HostKeyError):
            sc_client.connect("127.0.0.1", 1, "sidecomputer", key=None, known_hosts="", accept_new=False)
        known = os.path.join(TMP, "known_hosts")
        open(known, "w").close()
        pinned = paramiko.SSHClient()
        sc_client.configure_host_keys(pinned, known, accept_new=False)
        self.assertIsInstance(pinned._policy, paramiko.RejectPolicy)
        opted = paramiko.SSHClient()
        sc_client.configure_host_keys(opted, "/no/such/known_hosts", accept_new=True)
        self.assertIsInstance(opted._policy, paramiko.AutoAddPolicy)
        self.assertNotIn("WarningPolicy", open(sc_client.__file__).read())

    def test_audit_chain_records_requester_and_detects_tampering(self):
        err, out = call("submit_task", profile="echo", prompt="audit-me", requester="owner-bot")
        self.assertFalse(err)
        ok, reason = sclib.verify_audit()
        self.assertTrue(ok, reason)
        records = [rec for rec in sclib.read_audit() if rec.get("op") == "submit" and rec.get("id") == out["id"]]
        self.assertEqual(records[-1]["requester"], "owner-bot")
        self.assertEqual(records[-1]["key_id"], "test-key")
        path = sclib.spool("audit.log")
        lines = open(path).read().splitlines()
        tampered = json.loads(lines[-1])
        tampered["requester"] = "mallory"
        lines[-1] = json.dumps(tampered)
        open(path, "w").write("\n".join(lines) + "\n")
        ok, reason = sclib.verify_audit()
        self.assertFalse(ok)
        self.assertIn("hash", reason)
        # Restore a valid chain for later tests by dropping the torn tail via a fresh spool file rewrite
        # is not possible without the key; rebuild from the untampered prefix.
        open(path, "w").write("\n".join(lines[:-1]) + ("\n" if lines[:-1] else ""))
        ok, reason = sclib.verify_audit()
        self.assertTrue(ok, reason)

    def test_audit_gap_is_detected(self):
        call("submit_task", profile="echo", prompt="gap-a", requester="owner-bot")
        call("submit_task", profile="echo", prompt="gap-b", requester="owner-bot")
        path = sclib.spool("audit.log")
        lines = [line for line in open(path).read().splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 2)
        # Keep only the tail so its prev hash no longer matches the new head.
        open(path, "w").write(lines[-1] + "\n")
        ok, _reason = sclib.verify_audit()
        self.assertFalse(ok)
        open(path, "w").write("\n".join(lines) + "\n")
        ok, reason = sclib.verify_audit()
        self.assertTrue(ok, reason)

    def test_consequential_task_waits_for_human_approval(self):
        err, out = call("submit_task", profile="compute", command="echo RAN > ran.txt", timeout=30)
        self.assertFalse(err)
        self.assertEqual(out["state"], "pending_approval")
        self.assertIsNone(self.run_until(out["id"]))
        self.assertEqual(sclib.find_task(out["id"])[0], "pending")
        forged = "fedcba654321"
        sclib.write_json(sclib.spool("queue", forged + ".json"), {
            "id": forged, "profile": "compute", "kind": "command", "input": "echo NOPE > nope.txt",
            "timeout": 30, "state": "queued", "requester": "tester", "key_id": "test-key", "approved_by": "root"})
        rejected = self.run_until(forged)
        self.assertEqual(rejected["state"], "rejected")
        self.assertIn("approval", rejected["summary"])
        sclib.approve_task(out["id"], approver="tester")
        task = sclib.read_json(sclib.spool("queue", out["id"] + ".json"))
        task["input"] = "echo HACKED > ran.txt"
        sclib.write_json(sclib.spool("queue", out["id"] + ".json"), task)
        mismatched = self.run_until(out["id"])
        self.assertEqual(mismatched["id"], out["id"])
        self.assertEqual(mismatched["state"], "rejected")
        err, again = call("submit_task", profile="compute", command="echo RAN > ran.txt", timeout=30)
        self.assertFalse(err)
        sclib.approve_task(again["id"], approver="tester")
        done = self.run_until(again["id"])
        self.assertEqual(done["id"], again["id"])
        self.assertEqual(done["state"], "succeeded")
        self.assertTrue(os.path.exists(sclib.spool("artifacts", again["id"], "ran.txt")))

    def test_egress_denied_unless_scope_can_enforce_it(self):
        write_profile({"name": "net", "allow_command": True, "requires_approval": False, "network": True,
                       "max_timeout": 5, "artifact_max_bytes": 1000})
        err, out = call("submit_task", profile="net", command="echo LEAK > net.txt")
        self.assertFalse(err)
        done = self.run_until(out["id"])
        self.assertEqual(done["id"], out["id"])
        self.assertEqual(done["state"], "rejected")
        self.assertIn("egress", done["summary"])
        self.assertFalse(os.path.exists(sclib.spool("artifacts", out["id"], "net.txt")))
        self.assertIn("IPAddressDeny=any", worker.egress_properties({}))
        self.assertIn("IPAddressAllow=localhost", worker.egress_properties({}))
        self.assertEqual(worker.egress_properties({"network": True}), [])
        props = worker.resource_properties({"memory_max": "4G", "cpu_quota": "200%", "tasks_max": 256})
        self.assertIn("MemoryMax=4G", props)
        self.assertFalse(any("RLIMIT" in item for item in props))

    def test_key_grant_scopes_profiles(self):
        err, own = call("submit_task", profile="echo", prompt="mine", requester="owner-bot")
        self.assertFalse(err)
        original = sclib.load_grants()
        try:
            sclib.write_grant(os.environ["SC_GRANTS"], "test-key", ["echo"])
            sclib.write_grant(os.environ["SC_GRANTS"], "other-key", ["compute"])
            denied, body = call("submit_task", profile="compute", command="true")
            self.assertTrue(denied)
            self.assertIn("not granted", body["error"])
            os.environ["SC_KEY_ID"] = "other-key"
            hidden, _body = call("task_status", id=own["id"])
            self.assertTrue(hidden)
            os.environ["SC_KEY_ID"] = "test-key"
            allowed, _body = call("submit_task", profile="echo", prompt="still-ok")
            self.assertFalse(allowed)
        finally:
            os.environ["SC_KEY_ID"] = "test-key"
            sclib.write_grant(os.environ["SC_GRANTS"], "test-key", original["test-key"]["profiles"])

    def test_prompt_dash_is_not_a_flag(self):
        argv = worker.command_argv({"kind": "prompt", "input": "-n"}, {"prompt_runner": ["/bin/echo", "{prompt}"]})
        self.assertEqual(argv, ["/bin/echo", "--", "-n"])
        write_profile({"name": "dash", "allow_command": False, "requires_approval": False, "network": False,
                       "prompt_runner": ["/usr/bin/python3", "-c",
                                         "import sys; raise SystemExit(0 if sys.argv[1:]==['--','-n'] else 1)",
                                         "{prompt}"],
                       "max_timeout": 5, "artifact_max_bytes": 1000})
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="dash", prompt="-n")])[0])["id"]
        while worker.once():
            pass
        status = self.txt(self.gate_proc([self.tc(1, "task_status", id=tid)])[0])
        self.assertEqual(status["state"], "succeeded", status)

    def test_rlimit_as_not_applied(self):
        before = resource.getrlimit(resource.RLIMIT_AS)[0]
        out = subprocess.check_output(
            [sys.executable, "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])"],
            preexec_fn=lambda: worker.apply_rlimits(3), text=True)
        self.assertEqual(int(out.strip()), before)

    def test_cancel_during_start_does_not_run(self):
        write_profile({"name": "race", "allow_command": True, "requires_approval": False, "network": False,
                       "max_timeout": 5, "artifact_max_bytes": 1000})
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="race",
                                               command="echo RAN > ran.txt")])[0])["id"]
        def hook(claimed):
            if claimed == tid:
                sclib.request_cancel(claimed)
        worker.BEFORE_EXEC = hook
        try:
            done = self.run_until(tid)
        finally:
            worker.BEFORE_EXEC = None
        self.assertEqual(done["id"], tid)
        self.assertEqual(done["state"], "cancelled")
        self.assertFalse(os.path.exists(sclib.spool("artifacts", tid, "ran.txt")))

    def test_spool_policy_locks_out_ssh_user_and_worker(self):
        self.assertFalse(sclib.can("sidecomputer", "queue", "write"))
        self.assertFalse(sclib.can("sc-worker", "queue", "write"))
        self.assertTrue(sclib.can("sc-gate", "queue", "write"))
        self.assertTrue(sclib.can("sc-worker", "queue", "read"))
        self.assertFalse(sclib.can("sidecomputer", "done", "write"))
        self.assertFalse(sclib.can("sc-task", "done", "write"))
        self.assertFalse(sclib.can("sc-task", "artifacts", "read"))
        self.assertFalse(sclib.can("sidecomputer", "artifacts", "read"))
        self.assertFalse(sclib.can("sidecomputer", "private", "read"))
        self.assertFalse(sclib.can("sc-gate", "private", "read"))
        self.assertFalse(sclib.can("sc-task", "private", "read"))
        self.assertFalse(sclib.can("sc-worker", "approvals", "write"))
        self.assertFalse(sclib.can("sc-gate", "approvals", "write"))
        self.assertFalse(sclib.can("sidecomputer", "audit.log", "append"))
        self.assertFalse(sclib.can("sc-worker", "audit.log", "edit"))
        self.assertFalse(sclib.can("sc-gate", "audit.log", "edit"))
        self.assertTrue(sclib.can("sc-worker", "audit.log", "append"))
        self.assertFalse(sclib.can("sc-worker", "spool", "write"))
        self.assertFalse(sclib.can("sc-task", "queue", "read"))

    def test_readme_points_at_skills_repo(self):
        text = open(os.path.join(ROOT, "README.md")).read()
        self.assertNotIn("skills/sidecomputer-dispatch.md", text)
        self.assertNotIn("| `skills/` |", text)
        self.assertIn("vaiev/skills", text)
        self.assertIn("sidecomputer/dispatch/SKILL.md", text)

    def test_no_rotate_bot_key_anywhere(self):
        blob = ""
        for dirpath, _dirs, files in os.walk(ROOT):
            if os.path.basename(dirpath) == "tests":
                continue
            for name in files:
                if name.endswith((".py", ".sh", ".md", ".json")):
                    blob += open(os.path.join(dirpath, name)).read()
        self.assertNotIn("rotate_bot_key", blob)

    def test_chown_helper_rejects_non_root_and_escaping_links(self):
        import chown_artifact
        self.assertEqual(chown_artifact.main(["grant", "abc123abc123"]), 1)
        root = tempfile.mkdtemp()
        os.mkdir(os.path.join(root, "ok"))
        link = os.path.join(root, "ok", "passwd")
        os.symlink("/etc/passwd", link)
        self.assertFalse(chown_artifact.member_stays_inside(link, root))
        self.assertTrue(chown_artifact.member_stays_inside(os.path.join(root, "ok"), root))

    def test_bootstrap_rotation_and_host_fingerprint(self):
        with tempfile.TemporaryDirectory() as pre:
            env = dict(os.environ, SC_PREFIX=pre, SC_DRY_RUN="1")
            script = ["bash", os.path.join(ROOT, "bootstrap.sh"), "--profile", "compute", "--bot-pubkey"]
            def bootstrap(key, *options):
                result = subprocess.run(script + [key] + list(options), capture_output=True, text=True, env=env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)
            first = bootstrap(PUBKEY)
            self.assertEqual(first.get("host_key_fingerprint"), "")
            ak = os.path.join(pre, "home/sidecomputer/.ssh/authorized_keys")
            old_line = open(ak).read().strip()
            with open(ak, "a") as fh:
                fh.write('command="/usr/local/bin/sidecomputer-gate",restrict ssh-ed25519 AAAA legacy\n')
                fh.write('ssh-ed25519 AAAA sidecomputer-bot\n')
                fh.write('ssh-ed25519 AAAA unrelated-admin\n')
            host = os.path.join(pre, "etc/ssh/ssh_host_ed25519_key")
            new_key = "ssh-ed25519 " + base64.b64encode(b"replacement key").decode() + " new-bot"
            with open(host + ".pub", "w") as fh:
                fh.write(new_key + "\n")
            expected = "256 SHA256:test-host sidecomputer-host (ED25519)"
            bindir = os.path.join(pre, "bin")
            os.mkdir(bindir)
            keygen = os.path.join(bindir, "ssh-keygen")
            with open(keygen, "w") as fh:
                fh.write('#!/bin/sh\n[ "$1" = "-lf" ] && [ "$2" = "$SC_PREFIX/etc/ssh/ssh_host_ed25519_key.pub" ] || exit 1\n')
                fh.write("echo '" + expected + "'\n")
            os.chmod(keygen, 0o755)
            env["PATH"] = bindir + os.pathsep + env["PATH"]
            rotated = bootstrap(new_key, "--rotate")
            self.assertEqual(rotated["host_key_fingerprint"], expected)
            lines = open(ak).read().splitlines()
            self.assertNotIn(old_line, lines)
            self.assertFalse(any("legacy" in line for line in lines))
            self.assertNotIn('ssh-ed25519 AAAA sidecomputer-bot', lines)
            self.assertIn('ssh-ed25519 AAAA unrelated-admin', lines)
            self.assertTrue(any(new_key.split()[1] in line and "sidecomputer-bot" in line for line in lines))
            grants = sclib.load_grants(os.path.join(pre, "etc/sidecomputer/grants.json"))
            self.assertEqual(grants, {sclib.fingerprint_pubkey(new_key): {"profiles": ["compute"]}})

    def test_bootstrap_lockdown_and_die_json(self):
        text = open(os.path.join(ROOT, "bootstrap.sh")).read()
        self.assertNotIn("2770", text)
        self.assertNotIn("UMask=0007", text)
        pre = tempfile.mkdtemp()
        env = dict(os.environ, SC_PREFIX=pre, SC_DRY_RUN="1")
        bad = subprocess.run(["bash", os.path.join(ROOT, "bootstrap.sh"), 'bad"quote'],
                             capture_output=True, text=True, env=env)
        parsed = json.loads(bad.stdout)
        self.assertFalse(parsed["ok"])
        self.assertIn('"quote', parsed["error"])
        subprocess.run(["bash", os.path.join(ROOT, "bootstrap.sh"), "--profile", "compute",
                        "--bot-pubkey", PUBKEY, "--mode", "strict"],
                       check=True, capture_output=True, text=True, env=env)
        unit = open(os.path.join(pre, "etc/systemd/system/sidecomputer-worker.service")).read()
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=localhost", unit)
        mode = os.stat(os.path.join(pre, "var/lib/sidecomputer/queue")).st_mode
        self.assertTrue(mode & stat.S_ISGID)
        self.assertEqual(mode & 0o777, 0o750)
        key_mode = os.stat(os.path.join(pre, "etc/sidecomputer/audit.key")).st_mode & 0o777
        self.assertEqual(key_mode & 0o007, 0)
        grants = json.load(open(os.path.join(pre, "etc/sidecomputer/grants.json")))
        self.assertEqual(grants["keys"][sclib.fingerprint_pubkey(PUBKEY)]["profiles"], ["compute"])
        sudoers = open(os.path.join(pre, "etc/sudoers.d/sidecomputer")).read()
        self.assertNotIn("sidecomputer ALL=(root)", sudoers)
        self.assertIn("chown_artifact.py", sudoers)

if __name__ == "__main__":
    unittest.main(verbosity=2)
