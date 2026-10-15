import json, os, subprocess, sys, tempfile, time, unittest, shutil
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
GATE = os.path.join(ROOT, "gate")
TMP = tempfile.mkdtemp(prefix="sc-test-")
os.environ["SC_SPOOL"] = os.path.join(TMP, "spool"); os.environ["SC_PROFILES"] = os.path.join(TMP, "profiles")
os.environ["SC_SYSTEMD_RUN"] = "0"
shutil.copytree(os.path.join(ROOT, "profiles"), os.environ["SC_PROFILES"])
with open(os.path.join(os.environ["SC_PROFILES"], "echo.json"), "w") as f:
    json.dump({"name": "echo", "allow_command": False, "prompt_runner": ["/bin/echo", "got:{prompt}"],
               "max_timeout": 5, "artifact_max_bytes": 100}, f)
sys.path.insert(0, GATE); sys.path.insert(0, os.path.join(ROOT, "client"))
import sclib, gate, worker, sc_client

def call(_tool, **args):
    r = gate.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": _tool, "arguments": args}})
    res = r["result"]; return res["isError"], json.loads(res["content"][0]["text"])

class JsonRpc(unittest.TestCase):
    def test_initialize_and_list(self):
        r = gate.handle({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}})
        self.assertEqual(r["id"], 7); self.assertIn("tools", r["result"]["capabilities"])
        names = {t["name"] for t in gate.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
        self.assertEqual(names, {"submit_task", "task_status", "list_tasks", "cancel_task", "list_profiles", "request_artifact", "health"})
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
        art = self.txt(rs[3]); import base64
        self.assertEqual(base64.b64decode(art["data"]), b"data\n")
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
        tid = self.txt(self.gate_proc([self.tc(1, "submit_task", profile="echo", prompt="z" * 300)])[0])["id"]
        while worker.once():
            pass
        r = self.gate_proc([self.tc(1, "request_artifact", id=tid, name="stdout.log")])
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
    def run_bs(self, prefix, *a):
        env = dict(os.environ, SC_PREFIX=prefix, SC_DRY_RUN="1")
        p = subprocess.run(["bash", os.path.join(ROOT, "bootstrap.sh")] + list(a), capture_output=True, text=True, env=env)
        return p.returncode, p.stdout
    def test_idempotent_strict_and_open(self):
        pre = tempfile.mkdtemp(); key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly bot"
        for _ in range(2):
            rc, out = self.run_bs(pre, "--profile", "compute,repo-bridge", "--bot-pubkey", key, "--mode", "strict")
            self.assertEqual(rc, 0, out); self.assertTrue(json.loads(out)["ok"])
        ak = open(os.path.join(pre, "home/sidecomputer/.ssh/authorized_keys")).read().splitlines()
        self.assertEqual(len(ak), 1); self.assertTrue(ak[0].startswith('command="/usr/local/bin/sidecomputer-gate",restrict '))
        rc, out = self.run_bs(pre, "--profile", "compute", "--bot-pubkey", key, "--mode", "open")
        self.assertIn("less safe", json.loads(out)["warning"])
        ak = open(os.path.join(pre, "home/sidecomputer/.ssh/authorized_keys")).read().splitlines()
        self.assertEqual(len(ak), 2); self.assertNotIn("sidecomputer-gate", ak[1])
        self.assertNotEqual(self.run_bs(pre, "--profile", "nope", "--bot-pubkey", key)[0], 0)
        self.assertNotEqual(self.run_bs(pre, "--profile", "compute", "--bot-pubkey", "garbage")[0], 0)

class Client(unittest.TestCase):
    def test_normalize_pem(self):
        try:
            import paramiko
        except ImportError:
            self.skipTest("paramiko not available")
        k = paramiko.RSAKey.generate(2048); import io
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
