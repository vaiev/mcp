#!/usr/bin/env python3
"""Box-side SideComputer client: SSH (paramiko) -> forced-command gate -> MCP.
Usage: sc_client.py --host H [--port 22] --user sidecomputer --key-env SIDECOMPUTER_SSH_KEY tools|call <tool> '<json>'"""
import argparse, io, json, os, re, sys

def normalize_pem(raw):
    """Rebuild a private key whose newlines were collapsed into spaces (or literal \\n)."""
    raw = raw.strip().replace("\\n", "\n").replace("\r", "")
    m = re.search(r"(-----BEGIN [A-Z0-9 ]+-----)(.*?)(-----END [A-Z0-9 ]+-----)", raw, re.S)
    if not m:
        raise ValueError("no PEM BEGIN/END markers found")
    begin, body, end = m.groups()
    lines = [l.strip() for l in body.strip().split("\n")]
    headers = [l for l in lines if ":" in l]  # legacy 'Proc-Type:' headers
    b64 = "".join(re.sub(r"\s+", "", l) for l in lines if ":" not in l)
    out = [begin] + headers + ([""] if headers else []) + [b64[i:i + 64] for i in range(0, len(b64), 64)] + [end]
    return "\n".join(out) + "\n"

def load_key(pem):
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem))
        except Exception:
            continue
    raise ValueError("unsupported or invalid private key")

class MCPSession:
    def __init__(self, rfile, wfile):
        self.r, self.w, self.n = rfile, wfile, 0
    def _send(self, obj):
        self.w.write((json.dumps(obj) + "\n").encode()); self.w.flush()
    def request(self, method, params=None):
        self.n += 1
        self._send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}})
        while True:
            line = self.r.readline()
            if not line:
                raise RuntimeError("gate closed the connection")
            msg = json.loads(line)
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(msg["error"].get("message"))
                return msg["result"]
    def init(self):
        r = self.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                        "clientInfo": {"name": "sc_client", "version": "0.1.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

def connect(host, port, user, key, known_hosts=None):
    import paramiko
    c = paramiko.SSHClient()
    if known_hosts and os.path.exists(known_hosts):
        c.load_host_keys(known_hosts); c.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        c.set_missing_host_key_policy(paramiko.WarningPolicy())
    c.connect(host, port=port, username=user, pkey=key, allow_agent=False, look_for_keys=False, timeout=20)
    ch = c.get_transport().open_session()
    ch.exec_command("mcp")
    return c, MCPSession(ch.makefile("rb"), ch.makefile_stdin("wb"))

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True); ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", default="sidecomputer"); ap.add_argument("--key-env", default="SIDECOMPUTER_SSH_KEY")
    ap.add_argument("--known-hosts", default=os.path.expanduser("~/.ssh/known_hosts"))
    ap.add_argument("action", choices=["tools", "call"]); ap.add_argument("tool", nargs="?"); ap.add_argument("args", nargs="?", default="{}")
    a = ap.parse_args(argv)
    raw = os.environ.get(a.key_env)
    if not raw:
        sys.exit("env var %s is empty" % a.key_env)
    client, s = connect(a.host, a.port, a.user, load_key(normalize_pem(raw)), a.known_hosts)
    try:
        s.init()
        if a.action == "tools":
            res = s.request("tools/list")
        else:
            if not a.tool:
                sys.exit("call needs <tool>")
            res = s.request("tools/call", {"name": a.tool, "arguments": json.loads(a.args)})
        print(json.dumps(res, indent=2))
    finally:
        client.close()

if __name__ == "__main__":
    main()
