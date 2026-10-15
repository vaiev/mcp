#!/usr/bin/env python3
"""Box-side SideComputer client: SSH (paramiko) -> forced-command gate -> MCP.
Usage: sc_client.py --host H [--port 22] --user sidecomputer --key-env SIDECOMPUTER_SSH_KEY tools|call <tool> '<json>'

Host keys are required. A missing known_hosts file is a refusal, not trust-on-first-use.
Pass --accept-new once, on purpose, to store a new host key.
"""
import argparse, io, json, os, re, sys

try:
    import paramiko
except ImportError:  # the gate does not need paramiko; the client does
    paramiko = None

class HostKeyError(RuntimeError):
    pass

def normalize_pem(raw):
    """Rebuild a private key whose newlines were collapsed into spaces (or literal \\n)."""
    raw = raw.strip().replace("\\n", "\n").replace("\r", "")
    match = re.search(r"(-----BEGIN [A-Z0-9 ]+-----)(.*?)(-----END [A-Z0-9 ]+-----)", raw, re.S)
    if not match:
        raise ValueError("no PEM BEGIN/END markers found")
    begin, body, end = match.groups()
    lines = [line.strip() for line in body.strip().split("\n")]
    headers = [line for line in lines if ":" in line]
    b64 = "".join(re.sub(r"\s+", "", line) for line in lines if ":" not in line)
    out = [begin] + headers + ([""] if headers else []) + [b64[i:i + 64] for i in range(0, len(b64), 64)] + [end]
    return "\n".join(out) + "\n"

def load_key(pem):
    if paramiko is None:
        raise RuntimeError("paramiko is not installed")
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
        result = self.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                              "clientInfo": {"name": "sc_client", "version": "0.2.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

def configure_host_keys(client, known_hosts, accept_new=False):
    """Reject unknown hosts unless accept_new is explicit. Never fall back to warning-and-accept."""
    if paramiko is None:
        raise RuntimeError("paramiko is not installed")
    if accept_new:
        if known_hosts and os.path.isfile(known_hosts):
            client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client
    if not known_hosts or not os.path.isfile(known_hosts):
        raise HostKeyError("known_hosts is missing; refusing to connect (pass --accept-new to opt in)")
    client.load_host_keys(known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client

def connect(host, port, user, key, known_hosts=None, accept_new=False):
    if paramiko is None:
        raise RuntimeError("paramiko is not installed")
    client = paramiko.SSHClient()
    configure_host_keys(client, known_hosts, accept_new=accept_new)
    client.connect(host, port=port, username=user, pkey=key, allow_agent=False, look_for_keys=False, timeout=20)
    channel = client.get_transport().open_session()
    channel.exec_command("mcp")
    return client, MCPSession(channel.makefile("rb"), channel.makefile_stdin("wb"))

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="sidecomputer")
    parser.add_argument("--key-env", default="SIDECOMPUTER_SSH_KEY")
    parser.add_argument("--known-hosts", default=os.path.expanduser("~/.ssh/known_hosts"))
    parser.add_argument("--accept-new", action="store_true",
                        help="opt in to storing a new host key; without this, a missing known_hosts file is refused")
    parser.add_argument("action", choices=["tools", "call"])
    parser.add_argument("tool", nargs="?")
    parser.add_argument("args", nargs="?", default="{}")
    args = parser.parse_args(argv)
    raw = os.environ.get(args.key_env)
    if not raw:
        sys.exit("env var %s is empty" % args.key_env)
    client, session = connect(args.host, args.port, args.user, load_key(normalize_pem(raw)),
                              args.known_hosts, accept_new=args.accept_new)
    try:
        session.init()
        if args.action == "tools":
            result = session.request("tools/list")
        else:
            if not args.tool:
                sys.exit("call needs <tool>")
            result = session.request("tools/call", {"name": args.tool, "arguments": json.loads(args.args)})
        print(json.dumps(result, indent=2))
    finally:
        client.close()

if __name__ == "__main__":
    main()
