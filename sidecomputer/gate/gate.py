#!/usr/bin/env python3
"""sidecomputer-gate: forced-command MCP stdio server (JSON-RPC 2.0). stdlib only."""
import base64, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import sclib as L

VERSION = "0.1.0"
PROTO = "2024-11-05"
MAX_LINE = 65536
MAX_INPUT = 8000

def _s(t, **kw):
    return dict(type=t, **kw)

TOOLS = [
    {"name": "submit_task", "description": "Queue a task in a declared profile. Returns task id.",
     "inputSchema": {"type": "object", "properties": {"profile": _s("string"), "command": _s("string"),
                     "prompt": _s("string"), "timeout": _s("integer", minimum=1)}, "required": ["profile"]}},
    {"name": "task_status", "description": "Status, exit code, duration and redacted summary of a task.",
     "inputSchema": {"type": "object", "properties": {"id": _s("string")}, "required": ["id"]}},
    {"name": "list_tasks", "description": "List recent tasks (public fields only).",
     "inputSchema": {"type": "object", "properties": {"limit": _s("integer", minimum=1, maximum=100)}}},
    {"name": "cancel_task", "description": "Cancel a queued or running task.",
     "inputSchema": {"type": "object", "properties": {"id": _s("string")}, "required": ["id"]}},
    {"name": "list_profiles", "description": "List admin-declared profiles.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "request_artifact", "description": "Fetch one named artifact of a finished task (size-capped, logged).",
     "inputSchema": {"type": "object", "properties": {"id": _s("string"), "name": _s("string")}, "required": ["id", "name"]}},
    {"name": "health", "description": "Gate and queue health.", "inputSchema": {"type": "object", "properties": {}}},
]

class ToolError(Exception):
    pass

def t_submit(a):
    profs = L.load_profiles()
    p = profs.get(a.get("profile"))
    if not p:
        raise ToolError("unknown profile")
    cmd, prompt = a.get("command"), a.get("prompt")
    if (cmd is None) == (prompt is None):
        raise ToolError("give exactly one of command or prompt")
    text = cmd if cmd is not None else prompt
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_INPUT or "\x00" in text:
        raise ToolError("invalid command/prompt")
    if cmd is not None and not p.get("allow_command"):
        raise ToolError("profile does not allow raw commands")
    if prompt is not None and not p.get("prompt_runner"):
        raise ToolError("profile has no prompt runner")
    mx = p.get("max_timeout", 3600)
    to = a.get("timeout", min(600, mx))
    if not isinstance(to, int) or isinstance(to, bool) or to < 1:
        raise ToolError("invalid timeout")
    to = min(to, mx)
    tid = L.new_id()
    task = {"id": tid, "profile": p["name"], "kind": "command" if cmd is not None else "prompt",
            "input": text, "timeout": to, "state": "queued", "submitted_at": time.time()}
    L.write_json(L.spool("queue", tid + ".json"), task)
    L.log("audit.log", {"op": "submit", "id": tid, "profile": p["name"], "kind": task["kind"]})
    return {"id": tid, "state": "queued", "timeout": to}

def t_status(a):
    st, t = L.find_task(a.get("id"))
    if not t:
        raise ToolError("unknown task")
    return L.public_view(t)

def t_list(a):
    lim = a.get("limit", 20)
    if not isinstance(lim, int) or not 1 <= lim <= 100:
        lim = 20
    items = []
    for st in ("queue", "running", "done"):
        d = L.spool(st)
        for f in os.listdir(d) if os.path.isdir(d) else []:
            if f.endswith(".json"):
                try:
                    t = L.read_json(os.path.join(d, f))
                    items.append({k: t.get(k) for k in ("id", "profile", "state", "exit_code", "submitted_at")})
                except (OSError, ValueError):
                    pass
    items.sort(key=lambda x: x.get("submitted_at") or 0, reverse=True)
    return {"tasks": items[:lim]}

def t_cancel(a):
    tid = a.get("id")
    st, t = L.find_task(tid)
    if not t:
        raise ToolError("unknown task")
    if st == "queue":
        src = L.spool("queue", tid + ".json")
        t.update(state="cancelled", finished_at=time.time(), summary="cancelled before start")
        L.write_json(L.spool("done", tid + ".json"), t)
        try:
            os.unlink(src)
        except FileNotFoundError:
            pass
    elif st == "running":
        open(L.spool("running", tid + ".cancel"), "w").close()
    else:
        return {"id": tid, "state": t.get("state"), "note": "already finished"}
    L.log("audit.log", {"op": "cancel", "id": tid})
    return {"id": tid, "state": "cancelled" if st == "queue" else "cancelling"}

def t_profiles(a):
    return {"profiles": [{"name": p["name"], "description": p.get("description", ""),
                          "allow_command": bool(p.get("allow_command")), "prompt": bool(p.get("prompt_runner")),
                          "max_timeout": p.get("max_timeout", 3600)} for p in L.load_profiles().values()]}

def t_artifact(a):
    tid, name = a.get("id"), a.get("name")
    st, t = L.find_task(tid)
    if not t or st != "done":
        raise ToolError("task unknown or not finished")
    if not isinstance(name, str) or not L.NAME_RE.match(name) or name.startswith("."):
        raise ToolError("invalid artifact name")
    base = os.path.realpath(L.spool("artifacts", tid))
    path = os.path.realpath(os.path.join(base, name))
    if os.path.dirname(path) != base or not os.path.isfile(path):
        raise ToolError("artifact not found")
    cap = L.load_profiles().get(t.get("profile"), {}).get("artifact_max_bytes", 262144)
    size = os.path.getsize(path)
    ok = size <= cap
    L.log("artifacts.log", {"op": "request_artifact", "id": tid, "name": name, "size": size, "granted": ok})
    if not ok:
        raise ToolError("artifact exceeds cap (%d > %d bytes)" % (size, cap))
    with open(path, "rb") as fh:
        data = fh.read(cap + 1)
    return {"id": tid, "name": name, "size": size, "encoding": "base64", "data": base64.b64encode(data).decode()}

def t_health(a):
    c = {s: len([f for f in os.listdir(L.spool(s)) if f.endswith(".json")]) if os.path.isdir(L.spool(s)) else -1
         for s in ("queue", "running", "done")}
    hb = L.spool("worker.heartbeat")
    age = time.time() - os.path.getmtime(hb) if os.path.exists(hb) else None
    return {"ok": True, "version": VERSION, "counts": c,
            "worker_alive": age is not None and age < 30, "profiles": len(L.load_profiles())}

HANDLERS = {"submit_task": t_submit, "task_status": t_status, "list_tasks": t_list, "cancel_task": t_cancel,
            "list_profiles": t_profiles, "request_artifact": t_artifact, "health": t_health}

def err(i, code, msg):
    return {"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": msg}}

def handle(msg):
    """Handle one JSON-RPC message; returns response dict or None (notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return err(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
    i, m, params = msg.get("id"), msg["method"], msg.get("params") or {}
    notif = "id" not in msg
    if m == "initialize":
        r = {"protocolVersion": PROTO, "capabilities": {"tools": {}},
             "serverInfo": {"name": "sidecomputer-gate", "version": VERSION}}
    elif m.startswith("notifications/"):
        return None
    elif m == "ping":
        r = {}
    elif m == "tools/list":
        r = {"tools": TOOLS}
    elif m == "tools/call":
        if not isinstance(params, dict):
            return err(i, -32602, "Invalid params")
        name, args = params.get("name"), params.get("arguments") or {}
        h = HANDLERS.get(name)
        if not h or not isinstance(args, dict):
            return err(i, -32602, "Unknown tool or bad arguments")
        try:
            out, is_err = h(args), False
        except ToolError as e:
            out, is_err = {"error": str(e)}, True
        except Exception:
            out, is_err = {"error": "internal error"}, True
        r = {"content": [{"type": "text", "text": json.dumps(out)}], "isError": is_err}
    else:
        return None if notif else err(i, -32601, "Method not found")
    return None if notif else {"jsonrpc": "2.0", "id": i, "result": r}

def main():
    oc = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    if oc not in ("", "mcp", "sidecomputer-gate"):
        sys.stderr.write("sidecomputer-gate: only MCP over stdio is allowed\n")
        L.log("audit.log", {"op": "rejected_command"}) if os.path.isdir(L.SPOOL) else None
        return 1
    L.ensure_spool()
    for line in sys.stdin:
        if len(line) > MAX_LINE:
            resp = err(None, -32600, "Request too large")
        else:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                resp = err(None, -32700, "Parse error")
            else:
                resp = handle(msg) if not isinstance(msg, list) else err(None, -32600, "Batch not supported")
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0

if __name__ == "__main__":
    sys.exit(main())
