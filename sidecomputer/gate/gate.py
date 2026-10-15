#!/usr/bin/env python3
"""sidecomputer-gate: forced-command MCP stdio server (JSON-RPC 2.0). stdlib only."""
import base64, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import sclib as L

VERSION = "0.2.0"
PROTO = "2024-11-05"
MAX_LINE = 65536

def _s(kind, **kw):
    return dict(type=kind, **kw)

TOOLS = [
    {"name": "submit_task", "description": "Queue a task in a granted profile. Returns task id.",
     "inputSchema": {"type": "object", "properties": {"profile": _s("string"), "command": _s("string"),
                     "prompt": _s("string"), "timeout": _s("integer", minimum=1), "requester": _s("string")},
                     "required": ["profile"]}},
    {"name": "task_status", "description": "Status, exit code, duration and redacted summary of a task.",
     "inputSchema": {"type": "object", "properties": {"id": _s("string")}, "required": ["id"]}},
    {"name": "list_tasks", "description": "List recent tasks submitted by this key (public fields only).",
     "inputSchema": {"type": "object", "properties": {"limit": _s("integer", minimum=1, maximum=100)}}},
    {"name": "cancel_task", "description": "Cancel a queued or running task submitted by this key.",
     "inputSchema": {"type": "object", "properties": {"id": _s("string")}, "required": ["id"]}},
    {"name": "list_profiles", "description": "List profiles granted to this key.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "request_artifact", "description": "Fetch one named artifact of a finished task. Contents are redacted, size-capped, and logged.",
     "inputSchema": {"type": "object", "properties": {"id": _s("string"), "name": _s("string")}, "required": ["id", "name"]}},
    {"name": "health", "description": "Gate and queue health.", "inputSchema": {"type": "object", "properties": {}}},
]

class ToolError(Exception):
    pass

def _identity(args):
    requester = args.get("requester") if isinstance(args, dict) and args.get("requester") is not None else L.current_key_id()
    if not isinstance(requester, str) or not L.REQUESTER_RE.match(requester):
        raise ToolError("invalid requester")
    key_id = L.current_key_id()
    if not L.KEY_ID_RE.match(key_id or ""):
        raise ToolError("missing key id")
    return requester, key_id

def t_submit(args):
    requester, key_id = _identity(args)
    name = args.get("profile")
    if name not in L.granted_profiles():
        raise ToolError("profile not granted")
    profile = L.load_profiles().get(name)
    if not profile:
        raise ToolError("unknown profile")
    command, prompt = args.get("command"), args.get("prompt")
    if (command is None) == (prompt is None):
        raise ToolError("give exactly one of command or prompt")
    text = command if command is not None else prompt
    if not isinstance(text, str) or not text.strip() or len(text) > L.MAX_INPUT or "\x00" in text:
        raise ToolError("invalid command/prompt")
    if command is not None and not profile.get("allow_command"):
        raise ToolError("profile does not allow raw commands")
    if prompt is not None and not profile.get("prompt_runner"):
        raise ToolError("profile has no prompt runner")
    maximum = profile.get("max_timeout", 3600)
    timeout = args.get("timeout", min(600, maximum))
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        raise ToolError("invalid timeout")
    timeout = min(timeout, maximum)
    tid = L.new_id()
    kind = "command" if command is not None else "prompt"
    needs_approval = L.requires_approval(profile)
    task = {"id": tid, "profile": profile["name"], "kind": kind, "input": text, "timeout": timeout,
            "state": "pending_approval" if needs_approval else "queued", "submitted_at": time.time(),
            "requester": requester, "key_id": key_id}
    folder = "pending" if needs_approval else "queue"
    L.log("audit.log", {"op": "submit", "id": tid, "profile": profile["name"], "kind": kind,
                        "requester": requester, "key_id": key_id, "state": task["state"]})
    try:
        L.write_json(L.spool(folder, tid + ".json"), task)
    except Exception:
        try:
            L.log("audit.log", {"op": "enqueue_failed", "id": tid})
        except Exception:
            pass
        raise
    return {"id": tid, "state": task["state"], "timeout": timeout}

def t_status(args):
    _state, task = L.find_task(args.get("id"))
    if not L.task_visible(task):
        raise ToolError("unknown task")
    return L.public_view(task)

def _iter_tasks():
    for state in ("queue", "running", "done", "pending"):
        directory = L.spool(state)
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            if not name.endswith(".json"):
                continue
            try:
                yield L.read_json(os.path.join(directory, name))
            except (OSError, ValueError):
                continue

def t_list(args):
    limit = args.get("limit", 20)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        limit = 20
    items = []
    for task in _iter_tasks():
        if not L.task_visible(task):
            continue
        items.append({key: task.get(key) for key in ("id", "profile", "state", "exit_code", "submitted_at")})
    items.sort(key=lambda item: item.get("submitted_at") or 0, reverse=True)
    return {"tasks": items[:limit]}

def t_cancel(args):
    tid = args.get("id")
    if not L.ID_RE.match(tid or ""):
        raise ToolError("unknown task")
    with L.locked_task(tid):
        state, task = L.find_task(tid)
        if not L.task_visible(task):
            raise ToolError("unknown task")
        if state in ("queue", "pending"):
            L.request_cancel(tid)
            done = dict(task)
            done.update(state="cancelled", finished_at=time.time(), summary="cancelled before start")
            done.pop("input", None)
            L.write_json(L.spool("done", tid + ".json"), done)
            try:
                os.unlink(L.spool(state, tid + ".json"))
            except FileNotFoundError:
                pass
            result = "cancelled"
        elif state == "running":
            L.request_cancel(tid)
            result = "cancelling"
        else:
            return {"id": tid, "state": task.get("state"), "note": "already finished"}
    L.log("audit.log", {"op": "cancel", "id": tid, "requester": task.get("requester", ""),
                        "key_id": task.get("key_id", "")})
    return {"id": tid, "state": result}

def t_profiles(_args):
    granted = L.granted_profiles()
    profiles = []
    for profile in L.load_profiles().values():
        if profile["name"] not in granted:
            continue
        profiles.append({"name": profile["name"], "description": profile.get("description", ""),
                         "allow_command": bool(profile.get("allow_command")), "prompt": bool(profile.get("prompt_runner")),
                         "max_timeout": profile.get("max_timeout", 3600),
                         "requires_approval": L.requires_approval(profile),
                         "network": bool(profile.get("network") or profile.get("egress_allow"))})
    return {"profiles": profiles}

def t_artifact(args):
    tid, name = args.get("id"), args.get("name")
    state, task = L.find_task(tid)
    if not L.task_visible(task) or state != "done":
        raise ToolError("task unknown or not finished")
    denied = isinstance(name, str) and name in L.DENIED_ARTIFACTS
    if not isinstance(name, str) or denied or name.startswith(".") or not L.NAME_RE.match(name):
        L.log("artifacts.log", {"op": "request_artifact", "id": tid, "name": str(name)[:64], "granted": False})
        raise ToolError("artifact not available" if denied else "invalid artifact name")
    try:
        base = L.artifact_dir(tid)
    except ValueError:
        raise ToolError("artifact not found")
    path = os.path.realpath(os.path.join(base, name))
    private_root = os.path.realpath(L.spool("private"))
    if (os.path.dirname(path) != base or not os.path.isfile(path) or os.path.islink(os.path.join(base, name))
            or path == private_root or path.startswith(private_root + os.sep)):
        L.log("artifacts.log", {"op": "request_artifact", "id": tid, "name": name, "granted": False})
        raise ToolError("artifact not found")
    cap = L.load_profiles().get(task.get("profile"), {}).get("artifact_max_bytes", 262144)
    size = os.path.getsize(path)
    ok = size <= cap
    L.log("artifacts.log", {"op": "request_artifact", "id": tid, "name": name, "size": size, "granted": ok,
                           "requester": task.get("requester", ""), "key_id": task.get("key_id", "")})
    if not ok:
        raise ToolError("artifact exceeds cap (%d > %d bytes)" % (size, cap))
    with open(path, "rb") as fh:
        raw = fh.read(cap + 1)
    # Every download is redacted, including files a command redirected (cmd > out.txt).
    data = L.redact_artifact(raw)
    return {"id": tid, "name": name, "size": len(data), "raw_size": size, "redacted": True,
            "encoding": "base64", "data": base64.b64encode(data).decode()}

def t_health(_args):
    counts = {state: 0 for state in ("queue", "running", "done", "pending")}
    for state in counts:
        directory = L.spool(state)
        if not os.path.isdir(directory):
            counts[state] = -1
            continue
        for name in os.listdir(directory):
            if not name.endswith(".json"):
                continue
            try:
                task = L.read_json(os.path.join(directory, name))
            except (OSError, ValueError):
                continue
            if L.task_visible(task):
                counts[state] += 1
    heartbeat = L.spool("worker.heartbeat")
    age = time.time() - os.path.getmtime(heartbeat) if os.path.exists(heartbeat) else None
    return {"ok": True, "version": VERSION, "counts": counts, "artifact_redaction": "all",
            "worker_alive": age is not None and age < 30, "profiles": len(L.granted_profiles())}

HANDLERS = {"submit_task": t_submit, "task_status": t_status, "list_tasks": t_list, "cancel_task": t_cancel,
            "list_profiles": t_profiles, "request_artifact": t_artifact, "health": t_health}

def err(i, code, msg):
    return {"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": msg}}

def handle(msg):
    """Handle one JSON-RPC message; returns response dict or None (notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return err(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
    i, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    notif = "id" not in msg
    if method == "initialize":
        result = {"protocolVersion": PROTO, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "sidecomputer-gate", "version": VERSION}}
    elif method.startswith("notifications/"):
        return None
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        if not isinstance(params, dict):
            return err(i, -32602, "Invalid params")
        name, args = params.get("name"), params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if not handler or not isinstance(args, dict):
            return err(i, -32602, "Unknown tool or bad arguments")
        try:
            out, is_err = handler(args), False
        except ToolError as exc:
            out, is_err = {"error": str(exc)}, True
        except Exception:
            out, is_err = {"error": "internal error"}, True
        result = {"content": [{"type": "text", "text": json.dumps(out)}], "isError": is_err}
    else:
        return None if notif else err(i, -32601, "Method not found")
    return None if notif else {"jsonrpc": "2.0", "id": i, "result": result}

def main():
    os.umask(0o027)
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    if original not in ("", "mcp", "sidecomputer-gate"):
        sys.stderr.write("sidecomputer-gate: only MCP over stdio is allowed\n")
        try:
            L.ensure_spool()
            L.log("audit.log", {"op": "rejected_command", "requester": L.current_key_id() or "unknown",
                                "key_id": L.current_key_id() or "unknown"})
        except OSError:
            pass
        return 1
    L.ensure_spool()
    L.sweep_finished()
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
