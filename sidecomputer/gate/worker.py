#!/usr/bin/env python3
"""sidecomputer-worker: re-validates every queued task, then runs it outside the gate uid."""
import json, os, pwd, resource, shutil, signal, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import sclib as L

# Tests assign a callable(tid) to force a cancel after the claim and before exec.
BEFORE_EXEC = None
HELPER = os.environ.get("SC_CHOWN_HELPER", "/usr/local/lib/sidecomputer/chown_artifact.py")

def scope_available():
    return (os.environ.get("SC_SYSTEMD_RUN", "auto") != "0"
            and os.geteuid() == 0 and bool(shutil.which("systemd-run")))

def separation_available():
    if os.environ.get("SC_TASK_SEPARATION", "auto") == "0" or not shutil.which("sudo"):
        return False
    try:
        pwd.getpwnam("sc-task")
    except KeyError:
        return False
    return True

def expand_runner(argv, prompt):
    """Substitute {prompt}. A bare prompt slot is passed after -- so it cannot be a flag."""
    out = []
    for part in argv:
        if part == "{prompt}":
            if not out or out[-1] != "--":
                out.append("--")
            out.append(prompt)
        else:
            out.append(part.replace("{prompt}", prompt))
    return out

def command_argv(task, profile):
    if task["kind"] == "command":
        return ["/bin/sh", "-c", task["input"]]
    return expand_runner(list(profile["prompt_runner"]), task["input"])

def egress_properties(profile):
    """Default deny. network:true with no allow-list is the explicit opt-in to unrestricted egress."""
    if profile.get("network") is True and not profile.get("egress_allow"):
        return []
    props = ["IPAddressDeny=any", "IPAddressAllow=localhost"]
    for net in profile.get("egress_allow") or []:
        props.append("IPAddressAllow=" + net)
    return props

def resource_properties(profile):
    # MemoryMax is a cgroup limit. It is not applied as RLIMIT_AS (that breaks Node/V8).
    return ["MemoryMax=" + str(profile.get("memory_max", "2G")),
            "CPUQuota=" + str(profile.get("cpu_quota", "200%")),
            "TasksMax=" + str(profile.get("tasks_max", 256)),
            "NoNewPrivileges=yes", "PrivateTmp=yes"]

def build_argv(task, profile):
    argv = command_argv(task, profile)
    if scope_available():
        pre = ["systemd-run", "--quiet", "--scope", "--uid=sc-task", "--gid=sc-task"]
        for prop in resource_properties(profile) + egress_properties(profile):
            pre.extend(["-p", prop])
        return pre + ["--"] + argv
    if separation_available():
        adir = L.spool("artifacts", task["id"])
        env_args = ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + adir, "LANG=C.UTF-8",
                    "SC_TASK_ID=" + task["id"], "SC_ARTIFACTS=" + adir]
        for key, value in (profile.get("env") or {}).items():
            env_args.append("%s=%s" % (key, value))
        return ["sudo", "-n", "-u", "sc-task", "--", "/usr/bin/env"] + env_args + argv
    return argv

def apply_rlimits(timeout):
    """Limit CPU and file size. Leave RLIMIT_AS alone so V8 can reserve address space."""
    os.setsid()
    cpu = int(timeout) + 5
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    one_gib = 1 << 30
    resource.setrlimit(resource.RLIMIT_FSIZE, (one_gib, one_gib))

def task_env(task, profile, adir):
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": adir, "LANG": "C.UTF-8",
           "SC_TASK_ID": task["id"], "SC_ARTIFACTS": adir}
    env.update(profile.get("env") or {})
    return env

def egress_blocked(profile):
    if not L.network_requested(profile):
        return None
    if scope_available():
        return None
    return "refusing networked task: egress policy cannot be enforced"

def prepare_workdir(tid):
    adir = L.spool("artifacts", tid)
    os.makedirs(adir, exist_ok=True)
    os.chmod(adir, 0o750)
    if separation_available():
        subprocess.check_call(["sudo", "-n", HELPER, "grant", tid])
    return adir

def revoke_workdir(tid):
    if separation_available() and os.path.isdir(L.spool("artifacts", tid)):
        subprocess.call(["sudo", "-n", HELPER, "revoke", tid])

def prepare_logs(tid):
    directory = L.spool("private", tid)
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o700)
    return os.path.join(directory, "stdout.log"), os.path.join(directory, "stderr.log")

def _tail(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()[-20000:]
    except OSError:
        return ""

def _artifact_names(adir):
    if not os.path.isdir(adir):
        return []
    names = []
    for name in sorted(os.listdir(adir)):
        if name in L.DENIED_ARTIFACTS or name.startswith(".") or not L.NAME_RE.match(name):
            continue
        if os.path.islink(os.path.join(adir, name)):
            continue
        names.append(name)
    return names

def _finish(task, state, code, summary, adir, started):
    done = {"id": task["id"], "profile": task.get("profile"), "kind": task.get("kind"), "state": state,
            "exit_code": code, "duration_s": round(time.monotonic() - started, 3), "finished_at": time.time(),
            "submitted_at": task.get("submitted_at"), "started_at": task.get("started_at"), "summary": summary,
            "artifacts": _artifact_names(adir), "requester": task.get("requester"), "key_id": task.get("key_id"),
            "timeout": task.get("timeout"), "approved_by": task.get("approved_by")}
    done = {key: value for key, value in done.items() if value is not None or key == "exit_code"}
    L.write_json(L.spool("done", task["id"] + ".json"), done)
    for folder in ("running", "queue", "pending"):
        try:
            os.unlink(L.spool(folder, task["id"] + ".json"))
        except OSError:
            pass
    L.log("audit.log", {"op": "finished", "id": task["id"], "state": state, "exit_code": code,
                        "requester": task.get("requester") or "", "key_id": task.get("key_id") or "",
                        "profile": task.get("profile") or ""})
    return done

def _reject(task, summary, code=None):
    return _finish(task, "rejected" if code is None else "failed", code, summary,
                   L.spool("artifacts", task["id"]), time.monotonic())

def _next_queue_file():
    directory = L.spool("queue")
    if not os.path.isdir(directory):
        return None
    files = sorted((os.path.join(directory, name) for name in os.listdir(directory) if name.endswith(".json")),
                   key=lambda path: os.path.getmtime(path))
    for path in files:
        tid = os.path.basename(path)[:-5]
        if not L.ID_RE.match(tid):
            try:
                os.unlink(path)
            except OSError:
                pass
            continue
        if os.path.exists(L.spool("done", tid + ".json")) or os.path.exists(L.spool("running", tid + ".json")):
            try:
                os.unlink(path)
            except OSError:
                pass
            continue
        return path
    return None

def _wait(task, proc, adir, out_path, err_path, started):
    state = "failed"
    code = None
    deadline = started + task["timeout"]
    try:
        while proc.poll() is None:
            if L.cancellation_requested(task["id"]) or time.monotonic() > deadline:
                state = "cancelled" if L.cancellation_requested(task["id"]) else "timeout"
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                break
            time.sleep(0.2)
        code = proc.returncode
        if state == "failed":
            state = "succeeded" if code == 0 else "failed"
    finally:
        revoke_workdir(task["id"])
    summary = L.summarize(_tail(out_path), _tail(err_path), code if state == "succeeded" else 1)
    return _finish(task, state, code, summary, adir, started)

def once():
    L.ensure_spool()
    L.sweep_finished()
    path = _next_queue_file()
    if not path:
        return None
    tid = os.path.basename(path)[:-5]
    with L.locked_task(tid):
        if not os.path.exists(path):
            return None
        try:
            task = L.read_json(path)
        except (OSError, ValueError):
            task = {"id": tid, "requester": "invalid", "key_id": "invalid"}
            return _reject(task, "queue file is not valid json")
        if task.get("id") != tid:
            task["id"] = tid
            return _reject(task, "task id does not match queue file")
        if L.cancellation_requested(tid):
            return _finish(task, "cancelled", None, "cancelled before start", L.spool("artifacts", tid), time.monotonic())
        run_path = L.spool("running", tid + ".json")
        try:
            fd = os.open(run_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
        except FileExistsError:
            return None
        task["state"] = "running"
        task["started_at"] = time.time()
        os.write(fd, json.dumps({k: v for k, v in task.items() if k != "input"}).encode())
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        if BEFORE_EXEC is not None:
            BEFORE_EXEC(tid)
        if L.cancellation_requested(tid):
            return _finish(task, "cancelled", None, "cancelled before start", L.spool("artifacts", tid), time.monotonic())
        profile = L.load_profiles().get(task.get("profile"))
        reason = "profile is not declared" if profile is None else L.revalidate(task, profile)
        if reason:
            return _reject(task, reason)
        blocked = egress_blocked(profile)
        if blocked:
            return _reject(task, blocked)
        try:
            adir = prepare_workdir(tid)
            out_path, err_path = prepare_logs(tid)
            argv = build_argv(task, profile)
            stdout = open(out_path, "w")
            stderr = open(err_path, "w")
            try:
                proc = subprocess.Popen(argv, cwd=adir, env=task_env(task, profile, adir),
                                        stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                        preexec_fn=lambda: apply_rlimits(task["timeout"]))
            finally:
                stdout.close()
                stderr.close()
        except (OSError, subprocess.CalledProcessError) as exc:
            revoke_workdir(tid)
            text = getattr(exc, "strerror", None) or str(exc)
            return _reject(task, "could not start: %s" % text, 126)
        started = time.monotonic()
    return _wait(task, proc, adir, out_path, err_path, started)

def main():
    os.umask(0o077)
    if "--once" in sys.argv:
        once()
        return 0
    L.ensure_spool()
    while True:
        try:
            open(L.spool("worker.heartbeat"), "a").close()
            os.utime(L.spool("worker.heartbeat"))
        except OSError:
            pass
        if once() is None:
            time.sleep(1)

if __name__ == "__main__":
    sys.exit(main())
