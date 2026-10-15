#!/usr/bin/env python3
"""sidecomputer-worker: executes queued tasks with limits; records exit code, duration, redacted summary."""
import os, resource, shutil, signal, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import sclib as L

def _size(v):
    v = str(v).upper()
    mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}.get(v[-1:], 1)
    return int(v.rstrip("KMG")) * mult

def build_argv(task, prof):
    if task["kind"] == "command":
        argv = ["/bin/sh", "-c", task["input"]]
    else:
        argv = [x.replace("{prompt}", task["input"]) for x in prof["prompt_runner"]]
    if os.environ.get("SC_SYSTEMD_RUN", "auto") != "0" and shutil.which("systemd-run") and os.geteuid() == 0:
        props = ["MemoryMax=" + prof.get("memory_max", "2G"), "CPUQuota=" + prof.get("cpu_quota", "200%"),
                 "TasksMax=" + str(prof.get("tasks_max", 256)), "NoNewPrivileges=yes", "PrivateTmp=yes"]
        pre = ["systemd-run", "--quiet", "--scope", "--uid=sc-worker", "--gid=sc-worker"]
        for p in props:
            pre += ["-p", p]
        argv = pre + ["--"] + argv
    return argv

def run_task(path, prof_map):
    tid = os.path.basename(path)[:-5]
    task = L.read_json(path)
    prof = prof_map.get(task.get("profile"))
    run_path = L.spool("running", tid + ".json")
    os.replace(path, run_path)
    task.update(state="running", started_at=time.time())
    L.write_json(run_path, task)
    adir = L.spool("artifacts", tid)
    os.makedirs(adir, exist_ok=True)
    t0 = time.monotonic()
    code, state = None, "failed"
    out = err = ""
    if not prof:
        err, code = "profile no longer declared", 127
    else:
        mem = _size(prof.get("memory_max", "2G"))
        def limits():
            os.setsid()
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CPU, (task["timeout"] + 5,) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 30,) * 2)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": adir, "LANG": "C.UTF-8", "SC_TASK_ID": tid,
               "SC_ARTIFACTS": adir}
        env.update(prof.get("env", {}))
        with open(os.path.join(adir, "stdout.log"), "w+") as fo, open(os.path.join(adir, "stderr.log"), "w+") as fe:
            try:
                p = subprocess.Popen(build_argv(task, prof), cwd=adir, env=env, stdin=subprocess.DEVNULL,
                                     stdout=fo, stderr=fe, preexec_fn=limits)
                cancel = L.spool("running", tid + ".cancel")
                deadline = time.monotonic() + task["timeout"]
                while p.poll() is None:
                    if os.path.exists(cancel) or time.monotonic() > deadline:
                        state = "cancelled" if os.path.exists(cancel) else "timeout"
                        try:
                            os.killpg(p.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        p.wait()
                        break
                    time.sleep(0.2)
                code = p.returncode
                if state == "failed":
                    state = "succeeded" if code == 0 else "failed"
                if os.path.exists(cancel):
                    os.unlink(cancel)
            except OSError as e:
                code, err = 126, "could not start: %s" % e.strerror
            fo.seek(0); fe.seek(0)
            out = fo.read()[-20000:]
            err = (fe.read()[-20000:] + err)
    task.update(state=state, exit_code=code, duration_s=round(time.monotonic() - t0, 3),
                finished_at=time.time(), summary=L.summarize(out, err, code if state == "succeeded" else 1),
                artifacts=sorted(f for f in os.listdir(adir) if L.NAME_RE.match(f)))
    task.pop("input", None)  # raw input not kept in public record
    L.write_json(L.spool("done", tid + ".json"), task)
    os.unlink(run_path)
    L.log("audit.log", {"op": "finished", "id": tid, "state": state, "exit_code": code})
    return task

def once():
    L.ensure_spool()
    q = L.spool("queue")
    files = sorted((os.path.join(q, f) for f in os.listdir(q) if f.endswith(".json")), key=os.path.getmtime)
    if not files:
        return None
    return run_task(files[0], L.load_profiles())

def main():
    if "--once" in sys.argv:
        once(); return 0
    L.ensure_spool()
    while True:
        open(L.spool("worker.heartbeat"), "a").close(); os.utime(L.spool("worker.heartbeat"))
        if once() is None:
            time.sleep(1)

if __name__ == "__main__":
    sys.exit(main())
