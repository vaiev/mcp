#!/usr/bin/env python3
"""Root helper: hand one artifact directory to sc-task for a run, then take it back.

The worker is not root and cannot chown. sudoers allows sc-worker to run only this
script as root. It refuses every path that is not artifacts/<12 hex id>.
"""
import grp, os, pwd, sys
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import sclib as L

def member_stays_inside(path, root):
    """True when path is a non-link regular file or directory whose real path is under root."""
    if os.path.islink(path):
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    real = os.path.realpath(path)
    root_real = os.path.realpath(root)
    inside = real == root_real or real.startswith(root_real + os.sep)
    if not inside:
        return False
    if os.path.isfile(path) and info.st_nlink != 1:
        return False
    return True

def _ids(user):
    try:
        pw = pwd.getpwnam(user)
        group = grp.getgrgid(pw.pw_gid)
    except KeyError:
        raise SystemExit("missing user %s" % user)
    return pw.pw_uid, group.gr_gid

def _take(path, uid, gid, mode):
    os.lchown(path, uid, gid)
    if not os.path.islink(path):
        os.chmod(path, mode)

def grant(tid):
    path = L.artifact_dir(tid)
    if not os.path.isdir(path) or os.path.islink(path):
        raise SystemExit("missing artifact dir")
    uid, _gid = _ids("sc-task")
    _gate_uid, gate_gid = _ids("sc-gate")
    _take(path, uid, gate_gid, 0o2750)

def revoke(tid):
    path = L.artifact_dir(tid)
    if not os.path.isdir(path) or os.path.islink(path):
        raise SystemExit("missing artifact dir")
    worker_uid, _worker_gid = _ids("sc-worker")
    _gate_uid, gate_gid = _ids("sc-gate")
    for current, dirs, files in os.walk(path, followlinks=False):
        keep_dirs = []
        for name in dirs:
            child = os.path.join(current, name)
            if not member_stays_inside(child, path):
                try:
                    os.unlink(child)
                except OSError:
                    pass
                continue
            keep_dirs.append(name)
            _take(child, worker_uid, gate_gid, 0o2750)
        dirs[:] = keep_dirs
        for name in files:
            child = os.path.join(current, name)
            if not member_stays_inside(child, path):
                try:
                    os.unlink(child)
                except OSError:
                    pass
                continue
            _take(child, worker_uid, gate_gid, 0o640)
    _take(path, worker_uid, gate_gid, 0o2750)

def main(argv=None):
    if os.geteuid() != 0:
        sys.stderr.write("chown_artifact must run as root\n")
        return 1
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2 or argv[0] not in ("grant", "revoke"):
        sys.stderr.write("usage: chown_artifact.py grant|revoke TASK_ID\n")
        return 2
    try:
        if argv[0] == "grant":
            grant(argv[1])
        else:
            revoke(argv[1])
    except (ValueError, OSError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
