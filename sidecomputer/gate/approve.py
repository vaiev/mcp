#!/usr/bin/env python3
"""Approve one consequential task from the host console. Not an MCP tool."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import sclib as L

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write("usage: sidecomputer-approve TASK_ID\n")
        return 2
    try:
        L.approve_task(argv[0], approver=os.environ.get("SC_APPROVER", "root"))
    except (PermissionError, ValueError, OSError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    sys.stdout.write(json.dumps({"ok": True, "id": argv[0]}) + "\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
