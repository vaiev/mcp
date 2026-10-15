# Contributing

## Tests

From the repository root:

```bash
python3 -m pip install paramiko
python3 sidecomputer/tests/test_sidecomputer.py
```

Paramiko is only needed for the SSH client tests. Without it those tests skip, and the rest still run. GitHub Actions runs the same file on Ubuntu with Python 3.12.

`SC_PREFIX` and `SC_DRY_RUN=1` let `sidecomputer/bootstrap.sh` install into a scratch directory. You do not need root for the unit tests.

## Changes

- Keep the gate and worker on the Python standard library. Paramiko stays in the client.
- Add or extend a test for a behavior change, especially anything on the trust boundary (profiles, artifacts, the audit log, grants, approval, host keys).
- Do not commit private keys, `audit.key`, `.pem` files, or real host addresses. The public key in the tests is a fixture.
- Do not add an MCP tool that rotates the SSH key, approves a task, or rewrites `authorized_keys`. Those stay on the host, with an admin.
- Bootstrap must keep `command=` and `restrict` on every bot key line.

Security-sensitive changes need review before they merge. See [SECURITY.md](SECURITY.md) for reports.
