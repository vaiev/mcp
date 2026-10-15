# SideComputer kit

A remote, always-on Linux host that acts as a "second computer" for all of one owner's bots.
One bot (the **SideComputer bot**) holds the SSH key. After bootstrap that key can only speak MCP to a
gate: submit tasks, read status. No shell, no file access, no forwarding.

## Layout
| Path | Purpose |
|---|---|
| `bootstrap.sh` | Root-run, idempotent host setup. Prints a JSON summary. |
| `gate/gate.py` → `/usr/local/bin/sidecomputer-gate` | Forced-command MCP stdio server (JSON-RPC 2.0, stdlib only). |
| `gate/worker.py` → `sidecomputer-worker.service` | Runs queued tasks as `sc-worker` with limits. |
| `gate/sclib.py` | Spool, profile validation, redaction. |
| `profiles/*.json` | Declared profiles: `worker-cli-agents`, `repo-bridge`, `compute`, `custom`. |
| `client/sc_client.py` | Box-side paramiko client (`tools` / `call <tool> <json>`). |
| `tests/` | Unit + end-to-end tests (`python3 tests/test_sidecomputer.py`). |
| `skills/` | Bot skill texts: getting started, dispatch, admin. |

## Bootstrap
```
sudo ./bootstrap.sh --profile compute,repo-bridge --bot-pubkey "ssh-ed25519 AAAA... bot" --mode strict [--lock]
```
Creates the `sidecomputer` login user (password locked) and the `sc-worker` system user (shared group
`sidecomputer`), the spool `/var/lib/sidecomputer/{queue,running,done,artifacts}` (mode 2770), installs the
gate, the worker and the validated profiles (their `packages` via apt, `mcps` via npm), writes the systemd unit
(MemoryMax, CPUQuota, TasksMax, NoNewPrivileges, ProtectSystem=strict, ProtectHome) and
`/etc/ssh/sshd_config.d/60-sidecomputer.conf` (no passwords, no keyboard-interactive auth, root key-only or `no` with `--lock`).
Re-running it replaces the bot key line rather than duplicating it. `SC_PREFIX` + `SC_DRY_RUN=1` install into a
scratch directory for testing.

## Modes
- **strict** (recommended): `command="/usr/local/bin/sidecomputer-gate",restrict <key>` plus `ForceCommand` for the
  user. `--lock` also empties the admin user's `authorized_keys` (backup left next to it) and sets `PermitRootLogin no`.
- **open** (LESS SAFE): the key gets a normal shell (`restrict,pty`, so still no forwarding). Use it only for setup and
  debugging. The bot can then read everything the `sidecomputer` user can.

## Threat model
Assumes the bot, its prompts, or other bots that hand it tasks can be manipulated (prompt injection), and the key
may leak. Goal: a leaked or misused key can only run tasks inside declared profiles and see redacted summaries.
- Can do: `submit_task`, `task_status`, `list_tasks`, `cancel_task`, `list_profiles`, `request_artifact`, `health`.
- Cannot do: run a shell, read or write files, forward ports or the agent, install tools, add profiles, see raw stdout/stderr.
- What it sees: state, exit code, duration, artifact names, and a summary of at most 500 chars (last lines of
  output) after redaction (PEM keys, JWTs, common token formats, `secret=` pairs, URL credentials, emails, IPs, long
  hex/base64 blobs) and a printable-ASCII allowlist. The raw task input is dropped from the done record.
- Artifacts stay in `artifacts/<id>/`. `request_artifact` returns one file by safe name, capped by the profile's
  `artifact_max_bytes`, and every request is logged to `artifacts.log`. All ops go to `audit.log`.
- Not covered: a profile with `allow_command: true` runs arbitrary shell as `sc-worker`. The guardrail is the
  sandbox (unprivileged user, systemd limits, rlimits), not command filtering. Tasks have network access unless the
  admin adds e.g. `IPAddressDeny=` to the unit. The redaction is a heuristic, so do not route secrets through tasks.
  Exfiltration through a granted artifact is possible by design. Caps and logs make it visible, not impossible.

## Bot side
```
export SIDECOMPUTER_SSH_KEY="$(cat key)"   # newlines collapsed into spaces are repaired
python3 client/sc_client.py --host HOST --user sidecomputer --key-env SIDECOMPUTER_SSH_KEY tools
python3 client/sc_client.py --host HOST call submit_task '{"profile":"compute","command":"make test","timeout":600}'
python3 client/sc_client.py --host HOST call task_status '{"id":"<id>"}'
```
Any MCP client that can spawn `ssh -T sidecomputer@HOST` as a stdio server works as well.
Host keys come from `--known-hosts` (RejectPolicy if the file exists). Pin the host key after first contact.

## Other bots
Other bots never get the key or the host address. They hand a task to the SideComputer bot (profile, command or
prompt, timeout, requester). The SideComputer bot checks that the requester is on the owner's allowlist,
submits the task, polls, and returns only status, exit code, duration and summary. See `skills/sidecomputer-dispatch.md`.

## Caveats
- Once `--lock` is used, the only SSH access left is the gate. Re-bootstrap, key rotation or profile changes need
  console or provider (rescue/cloud-init) access, or a separate admin key you kept out of band.
- Profiles are installed only by bootstrap (an admin step). The gate ignores invalid profile files.
- `systemd-run --scope` per task is used only when the worker runs as root. The shipped unit runs as `sc-worker`,
  so per-task limits are rlimits plus the unit's cgroup limits, which all tasks share.
- The prompt runner (`sc-agent-runner` in `worker-cli-agents`) is a placeholder for whichever CLI agent the admin installs.
