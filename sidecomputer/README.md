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
| `gate/approve.py` | Host-console approval for consequential tasks. Not an MCP tool. |

## Bootstrap
```
sudo ./bootstrap.sh --profile compute,repo-bridge --bot-pubkey "ssh-ed25519 AAAA... bot" --mode strict [--lock]
```
Creates separate users (`sidecomputer` login, `sc-gate`, `sc-worker`, `sc-task`). The spool is not
group-writable: only `sc-gate` can create queue files, only `sc-worker` can write results, and the audit log
is append-only. Raw stdout/stderr go to `private/`, not `artifacts/`. The systemd unit sets
`IPAddressDeny=any` and `IPAddressAllow=localhost` (MemoryMax, CPUQuota, TasksMax, NoNewPrivileges,
ProtectSystem=strict, ProtectHome). sshd disables passwords and keyboard-interactive auth.
Re-running replaces the bot key line rather than duplicating it, and every `authorized_keys` entry keeps
`command=` and `restrict`. There is no key-rotation tool on the gate; rotation is this admin step.
`SC_PREFIX` + `SC_DRY_RUN=1` install into a scratch directory for testing.

## Modes
- **strict** (recommended): `command="/usr/local/bin/sidecomputer-gate",restrict <key>` plus `ForceCommand` for the
  user. `--lock` also empties the admin user's `authorized_keys` (backup left next to it) and sets `PermitRootLogin no`.
- **open** (less safe): the bot key still has `command=` and `restrict` (no shell), but sshd does not set
  `ForceCommand` for the whole user. Use it only while debugging.

## Threat model
Assumes the bot, its prompts, or other bots that hand it tasks can be manipulated (prompt injection), and the key
may leak. Goal: a leaked or misused key can only run tasks inside declared profiles and see redacted summaries.
- Can do: `submit_task`, `task_status`, `list_tasks`, `cancel_task`, `list_profiles`, `request_artifact`, `health`.
- Cannot do: run a shell, read or write files, forward ports or the agent, install tools, add profiles, rotate
  the SSH key, approve its own consequential tasks, or see raw stdout/stderr.
- What it sees: state, exit code, duration, artifact names, and a summary of at most 500 chars (last lines of
  output) after redaction (PEM keys, JWTs, common token formats, `secret=` pairs, URL credentials, emails, IPs, long
  hex/base64 blobs) and a printable-ASCII allowlist. The raw task input is dropped from the done record.
- `request_artifact` returns one file by safe name, capped by the profile's `artifact_max_bytes`. The bytes are
  redacted with the same rules, so `cmd > out.txt` does not return secrets or IPs. `stdout.log` and `stderr.log`
  are not artifacts. Every request is logged. The audit log is a hash chain recording the key id and requester.
- Consequential tasks (raw commands, network, or `requires_approval`) stay pending until an admin runs
  `sidecomputer-approve` on the host. The worker re-checks kind, timeout and that approval against the profile.
  Egress is denied by default. A profile must set `network: true` or `egress_allow` to ask for more, and the
  worker refuses that request unless a privileged cgroup scope can enforce it.
- An SSH key can submit only the profiles named in `/etc/sidecomputer/grants.json`.
- Not covered: a profile with `allow_command: true` runs a shell as `sc-task` after approval. The guardrail is
  the unprivileged user, the cgroup limits, and redaction, not command filtering. Redaction is a heuristic.
  Do not route secrets through tasks.

## Bot side
```
export SIDECOMPUTER_SSH_KEY="$(cat key)"   # newlines collapsed into spaces are repaired
python3 client/sc_client.py --host HOST --user sidecomputer --key-env SIDECOMPUTER_SSH_KEY tools
python3 client/sc_client.py --host HOST call submit_task '{"profile":"compute","command":"make test","timeout":600}'
python3 client/sc_client.py --host HOST call task_status '{"id":"<id>"}'
```
Any MCP client that can spawn `ssh -T sidecomputer@HOST` as a stdio server works as well.
Host keys come from `--known-hosts`. If that file is missing the client refuses to connect. `--accept-new` is the explicit opt-in to store a new key; there is no trust-on-first-use default.

## Other bots
Other bots never get the key or the host address. They hand a task to the SideComputer bot (profile, command or
prompt, timeout, requester). The SideComputer bot checks that the requester is on the owner's allowlist,
submits the task, polls, and returns only status, exit code, duration and summary. Dispatch skill:
[vaiev/skills `sidecomputer/dispatch/SKILL.md`](https://github.com/vaiev/skills/blob/main/sidecomputer/dispatch/SKILL.md).

## Caveats
- Once `--lock` is used, the only SSH access left is the gate. Re-bootstrap, key rotation or profile changes need
  console or provider (rescue/cloud-init) access, or a separate admin key you kept out of band.
- Profiles are installed only by bootstrap (an admin step). The gate ignores invalid profile files.
- The shipped unit runs the worker as `sc-worker`. Memory is `MemoryMax` on the cgroup. The worker does not set
  `RLIMIT_AS` (a 4G address-space limit breaks Node/V8). A prompt is passed after `--`, so a prompt that starts
  with `-` is not a runner flag.
- The prompt runner (`sc-agent-runner` in `worker-cli-agents`) is a placeholder for whichever CLI agent the admin installs.
