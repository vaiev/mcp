# SideComputer

A 24/7 Linux host that one owner's bots can use as a second computer. One bot holds the SSH key. After bootstrap that key can only speak MCP to a gate: submit a task, read status, fetch a redacted artifact. No shell, no file access, no port forwarding, no key rotation.

## Quickstart

On the bot's machine, make a key and keep the private half there:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/sidecomputer-bot -N ""
chmod 600 ~/.ssh/sidecomputer-bot
```

Keep the private key permissions at `600`. Copy only `~/.ssh/sidecomputer-bot.pub` to the host as `sidecomputer-bot.pub`. On the host, as root, install one or more profiles and pin that public key to the gate:

```bash
sudo ./bootstrap.sh \
  --profile compute,repo-bridge \
  --bot-pubkey sidecomputer-bot.pub \
  --mode strict
```

Bootstrap prints one JSON line. `strict` sets `command=` and `restrict` on the key and `ForceCommand` for the `sidecomputer` user. Re-running with the same key replaces its line instead of adding another. To rotate, obtain explicit owner approval, then run `bootstrap.sh --rotate` with the new public key (`--bot-pubkey`) and the desired profiles. This removes previous SideComputer gate keys and prunes their grants; a plain re-run does not revoke the old key. An admin session or shell alone is not approval; there is no MCP rotation tool. Lines written by bootstrap carry `command=` and `restrict`; bootstrap does not police other lines.

Pin the host key before the client will connect. By default, the client refuses a missing `known_hosts` file. `--accept-new` enables trust-on-first-use (TOFU) and is discouraged; prefer the explicit fingerprint check below. Fetch the key into a temporary file and print its fingerprint:

```bash
python3 -m pip install paramiko
host_key_file=$(mktemp)
ssh-keyscan -t ed25519 -H HOST > "$host_key_file"
ssh-keygen -lf "$host_key_file"
```

Compare the printed fingerprint with `host_key_fingerprint` from trusted bootstrap JSON output, or run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the provider console and compare its fingerprint. Only if they match, append the verified key and connect:

```bash
cat "$host_key_file" >> ~/.ssh/known_hosts
rm -f "$host_key_file"
export SIDECOMPUTER_SSH_KEY="$(cat ~/.ssh/sidecomputer-bot)"
python3 client/sc_client.py --host HOST --user sidecomputer \
  --key-env SIDECOMPUTER_SSH_KEY --known-hosts ~/.ssh/known_hosts tools
```

The client currently supports only `--key-env`, with no key-file option. This exposes the private key to the process environment, including child processes that inherit it. Keep the source key file at mode `0600` and unset `SIDECOMPUTER_SSH_KEY` when finished.

`compute` is a consequential profile, so the task waits until someone at the host console approves it:

```bash
python3 client/sc_client.py --host HOST call submit_task \
  '{"profile":"compute","command":"make test","timeout":600,"requester":"owner-bot"}'
# on the host, as root:
sudo sidecomputer-approve TASK_ID
python3 client/sc_client.py --host HOST call task_status '{"id":"TASK_ID"}'
```

You get state, exit code, duration, and a redacted summary. `request_artifact` returns file bytes only after the same redaction, so a redirected `cmd > out.txt` does not hand back secrets or IP addresses.

`SC_PREFIX` and `SC_DRY_RUN=1` install into a scratch directory. Tests:

```bash
python3 -m pip install paramiko
python3 sidecomputer/tests/test_sidecomputer.py
```

## Architecture and threat model

Callers are untrusted. The bot, its prompts, and any other bot that hands it a task may be manipulated, and the SSH key may leak. The host only runs work that a granted profile allows, and the bot only sees redacted results.

```mermaid
flowchart TB
  subgraph callers [Untrusted callers]
    others[Other bots]
    bot[SideComputer bot<br/>one SSH key]
  end
  subgraph edge [SSH boundary]
    ssh["sshd: command= and restrict"]
  end
  subgraph gatebox [sc-gate, not the login shell]
    gate[MCP gate]
    grants[per-key profile grants]
  end
  subgraph work [Spool]
    pending[pending approval]
    queue[queue]
    worker[sc-worker re-checks the profile]
    task[sc-task runs the command]
    private[private logs, not downloadable]
    artifacts[artifacts, redacted on fetch]
    audit[append-only audit hash chain]
  end
  admin[Host admin]

  others -->|profile, prompt, requester| bot
  bot -->|SSH| ssh --> gate
  gate --> grants
  gate -->|consequential| pending
  admin -->|approval bound to the task hash| queue
  gate -->|not consequential| queue
  queue --> worker --> task
  task --> private
  task --> artifacts
  gate --> audit
  worker --> audit
  gate -->|status and redacted bytes| bot
```

| Boundary | What it stops |
|---|---|
| `command=` and `restrict` | A leaked key getting a shell, a file transfer, or a forward. |
| Grants | That key using every profile. It only sees tasks it submitted. |
| Worker re-check | A queue file that asks for a command the profile does not allow, or a timeout past the profile max. |
| Host approval | The bot approving its own shell, network, or other consequential task. |
| `IPAddressDeny=any` | Tasks reaching the network unless a profile opts in and a cgroup scope can enforce it. |
| Redaction | Raw secrets and IPs in summaries and in downloaded artifacts, including `cmd > out.txt`. |
| Hash-chained audit log | A rewritten or gapped history. Each record has the key id and the requester. |

What a caller can do: `submit_task`, `task_status`, `list_tasks`, `cancel_task`, `list_profiles`, `request_artifact`, `health`.

What it cannot do: run a shell, read or write files, forward ports or an agent, install tools, add profiles, rotate the SSH key, approve its own consequential task, or read raw stdout/stderr. `stdout.log` and `stderr.log` are not artifacts.

Other bots never receive the key or the host address. They hand the SideComputer bot a profile, a command or prompt, a timeout, and a requester. The dispatch skill is [vaiev/skills `sidecomputer/dispatch/SKILL.md`](https://github.com/vaiev/skills/blob/main/sidecomputer/dispatch/SKILL.md).

## Layout

| Path | Purpose |
|---|---|
| `bootstrap.sh` | Root-run, idempotent host setup. Prints a JSON summary. |
| `scripts/sidecomputer-gate.sh` | SSH forced command. Runs the gate as `sc-gate`. |
| `gate/gate.py` | MCP stdio server (JSON-RPC 2.0, stdlib only). |
| `gate/worker.py` | `sidecomputer-worker.service`. Re-validates, then runs the task. |
| `gate/sclib.py` | Spool policy, profile checks, redaction, audit chain, grants. |
| `gate/approve.py` | Host-console approval. Not an MCP tool. |
| `gate/chown_artifact.py` | Root helper that lends one artifact directory to `sc-task` and takes it back. |
| `profiles/*.json` | `worker-cli-agents`, `repo-bridge`, `compute`, `custom`. |
| `client/sc_client.py` | Paramiko client: `tools` or `call <tool> <json>`. |
| `tests/` | `python3 tests/test_sidecomputer.py`. |

## Bootstrap

```bash
sudo ./bootstrap.sh --profile compute,repo-bridge \
  --bot-pubkey "ssh-ed25519 AAAA... bot" --mode strict [--lock] [--rotate]
```

This creates `sidecomputer` (login, password locked), `sc-gate`, `sc-worker`, and `sc-task`. The login user is not in the spool groups. Only `sc-gate` can create queue files. Only `sc-worker` can write results. `sc-task` runs the command and cannot read the queue, other tasks' directories, private logs, or the audit log. The audit log is append-only and hash-chained.

The worker unit sets `IPAddressDeny=any` and `IPAddressAllow=localhost`, plus MemoryMax, CPUQuota, TasksMax, NoNewPrivileges, ProtectSystem=strict, and ProtectHome. sshd disables password and keyboard-interactive authentication. Memory is the cgroup `MemoryMax`. The worker does not set `RLIMIT_AS`, because a 4G address-space limit breaks Node and V8. A prompt is passed after `--`, so a value that starts with `-` is not a runner flag.

Profiles are validated before they are installed. Invalid profile files are ignored. Packages install with apt; `mcps` entries install with npm when those tools exist.

### Modes

- **strict** (use this): `command="/usr/local/bin/sidecomputer-gate",restrict` on the key, plus `ForceCommand` for the user. `--lock` also empties the admin user's `authorized_keys` (a backup is left beside it) and sets `PermitRootLogin no`.
- **open** (less safe): the bot key still has `command=` and `restrict`, so it still cannot get a shell. sshd does not set `ForceCommand` for the whole user. Use it only while debugging.

In strict mode, `--lock` backs up the selected admin user's `authorized_keys` to `authorized_keys.sc-locked.bak` and empties it; it also sets `PermitRootLogin no`. Other users' keys are untouched, and `--lock` makes no additional password-authentication changes beyond the bootstrap defaults above, so it does not guarantee that the gate is the only SSH path. Keep console/provider recovery access for administration. To rotate, obtain explicit owner approval and run `bootstrap.sh --rotate` with the new public key and desired profiles; a plain re-run does not revoke the old key. Access to an admin session or shell alone is not approval.

## Tasks

`submit_task` takes a profile and exactly one of `command` or `prompt`, plus an optional timeout and requester. The timeout is clamped to the profile maximum. If the profile allows a raw command, enables network, or sets `requires_approval`, the task stays in `pending` until root runs:

```bash
sudo sidecomputer-approve TASK_ID
```

The approval is a hash of the task. Editing the command after approval makes the worker reject it. The worker also rejects a queue file whose kind the profile does not allow.

A profile that sets `network: true` or `egress_allow` is asking to leave the default deny. The worker refuses that task unless a privileged cgroup scope can apply the allow list. Shipped profiles leave `network` false.

`request_artifact` serves one safe name from `artifacts/<id>/`, under the profile byte cap, and writes the request to the log. The returned bytes are redacted (PEM keys, JWTs, common token shapes, `secret=` pairs, URL credentials, emails, IP addresses, long hex or base64 blobs, then a printable-ASCII allowlist). Symlinks are not served.

The summary is at most 500 characters from the tail of the output, with the same redaction. The raw task input is dropped from the done record.

## What this does not promise

A profile with `allow_command: true` runs a shell as `sc-task` after a human approval. The limits are the user, the cgroup, and redaction, not a command filter. Redaction is a heuristic. Do not send secrets through tasks.

Tasks share the `sc-task` user one at a time. Private logs, the queue, and the audit log are not owned by that user. The prompt runner in `worker-cli-agents` (`sc-agent-runner`) is a placeholder for the CLI agent an admin installs.
