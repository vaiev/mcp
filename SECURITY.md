# Security

SideComputer assumes the bot, its prompts, and the SSH key may be hostile or leaked. The controls are described in the [threat model](sidecomputer/README.md#architecture-and-threat-model).

## Reporting

Please report a vulnerability through a private GitHub security advisory on [vaiev/mcp](https://github.com/vaiev/mcp). Do not open a public issue that includes exploit details, host addresses, private keys, or audit logs.

## In scope

- The gate, worker, bootstrap, approval helper, and SSH client in `sidecomputer/`
- Spool permissions, profile grants, the audit hash chain, artifact redaction, and host-key handling
- A downloaded artifact or summary that still contains a secret or an IP address the redactor claims to catch
- An `authorized_keys` entry written by bootstrap that lacks `command=` or `restrict`

## Out of scope

- A profile that sets `allow_command: true` and has been approved on the host. That task is allowed to run a shell as `sc-task`.
- Redaction of formats the published patterns do not match. Treat redaction as a backstop, not a place to put secrets.
- Compromise of root on the host, or of the machine that holds the bot's private key, beyond what the gate already refuses to do with that key.

Key rotation requires explicit owner approval before an admin runs `bootstrap.sh` on the host. An admin session or shell on the host alone is not approval. The gate does not expose a tool for it.
