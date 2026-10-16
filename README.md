# VAIEV MCP servers

MCP servers published by [VAIEV](https://github.com/vaiev).

## Servers

| Server | What it does |
|---|---|
| [`sidecomputer`](sidecomputer/README.md) | An SSH forced-command MCP gate. Bots submit tasks to a 24/7 host and get back status plus a redacted summary. |
| [`control-mcp`](control-mcp/README.md) | A local control server template: allow-listed infrastructure actions from a TOML file, no shell, approvals for changes, audit log, output redaction, deletions refused. |

Start with the [SideComputer quickstart](sidecomputer/README.md#quickstart).

Companion bot skills live in [vaiev/skills](https://github.com/vaiev/skills). Agent rules and the project starter that `control-mcp` fits into: [vaiev/guardrails](https://github.com/vaiev/guardrails). The SideComputer dispatch skill is `sidecomputer/dispatch/SKILL.md`.

## Project

- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Apache-2.0](LICENSE)
