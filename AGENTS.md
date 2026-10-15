# AGENTS.md

Instructions for AI agents (Codex, Claude Code, Antigravity, Grok Bot) working in this repository.

## Language
Code, comments, specs, commit messages and PRs: English.

## Workflow
- TDD: add or update a failing test first, then the fix. Run the full test suite before every commit.
- Test command: `python3 sidecomputer/tests/test_sidecomputer.py`
- Small, focused commits with conventional prefixes (`fix:`, `feat:`, `docs:`, `test:`, `chore:`).
- Work on a branch and open a PR. Never push to `main` directly.
- PRs in vaiev/mcp and vaiev/skills merge only after Review Bot approves.

## Guardrails
- Never commit secrets: private keys, tokens, `audit.key`, `.env`, auth files, IP addresses or host names of private machines.
- Do not change repository visibility, publish releases, or post outside the PR without owner approval.
- No force pushes or history rewrites on shared branches.
- Cross-repo contracts (e.g. `authorized_keys` prefix written by vaiev/mcp bootstrap and read by vaiev/skills rotate_bot_key) must stay in sync; change both sides with tests.

## Layout
- `sidecomputer/gate/`: MCP gate, worker, shared library, approval helper
- `sidecomputer/client/`: Paramiko SSH client
- `sidecomputer/bootstrap.sh`: host installer (the only key writer)
- `sidecomputer/profiles/`: task profiles
- `sidecomputer/tests/`: test suite
