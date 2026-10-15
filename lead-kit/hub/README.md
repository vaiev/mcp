# Hub CLI

Hub coordinates agent work and searches shared notes, decisions and documents using
SQLite WAL and FTS5, with optional sqlite-vec/fastembed semantic search.

See [Lead Kit setup and command guide](../README.md) for installation, environment
variables, source configuration and coordination conventions. Install with
`bash lead-kit/install.sh` from the repository root; add `--with-vectors` for embeddings.

For direct checkout use:

```sh
export HUB_HOME="$(pwd)/lead-kit/hub"
export HUB_DB="$(mktemp -d)/hub.db"
export HUB_BOT=worker
"$HUB_HOME/hub" brief
"$HUB_HOME/hub" status
```

`hub.py` defaults to `$HUB_HOME/hub.db` (or the standard user install directory when
`HUB_HOME` is unset). The wrapper resolves symlinks and uses its directory as the default
home. Model cache and interpreter paths are configurable. No agent identity is assumed.

`kb-sources.sh` reads optional trusted `$HUB_KB_CONFIG` or
`$HUB_HOME/kb-sources.conf`. Configure `KB_ORG`, newline-separated `KB_REPOS`,
`KB_SRC`, and newline-separated `KB_DOCS`. Empty lists ingest no new sources.

Ingest chunks Markdown by heading, deduplicates content, redacts recognizable sensitive
patterns and skips unchanged files. Search and ask cover notes, decisions and documents.
Refresh reports missing files without removing their existing indexed content.

Tests use temporary databases:

```sh
python3 lead-kit/hub/test_hub.py
```
