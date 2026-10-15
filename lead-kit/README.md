# Lead Kit

A local knowledge and coordination CLI for collaborating agents. Hub stores work claims,
notes, decisions, handoffs and searchable documents in SQLite with FTS5. Optional vectors
add semantic search; the standard installation needs only Python 3 with SQLite FTS5,
Bash and basic Unix utilities.

```sh
bash lead-kit/install.sh
# Optional semantic search (downloads Python dependencies):
bash lead-kit/install.sh --with-vectors
export PATH="$HOME/.local/bin:$PATH"
export HUB_BOT=worker
hub status
```

Installation can be repeated safely: it updates program files while preserving the database,
config, model cache and virtual environment. Vector models download on first use and are
cached locally. Set `HUB_EMBED=none` to disable vectors. After enabling vectors, run
`hub reindex` to embed existing content. Use the same embedding dimension (384) as the
schema when selecting another model.

| Variable | Default / meaning |
| --- | --- |
| `HUB_HOME` | Install directory: `$HOME/.local/share/lead-kit/hub`; wrappers use their resolved directory when unset |
| `HUB_DB` | `$HUB_HOME/hub.db`; parent directories are created |
| `HUB_BOT` | Agent identity; no default. Author commands also accept `--bot` |
| `HUB_BIN_DIR` | Installer symlink directory: `$HOME/.local/bin` |
| `HUB_PYTHON` | Wrapper interpreter: `$HUB_HOME/.venv/bin/python`, falling back to `python3` |
| `HUB_EMBED` | `fastembed`; `none` disables vectors |
| `HUB_EMBED_MODEL` | `BAAI/bge-small-en-v1.5` |
| `HUB_MODEL_CACHE` | `$HUB_HOME/.models` |
| `HUB_KB_CONFIG` | `$HUB_HOME/kb-sources.conf`, optional trusted shell config |
| `KB_SRC` | `$HUB_HOME/kb-src`, repository clone directory |
| `KB_ORG` | GitHub organization; required if repositories are listed |
| `KB_REPOS` | Newline-separated repository names; empty by default |
| `KB_DOCS` | Newline-separated extra file/directory paths; empty by default |

Paths containing spaces are supported. Use absolute paths in configuration; relative paths
are resolved from the calling directory. Environment settings override config, including
empty lists. Config is sourced as shell code: only use a trusted file. Example:

```sh
# Save as $HUB_HOME/kb-sources.conf
KB_ORG=example
KB_REPOS='project-one
project-two'
KB_DOCS="$HOME/documents/team guide
$HOME/documents/specs"
```

Run `"$HUB_HOME/kb-sources.sh"` to clone or fast-forward configured repositories,
ingest their text documents with GitHub citations, ingest extra paths under `general`,
and refresh existing sources. Git credentials use your normal Git configuration. A failed
clone, pull or ingestion stops the script. Unchanged documents are skipped by hash.

Start each session with `hub brief` and `hub status`. Check claims before working,
claim a focused task, record useful findings and pass actionable context to another agent:

```sh
hub brief                          # uses HUB_BOT; or hub brief worker
hub status
hub work list --project app --active
hub work claim "Improve search" --project app --branch feat/search
hub work update 1 --status blocked --notes "Waiting for review"
hub note add "Search constraint" --project app --kind lesson --body "Explain the finding"
hub handoff add reviewer "Review the search branch; check ranking" --project app
hub handoff list --to reviewer
hub handoff done 1
hub work release 1 --notes "Completed and verified"
hub ingest ./docs --project app
hub ingest --refresh
hub ingest --list
hub ask "How does search work?"
hub search "ranking" --fts
hub decision add "Use keyword search" --project app --rationale "Works offline"
hub decision list --project app
```

Claims are unique by project and case-insensitive task while open. Keep status current,
release completed claims, write short factual notes with file/PR references, and mark
handoffs done after acting on them. Never store credentials or private machine details;
pattern-based refusal/redaction is only a basic safeguard. `ask` returns ranked source
excerpts with citations. Use `hub --json COMMAND` for machine output and
`hub COMMAND --help` for all options.

Validate from the repository root:

```sh
python3 lead-kit/hub/test_hub.py
bash -n lead-kit/install.sh lead-kit/hub/hub lead-kit/hub/kb-sources.sh
```
