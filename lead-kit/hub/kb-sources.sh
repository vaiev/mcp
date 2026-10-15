#!/usr/bin/env bash
# Config is trusted shell code. Lists are newline-delimited (one item per line).
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
HUB_HOME=${HUB_HOME:-$SCRIPT_DIR}
CONFIG=${HUB_KB_CONFIG:-$HUB_HOME/kb-sources.conf}
# Environment values take precedence over config values, including empty lists.
for key in HUB_HOME KB_SRC KB_REPOS KB_ORG KB_DOCS; do
    if [[ -v $key ]]; then declare "saved_$key=${!key}"; fi
done
if [[ -f "$CONFIG" ]]; then source "$CONFIG"; fi
for key in HUB_HOME KB_SRC KB_REPOS KB_ORG KB_DOCS; do
    saved="saved_$key"
    if [[ -v $saved ]]; then printf -v "$key" '%s' "${!saved}"; fi
done
export HUB_HOME
KB_SRC=${KB_SRC:-$HUB_HOME/kb-src}
KB_REPOS=${KB_REPOS:-}
KB_ORG=${KB_ORG:-}
KB_DOCS=${KB_DOCS:-}
HUB="$HUB_HOME/hub"
mkdir -p -- "$KB_SRC"
while IFS= read -r repo; do
    [[ -n "$repo" ]] || continue
    if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+$ || "$repo" == . || "$repo" == .. || ! "$KB_ORG" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo 'KB_REPOS requires simple repository names and a valid KB_ORG' >&2; exit 1
    fi
    dest="$KB_SRC/$repo"
    if [[ -d "$dest/.git" ]]; then
        git -C "$dest" pull -q --ff-only
    else
        git clone -q "https://github.com/$KB_ORG/$repo.git" "$dest"
    fi
    # Use the actual branch for citations; ingest each file so root files retain correct URLs.
    branch=$(git -C "$dest" symbolic-ref --short HEAD)
    while IFS= read -r -d '' file; do
        relative=${file#"$dest/"}
        parent=$(dirname -- "$relative")
        base="https://github.com/$KB_ORG/$repo/blob/$branch"
        [[ "$parent" == . ]] || base="$base/$parent"
        "$HUB" ingest "$file" --project "$repo" --url-base "$base"
    done < <(find "$dest" -type d \( -name .git -o -name node_modules -o -name .venv -o -name target -o -name dist -o -name .next -o -name __pycache__ \) -prune -o -type f \( -iname '*.md' -o -iname '*.markdown' -o -iname '*.txt' -o -iname '*.rst' \) -print0)
done <<< "$KB_REPOS"
while IFS= read -r doc; do
    [[ -n "$doc" ]] || continue
    [[ -e "$doc" ]] || { echo "Missing KB_DOCS path: $doc" >&2; exit 1; }
    "$HUB" ingest "$doc" --project general
done <<< "$KB_DOCS"
"$HUB" ingest --refresh
