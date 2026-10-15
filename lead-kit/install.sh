#!/usr/bin/env bash
set -euo pipefail
WITH_VECTORS=false
for arg in "$@"; do
    case "$arg" in
        --with-vectors) WITH_VECTORS=true ;;
        -h|--help) echo 'Usage: install.sh [--with-vectors]'; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/hub" && pwd)
HUB_HOME=${HUB_HOME:-$HOME/.local/share/lead-kit/hub}
HUB_BIN_DIR=${HUB_BIN_DIR:-$HOME/.local/bin}
mkdir -p -- "$HUB_HOME" "$HUB_BIN_DIR"
HUB_HOME=$(cd -- "$HUB_HOME" && pwd)
for file in hub hub.py kb-sources.sh README.md; do
    if [[ "$SOURCE/$file" != "$HUB_HOME/$file" ]]; then
        install -m 644 "$SOURCE/$file" "$HUB_HOME/$file"
    fi
done
chmod +x "$HUB_HOME/hub" "$HUB_HOME/kb-sources.sh"
if "$WITH_VECTORS"; then
    [[ -x "$HUB_HOME/.venv/bin/python" ]] || python3 -m venv "$HUB_HOME/.venv"
    "$HUB_HOME/.venv/bin/python" -m pip install sqlite-vec==0.1.9 fastembed==0.8.0
fi
if [[ -e "$HUB_BIN_DIR/hub" && ! -L "$HUB_BIN_DIR/hub" ]]; then
    echo "Refusing to replace existing file: $HUB_BIN_DIR/hub" >&2; exit 1
fi
ln -sfn -- "$HUB_HOME/hub" "$HUB_BIN_DIR/hub"
printf 'Installed hub to %s. Add %s to PATH.\n' "$HUB_HOME" "$HUB_BIN_DIR"
