#!/usr/bin/env bash
# webapp-audit — thin wrapper: audit <url|path> [--deep] [--no-browser] [--json] [--out file]
# Resolves its own symlink (installed as ~/scripts/audit) so it can be called from anywhere.
set -euo pipefail
SRC="${BASH_SOURCE[0]}"
while [ -L "$SRC" ]; do
  DIR="$(cd -P "$(dirname "$SRC")" && pwd)"
  SRC="$(readlink "$SRC")"
  case "$SRC" in /*) ;; *) SRC="$DIR/$SRC" ;; esac
done
HERE="$(cd -P "$(dirname "$SRC")" && pwd)"
exec python3 "$HERE/scripts/audit.py" "$@"
