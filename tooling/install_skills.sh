#!/usr/bin/env bash
# Installs the vendored Claude Code skills used by this project into the
# current user's ~/.claude/skills (skips any skill that already exists).
set -euo pipefail
SRC="$(cd "$(dirname "$0")/skills" && pwd)"
DEST="${HOME}/.claude/skills"
mkdir -p "$DEST"
for d in "$SRC"/*/; do
  name="$(basename "$d")"
  if [ -e "$DEST/$name" ]; then
    echo "skip   $name (already installed)"
  else
    cp -R "$d" "$DEST/$name" && echo "install $name"
  fi
done
echo "Done. Project-specific skills (liveness-kiosk, pad-evaluation) load automatically from Project/.claude/skills/."
