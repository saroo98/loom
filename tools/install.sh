#!/usr/bin/env bash
# Loom skill installer (macOS / Linux / Git Bash)
# Installs the /loom skill for Claude Code and Codex, stamping this repo's path into the
# installed copies. Idempotent: re-run after moving the repo or updating Loom.
set -euo pipefail

LOOM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="$LOOM_ROOT/skill/loom/SKILL.md"
PROMPT_SRC="$LOOM_ROOT/skill/codex-prompt/loom.md"
[ -f "$SKILL_SRC" ] || { echo "Not a Loom repo (missing $SKILL_SRC)" >&2; exit 1; }

install_one() { # src dest what
  mkdir -p "$(dirname "$2")"
  sed "s|{{LOOM_PATH}}|$LOOM_ROOT|g" "$1" > "$2"
  echo "Installed: $3 -> $2"
}

install_one "$SKILL_SRC"  "$HOME/.claude/skills/loom/SKILL.md" "Claude Code skill"
install_one "$SKILL_SRC"  "$HOME/.codex/skills/loom/SKILL.md"  "Codex skill"
install_one "$PROMPT_SRC" "$HOME/.codex/prompts/loom.md"       "Codex /loom prompt (legacy explicit invocation)"

echo
echo "Loom repo path stamped: $LOOM_ROOT"
echo "Claude Code: type /loom  |  Codex: /loom (prompt) or describe a planning task (skill auto-triggers)"
echo "Restart the CLI/session if the command does not appear."
