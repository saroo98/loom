#!/usr/bin/env bash
# Loom installer launcher for macOS/Linux/Git Bash. Policy lives in loom_install.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SCRIPT_DIR/loom_install.py"
[ -f "$INSTALLER" ] || { echo "Missing installer engine: $INSTALLER" >&2; exit 2; }

if command -v python3 >/dev/null 2>&1; then PYTHON=python3
elif command -v python >/dev/null 2>&1; then PYTHON=python
else echo "Python 3.11+ is required" >&2; exit 2
fi

exec "$PYTHON" "$INSTALLER" "$@"
