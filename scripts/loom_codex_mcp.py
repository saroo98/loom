#!/usr/bin/env python3
"""Bootstrap the installed plugin, then replace this process with Loom's stable MCP."""

import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import loom_bootstrap


def main():
    plugin_root = Path(__file__).resolve().parents[1]
    loom_home = (Path.home() / ".loom").resolve()
    result = loom_bootstrap.reconcile(plugin_root, loom_home)
    launcher_result = result.get("launcher")
    if not isinstance(launcher_result, dict) \
            or "python_launcher" not in launcher_result:
        raise RuntimeError("Loom bootstrap returned no stable Python launcher")
    launcher = Path(launcher_result["python_launcher"]).resolve()
    if not launcher.is_file() or launcher.is_symlink():
        raise RuntimeError("Loom bootstrap did not produce a safe stable launcher")
    os.execv(sys.executable, [
        sys.executable, "-B", str(launcher), "--home", str(loom_home), "mcp",
    ])


if __name__ == "__main__":
    main()
