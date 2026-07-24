#!/usr/bin/env python3
"""Start Codex MCP immediately and bootstrap Loom lazily on the first tool call."""

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
TOOLS = SCRIPTS.parent / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_bootstrap
import loom_mcp_server


class _LazyLauncher:
    """Resolve one receipt-owned stable launcher only after MCP handshaking."""

    def __init__(self, plugin_root, loom_home):
        self.plugin_root = Path(plugin_root).resolve()
        self.loom_home = Path(loom_home).resolve()
        self._launcher = None

    def __call__(self):
        if self._launcher is not None:
            return self._launcher
        try:
            result = loom_bootstrap.reconcile(self.plugin_root, self.loom_home)
        except loom_bootstrap.BootstrapError as exc:
            raise loom_mcp_server.McpError(
                -32000, f"Loom bootstrap blocked: {exc}") from exc
        launcher_result = result.get("launcher")
        if not isinstance(launcher_result, dict) \
                or "python_launcher" not in launcher_result:
            raise loom_mcp_server.McpError(
                -32603, "Loom bootstrap returned no stable Python launcher")
        launcher = Path(launcher_result["python_launcher"]).resolve()
        if not launcher.is_file() or launcher.is_symlink():
            raise loom_mcp_server.McpError(
                -32603, "Loom bootstrap did not produce a safe stable launcher")
        self._launcher = launcher
        return launcher


def main():
    plugin_root = Path(__file__).resolve().parents[1]
    loom_home = (Path.home() / ".loom").resolve()
    version = (plugin_root / "VERSION").read_text(encoding="utf-8").strip()
    return loom_mcp_server.serve(
        loom_home, None, launcher_resolver=_LazyLauncher(plugin_root, loom_home),
        server_version=version, integration_source="codex-plugin")


if __name__ == "__main__":
    raise SystemExit(main())
