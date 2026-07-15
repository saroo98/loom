#!/usr/bin/env python3
"""Bounded offline bootstrap for signed Loom marketplace payloads."""

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


MAX_INPUT = 64 * 1024


class BootstrapError(RuntimeError):
    pass


def _load(path, label):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"{label} is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise BootstrapError(f"{label} is not an object")
    return value


def _empty_inventory():
    return hashlib.sha256(b"loom-empty-owner-vault-v1").hexdigest()


def reconcile(plugin_root, home):
    plugin_root = Path(plugin_root).resolve()
    home = Path(home).resolve()
    tools = plugin_root / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    import loom_adapters
    import loom_crypto
    import loom_migrate
    import loom_owner
    import loom_reliability
    import loom_update

    manifest = _load(plugin_root / ".codex-plugin" / "plugin.json", "plugin manifest")
    version = manifest.get("version")
    platform_id = loom_update.platform_id()
    binary_name = "loom-vault.exe" if platform_id.startswith("windows-") else "loom-vault"
    helper = plugin_root / "crypto" / platform_id / binary_name
    payload = plugin_root / "runtime-payload" / platform_id
    release = plugin_root / "release"
    bundle = _load(release / "metadata.json", "signed release metadata")
    supplied_root = _load(release / "trusted-root.json", "trusted root")
    trust_path = home / "runtime" / "trusted-root.json"
    trusted_root = _load(trust_path, "installed trusted root") if trust_path.is_file() \
        else supplied_root
    manager = loom_update.SharedRuntime(home, plugin_roots=[plugin_root])
    if manager.current_path.is_file() and manager.current().get("version") == version:
        launcher = loom_adapters.install_launcher(
            home, plugin_root / "tools" / "loom_launcher.py")
        return {"status": "current", "version": version, "launcher": launcher}

    vault = None
    before_hash = _empty_inventory()
    current_runtime = None
    if manager.current_path.is_file():
        current = manager.current()
        current_runtime = manager.versions / current["path"]
    vault_path = home / "vault" / "owner.sqlite3"
    if vault_path.is_file():
        vault, _crypto = loom_owner.open_owner_vault(home, helper)
        before_hash = vault.semantic_inventory()["sha256"]
    elif current_runtime is not None and (current_runtime / ".loom-instance-id").is_file():
        expected = (current_runtime / ".loom-instance-id").read_text(encoding="utf-8").strip()
        opened = loom_owner.initialize_owner_vault(home, helper)
        vault = opened["vault"]
        loom_migrate.migrate_v1(
            home, current_runtime, vault, expected_instance_id=expected)
        before_hash = vault.semantic_inventory()["sha256"]

    def health_check(staged):
        orchestrator = staged / "tools" / "loom_orchestrator.py"
        staged_helper = staged / "bin" / binary_name
        if not orchestrator.is_file() or not staged_helper.is_file():
            return {"healthy": False, "migration_complete": False,
                    "disposable_request_passed": False,
                    "before_inventory_sha256": before_hash,
                    "after_inventory_sha256": "0" * 64}
        syntax_script = (
            "import ast,pathlib,sys;root=pathlib.Path(sys.argv[1]);"
            "[ast.parse(p.read_text(encoding='utf-8'),filename=str(p)) "
            "for p in root.rglob('*.py')]")
        compile_result = subprocess.run(
            [sys.executable, "-B", "-c", syntax_script, str(staged / "tools")],
            capture_output=True, timeout=30, check=False)
        disposable = False
        with tempfile.TemporaryDirectory(prefix="loom-health-") as temporary:
            script = (
                "import sys,uuid;sys.path.insert(0,sys.argv[1]);import loom_runtime;"
                "p=loom_runtime.prepare_invocation('plan a safe text file',"
                "instance_id=str(uuid.UUID(sys.argv[2])),invocation_id=str(uuid.uuid4()),"
                "cwd=sys.argv[3],explicit_target=sys.argv[3],owner_home=sys.argv[4]);"
                "assert p.intent=='plan' and p.project_id.startswith('p-')")
            identity = vault.identity()["owner_vault_id"] if vault is not None \
                else "00000000-0000-4000-8000-000000000001"
            probe = subprocess.run(
                [sys.executable, "-B", "-c", script, str(staged / "tools"), identity,
                 temporary, str(home)], capture_output=True, timeout=30, check=False)
            disposable = probe.returncode == 0
        after_hash = before_hash
        if vault_path.is_file():
            reopened, _crypto = loom_owner.open_owner_vault(home, staged_helper)
            after_hash = reopened.semantic_inventory()["sha256"]
        return {"healthy": compile_result.returncode == 0 and disposable,
                "migration_complete": before_hash == after_hash,
                "disposable_request_passed": disposable,
                "before_inventory_sha256": before_hash,
                "after_inventory_sha256": after_hash}

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")
    result = manager.stage_update(
        payload, bundle, trusted_root=trusted_root,
        verify_signature=lambda message, signature, public: loom_crypto.verify_signature(
            helper, message, signature, public),
        vault_schema=1, health_check=health_check, now=now)
    if not trust_path.exists():
        loom_reliability.atomic_write_json(trust_path, supplied_root)
    launcher = loom_adapters.install_launcher(home, plugin_root / "tools" / "loom_launcher.py")
    return {**result, "launcher": launcher}


def _hook_event():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        return 0
    try:
        event = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        return 0
    if not isinstance(event, dict) or event.get("hook_event_name") not in {None, "SessionStart"}:
        return 0
    plugin_root = Path(os.environ.get("PLUGIN_ROOT", Path(__file__).resolve().parents[1]))
    try:
        plugin = _load(plugin_root / ".codex-plugin" / "plugin.json", "plugin manifest")
        pointer_path = Path.home() / ".loom" / "runtime" / "current.json"
        current = _load(pointer_path, "runtime pointer") if pointer_path.is_file() else None
    except Exception:
        return 0
    if current is None or current.get("version") != plugin.get("version"):
        print(json.dumps({"continue": True, "systemMessage":
            "A Loom update is available. It will be verified before the next /loom request."},
            separators=(",", ":")))
    return 0


def main(argv=None):
    if argv is None and len(sys.argv) == 1 and not sys.stdin.isatty():
        return _hook_event()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ensure", action="store_true")
    parser.add_argument("--plugin-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--home", default=str(Path.home() / ".loom"))
    args = parser.parse_args(argv)
    try:
        result = reconcile(args.plugin_root, args.home)
    except Exception as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
