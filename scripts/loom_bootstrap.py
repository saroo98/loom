#!/usr/bin/env python3
"""Bounded offline bootstrap for signed Loom marketplace payloads."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
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


def _verified_current_runtime(home):
    """Locate and hash-check the already-active runtime before importing any update code."""
    home = Path(home).resolve()
    pointer_path = home / "runtime" / "current.json"
    if not pointer_path.is_file():
        return None
    pointer = _load(pointer_path, "runtime pointer")
    if set(pointer) != {
            "version", "path", "payload_sha256", "release_sequence", "previous"} \
            or pointer.get("path") != pointer.get("version") \
            or not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?",
                str(pointer.get("version", ""))):
        raise BootstrapError("runtime pointer is unsafe")
    versions = (home / "runtime" / "versions").resolve()
    runtime = (versions / pointer["path"]).resolve()
    if not runtime.is_dir() or not runtime.is_relative_to(versions):
        raise BootstrapError("runtime pointer escapes the version store")
    manifest = _load(runtime / "RUNTIME-MANIFEST.json", "active runtime manifest")
    if set(manifest) != {"schema_version", "version", "platform", "files"} \
            or manifest.get("schema_version") != 1 \
            or manifest.get("version") != pointer["version"] \
            or not isinstance(manifest.get("files"), list):
        raise BootstrapError("active runtime manifest contract is invalid")
    expected = set()
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} \
                or not isinstance(item["path"], str) or "\\" in item["path"]:
            raise BootstrapError("active runtime manifest target is invalid")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise BootstrapError("active runtime manifest target traverses")
        path = runtime.joinpath(*relative.parts)
        if not path.is_file() or path.is_symlink():
            raise BootstrapError("active runtime manifest target is missing or redirected")
        raw = path.read_bytes()
        if len(raw) != item["bytes"] \
                or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise BootstrapError("active runtime bytes do not match their manifest")
        expected.add(relative.as_posix())
    ignored = {
        "RUNTIME-MANIFEST.json", ".loom-runtime-receipt.json",
        ".loom-install-receipt.json", ".loom-health-receipt.json",
    }
    observed = {
        path.relative_to(runtime).as_posix() for path in runtime.rglob("*")
        if path.is_file() and path.name not in ignored
    }
    if observed != expected:
        raise BootstrapError("active runtime contains unlisted or missing files")
    return runtime


def _migrate_legacy_staged(home, helper, current_runtime, expected_instance_id, *,
                           owner_module, migrate_module, reliability_module):
    """Migrate into an isolated vault and activate only a verified standalone backup."""
    home = Path(home).resolve()
    vault_dir = home / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    active = vault_dir / "owner.sqlite3"
    journal_path = vault_dir / "bootstrap-journal.json"
    staged_home = vault_dir / ".legacy-migration-home"
    prepared = vault_dir / ".owner.sqlite3.prepared"
    source_hash = reliability_module.deterministic_manifest(
        current_runtime)["root_sha256"]
    expected_journal = {
        "schema_version": 1,
        "kind": "legacy-v1-migration",
        "expected_instance_id": expected_instance_id,
        "source_runtime_sha256": source_hash,
    }
    if journal_path.is_file():
        journal = _load(journal_path, "bootstrap journal")
        if any(journal.get(key) != value for key, value in expected_journal.items()) \
                or journal.get("state") not in {"preparing", "prepared", "complete"} \
                or set(journal) != set(expected_journal) | {"state", "inventory_sha256"}:
            raise BootstrapError("bootstrap journal does not match the legacy source")
        if active.is_file():
            vault, crypto = owner_module.open_owner_vault(home, helper)
            inventory = vault.semantic_inventory()["sha256"]
            if journal["state"] not in {"prepared", "complete"} \
                    or inventory != journal["inventory_sha256"]:
                raise BootstrapError("active vault does not match the prepared migration")
            reliability_module.atomic_write_json(
                journal_path, {**expected_journal, "state": "complete",
                               "inventory_sha256": inventory})
            return vault, crypto
    else:
        reliability_module.atomic_write_json(
            journal_path, {**expected_journal, "state": "preparing",
                           "inventory_sha256": None})
    if active.exists():
        raise BootstrapError("active vault exists without a completed migration journal")

    opened = owner_module.initialize_owner_vault(staged_home, helper)
    staged_vault = opened["vault"]
    migrate_module.migrate_v1(
        staged_home, current_runtime, staged_vault,
        expected_instance_id=expected_instance_id)
    inventory = staged_vault.semantic_inventory()["sha256"]
    reliability_module.atomic_write_json(
        journal_path, {**expected_journal, "state": "prepared",
                       "inventory_sha256": inventory})

    temporary = vault_dir / f".owner.sqlite3.backup-{os.getpid()}"
    if temporary.exists():
        raise BootstrapError("migration backup target already exists")
    try:
        staged_vault.online_backup(temporary)
        if prepared.exists():
            prepared.unlink()
        os.replace(temporary, prepared)
        os.replace(prepared, active)
        vault, crypto = owner_module.open_owner_vault(home, helper)
        if vault.semantic_inventory()["sha256"] != inventory:
            raise BootstrapError("activated migration inventory changed")
        reliability_module.atomic_write_json(
            journal_path, {**expected_journal, "state": "complete",
                           "inventory_sha256": inventory})
    finally:
        temporary.unlink(missing_ok=True)
    if staged_home.is_dir():
        shutil.rmtree(staged_home)
    return vault, crypto


def reconcile(plugin_root, home):
    plugin_root = Path(plugin_root).resolve()
    home = Path(home).resolve()
    manifest = _load(plugin_root / ".codex-plugin" / "plugin.json", "plugin manifest")
    version = manifest.get("version")
    current_runtime = _verified_current_runtime(home)
    # Updates use only the already-verified runtime's Python modules until the incoming
    # payload has passed signature, target, extraction, and health verification. A fresh
    # marketplace install has no earlier Loom trust anchor and therefore uses plugin code.
    tools = (current_runtime / "tools") if current_runtime is not None \
        else (plugin_root / "tools")
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    import loom_adapters
    import loom_crypto
    import loom_migrate
    import loom_owner
    import loom_reliability
    import loom_update

    platform_id = loom_update.platform_id()
    binary_name = "loom-vault.exe" if platform_id.startswith("windows-") else "loom-vault"
    helper = ((current_runtime / "bin" / binary_name) if current_runtime is not None
              else (plugin_root / "crypto" / platform_id / binary_name))
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
            home, current_runtime / "tools" / "loom_launcher.py")
        return {"status": "current", "version": version, "launcher": launcher}

    vault = None
    before_hash = _empty_inventory()
    if manager.current_path.is_file():
        current = manager.current()
        current_runtime = manager.versions / current["path"]
    vault_path = home / "vault" / "owner.sqlite3"
    if vault_path.is_file():
        vault, _crypto = loom_owner.open_owner_vault(home, helper)
        before_hash = vault.semantic_inventory()["sha256"]
    elif current_runtime is not None and (current_runtime / ".loom-instance-id").is_file():
        expected = (current_runtime / ".loom-instance-id").read_text(encoding="utf-8").strip()
        vault, _crypto = _migrate_legacy_staged(
            home, helper, current_runtime, expected,
            owner_module=loom_owner, migrate_module=loom_migrate,
            reliability_module=loom_reliability)
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
    activated = manager.current()
    active_runtime = manager.versions / activated["path"]
    launcher = loom_adapters.install_launcher(
        home, active_runtime / "tools" / "loom_launcher.py")
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
