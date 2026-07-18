#!/usr/bin/env python3
"""Bounded offline bootstrap for signed payloads or receipt-proven direct installs."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from pathlib import PurePosixPath


MAX_INPUT = 64 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_FILES = 100_000


class BootstrapError(RuntimeError):
    pass


def _redirect(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise BootstrapError(f"cannot inspect runtime path: {path}: {exc}") from exc


def _trusted_os_alias(path):
    if sys.platform != "darwin":
        return False
    expected = {Path("/var"): Path("/private/var"),
                Path("/tmp"): Path("/private/tmp")}.get(Path(path))
    return expected is not None and Path(path).resolve(strict=False) == expected


def _source_root(path):
    try:
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise BootstrapError(f"plugin root is invalid: {exc}") from exc
    if not root.is_dir():
        raise BootstrapError("plugin root is not a directory")
    for component in [*reversed(root.parents), root]:
        if _redirect(component) and not _trusted_os_alias(component):
            raise BootstrapError(f"plugin root traverses a redirect: {component}")
    return root


def _runtime_files(root):
    pending = [Path(root)]
    count = 0
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise BootstrapError(f"cannot inspect active runtime: {directory}: {exc}") from exc
        for entry in entries:
            count += 1
            if count > MAX_RUNTIME_FILES:
                raise BootstrapError("runtime tree exceeds its entry bound")
            path = Path(entry.path)
            if _redirect(path):
                raise BootstrapError("active runtime contains a redirected entry")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                yield path
            else:
                raise BootstrapError("active runtime contains a non-regular entry")


def _load(path, label):
    try:
        path = Path(path)
        if not path.is_file() or path.is_symlink() \
                or path.stat().st_size > MAX_JSON_BYTES:
            raise BootstrapError(f"{label} is missing, redirected, or oversized")
        raw = path.read_bytes()
        if len(raw) > MAX_JSON_BYTES:
            raise BootstrapError(f"{label} changed above its size bound")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"{label} is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise BootstrapError(f"{label} is not an object")
    return value


def _canonical_hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def _direct_install_receipt(plugin_root):
    """Verify a direct install before importing any of its executable Python."""
    plugin_root = _source_root(plugin_root)
    receipt = _load(plugin_root / ".loom-install-receipt.json",
                    "direct installation receipt")
    fields = {"schema_version", "install_id", "files", "receipt_hash"}
    if set(receipt) != fields or receipt.get("schema_version") != 1 \
            or not isinstance(receipt.get("files"), list) \
            or not 1 <= len(receipt["files"]) <= MAX_RUNTIME_FILES:
        raise BootstrapError("direct installation receipt contract is invalid")
    try:
        if str(uuid.UUID(receipt["install_id"])) != receipt["install_id"]:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise BootstrapError("direct installation identity is invalid") from exc
    body = {key: receipt[key] for key in
            ("schema_version", "install_id", "files")}
    if receipt["receipt_hash"] != _canonical_hash(body):
        raise BootstrapError("direct installation receipt hash is invalid")
    owned = set()
    canonical = set()
    for item in receipt["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} \
                or not isinstance(item["path"], str) or "\\" in item["path"] \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            raise BootstrapError("direct installation owned-file record is invalid")
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or any(part in {"", ".", ".."}
                                         for part in relative.parts):
            raise BootstrapError("direct installation owned path is unsafe")
        path_key = relative.as_posix()
        case_key = path_key.casefold()
        if path_key in owned or case_key in canonical:
            raise BootstrapError("direct installation owned path is duplicated")
        path = plugin_root.joinpath(*relative.parts)
        if not path.is_file() or _redirect(path) \
                or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise BootstrapError(
                f"direct installation owned file changed or is missing: {path_key}")
        owned.add(path_key)
        canonical.add(case_key)
    observed = {
        path.relative_to(plugin_root).as_posix()
        for path in _runtime_files(plugin_root)
        if path.name != ".loom-install-receipt.json"
    }
    if observed != owned:
        raise BootstrapError(
            "direct installation contains unowned, missing, or substituted files")
    return receipt


def _stage_direct_runtime(plugin_root, manager, *, version, platform_id,
                          binary_name, source_receipt, reliability_module,
                          package_module):
    """Build one immutable unattested runtime without changing the active pointer."""
    final = manager.versions / version
    if final.exists():
        raise BootstrapError("direct runtime version path already exists")
    staging = manager.versions / f".{version}.direct-staged-{uuid.uuid4().hex}"
    staging.mkdir()
    try:
        for item in source_receipt["files"]:
            relative = PurePosixPath(item["path"])
            source = Path(plugin_root).joinpath(*relative.parts)
            target = staging.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        helper = None
        helper_origin = None
        candidates = (
            Path(plugin_root) / "crypto" / platform_id / binary_name,
            Path(plugin_root) / "bin" / binary_name,
        )
        owned = {item["path"] for item in source_receipt["files"]}
        for candidate in candidates:
            try:
                relative = candidate.relative_to(plugin_root).as_posix()
            except ValueError:
                continue
            if relative in owned and candidate.is_file() and not _redirect(candidate):
                helper = candidate
                helper_origin = "installer-owned"
                break
        if helper is None:
            cargo = shutil.which("cargo")
            manifest = Path(plugin_root) / "vault-helper" / "Cargo.toml"
            lock = Path(plugin_root) / "vault-helper" / "Cargo.lock"
            if cargo is None or not manifest.is_file() or not lock.is_file():
                raise BootstrapError(
                    "direct source bootstrap requires an installer-owned platform helper "
                    "or a local Rust toolchain")
            build_root = staging / ".direct-cargo-build"
            build_environment = {**os.environ}
            build_environment.setdefault("RUST_MIN_STACK", str(16 * 1024 * 1024))
            result = subprocess.run([
                cargo, "build", "--release", "--locked", "--offline",
                "--manifest-path", str(manifest), "--target-dir", str(build_root),
            ], cwd=plugin_root, env=build_environment, capture_output=True,
                timeout=300, check=False)
            helper = build_root / "release" / binary_name
            if result.returncode != 0 or not helper.is_file():
                raise BootstrapError(
                    "direct source crypto helper build failed; Cargo must have all "
                    "locked dependencies available offline")
            helper_origin = "locally-built-from-receipt-owned-source"
        package_module._verify_helper_platform(platform_id, helper)
        binary = staging / "bin" / binary_name
        binary.parent.mkdir(parents=True, exist_ok=True)
        package_module._copy_helper_executable(helper, binary)
        build_root = staging / ".direct-cargo-build"
        if build_root.exists():
            shutil.rmtree(build_root)

        direct_body = {
            "schema_version": 1,
            "delivery_authority": "direct-source-install-unattested",
            "source_install_id": source_receipt["install_id"],
            "source_receipt_hash": source_receipt["receipt_hash"],
            "version": version,
            "platform": platform_id,
            "helper_origin": helper_origin,
        }
        reliability_module.atomic_write_json(
            staging / ".loom-direct-source-receipt.json",
            {**direct_body, "receipt_hash": _canonical_hash(direct_body)})
        runtime_files = [{
            "path": path.relative_to(staging).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        } for path in _runtime_files(staging)]
        runtime_files.sort(key=lambda item: item["path"])
        manifest = {"schema_version": 1, "version": version,
                    "platform": platform_id, "files": runtime_files}
        reliability_module.atomic_write_json(
            staging / "RUNTIME-MANIFEST.json", manifest)
        runtime_owned = [*map(lambda item: item["path"], runtime_files),
                         "RUNTIME-MANIFEST.json"]
        install = reliability_module.installation_receipt(
            staging, runtime_owned, install_id=str(uuid.uuid4()))
        reliability_module.atomic_write_json(
            staging / ".loom-install-receipt.json", install)
        payload_sha256 = hashlib.sha256(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return staging, final, binary, payload_sha256
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def _verify_recoverable_direct_runtime(final, *, version, platform_id, binary_name,
                                       source_receipt):
    """Verify an orphaned post-rename runtime so an interrupted activation can resume."""
    final = Path(final)
    direct = _load(final / ".loom-direct-source-receipt.json",
                   "direct runtime receipt")
    direct_body = {key: direct.get(key) for key in (
        "schema_version", "delivery_authority", "source_install_id",
        "source_receipt_hash", "version", "platform", "helper_origin")}
    expected_direct = {
        "schema_version": 1,
        "delivery_authority": "direct-source-install-unattested",
        "source_install_id": source_receipt["install_id"],
        "source_receipt_hash": source_receipt["receipt_hash"],
        "version": version,
        "platform": platform_id,
        "helper_origin": direct.get("helper_origin"),
    }
    if set(direct) != set(direct_body) | {"receipt_hash"} \
            or direct_body != expected_direct \
            or direct.get("helper_origin") not in {
                "installer-owned", "locally-built-from-receipt-owned-source"} \
            or direct.get("receipt_hash") != _canonical_hash(direct_body):
        raise BootstrapError("orphaned direct runtime receipt is invalid")
    manifest = _load(final / "RUNTIME-MANIFEST.json", "direct runtime manifest")
    if set(manifest) != {"schema_version", "version", "platform", "files"} \
            or manifest.get("schema_version") != 1 \
            or manifest.get("version") != version \
            or manifest.get("platform") != platform_id \
            or not isinstance(manifest.get("files"), list):
        raise BootstrapError("orphaned direct runtime manifest is invalid")
    expected = set()
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} \
                or not isinstance(item["path"], str) or "\\" in item["path"] \
                or type(item["bytes"]) is not int or item["bytes"] < 0 \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            raise BootstrapError("orphaned direct runtime target is invalid")
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or any(part in {"", ".", ".."}
                                         for part in relative.parts):
            raise BootstrapError("orphaned direct runtime target is unsafe")
        path = final.joinpath(*relative.parts)
        raw = path.read_bytes() if path.is_file() and not _redirect(path) else None
        if raw is None or len(raw) != item["bytes"] \
                or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise BootstrapError("orphaned direct runtime bytes changed")
        expected.add(relative.as_posix())
    ignored = {"RUNTIME-MANIFEST.json", ".loom-install-receipt.json",
               ".loom-health-receipt.json"}
    observed = {path.relative_to(final).as_posix()
                for path in _runtime_files(final) if path.name not in ignored}
    if observed != expected:
        raise BootstrapError("orphaned direct runtime has unlisted files")
    install = _load(final / ".loom-install-receipt.json",
                    "direct runtime installation receipt")
    install_fields = {"schema_version", "install_id", "files", "receipt_hash"}
    if set(install) != install_fields or install.get("schema_version") != 1 \
            or not isinstance(install.get("files"), list) \
            or install.get("receipt_hash") != _canonical_hash({
                key: install[key] for key in ("schema_version", "install_id", "files")
            }):
        raise BootstrapError("orphaned direct runtime installation receipt is invalid")
    try:
        if str(uuid.UUID(install["install_id"])) != install["install_id"]:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise BootstrapError("orphaned direct runtime installation identity is invalid") \
            from exc
    installed = set()
    for item in install["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
            raise BootstrapError("orphaned direct runtime owned-file record is invalid")
        relative = PurePosixPath(str(item["path"]))
        if relative.is_absolute() or any(part in {"", ".", ".."}
                                         for part in relative.parts):
            raise BootstrapError("orphaned direct runtime owned path is unsafe")
        path = final.joinpath(*relative.parts)
        raw = path.read_bytes() if path.is_file() and not _redirect(path) else None
        if raw is None or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise BootstrapError("orphaned direct runtime owned bytes changed")
        installed.add(relative.as_posix())
    if installed != expected | {"RUNTIME-MANIFEST.json"}:
        raise BootstrapError("orphaned direct runtime installation ownership is incomplete")
    health = _load(final / ".loom-health-receipt.json", "direct health receipt")
    health_fields = {
        "schema_version", "version", "delivery_authority", "source_receipt_hash",
        "healthy", "migration_complete", "disposable_request_passed",
        "before_inventory_sha256", "after_inventory_sha256",
    }
    if set(health) != health_fields or health["schema_version"] != 1 \
            or health["version"] != version \
            or health["delivery_authority"] != "direct-source-install-unattested" \
            or health["source_receipt_hash"] != source_receipt["receipt_hash"] \
            or health["healthy"] is not True \
            or health["migration_complete"] is not True \
            or health["disposable_request_passed"] is not True \
            or health["before_inventory_sha256"] != health["after_inventory_sha256"]:
        raise BootstrapError("orphaned direct runtime health is invalid")
    binary = final / "bin" / binary_name
    if not binary.is_file() or _redirect(binary):
        raise BootstrapError("orphaned direct runtime helper is unavailable")
    payload = hashlib.sha256(json.dumps(
        manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return binary, payload


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
        path.relative_to(runtime).as_posix() for path in _runtime_files(runtime)
        if path.name not in ignored
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
        home, current_runtime, staged_vault,
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
    plugin_root = _source_root(plugin_root)
    home = Path(home).resolve()
    manifest = _load(plugin_root / ".codex-plugin" / "plugin.json", "plugin manifest")
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise BootstrapError("plugin manifest version is invalid")
    release = plugin_root / "release"
    for boundary in (plugin_root / ".codex-plugin", release):
        if boundary.exists() and _redirect(boundary):
            raise BootstrapError("plugin trust metadata traverses a redirected directory")
    metadata_path = release / "metadata.json"
    trusted_root_path = release / "trusted-root.json"
    if metadata_path.exists() != trusted_root_path.exists():
        raise BootstrapError("signed delivery metadata is incomplete; refusing fallback")
    signed_delivery = metadata_path.is_file() and trusted_root_path.is_file()
    direct_receipt = None if signed_delivery else _direct_install_receipt(plugin_root)
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
    import loom_plugin_package
    import loom_reliability
    import loom_update

    platform_id = loom_update.platform_id()
    binary_name = "loom-vault.exe" if platform_id.startswith("windows-") else "loom-vault"
    manager = loom_update.SharedRuntime(home, plugin_roots=[plugin_root])
    if manager.current_path.is_file() and manager.current().get("version") == version:
        manager.reconcile_current_metadata()
        launcher = loom_adapters.install_launcher(
            home, current_runtime / "tools" / "loom_launcher.py")
        authority = ("direct-source-install-unattested"
                     if (current_runtime / ".loom-direct-source-receipt.json").is_file()
                     else "signed-release")
        return {"status": "current", "version": version,
                "delivery_authority": authority, "launcher": launcher}
    if direct_receipt is not None and manager.current_path.is_file():
        raise BootstrapError(
            "an unattested direct source cannot replace an active runtime; "
            "install a signed update")

    direct_staging = direct_final = None
    if direct_receipt is not None:
        direct_final = manager.versions / version
        if direct_final.exists():
            helper, direct_payload_hash = _verify_recoverable_direct_runtime(
                direct_final, version=version, platform_id=platform_id,
                binary_name=binary_name, source_receipt=direct_receipt)
        else:
            direct_staging, direct_final, helper, direct_payload_hash = \
                _stage_direct_runtime(
                    plugin_root, manager, version=version, platform_id=platform_id,
                    binary_name=binary_name, source_receipt=direct_receipt,
                    reliability_module=loom_reliability,
                    package_module=loom_plugin_package)
    else:
        helper = ((current_runtime / "bin" / binary_name)
                  if current_runtime is not None
                  else (plugin_root / "crypto" / platform_id / binary_name))
    payload = plugin_root / "runtime-payload" / platform_id
    trust_path = home / "runtime" / "trusted-root.json"
    if signed_delivery:
        bundle = _load(metadata_path, "signed release metadata")
        supplied_root = _load(trusted_root_path, "trusted root")
        trusted_root = _load(trust_path, "installed trusted root") \
            if trust_path.is_file() else supplied_root

    vault = None
    before_hash = _empty_inventory()
    if manager.current_path.is_file():
        current = manager.current()
        current_runtime = manager.versions / current["path"]
    vault_path = home / "vault" / "owner.sqlite3"
    if vault_path.is_file():
        vault, _crypto = loom_owner.open_owner_vault(home, helper)
        before_hash = vault.semantic_inventory()["sha256"]
    legacy_runtime = current_runtime if current_runtime is not None \
        else (plugin_root if direct_receipt is not None else None)
    if vault is None and legacy_runtime is not None \
            and (legacy_runtime / ".loom-instance-id").is_file():
        expected = (legacy_runtime / ".loom-instance-id").read_text(
            encoding="utf-8").strip()
        legacy_state = home / "instances" / expected
        if legacy_state.is_dir():
            vault, _crypto = _migrate_legacy_staged(
                home, helper, legacy_runtime, expected,
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
    if direct_receipt is not None:
        if direct_staging is not None:
            health = health_check(direct_staging)
            if health.get("healthy") is not True \
                    or health.get("migration_complete") is not True \
                    or health.get("disposable_request_passed") is not True \
                    or health.get("before_inventory_sha256") \
                    != health.get("after_inventory_sha256"):
                shutil.rmtree(direct_staging, ignore_errors=True)
                raise BootstrapError("direct source runtime health check failed")
            loom_reliability.atomic_write_json(
                direct_staging / ".loom-health-receipt.json", {
                    "schema_version": 1, "version": version,
                    "delivery_authority": "direct-source-install-unattested",
                    "source_receipt_hash": direct_receipt["receipt_hash"],
                    **health,
                })
            os.replace(direct_staging, direct_final)
        pointer = {
            "version": version, "path": version,
            "payload_sha256": direct_payload_hash,
            "release_sequence": 1, "previous": None,
        }
        manager.activate_direct_baseline(pointer)
        active_runtime = _verified_current_runtime(home)
        launcher = loom_adapters.install_launcher(
            home, active_runtime / "tools" / "loom_launcher.py")
        return {
            "status": "activated", "version": version,
            "delivery_authority": "direct-source-install-unattested",
            "source_receipt_hash": direct_receipt["receipt_hash"],
            "launcher": launcher,
        }

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
    return {**result, "delivery_authority": "signed-release", "launcher": launcher}


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
