#!/usr/bin/env python3
"""Ownership-safe Codex user integration for Loom's local MCP and hooks."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import loom_reliability
import loom_adapters
import loom_install


RECEIPT_VERSION = 3
MAX_HOOKS_BYTES = 256 * 1024
MAX_CODEX_INVENTORY_BYTES = 1024 * 1024
MAX_PLUGIN_MIGRATION_RECEIPT_BYTES = 4 * 1024 * 1024
LEGACY_PLUGIN_TREE_BOUNDS = {
    "max_entries": 4096,
    "max_file_bytes": 32 * 1024 * 1024,
    "max_total_bytes": 128 * 1024 * 1024,
}
PLUGIN_MIGRATION_VERSION = 1
PLUGIN_MCP_SERVER = {
    "command": "python",
    "args": ["-B", "./scripts/loom_codex_mcp.py"],
    "cwd": ".",
    "env_vars": [
        "HOME", "USERPROFILE", "CODEX_HOME", "CARGO_HOME", "RUSTUP_HOME"],
    "tool_timeout_sec": 900,
}


class IntegrationError(RuntimeError):
    pass


def _codex_executable(user_home, explicit=None):
    """Select a Codex binary that actually supports plugin inventory."""
    candidates = []
    if explicit:
        try:
            resolved = Path(explicit).resolve()
        except (OSError, RuntimeError):
            return Path("")
        return (
            resolved
            if resolved.is_file() and not resolved.is_symlink()
            else Path(""))
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            root = Path(local) / "OpenAI" / "Codex" / "bin"
            versioned = []
            try:
                versioned = sorted(
                    root.glob("*/codex.exe"),
                    key=lambda item: item.stat().st_mtime_ns,
                    reverse=True)[:64]
            except OSError:
                versioned = []
            candidates.extend(versioned)
            candidates.append(root / "codex.exe")
    elif sys.platform == "darwin":
        candidates.extend((
            Path("/Applications/Codex.app/Contents/Resources/codex"),
            Path(user_home) / "Applications" / "Codex.app" / "Contents" /
            "Resources" / "codex",
        ))
    discovered = shutil.which("codex")
    if discovered:
        candidates.append(Path(discovered))
    seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        key = os.path.normcase(str(resolved))
        if key in seen:
            continue
        seen.add(key)
        if resolved.is_file() and not resolved.is_symlink() \
                and _supports_plugin_inventory(
                    resolved, Path(user_home) / ".codex"):
            return resolved
    return Path("")


def _supports_plugin_inventory(codex, codex_home):
    environment = {**os.environ, "CODEX_HOME": str(Path(codex_home).resolve())}
    try:
        completed = subprocess.run(
            [str(codex), "plugin", "list", "--json"],
            capture_output=True, text=True, timeout=10,
            check=False, env=environment)
        if completed.returncode != 0 \
                or len(completed.stdout.encode("utf-8")) > MAX_CODEX_INVENTORY_BYTES:
            return False
        value = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(value, (list, dict))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise IntegrationError(f"Codex hooks contain a duplicate field: {key}")
        value[key] = item
    return value


def _read_hooks(path):
    if not os.path.lexists(path):
        return {"hooks": {}}, None
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_HOOKS_BYTES:
        raise IntegrationError("Codex hooks file is redirected, irregular, or oversized")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationError(f"Codex hooks file is invalid: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("hooks"), dict):
        raise IntegrationError("Codex hooks file has no valid hooks object")
    return value, raw


def _commands(launcher, loom_home):
    launcher = str(Path(launcher).resolve())
    loom_home = str(Path(loom_home).resolve())
    python = str(Path(sys.executable).resolve())
    prefix = f'"{python}" -B "{launcher}" --home "{loom_home}"'
    lifecycle = {"type": "command", "command": prefix + " hook-lifecycle",
                 "commandWindows": prefix + " hook-lifecycle", "timeout": 5}
    return {
        "SessionStart": {
            "matcher": "startup|resume|clear|compact",
            "hooks": [{"type": "command", "command": prefix + " hook-session-start",
                       "commandWindows": prefix + " hook-session-start", "timeout": 2,
                       "statusMessage": "Checking Loom runtime"}],
        },
        "UserPromptSubmit": {
            "hooks": [{"type": "command", "command": prefix + " hook-user-prompt",
                       "commandWindows": prefix + " hook-user-prompt", "timeout": 180,
                       "statusMessage": "Sealing Loom request"}],
        },
        "PreToolUse": {
            "matcher": "apply_patch|Edit|Write",
            "hooks": [{**lifecycle, "statusMessage": "Checking Loom write scope"}],
        },
        "PostToolUse": {
            "matcher": "Bash|apply_patch|Edit|Write",
            "hooks": [{**lifecycle, "statusMessage": "Recording Loom freshness"}],
        },
        "PreCompact": {
            "matcher": "manual|auto",
            "hooks": [{**lifecycle, "statusMessage": "Sealing Loom continuity"}],
        },
        "PostCompact": {
            "matcher": "manual|auto",
            "hooks": [{**lifecycle, "statusMessage": "Restoring Loom continuity"}],
        },
        "Stop": {"hooks": [lifecycle]},
        "SubagentStart": {"hooks": [lifecycle]},
        "SubagentStop": {"hooks": [lifecycle]},
    }


def _entry_hash(entry):
    return _sha(json.dumps(entry, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8"))


def _receipt_path(loom_home):
    return Path(loom_home) / "adapters" / "receipts" / "codex-integration.json"


def _plugin_migration_path(user_home):
    return Path(user_home) / ".codex" / "loom-plugin-migration.json"


def _read_plugin_migration(path):
    if not os.path.lexists(path):
        return None
    if not path.is_file() or path.is_symlink() \
            or path.stat().st_size > MAX_PLUGIN_MIGRATION_RECEIPT_BYTES:
        raise IntegrationError("Codex plugin migration receipt is unsafe")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationError(
            f"Codex plugin migration receipt is invalid: {exc}") from exc
    fields = {
        "schema_version", "state", "source", "archive", "install_id",
        "install_receipt_hash", "tree_manifest", "plugin",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != PLUGIN_MIGRATION_VERSION \
            or value.get("state") not in {"prepared", "moved", "retired"} \
            or not isinstance(value.get("source"), str) \
            or not isinstance(value.get("archive"), str) \
            or not isinstance(value.get("install_id"), str) \
            or not isinstance(value.get("install_receipt_hash"), str) \
            or not isinstance(value.get("plugin"), dict):
        raise IntegrationError("Codex plugin migration receipt shape is invalid")
    try:
        loom_reliability.validate_exact_tree_manifest(
            value["tree_manifest"], **LEGACY_PLUGIN_TREE_BOUNDS)
    except loom_reliability.ReliabilityError as exc:
        raise IntegrationError(
            f"Codex plugin migration tree evidence is invalid: {exc}") from exc
    return value


def _tree_state(path, expected):
    if not os.path.lexists(path):
        return "absent"
    try:
        actual = loom_reliability.exact_tree_manifest(
            path, **LEGACY_PLUGIN_TREE_BOUNDS)
    except loom_reliability.ReliabilityError:
        return "changed"
    return (
        "equal"
        if loom_reliability.exact_tree_manifests_equal(
            actual, expected, **LEGACY_PLUGIN_TREE_BOUNDS)
        else "changed")


def _prepare_legacy_skill_retirement(user_home, plugin):
    source = Path(user_home) / ".codex" / "skills" / "loom"
    migration_path = _plugin_migration_path(user_home)
    existing = _read_plugin_migration(migration_path)
    if existing is not None:
        expected_source = str(source.resolve())
        expected_archive = str(
            (Path(user_home) / ".codex" / "retired-loom"
             / f"direct-{existing['install_id']}").resolve())
        if existing["source"] != expected_source \
                or existing["archive"] != expected_archive:
            raise IntegrationError(
                "Codex plugin migration receipt names an unexpected namespace")
        source_state = _tree_state(Path(existing["source"]), existing["tree_manifest"])
        archive_state = _tree_state(Path(existing["archive"]), existing["tree_manifest"])
        if source_state == "equal" and archive_state == "absent" \
                and existing["state"] == "prepared":
            return {
                "receipt": existing, "path": migration_path,
                "moved_this_call": False,
            }
        if source_state == "absent" and archive_state == "equal" \
                and existing["state"] == "prepared":
            existing["state"] = "moved"
            loom_reliability.atomic_write_json(migration_path, existing)
            return {
                "receipt": existing, "path": migration_path,
                "moved_this_call": False,
            }
        if source_state == "absent" and archive_state == "equal" \
                and existing["state"] in {"moved", "retired"}:
            return {
                "receipt": existing, "path": migration_path,
                "moved_this_call": False,
            }
        raise IntegrationError(
            "legacy Loom skill migration namespace changed; refusing reconciliation")
    if not os.path.lexists(source):
        return None
    if not source.is_dir() or source.is_symlink():
        raise IntegrationError("legacy Codex Loom skill is redirected or irregular")
    try:
        checked = loom_install.check(source)
        tree = loom_reliability.exact_tree_manifest(
            source, **LEGACY_PLUGIN_TREE_BOUNDS)
        install_receipt = json.loads(
            (source / loom_install.RECEIPT).read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object)
    except (loom_install.InstallError, loom_reliability.ReliabilityError,
            OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationError(
            f"legacy Codex Loom skill is not an exact receipt-owned install: {exc}") \
            from exc
    expected_files = {
        item["path"] for item in install_receipt.get("files", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)}
    expected_files.add(loom_install.RECEIPT)
    actual_files = {
        item["path"] for item in tree["entries"] if item["kind"] == "file"}
    if actual_files != expected_files:
        raise IntegrationError(
            "legacy Codex Loom skill contains unowned or missing files")
    archive = (
        Path(user_home) / ".codex" / "retired-loom"
        / f"direct-{checked['install_id']}")
    if os.path.lexists(archive):
        raise IntegrationError("legacy Codex Loom rollback archive already exists")
    value = {
        "schema_version": PLUGIN_MIGRATION_VERSION,
        "state": "prepared",
        "source": str(source.resolve()),
        "archive": str(archive.resolve()),
        "install_id": checked["install_id"],
        "install_receipt_hash": checked["receipt_hash"],
        "tree_manifest": tree,
        "plugin": {
            "plugin_id": plugin.get("plugin_id"),
            "marketplace": plugin["marketplace"],
            "version": plugin["version"],
        },
    }
    migration_path.parent.mkdir(parents=True, exist_ok=True)
    loom_reliability.atomic_write_json(migration_path, value)
    return {"receipt": value, "path": migration_path, "moved_this_call": False}


def _activate_legacy_skill_retirement(retirement):
    if retirement is None:
        return None
    value = retirement["receipt"]
    source = Path(value["source"])
    archive = Path(value["archive"])
    source_state = _tree_state(source, value["tree_manifest"])
    archive_state = _tree_state(archive, value["tree_manifest"])
    if source_state == "absent" and archive_state == "equal":
        return retirement
    if source_state != "equal" or archive_state != "absent":
        raise IntegrationError(
            "legacy Codex Loom skill cannot be retired from its current state")
    archive.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(source, archive)
    except OSError as exc:
        raise IntegrationError(
            f"legacy Codex Loom skill retirement failed: {exc}") from exc
    if _tree_state(archive, value["tree_manifest"]) != "equal" \
            or os.path.lexists(source):
        raise IntegrationError(
            "legacy Codex Loom skill retirement could not be proven")
    value["state"] = "moved"
    loom_reliability.atomic_write_json(retirement["path"], value)
    retirement["moved_this_call"] = True
    return retirement


def _rollback_legacy_skill_retirement(retirement):
    if retirement is None or not retirement.get("moved_this_call"):
        return
    value = retirement["receipt"]
    source = Path(value["source"])
    archive = Path(value["archive"])
    if os.path.lexists(source) \
            or _tree_state(archive, value["tree_manifest"]) != "equal":
        raise IntegrationError(
            "legacy Codex Loom skill rollback namespace is inconsistent")
    try:
        os.replace(archive, source)
    except OSError as exc:
        raise IntegrationError(
            f"legacy Codex Loom skill rollback failed: {exc}") from exc
    if _tree_state(source, value["tree_manifest"]) != "equal":
        raise IntegrationError("legacy Codex Loom skill rollback could not be proven")
    retirement["path"].unlink()


def _seal_legacy_skill_retirement(retirement):
    if retirement is None:
        return {"status": "absent"}
    value = retirement["receipt"]
    if _tree_state(Path(value["archive"]), value["tree_manifest"]) != "equal" \
            or os.path.lexists(value["source"]):
        raise IntegrationError("legacy Codex Loom skill retirement is not durable")
    value["state"] = "retired"
    loom_reliability.atomic_write_json(retirement["path"], value)
    return {
        "status": "retired",
        "install_id": value["install_id"],
        "archive": value["archive"],
    }


def _owned_codex_adapter_state(user_home, loom_home, legacy_archive):
    receipt_path = loom_adapters._receipt_path(loom_home, "codex")
    capability_path = loom_adapters._capability_path(loom_home, "codex")
    present = (os.path.lexists(receipt_path), os.path.lexists(capability_path))
    if present == (False, False):
        return []
    if present != (True, True) or not receipt_path.is_file() \
            or receipt_path.is_symlink() or not capability_path.is_file() \
            or capability_path.is_symlink():
        raise IntegrationError("legacy Codex adapter ownership state is incomplete")
    try:
        receipt = json.loads(
            receipt_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationError(
            f"legacy Codex adapter receipt is invalid: {exc}") from exc
    target = Path(user_home) / ".codex" / "skills" / "loom" / "SKILL.md"
    observed = (
        Path(legacy_archive) / "SKILL.md"
        if legacy_archive is not None else target)
    if not observed.is_file() or observed.is_symlink() \
            or receipt.get("schema_version") != 2 \
            or receipt.get("protocol_version") != 2 \
            or receipt.get("agent") != "codex" \
            or receipt.get("path") != str(target) \
            or receipt.get("sha256") != _sha(observed.read_bytes()) \
            or receipt.get("capability_receipt_sha256") \
            != _sha(capability_path.read_bytes()):
        raise IntegrationError(
            "legacy Codex adapter ownership state changed; refusing retirement")
    return [receipt_path, capability_path]


def _load_receipt(path):
    if not os.path.lexists(path):
        return None
    if not path.is_file() or path.is_symlink():
        raise IntegrationError("Codex integration receipt is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationError(f"Codex integration receipt is invalid: {exc}") from exc
    current_fields = {
        "schema_version", "hooks_path", "entries", "mcp_name",
        "mcp_command_sha256", "mcp_managed", "generation",
    }
    legacy_fields = {
        "schema_version", "hooks_path", "entries", "mcp_name", "generation",
    }
    intermediate_fields = legacy_fields | {"mcp_command_sha256"}
    if not isinstance(value, dict) \
            or frozenset(value) not in {
                frozenset(current_fields), frozenset(intermediate_fields),
                frozenset(legacy_fields)} \
            or value.get("schema_version") not in {1, 2, RECEIPT_VERSION} \
            or value.get("mcp_name") not in {None, "loom"} \
            or type(value.get("generation")) is not int \
            or not isinstance(value.get("entries"), dict):
        raise IntegrationError("Codex integration receipt shape is invalid")
    normalized = dict(value)
    normalized["mcp_command_sha256"] = value.get("mcp_command_sha256")
    normalized["mcp_managed"] = value.get("mcp_managed", True)
    if type(normalized["mcp_managed"]) is not bool \
            or normalized["mcp_managed"] != (normalized["mcp_name"] == "loom"):
        raise IntegrationError("Codex integration MCP ownership is invalid")
    return normalized


def _merge_hooks(value, desired, receipt):
    merged = json.loads(json.dumps(value))
    events = merged["hooks"]
    receipt_entries = {} if receipt is None else receipt["entries"]
    for event, entry in desired.items():
        rows = events.setdefault(event, [])
        if not isinstance(rows, list):
            raise IntegrationError(f"Codex {event} hooks are invalid")
        owned_hash = receipt_entries.get(event)
        matching = [row for row in rows if _entry_hash(row) == _entry_hash(entry)]
        loom_like = [row for row in rows if isinstance(row, dict)
                     and ".loom" in json.dumps(row).lower()]
        if receipt is None:
            if matching or loom_like:
                raise IntegrationError(f"unowned Loom {event} hook already exists")
            rows.append(entry)
        else:
            if owned_hash is None:
                if matching or loom_like:
                    raise IntegrationError(f"unowned Loom {event} hook already exists")
                rows.append(entry)
            else:
                owned = [row for row in rows if _entry_hash(row) == owned_hash]
                if len(owned) != 1:
                    raise IntegrationError(f"owned Loom {event} hook changed or is missing")
                index = rows.index(owned[0])
                rows[index] = entry
        receipt_entries[event] = _entry_hash(entry)
    return merged, receipt_entries


def _preserved_hook_entries(value, receipt, hooks_path):
    """Validate existing Loom hooks without installing or rewriting any hook."""
    entries = {} if receipt is None else dict(receipt["entries"])
    if receipt is not None and Path(receipt["hooks_path"]) != Path(hooks_path):
        raise IntegrationError("Codex integration receipt names a different hooks file")
    owned_hashes = set(entries.values())
    for event, rows in value["hooks"].items():
        if not isinstance(rows, list):
            raise IntegrationError(f"Codex {event} hooks are invalid")
        for row in rows:
            digest = _entry_hash(row)
            if isinstance(row, dict) and ".loom" in json.dumps(row).lower() \
                    and digest not in owned_hashes:
                raise IntegrationError(
                    f"unowned Loom {event} hook shadows the verified plugin")
    for event, expected in entries.items():
        rows = value["hooks"].get(event)
        if not isinstance(rows, list) \
                or len([row for row in rows if _entry_hash(row) == expected]) != 1:
            raise IntegrationError(f"owned Loom {event} hook changed or is missing")
    return entries


def _remove_hooks(value, receipt):
    changed = json.loads(json.dumps(value))
    for event, expected_hash in receipt["entries"].items():
        rows = changed["hooks"].get(event)
        if not isinstance(rows, list):
            raise IntegrationError(f"owned Loom {event} hook is missing")
        matches = [row for row in rows if _entry_hash(row) == expected_hash]
        if len(matches) != 1:
            raise IntegrationError(f"owned Loom {event} hook changed; refusing removal")
        rows.remove(matches[0])
        if not rows:
            changed["hooks"].pop(event)
    return changed


def _write_hooks(path, value):
    raw = _hooks_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    loom_reliability.atomic_write_bytes(path, raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return raw


def _hooks_bytes(value):
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if len(raw) > MAX_HOOKS_BYTES:
        raise IntegrationError("merged Codex hooks exceed their byte bound")
    return raw


def _mcp_rows(codex, *, codex_home):
    environment = {**os.environ, "CODEX_HOME": str(codex_home)}
    result = subprocess.run([str(codex), "mcp", "list", "--json"],
                            capture_output=True, text=True, timeout=20,
                            check=False, env=environment)
    if result.returncode != 0:
        raise IntegrationError("Codex could not read its MCP configuration: "
                               + result.stderr.strip()[:512])
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise IntegrationError("Codex returned invalid MCP inventory JSON") from exc
    rows = value if isinstance(value, list) else value.get("servers", []) if isinstance(value, dict) else []
    if not isinstance(rows, list):
        raise IntegrationError("Codex MCP inventory has an unsupported shape")
    return rows


def _plugin_rows(codex, *, codex_home):
    environment = {**os.environ, "CODEX_HOME": str(codex_home)}
    result = subprocess.run([str(codex), "plugin", "list", "--json"],
                            capture_output=True, text=True, timeout=20,
                            check=False, env=environment)
    if result.returncode != 0:
        raise IntegrationError("Codex could not read its plugin inventory: "
                               + result.stderr.strip()[:512])
    if len(result.stdout.encode("utf-8")) > MAX_CODEX_INVENTORY_BYTES:
        raise IntegrationError("Codex plugin inventory is oversized")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise IntegrationError("Codex returned invalid plugin inventory JSON") from exc
    rows = value.get("installed", []) if isinstance(value, dict) else []
    if not isinstance(rows, list):
        raise IntegrationError("Codex plugin inventory has an unsupported shape")
    return rows


def _verified_loom_plugin(codex, *, codex_home):
    rows = [
        row for row in _plugin_rows(codex, codex_home=codex_home)
        if isinstance(row, dict) and row.get("name") == "loom"
        and row.get("installed") is True and row.get("enabled") is True
    ]
    if len(rows) != 1:
        identities = sorted({
            str(row.get("pluginId") or (
                f"loom@{row.get('marketplaceName')}"
                if isinstance(row.get("marketplaceName"), str)
                else "loom@unknown"))
            for row in rows
        })[:8]
        detail = ", ".join(identities) if identities else "none"
        raise IntegrationError(
            "exactly one enabled Loom plugin is required before plugin-mode migration; "
            f"observed {len(rows)}: {detail}")
    row = rows[0]
    if not isinstance(row.get("version"), str) or not row["version"] \
            or not isinstance(row.get("marketplaceName"), str) \
            or not row["marketplaceName"]:
        raise IntegrationError("installed Loom plugin identity is incomplete")
    candidates = [
        Path(codex_home) / "plugins" / "cache" / row["marketplaceName"]
        / "loom" / row["version"]]
    for candidate in candidates:
        try:
            root = loom_reliability._absolute(
                candidate, "installed Loom plugin", must_exist=True)
        except loom_reliability.ReliabilityError:
            continue
        manifest = root / ".codex-plugin" / "plugin.json"
        mcp = root / ".mcp.json"
        script = root / "scripts" / "loom_codex_mcp.py"
        if not root.is_dir() or root.is_symlink() \
                or not manifest.is_file() or manifest.is_symlink() \
                or not mcp.is_file() or mcp.is_symlink() \
                or not script.is_file() or script.is_symlink():
            continue
        try:
            manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
            mcp_value = json.loads(mcp.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        server = (mcp_value.get("mcpServers", {}).get("loom")
                  if isinstance(mcp_value, dict) else None)
        if isinstance(manifest_value, dict) \
                and manifest_value.get("name") == "loom" \
                and manifest_value.get("version") == row["version"] \
                and server == PLUGIN_MCP_SERVER:
            return {
                "plugin_id": row.get("pluginId"),
                "marketplace": row["marketplaceName"],
                "version": row["version"],
                "root": str(root),
            }
    raise IntegrationError(
        "the enabled Loom plugin payload could not be verified from Codex inventory")


def _mcp_named(rows, name):
    return [row for row in rows if isinstance(row, dict) and row.get("name") == name]


def _is_verified_plugin_mcp_row(row, plugin):
    if not isinstance(row, dict) or row.get("name") != "loom" \
            or row.get("enabled") is not True \
            or not isinstance(row.get("transport"), dict):
        return False
    transport = row["transport"]
    if set(transport) != {
            "type", "command", "args", "env", "env_vars", "cwd"} \
            or transport.get("type") != "stdio" \
            or transport.get("command") != PLUGIN_MCP_SERVER["command"] \
            or transport.get("args") != PLUGIN_MCP_SERVER["args"] \
            or transport.get("env") is not None \
            or transport.get("env_vars") != PLUGIN_MCP_SERVER["env_vars"] \
            or row.get("tool_timeout_sec") \
            != float(PLUGIN_MCP_SERVER["tool_timeout_sec"]):
        return False
    try:
        observed = Path(transport["cwd"]).resolve()
        expected = (
            Path(plugin["root"]) / PLUGIN_MCP_SERVER["cwd"]).resolve()
    except (KeyError, TypeError, OSError, RuntimeError):
        return False
    return observed == expected


def _plugin_mcp_inventory(rows, plugin):
    named = _mcp_named(rows, "loom")
    canonical = [
        row for row in named if _is_verified_plugin_mcp_row(row, plugin)]
    shadows = [row for row in named if row not in canonical]
    if len(canonical) > 1:
        raise IntegrationError(
            "Codex exposed more than one verified Loom plugin MCP transport")
    return canonical, shadows


def _expected_mcp_transport(launcher, loom_home):
    return {
        "type": "stdio",
        "command": str(Path(sys.executable).resolve()),
        "args": ["-B", str(Path(launcher).resolve()), "--home",
                 str(Path(loom_home).resolve()), "mcp"],
        "env": None,
        "env_vars": [],
        "cwd": None,
    }


def _mcp_transport_hash(row):
    if not isinstance(row, dict) or not isinstance(row.get("transport"), dict):
        raise IntegrationError("Codex MCP inventory omitted the Loom transport")
    return _entry_hash(row["transport"])


def _mcp_command(codex, action, *, codex_home, launcher=None, loom_home=None):
    environment = {**os.environ, "CODEX_HOME": str(codex_home)}
    command = [str(codex), "mcp", action, "loom"]
    if action == "add":
        command.extend(["--", str(Path(sys.executable).resolve()), "-B",
                        str(Path(launcher).resolve()), "--home",
                        str(Path(loom_home).resolve()), "mcp"])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                            check=False, env=environment)
    if result.returncode != 0:
        raise IntegrationError(f"Codex MCP {action} failed: " + result.stderr.strip()[:512])


def _reconcile_transaction(user_home, loom_home, codex, *, plugin=None):
    _lock, journal_path, _generation = loom_adapters._transaction_paths(loom_home)
    if os.path.lexists(journal_path):
        try:
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrationError(f"Codex integration transaction is invalid: {exc}") from exc
        if not isinstance(journal, dict):
            raise IntegrationError("Codex integration transaction is invalid")
        operation = journal.get("operation")
        if journal.get("status") == "prepared" \
                and isinstance(operation, str) \
                and operation.startswith("codex-integration-") \
                and operation not in {
                    "codex-integration-install-mcp-add",
                    "codex-integration-install",
                    "codex-integration-plugin-migrate-mcp-remove",
                    "codex-integration-uninstall-mcp-remove",
                    "codex-integration-uninstall"}:
            raise IntegrationError("Codex integration transaction operation is unsupported")
        if journal.get("status") == "prepared" and operation in {
                "codex-integration-install-mcp-add",
                "codex-integration-plugin-migrate-mcp-remove",
                "codex-integration-uninstall-mcp-remove"}:
            if not Path(codex).is_file():
                raise IntegrationError(
                    "Codex executable is required to recover an interrupted integration")
            launcher = Path(loom_home) / "bin" / "loom.py"
            expected = _entry_hash(_expected_mcp_transport(launcher, loom_home))
            inventory = _mcp_rows(
                codex, codex_home=Path(user_home) / ".codex")
            rows = _mcp_named(inventory, "loom")
            if operation == "codex-integration-install-mcp-add":
                if len(rows) == 1 and _mcp_transport_hash(rows[0]) == expected:
                    _mcp_command(codex, "remove", codex_home=Path(user_home) / ".codex")
                    if _mcp_named(_mcp_rows(
                            codex, codex_home=Path(user_home) / ".codex"), "loom"):
                        raise IntegrationError(
                            "interrupted Codex MCP install removal was not durable")
                elif rows:
                    raise IntegrationError(
                        "interrupted Codex MCP install no longer matches its exact transport")
            elif operation == "codex-integration-plugin-migrate-mcp-remove":
                if plugin is None:
                    raise IntegrationError(
                        "interrupted plugin migration has no verified plugin identity")
                canonical, shadows = _plugin_mcp_inventory(inventory, plugin)
                if not shadows and len(canonical) == 1:
                    _mcp_command(
                        codex, "add",
                        codex_home=Path(user_home) / ".codex",
                        launcher=launcher, loom_home=loom_home)
                    restored_inventory = _mcp_rows(
                        codex, codex_home=Path(user_home) / ".codex")
                    _restored_plugin, restored_shadows = _plugin_mcp_inventory(
                        restored_inventory, plugin)
                    if len(restored_shadows) != 1 \
                            or _mcp_transport_hash(
                                restored_shadows[0]) != expected:
                        raise IntegrationError(
                            "interrupted Codex plugin migration restoration "
                            "was not durable")
                elif len(shadows) != 1 \
                        or _mcp_transport_hash(shadows[0]) != expected:
                    raise IntegrationError(
                        "interrupted Codex plugin migration no longer matches "
                        "its exact user transport")
            else:
                if not rows:
                    _mcp_command(codex, "add", codex_home=Path(user_home) / ".codex",
                                 launcher=launcher, loom_home=loom_home)
                    restored = _mcp_named(_mcp_rows(
                        codex, codex_home=Path(user_home) / ".codex"), "loom")
                    if len(restored) != 1 \
                            or _mcp_transport_hash(restored[0]) != expected:
                        raise IntegrationError(
                            "interrupted Codex MCP uninstall restoration was not durable")
                elif len(rows) != 1 or _mcp_transport_hash(rows[0]) != expected:
                    raise IntegrationError(
                        "interrupted Codex MCP uninstall no longer matches its exact transport")
    try:
        loom_adapters._recover_transaction(user_home, loom_home)
    except loom_adapters.AdapterError as exc:
        raise IntegrationError(str(exc)) from exc


def _install_locked(
        user_home, loom_home, *, approved, codex_executable=None, verified=True,
        manage_mcp=True, plugin_mode=False, verified_plugin=None,
        legacy_archive=None, preserve_owned_hooks=False):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    launcher = loom_home / "bin" / "loom.py"
    if not launcher.is_file() or launcher.is_symlink():
        raise IntegrationError("receipt-owned stable launcher is unavailable")
    codex = _codex_executable(user_home, codex_executable)
    if plugin_mode and manage_mcp:
        raise IntegrationError("plugin mode cannot install a second user-level MCP server")
    if (manage_mcp or plugin_mode) and not codex.is_file():
        raise IntegrationError("Codex executable is unavailable")
    hooks_path = user_home / ".codex" / "hooks.json"
    receipt_path = _receipt_path(loom_home)
    receipt = _load_receipt(receipt_path)
    desired = _commands(launcher, loom_home) if verified else {}
    plugin = None
    if plugin_mode:
        plugin = verified_plugin or _verified_loom_plugin(
            codex, codex_home=user_home / ".codex")
    preview = {
        "status": "approval-required",
        "mcp": "plugin:loom" if plugin_mode else "loom" if manage_mcp else None,
        "hooks": sorted(desired), "hooks_path": str(hooks_path),
        "plugin": plugin,
    }
    if not approved:
        return preview
    codex_home = user_home / ".codex"
    codex_home.mkdir(parents=True, exist_ok=True)
    value, before = _read_hooks(hooks_path)
    rows = (
        _mcp_rows(codex, codex_home=codex_home)
        if manage_mcp or plugin_mode else [])
    if plugin_mode:
        plugin_mcp, existing = _plugin_mcp_inventory(rows, plugin)
    else:
        plugin_mcp, existing = [], _mcp_named(rows, "loom")
    expected_mcp_hash = _entry_hash(_expected_mcp_transport(launcher, loom_home))
    migrating_owned_mcp = bool(
        plugin_mode and receipt is not None and receipt["mcp_managed"])
    if receipt is not None and receipt["mcp_managed"] != manage_mcp \
            and not migrating_owned_mcp:
        raise IntegrationError(
            "Codex integration mode changed; uninstall the owned integration first")
    if plugin_mode and existing:
        if not migrating_owned_mcp or len(existing) != 1 \
                or receipt["mcp_command_sha256"] is None \
                or _mcp_transport_hash(existing[0]) \
                != receipt["mcp_command_sha256"]:
            raise IntegrationError(
                "an unowned or changed user-level Loom MCP shadows the verified plugin")
    if plugin_mode and not existing and len(plugin_mcp) != 1:
        raise IntegrationError(
            "the verified Loom plugin MCP is not active in Codex")
    if plugin_mode and migrating_owned_mcp and not existing:
        if receipt["mcp_command_sha256"] is None:
            raise IntegrationError(
                "legacy Codex MCP ownership must be refreshed before plugin migration")
    if manage_mcp and receipt is None and existing:
        raise IntegrationError("unowned Codex MCP server named loom already exists")
    if manage_mcp and receipt is not None and existing:
        observed_mcp_hash = _mcp_transport_hash(existing[0]) if len(existing) == 1 else None
        receipt_mcp_hash = receipt["mcp_command_sha256"]
        if len(existing) != 1 or observed_mcp_hash != expected_mcp_hash \
                or receipt_mcp_hash not in {None, expected_mcp_hash}:
            raise IntegrationError("owned Codex MCP transport changed; refusing overwrite")
    if preserve_owned_hooks:
        merged = value
        entry_hashes = _preserved_hook_entries(value, receipt, hooks_path)
    else:
        merged, entry_hashes = _merge_hooks(value, desired, receipt) if verified \
            else (value, {})
    generation = 1 if receipt is None else receipt["generation"] + 1
    new_receipt = {"schema_version": RECEIPT_VERSION,
                   "hooks_path": str(hooks_path), "entries": entry_hashes,
                   "mcp_name": "loom" if manage_mcp else None,
                   "mcp_command_sha256": expected_mcp_hash if manage_mcp else None,
                   "mcp_managed": manage_mcp,
                   "generation": generation}
    hooks_content = _hooks_bytes(merged)
    receipt_content = loom_adapters._json_bytes(new_receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    retired_adapter_state = (
        _owned_codex_adapter_state(
            user_home, loom_home, legacy_archive)
        if plugin_mode else [])
    operation = (
        "codex-integration-plugin-migrate-mcp-remove"
        if plugin_mode and existing else
        "codex-integration-install-mcp-add"
        if manage_mcp and not existing else
        "codex-integration-install")
    file_targets = (
        [] if preserve_owned_hooks else [(hooks_path, hooks_content)])
    journal, journal_path, generation_path = loom_adapters._begin_transaction(
        user_home, loom_home, operation,
        [*file_targets, (receipt_path, receipt_content),
         *((path, None) for path in retired_adapter_state)])
    mcp_added = False
    mcp_removed = False
    try:
        if not preserve_owned_hooks:
            loom_reliability.atomic_write_bytes(hooks_path, hooks_content)
        if plugin_mode and existing:
            _mcp_command(codex, "remove", codex_home=codex_home)
            mcp_removed = True
        if manage_mcp and not existing:
            _mcp_command(codex, "add", codex_home=codex_home,
                         launcher=launcher, loom_home=loom_home)
            mcp_added = True
        if manage_mcp:
            installed = _mcp_named(
                _mcp_rows(codex, codex_home=codex_home), "loom")
            if len(installed) != 1 or _mcp_transport_hash(installed[0]) != expected_mcp_hash:
                raise IntegrationError("Codex did not retain exactly one Loom MCP server")
        if plugin_mode:
            retained_plugin, retained_shadows = _plugin_mcp_inventory(
                _mcp_rows(codex, codex_home=codex_home), plugin)
        else:
            retained_plugin, retained_shadows = [], []
        if plugin_mode and (
                len(retained_plugin) != 1 or retained_shadows):
            raise IntegrationError(
                "Codex did not retain exactly one verified plugin MCP transport")
        for path in retired_adapter_state:
            path.unlink()
        if any(os.path.lexists(path) for path in retired_adapter_state):
            raise IntegrationError(
                "legacy Codex adapter ownership state was not retired")
        loom_reliability.atomic_write_bytes(receipt_path, receipt_content)
        loom_adapters._finish_transaction(
            journal, journal_path, generation_path, "committed")
    except BaseException as exc:
        if manage_mcp and mcp_added:
            try:
                _mcp_command(codex, "remove", codex_home=codex_home)
            except IntegrationError:
                raise IntegrationError(
                    "Codex integration failed and MCP rollback was incomplete") from exc
        if plugin_mode and mcp_removed:
            try:
                _mcp_command(
                    codex, "add", codex_home=codex_home,
                    launcher=launcher, loom_home=loom_home)
                restored = _mcp_named(
                    _mcp_rows(codex, codex_home=codex_home), "loom")
                if len(restored) != 1 \
                        or _mcp_transport_hash(restored[0]) != expected_mcp_hash:
                    raise IntegrationError(
                        "Codex plugin migration rollback restored the wrong MCP transport")
            except IntegrationError:
                raise IntegrationError(
                    "Codex plugin migration failed and MCP rollback was incomplete") from exc
        try:
            journal["status"] = "prepared"
            loom_reliability.atomic_write_json(journal_path, journal)
            loom_adapters._recover_transaction(user_home, loom_home)
        except (loom_adapters.AdapterError, loom_reliability.ReliabilityError) as recovery_exc:
            raise IntegrationError(
                "Codex integration failed and file rollback was incomplete") from recovery_exc
        raise IntegrationError("Codex integration failed safely; prior files were restored") from exc
    mode = (
        "plugin-standard+verified" if plugin_mode and verified else
        "plugin-standard" if plugin_mode else
        "standard+verified" if verified and manage_mcp else
        "verified-hooks" if verified else "standard")
    return {"status": "installed", "mode": mode,
            "generation": generation, "hooks": sorted(entry_hashes),
            "mcp": "plugin:loom" if plugin_mode else "loom" if manage_mcp else None,
            "plugin": plugin}


def install(user_home, loom_home, *, approved, codex_executable=None, verified=True,
            manage_mcp=True, plugin_mode=False, preserve_owned_hooks=False):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    codex = _codex_executable(user_home, codex_executable)
    lock_path, _journal, _generation = loom_adapters._transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            plugin = (
                _verified_loom_plugin(
                    codex, codex_home=user_home / ".codex")
                if plugin_mode else None)
            _reconcile_transaction(
                user_home, loom_home, codex, plugin=plugin)
            retirement = None
            if plugin_mode and approved:
                retirement = _activate_legacy_skill_retirement(
                    _prepare_legacy_skill_retirement(user_home, plugin))
            try:
                result = _install_locked(
                    user_home, loom_home, approved=approved,
                    codex_executable=codex_executable, verified=verified,
                    manage_mcp=manage_mcp, plugin_mode=plugin_mode,
                    verified_plugin=plugin,
                    preserve_owned_hooks=preserve_owned_hooks,
                    legacy_archive=(
                        retirement["receipt"]["archive"]
                        if retirement is not None
                        and not os.path.lexists(
                            retirement["receipt"]["source"])
                        else None))
            except BaseException as exc:
                try:
                    _rollback_legacy_skill_retirement(retirement)
                except IntegrationError as rollback_exc:
                    raise IntegrationError(
                        "Codex plugin integration failed and legacy skill rollback "
                        "was incomplete") from rollback_exc
                raise
            if plugin_mode and approved:
                result["legacy_skill"] = _seal_legacy_skill_retirement(retirement)
            return result
    except loom_reliability.ReliabilityError as exc:
        raise IntegrationError(str(exc)) from exc


def canonicalize_plugin(user_home, loom_home, *, approved, codex_executable=None):
    """Retire only owned legacy routes while preserving hook bytes exactly."""
    user_home = loom_reliability._absolute(
        user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(
        loom_home, "Loom home", must_exist=True)
    if not approved:
        return {
            "status": "approval-required",
            "operation": "plugin-route-canonicalization",
        }
    codex = _codex_executable(user_home, codex_executable)
    if not codex.is_file():
        raise IntegrationError("Codex executable is unavailable")
    plugin = _verified_loom_plugin(
        codex, codex_home=user_home / ".codex")
    retirement = _prepare_legacy_skill_retirement(user_home, plugin)
    receipt = _load_receipt(_receipt_path(loom_home))
    hooks_path = user_home / ".codex" / "hooks.json"
    hooks, _raw = _read_hooks(hooks_path)
    entries = _preserved_hook_entries(hooks, receipt, hooks_path)
    plugin_mcp, shadows = _plugin_mcp_inventory(
        _mcp_rows(codex, codex_home=user_home / ".codex"), plugin)
    if not shadows and len(plugin_mcp) != 1:
        raise IntegrationError(
            "the verified Loom plugin MCP is not active in Codex")
    retirement_pending = retirement is not None \
        and retirement["receipt"]["state"] != "retired"
    if not retirement_pending and not shadows \
            and (receipt is None or not receipt["mcp_managed"]):
        return {
            "status": "current",
            "mode": "plugin-standard",
            "hooks": sorted(entries),
            "mcp": "plugin:loom",
            "plugin": plugin,
            "legacy_skill": {
                "status": "retired" if retirement is not None else "absent"},
        }
    return install(
        user_home, loom_home, approved=approved,
        codex_executable=codex, verified=False,
        manage_mcp=False, plugin_mode=True, preserve_owned_hooks=True)


def _uninstall_locked(user_home, loom_home, *, approved, codex_executable=None):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    receipt_path = _receipt_path(loom_home)
    receipt = _load_receipt(receipt_path)
    if receipt is None:
        raise IntegrationError("no owned Codex integration exists")
    if not approved:
        return {"status": "approval-required", "hooks": sorted(receipt["entries"]),
                "mcp": receipt["mcp_name"]}
    hooks_path = Path(receipt["hooks_path"])
    if hooks_path != user_home / ".codex" / "hooks.json":
        raise IntegrationError("Codex hook receipt path is outside the expected user configuration")
    value, _before = _read_hooks(hooks_path)
    changed = _remove_hooks(value, receipt)
    codex = _codex_executable(user_home, codex_executable)
    if receipt["mcp_managed"]:
        if not codex.is_file():
            raise IntegrationError("Codex executable is unavailable")
        rows = _mcp_rows(codex, codex_home=user_home / ".codex")
        owned_mcp = _mcp_named(rows, "loom")
        if receipt["mcp_command_sha256"] is None:
            raise IntegrationError(
                "legacy Codex integration must be refreshed before ownership-safe removal")
        if len(owned_mcp) != 1 \
                or _mcp_transport_hash(owned_mcp[0]) != receipt["mcp_command_sha256"]:
            raise IntegrationError("owned Loom MCP configuration changed or is missing")
    hooks_content = _hooks_bytes(changed)
    operation = ("codex-integration-uninstall-mcp-remove"
                 if receipt["mcp_managed"] else "codex-integration-uninstall")
    journal, journal_path, generation_path = loom_adapters._begin_transaction(
        user_home, loom_home, operation,
        [(hooks_path, hooks_content), (receipt_path, None)])
    try:
        loom_reliability.atomic_write_bytes(hooks_path, hooks_content)
        if receipt["mcp_managed"]:
            _mcp_command(codex, "remove", codex_home=user_home / ".codex")
        receipt_path.unlink()
        loom_adapters._finish_transaction(
            journal, journal_path, generation_path, "committed")
    except BaseException as exc:
        journal["status"] = "prepared"
        try:
            loom_reliability.atomic_write_json(journal_path, journal)
            if receipt["mcp_managed"]:
                current = _mcp_named(
                    _mcp_rows(codex, codex_home=user_home / ".codex"), "loom")
                if not current:
                    _mcp_command(codex, "add", codex_home=user_home / ".codex",
                                 launcher=loom_home / "bin" / "loom.py",
                                 loom_home=loom_home)
                    current = _mcp_named(
                        _mcp_rows(codex, codex_home=user_home / ".codex"), "loom")
                if len(current) != 1 \
                        or _mcp_transport_hash(current[0]) \
                        != receipt["mcp_command_sha256"]:
                    raise IntegrationError(
                        "Codex MCP rollback did not restore the exact owned transport")
            loom_adapters._recover_transaction(user_home, loom_home)
        except (IntegrationError, loom_adapters.AdapterError,
                loom_reliability.ReliabilityError) as recovery_exc:
            raise IntegrationError(
                "Codex integration removal failed and rollback was incomplete") \
                from recovery_exc
        raise IntegrationError(
            "Codex integration removal failed safely; prior state was restored") from exc
    return {"status": "uninstalled", "hooks_removed": len(receipt["entries"]),
            "mcp_removed": receipt["mcp_managed"], "vault_preserved": True}


def uninstall(user_home, loom_home, *, approved, codex_executable=None):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    codex = _codex_executable(user_home, codex_executable)
    lock_path, _journal, _generation = loom_adapters._transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            _reconcile_transaction(user_home, loom_home, codex)
            return _uninstall_locked(
                user_home, loom_home, approved=approved,
                codex_executable=codex_executable)
    except loom_reliability.ReliabilityError as exc:
        raise IntegrationError(str(exc)) from exc
