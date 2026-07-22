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


RECEIPT_VERSION = 3
MAX_HOOKS_BYTES = 256 * 1024


class IntegrationError(RuntimeError):
    pass


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


def _mcp_named(rows, name):
    return [row for row in rows if isinstance(row, dict) and row.get("name") == name]


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


def _reconcile_transaction(user_home, loom_home, codex):
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
                    "codex-integration-uninstall-mcp-remove",
                    "codex-integration-uninstall"}:
            raise IntegrationError("Codex integration transaction operation is unsupported")
        if journal.get("status") == "prepared" and operation in {
                "codex-integration-install-mcp-add",
                "codex-integration-uninstall-mcp-remove"}:
            if not Path(codex).is_file():
                raise IntegrationError(
                    "Codex executable is required to recover an interrupted integration")
            launcher = Path(loom_home) / "bin" / "loom.py"
            expected = _entry_hash(_expected_mcp_transport(launcher, loom_home))
            rows = _mcp_named(_mcp_rows(codex, codex_home=Path(user_home) / ".codex"), "loom")
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


def _install_locked(user_home, loom_home, *, approved, codex_executable=None, verified=True,
                    manage_mcp=True):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    launcher = loom_home / "bin" / "loom.py"
    if not launcher.is_file() or launcher.is_symlink():
        raise IntegrationError("receipt-owned stable launcher is unavailable")
    codex = Path(codex_executable or shutil.which("codex") or "")
    if manage_mcp and not codex.is_file():
        raise IntegrationError("Codex executable is unavailable")
    hooks_path = user_home / ".codex" / "hooks.json"
    receipt_path = _receipt_path(loom_home)
    receipt = _load_receipt(receipt_path)
    desired = _commands(launcher, loom_home) if verified else {}
    preview = {"status": "approval-required", "mcp": "loom" if manage_mcp else None,
               "hooks": sorted(desired), "hooks_path": str(hooks_path)}
    if not approved:
        return preview
    codex_home = user_home / ".codex"
    codex_home.mkdir(parents=True, exist_ok=True)
    value, before = _read_hooks(hooks_path)
    rows = _mcp_rows(codex, codex_home=codex_home) if manage_mcp else []
    existing = _mcp_named(rows, "loom")
    expected_mcp_hash = _entry_hash(_expected_mcp_transport(launcher, loom_home))
    if receipt is not None and receipt["mcp_managed"] != manage_mcp:
        raise IntegrationError(
            "Codex integration mode changed; uninstall the owned integration first")
    if manage_mcp and receipt is None and existing:
        raise IntegrationError("unowned Codex MCP server named loom already exists")
    if manage_mcp and receipt is not None and existing:
        observed_mcp_hash = _mcp_transport_hash(existing[0]) if len(existing) == 1 else None
        receipt_mcp_hash = receipt["mcp_command_sha256"]
        if len(existing) != 1 or observed_mcp_hash != expected_mcp_hash \
                or receipt_mcp_hash not in {None, expected_mcp_hash}:
            raise IntegrationError("owned Codex MCP transport changed; refusing overwrite")
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
    operation = ("codex-integration-install-mcp-add"
                 if manage_mcp and not existing else "codex-integration-install")
    journal, journal_path, generation_path = loom_adapters._begin_transaction(
        user_home, loom_home, operation,
        [(hooks_path, hooks_content), (receipt_path, receipt_content)])
    mcp_added = False
    try:
        loom_reliability.atomic_write_bytes(hooks_path, hooks_content)
        if manage_mcp and not existing:
            _mcp_command(codex, "add", codex_home=codex_home,
                         launcher=launcher, loom_home=loom_home)
            mcp_added = True
        if manage_mcp:
            installed = _mcp_named(
                _mcp_rows(codex, codex_home=codex_home), "loom")
            if len(installed) != 1 or _mcp_transport_hash(installed[0]) != expected_mcp_hash:
                raise IntegrationError("Codex did not retain exactly one Loom MCP server")
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
        try:
            journal["status"] = "prepared"
            loom_reliability.atomic_write_json(journal_path, journal)
            loom_adapters._recover_transaction(user_home, loom_home)
        except (loom_adapters.AdapterError, loom_reliability.ReliabilityError) as recovery_exc:
            raise IntegrationError(
                "Codex integration failed and file rollback was incomplete") from recovery_exc
        raise IntegrationError("Codex integration failed safely; prior files were restored") from exc
    mode = ("standard+verified" if verified and manage_mcp else
            "verified-hooks" if verified else "standard")
    return {"status": "installed", "mode": mode,
            "generation": generation, "hooks": sorted(desired),
            "mcp": "loom" if manage_mcp else None}


def install(user_home, loom_home, *, approved, codex_executable=None, verified=True,
            manage_mcp=True):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    codex = Path(codex_executable or shutil.which("codex") or "")
    lock_path, _journal, _generation = loom_adapters._transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            _reconcile_transaction(user_home, loom_home, codex)
            return _install_locked(
                user_home, loom_home, approved=approved,
                codex_executable=codex_executable, verified=verified,
                manage_mcp=manage_mcp)
    except loom_reliability.ReliabilityError as exc:
        raise IntegrationError(str(exc)) from exc


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
    codex = Path(codex_executable or shutil.which("codex") or "")
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
    codex = Path(codex_executable or shutil.which("codex") or "")
    lock_path, _journal, _generation = loom_adapters._transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            _reconcile_transaction(user_home, loom_home, codex)
            return _uninstall_locked(
                user_home, loom_home, approved=approved,
                codex_executable=codex_executable)
    except loom_reliability.ReliabilityError as exc:
        raise IntegrationError(str(exc)) from exc
