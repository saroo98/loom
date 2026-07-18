#!/usr/bin/env python3
"""Receipt-owned global adapters that route supported agents to one Loom launcher."""

import hashlib
import base64
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import loom_adapter_protocol
import loom_host_registry
import loom_reliability


AGENTS = {name: value["adapter_path"]
          for name, value in loom_host_registry.HOSTS.items()}


class AdapterError(RuntimeError):
    pass


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _transaction_paths(loom_home):
    root = Path(loom_home) / "adapters"
    return (Path(loom_home) / "locks" / "adapter-transaction.lock",
            root / "transaction.json", root / "generation.json")


def _allowed_transaction_path(path, user_home, loom_home):
    try:
        path = loom_reliability._absolute(path, "adapter transaction path")
        user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
        loom_home = loom_reliability._absolute(loom_home, "Loom home")
    except loom_reliability.ReliabilityError:
        return False
    return path.is_relative_to(user_home) or path.is_relative_to(loom_home)


def _recover_transaction(user_home, loom_home):
    _lock, journal_path, _generation = _transaction_paths(loom_home)
    if not journal_path.exists():
        return None
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"adapter transaction journal is corrupt: {exc}") from exc
    if not isinstance(journal, dict) or journal.get("schema_version") != 1 \
            or journal.get("status") not in {"prepared", "committed", "rolled-back"} \
            or not isinstance(journal.get("entries"), list) \
            or len(journal["entries"]) > 96:
        raise AdapterError("adapter transaction journal is invalid")
    if journal["status"] != "prepared":
        return journal.get("generation")
    for item in reversed(journal["entries"]):
        if not isinstance(item, dict) or set(item) != {
                "path", "before_base64", "before_sha256", "after_sha256"}:
            raise AdapterError("adapter transaction entry is invalid")
        path = Path(item["path"])
        if not _allowed_transaction_path(path, user_home, loom_home):
            raise AdapterError("adapter transaction path escapes its owned roots")
        before = (base64.b64decode(item["before_base64"], validate=True)
                  if item["before_base64"] is not None else None)
        if (None if before is None else _sha(before)) != item["before_sha256"]:
            raise AdapterError("adapter transaction recovery bytes are invalid")
        current = _sha(path.read_bytes()) if path.is_file() and not path.is_symlink() else None
        if current not in {item["before_sha256"], item["after_sha256"]}:
            raise AdapterError("adapter changed after interrupted transaction; refusing recovery")
        if before is None:
            path.unlink(missing_ok=True)
        else:
            loom_reliability.atomic_write_bytes(path, before)
    journal["status"] = "rolled-back"
    journal["recovered_after_interruption"] = True
    loom_reliability.atomic_write_json(journal_path, journal)
    return journal["generation"]


def _begin_transaction(user_home, loom_home, operation, changes):
    _lock, journal_path, generation_path = _transaction_paths(loom_home)
    try:
        generation_value = (json.loads(generation_path.read_text(encoding="utf-8"))
                            if generation_path.exists() else {"generation": 0})
        generation = generation_value["generation"] + 1
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AdapterError(f"adapter generation is invalid: {exc}") from exc
    if type(generation) is not int or not 1 <= generation <= 2 ** 63 - 1:
        raise AdapterError("adapter generation is outside its bound")
    entries = []
    for path, after in changes:
        try:
            path = loom_reliability._absolute(path, "adapter transaction path")
        except loom_reliability.ReliabilityError as exc:
            raise AdapterError(str(exc)) from exc
        if not _allowed_transaction_path(path, user_home, loom_home) \
                or (after is not None and not isinstance(after, bytes)):
            raise AdapterError("adapter transaction change is invalid")
        before = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        entries.append({
            "path": str(path),
            "before_base64": (base64.b64encode(before).decode("ascii")
                              if before is not None else None),
            "before_sha256": None if before is None else _sha(before),
            "after_sha256": None if after is None else _sha(after),
        })
    journal = {"schema_version": 1, "transaction_id": str(uuid.uuid4()),
               "generation": generation, "operation": operation,
               "status": "prepared", "entries": entries}
    loom_reliability.atomic_write_json(journal_path, journal)
    return journal, journal_path, generation_path


def _finish_transaction(journal, journal_path, generation_path, status):
    journal["status"] = status
    loom_reliability.atomic_write_json(journal_path, journal)
    if status == "committed":
        loom_reliability.atomic_write_json(
            generation_path, {"schema_version": 1, "generation": journal["generation"],
                              "transaction_id": journal["transaction_id"]})


def _adapter(agent):
    return ("---\nname: loom\ndescription: Route one request through the shared local Loom runtime.\n"
            "---\n\nUse one surface: `/loom <request>`. Run the stable user-scoped launcher at "
            f"`~/.loom/bin/loom --home ~/.loom invoke --agent {agent} --agent-version "
            "<current-host-version> --request <verbatim-request> --cwd <absolute-project-root>`. "
            "This is Loom adapter protocol v2; the adapter is stateless and must not plan, "
            "select memory, inspect the vault, migrate state, or cache policy. "
            "Never invoke a plugin-cache "
            "path or create repository-local Loom files. Return the launcher's compact receipt.\n") \
        .encode("utf-8")


def _receipt_path(loom_home, agent):
    return Path(loom_home) / "adapters" / "receipts" / f"{agent}.json"


def _capability_path(loom_home, agent):
    return Path(loom_home) / "adapters" / "capabilities" / f"{agent}.json"


def _preflight(target, receipt_path, capability_path):
    if not target.exists():
        if receipt_path.exists() or capability_path.exists():
            raise AdapterError("adapter ownership state exists without its target")
        return None
    if not target.is_file() or target.is_symlink() or not receipt_path.is_file():
        raise AdapterError(f"unowned split-brain Loom adapter exists at {target}")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"adapter ownership receipt is invalid: {exc}") from exc
    version = receipt.get("schema_version")
    if version not in {1, 2} or receipt.get("path") != str(target) \
            or receipt.get("sha256") != _sha(target.read_bytes()):
        raise AdapterError(f"owned adapter changed; refusing to overwrite {target}")
    if version == 2 and (receipt.get("protocol_version") != 2
                         or receipt.get("adapter_version") != loom_adapter_protocol.ADAPTER_VERSION
                         or receipt.get("launcher") != "~/.loom/bin/loom"):
        raise AdapterError(f"adapter ownership receipt is incompatible: {target}")
    if version == 2 and (not capability_path.is_file()
                         or receipt.get("capability_receipt_sha256") != _sha(
                             capability_path.read_bytes())):
        raise AdapterError(f"adapter capability receipt is invalid: {target}")
    if version == 1 and capability_path.exists():
        raise AdapterError(f"unowned adapter capability receipt exists: {target}")
    return _sha(receipt_path.read_bytes()) if version == 1 else receipt.get(
        "legacy_receipt_sha256")


def _install_launcher_locked(loom_home, launcher_source):
    loom_home = loom_reliability._absolute(loom_home, "Loom home")
    source = loom_reliability._absolute(
        launcher_source, "launcher source", must_exist=True)
    if not source.is_file():
        raise AdapterError("launcher source is not a regular file")
    binary = loom_home / "bin"
    binary.mkdir(parents=True, exist_ok=True)
    receipt_path = binary / ".loom-launcher-receipt.json"
    python_launcher = binary / "loom.py"
    posix = binary / "loom"
    windows = binary / "loom.cmd"
    dependencies = {}
    for name in ("loom_update.py", "loom_reliability.py",
                 "loom_adapter_protocol.py", "loom_adapter_bridge.py",
                 "loom_host_registry.py"):
        dependency = source.parent / name
        if not dependency.is_file() or dependency.is_symlink():
            raise AdapterError(f"launcher dependency is unavailable: {name}")
        dependencies[binary / name] = dependency.read_bytes()
    host_contract = source.parent.parent / "contracts" / "host-contracts-v2.json"
    if not host_contract.is_file() or host_contract.is_symlink():
        raise AdapterError("versioned host contract is unavailable")
    dependencies[binary / "host-contracts-v2.json"] = host_contract.read_bytes()
    targets = {
        python_launcher: source.read_bytes(),
        posix: b'#!/bin/sh\nexec python3 "$(dirname "$0")/loom.py" "$@"\n',
        windows: b'@echo off\r\npy -3 "%~dp0loom.py" %*\r\n',
        **dependencies,
    }
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for target in targets:
            expected = receipt.get("files", {}).get(target.name)
            if target.exists() and expected != _sha(target.read_bytes()):
                raise AdapterError("owned stable launcher changed; refusing overwrite")
    elif any(target.exists() for target in targets):
        raise AdapterError("unowned stable launcher already exists")
    receipt = {"schema_version": 1, "files": {
        target.name: _sha(content) for target, content in targets.items()}}
    receipt_content = _json_bytes(receipt)
    user_home = loom_home.parent
    _recover_transaction(user_home, loom_home)
    journal, journal_path, generation_path = _begin_transaction(
        user_home, loom_home, "install-launcher",
        [*targets.items(), (receipt_path, receipt_content)])
    try:
        for target, content in targets.items():
            loom_reliability.atomic_write_bytes(target, content)
        loom_reliability.atomic_write_bytes(receipt_path, receipt_content)
        for target, content in targets.items():
            if not target.is_file() or target.is_symlink() \
                    or _sha(target.read_bytes()) != _sha(content):
                raise AdapterError("stable launcher verification failed")
        if _sha(receipt_path.read_bytes()) != _sha(receipt_content):
            raise AdapterError("stable launcher receipt verification failed")
        try:
            os.chmod(posix, 0o700)
        except OSError:
            pass
        _finish_transaction(journal, journal_path, generation_path, "committed")
    except BaseException as exc:
        try:
            journal["status"] = "prepared"
            loom_reliability.atomic_write_json(journal_path, journal)
            _recover_transaction(user_home, loom_home)
        except BaseException as recovery_exc:
            raise AdapterError(
                "stable launcher installation failed and recovery was incomplete") from recovery_exc
        raise AdapterError(
            "stable launcher installation failed safely; prior state was restored") from exc
    return {"status": "installed", "python_launcher": str(python_launcher),
            "posix_launcher": str(posix), "windows_launcher": str(windows)}


def install_launcher(loom_home, launcher_source):
    loom_home = loom_reliability._absolute(loom_home, "Loom home")
    lock_path, _journal, _generation = _transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return _install_launcher_locked(loom_home, launcher_source)
    except loom_reliability.ReliabilityError as exc:
        raise AdapterError(str(exc)) from exc


def _connect_all_locked(user_home, loom_home, *, approved, which=None, versions=None):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home")
    detected_records = loom_host_registry.detect(
        user_home, which=which, versions=versions)
    detected = [item["id"] for item in detected_records]
    eligible = [item for item in detected_records if item["connectable"]]
    if not approved:
        return {"status": "approval-required", "detected": detected,
                "eligible": [item["id"] for item in eligible],
                "connected": 0, "receipts": [], "unsupported": [
                    item["id"] for item in detected_records if not item["connectable"]]}
    launcher = loom_home / "bin" / "loom.py"
    launcher_receipt = loom_home / "bin" / ".loom-launcher-receipt.json"
    try:
        ownership = json.loads(launcher_receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"shared launcher is not receipt-owned: {exc}") from exc
    if not launcher.is_file() or launcher.is_symlink() \
            or ownership.get("files", {}).get("loom.py") != _sha(launcher.read_bytes()):
        raise AdapterError("shared launcher is missing, changed, or unowned")
    probe = subprocess.run(
        [sys.executable, "-B", str(launcher), "--home", str(loom_home),
         "adapter-probe", "--protocol-min", "2", "--protocol-max", "2"],
        capture_output=True, text=True, timeout=15, check=False)
    try:
        probe_value = json.loads(probe.stdout)
    except json.JSONDecodeError as exc:
        raise AdapterError("shared launcher verification returned invalid output") from exc
    if probe.returncode != 0 or probe_value.get("status") != "ready" \
            or probe_value.get("protocol_version") != 2:
        raise AdapterError("shared launcher verification failed; no adapter was installed")
    plans = []
    for record in eligible:
        agent = record["id"]
        target = user_home.joinpath(*Path(AGENTS[agent]).parts)
        for alternate in record["global_roots"]:
            candidate = user_home.joinpath(*Path(alternate).parts)
            if candidate != target and candidate.exists():
                raise AdapterError(
                    f"unowned alternate Loom route would cause split-brain execution: {candidate}")
        receipt = _receipt_path(loom_home, agent)
        capability = _capability_path(loom_home, agent)
        legacy = _preflight(target, receipt, capability)
        content = _adapter(agent)
        capability_value = {
            "schema_version": 2,
            "receipt_id": f"cap-{uuid.uuid4()}",
            "session_id": str(uuid.uuid4()),
            "protocol_version": 2,
            "host": agent,
            "host_version": record["version"],
            "adapter_version": loom_adapter_protocol.ADAPTER_VERSION,
            "runtime_version": probe_value["version"],
            "evidence_status": record["evidence_status"],
            "detection_evidence": record["detection_evidence"],
            "usage_fields": [],
            "cache_evidence": False,
            "response_identity": False,
            "latency_events": False,
            "limitations": ["real-host invocation not yet independently verified"],
        }
        capability_content = _json_bytes(capability_value)
        receipt_value = {"schema_version": 2, "protocol_version": 2,
                         "agent": agent, "host_version": record["version"],
                         "adapter_version": loom_adapter_protocol.ADAPTER_VERSION,
                         "path": str(target), "sha256": _sha(content),
                         "launcher": "~/.loom/bin/loom",
                         "evidence_status": record["evidence_status"],
                         "capability_receipt_sha256": _sha(capability_content),
                         "legacy_receipt_sha256": legacy}
        plans.append((record, target, receipt, capability, content, legacy,
                      capability_content, _json_bytes(receipt_value), receipt_value))
    receipts = []
    prior = [(target, target.read_bytes() if target.exists() else None,
              receipt_path, receipt_path.read_bytes() if receipt_path.exists() else None)
             for _record, target, receipt_path, _capability_path_value,
             _content, _legacy, _capability_content, _receipt_content,
             _receipt_value in plans]
    prior_capabilities = [(capability_path,
                           capability_path.read_bytes() if capability_path.exists() else None)
                          for _record, _target, _receipt, capability_path,
                          _content, _legacy, _capability_content, _receipt_content,
                          _receipt_value in plans]
    changes = []
    for (_record, target, receipt_path, capability_path, content, _legacy,
         capability_content, receipt_content, _receipt_value) in plans:
        changes.extend([(target, content), (capability_path, capability_content),
                        (receipt_path, receipt_content)])
    journal, journal_path, generation_path = _begin_transaction(
        user_home, loom_home, "connect", changes)
    try:
        for (record, target, receipt_path, capability_path, content, _legacy,
             capability_content, receipt_content, receipt_value) in plans:
            agent = record["id"]
            target.parent.mkdir(parents=True, exist_ok=True)
            loom_reliability.atomic_write_bytes(target, content)
            loom_reliability.atomic_write_bytes(capability_path, capability_content)
            loom_reliability.atomic_write_bytes(receipt_path, receipt_content)
            if _sha(target.read_bytes()) != receipt_value["sha256"] \
                    or _sha(capability_path.read_bytes()) \
                    != receipt_value["capability_receipt_sha256"]:
                raise AdapterError(f"adapter verification failed for {agent}")
            receipts.append(str(receipt_path))
        _finish_transaction(journal, journal_path, generation_path, "committed")
    except BaseException as exc:
        rollback_failed = False
        for target, old_target, receipt_path, old_receipt in reversed(prior):
            try:
                if old_target is None:
                    target.unlink(missing_ok=True)
                else:
                    loom_reliability.atomic_write_bytes(target, old_target)
                if old_receipt is None:
                    receipt_path.unlink(missing_ok=True)
                else:
                    loom_reliability.atomic_write_bytes(receipt_path, old_receipt)
            except BaseException:
                rollback_failed = True
        for capability_path, old_capability in reversed(prior_capabilities):
            try:
                if old_capability is None:
                    capability_path.unlink(missing_ok=True)
                else:
                    loom_reliability.atomic_write_bytes(capability_path, old_capability)
            except BaseException:
                rollback_failed = True
        if rollback_failed:
            raise AdapterError("adapter connection failed and rollback was incomplete") from exc
        try:
            _finish_transaction(journal, journal_path, generation_path, "rolled-back")
        except BaseException as journal_exc:
            raise AdapterError(
                "adapter connection rolled back but its journal could not be sealed") from journal_exc
        raise AdapterError("adapter connection failed safely; prior state was restored") from exc
    return {"status": "connected", "detected": detected,
            "eligible": [item["id"] for item in eligible],
            "unsupported": [item["id"] for item in detected_records
                            if not item["connectable"]],
            "connected": len(plans), "verified": len(plans), "receipts": receipts}


def connect_all(user_home, loom_home, *, approved, which=None, versions=None):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home")
    if not approved:
        return _connect_all_locked(
            user_home, loom_home, approved=False, which=which, versions=versions)
    lock_path, _journal, _generation = _transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            _recover_transaction(user_home, loom_home)
            return _connect_all_locked(
                user_home, loom_home, approved=True, which=which, versions=versions)
    except loom_reliability.ReliabilityError as exc:
        raise AdapterError(str(exc)) from exc


def _disconnect_all_locked(user_home, loom_home, *, approved):
    """Remove only unchanged adapter files proven by Loom ownership receipts."""
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    receipts_root = loom_home / "adapters" / "receipts"
    planned = []
    for agent in AGENTS:
        receipt_path = _receipt_path(loom_home, agent)
        if not receipt_path.exists():
            continue
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            target = loom_reliability._absolute(receipt["path"], "adapter target", must_exist=True)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError,
                loom_reliability.ReliabilityError) as exc:
            raise AdapterError(f"adapter ownership receipt is invalid: {exc}") from exc
        expected = user_home.joinpath(*Path(AGENTS[agent]).parts)
        if target != expected or receipt.get("agent") != agent \
                or receipt.get("schema_version") != 2 \
                or receipt.get("protocol_version") != 2 \
                or not target.is_file() or target.is_symlink() \
                or receipt.get("sha256") != _sha(target.read_bytes()):
            raise AdapterError(f"owned adapter changed; refusing to remove {target}")
        capability_path = _capability_path(loom_home, agent)
        if not capability_path.is_file() \
                or receipt.get("capability_receipt_sha256") != _sha(
                    capability_path.read_bytes()):
            raise AdapterError(f"adapter capability receipt changed; refusing to remove {target}")
        planned.append((target, receipt_path, capability_path))
    if not approved:
        return {"status": "approval-required", "connected": len(planned), "removed": 0}
    changes = [(path, None) for row in planned for path in row]
    journal, journal_path, generation_path = _begin_transaction(
        user_home, loom_home, "disconnect", changes)
    try:
        for target, receipt_path, capability_path in planned:
            target.unlink()
            receipt_path.unlink()
            capability_path.unlink()
            try:
                target.parent.rmdir()
            except OSError:
                pass
        _finish_transaction(journal, journal_path, generation_path, "committed")
    except BaseException as exc:
        try:
            journal["status"] = "prepared"
            loom_reliability.atomic_write_json(journal_path, journal)
            _recover_transaction(user_home, loom_home)
        except BaseException as recovery_exc:
            raise AdapterError("adapter disconnect failed and recovery was incomplete") from recovery_exc
        raise AdapterError("adapter disconnect failed safely; prior state was restored") from exc
    try:
        receipts_root.rmdir()
    except OSError:
        pass
    try:
        (loom_home / "adapters" / "capabilities").rmdir()
    except OSError:
        pass
    return {"status": "disconnected", "removed": len(planned)}


def disconnect_all(user_home, loom_home, *, approved):
    """Remove only unchanged adapter files proven by Loom ownership receipts."""
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    if not approved:
        return _disconnect_all_locked(user_home, loom_home, approved=False)
    lock_path, _journal, _generation = _transaction_paths(loom_home)
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            _recover_transaction(user_home, loom_home)
            return _disconnect_all_locked(user_home, loom_home, approved=True)
    except loom_reliability.ReliabilityError as exc:
        raise AdapterError(str(exc)) from exc
