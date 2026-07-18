#!/usr/bin/env python3
"""Closed, versioned host contracts for Loom's thin local adapters."""

import json
import re
import shutil
from pathlib import Path, PurePosixPath


_MODULE = Path(__file__).resolve()
CONTRACT_PATH = (_MODULE.parent / "host-contracts-v2.json"
                 if (_MODULE.parent / "host-contracts-v2.json").is_file()
                 else _MODULE.parents[1] / "contracts" / "host-contracts-v2.json")
HOST_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
EVIDENCE = {"simulated-conformant", "experimental", "unsupported", "real-host-verified"}
CONNECTABLE = {"simulated-conformant", "real-host-verified"}
MAX_BYTES = 256 * 1024


class HostContractError(RuntimeError):
    pass


def _relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise HostContractError("host contract path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HostContractError("host contract path is unsafe")
    return path.as_posix()


def _string_list(value, *, allow_empty=True):
    if not isinstance(value, list) or len(value) > 16 or (not allow_empty and not value) \
            or len(value) != len(set(value)) \
            or any(not isinstance(item, str) or not item or len(item) > 256 for item in value):
        raise HostContractError("host contract list is invalid")
    return list(value)


def _load(path=CONTRACT_PATH):
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise HostContractError("host contract registry is missing, redirected, or oversized")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HostContractError(f"host contract registry is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "contract_id", "reviewed_at", "hosts"} \
            or value.get("schema_version") != 2 \
            or value.get("contract_id") != "loom-host-contracts-v2" \
            or not isinstance(value.get("reviewed_at"), str) \
            or not isinstance(value.get("hosts"), list) \
            or not 1 <= len(value["hosts"]) <= 32:
        raise HostContractError("host contract registry shape is invalid")
    required = {
        "id", "surfaces", "global_roots", "canonical_root", "project_roots",
        "config_markers", "executables", "version_command", "headless_command",
        "precedence", "adapter_kind", "contract_status", "evidence_status",
        "proof_ttl_days", "sources", "update_operation", "uninstall_operation",
    }
    hosts = {}
    for row in value["hosts"]:
        if not isinstance(row, dict) or set(row) != required \
                or not isinstance(row.get("id"), str) or not HOST_ID.fullmatch(row["id"]) \
                or row["id"] in hosts or row.get("evidence_status") not in EVIDENCE \
                or type(row.get("proof_ttl_days")) is not int \
                or not 1 <= row["proof_ttl_days"] <= 90:
            raise HostContractError("host contract entry is invalid")
        normalized = dict(row)
        normalized["surfaces"] = _string_list(row["surfaces"], allow_empty=False)
        normalized["global_roots"] = [_relative(item) for item in _string_list(
            row["global_roots"], allow_empty=False)]
        normalized["canonical_root"] = _relative(row["canonical_root"])
        if normalized["canonical_root"] not in normalized["global_roots"]:
            raise HostContractError("canonical host root is not a declared global root")
        normalized["project_roots"] = [_relative(item) for item in _string_list(
            row["project_roots"])]
        normalized["config_markers"] = [_relative(item) for item in _string_list(
            row["config_markers"])]
        for key in ("executables", "version_command", "headless_command", "sources"):
            normalized[key] = _string_list(row[key], allow_empty=(key != "sources"))
        for key in ("precedence", "adapter_kind", "contract_status",
                    "update_operation", "uninstall_operation"):
            if not isinstance(row.get(key), str) or not row[key] or len(row[key]) > 128:
                raise HostContractError("host contract text field is invalid")
        normalized["adapter_path"] = normalized["canonical_root"]
        hosts[row["id"]] = normalized
    return value["contract_id"], value["reviewed_at"], hosts


CONTRACT_ID, REVIEWED_AT, HOSTS = _load()


def contract(host_id):
    """Return public host facts without turning them into conformance evidence."""
    value = HOSTS.get(host_id)
    if value is None:
        raise KeyError(host_id)
    return {key: value[key] for key in (
        "surfaces", "global_roots", "canonical_root", "project_roots",
        "adapter_kind", "evidence_status", "sources", "headless_command",
        "version_command", "contract_status", "precedence", "proof_ttl_days",
        "update_operation", "uninstall_operation")}


def global_skill_paths(host_id=None):
    rows = [HOSTS[host_id]] if host_id is not None else HOSTS.values()
    return tuple(sorted({path for row in rows for path in row["global_roots"]}))


def project_skill_paths():
    return tuple(sorted({path for row in HOSTS.values() for path in row["project_roots"]}))


def detect(user_home, *, which=None, versions=None):
    root = Path(user_home).resolve()
    finder = which or shutil.which
    versions = versions or {}
    results = []
    for host_id, value in HOSTS.items():
        markers = [marker for marker in value["config_markers"]
                   if root.joinpath(*PurePosixPath(marker).parts).exists()]
        executable = next((name for name in value["executables"] if finder(name)), None)
        if not markers and executable is None:
            continue
        results.append({
            "id": host_id,
            "version": versions.get(host_id),
            "adapter_kind": value["adapter_kind"],
            "adapter_path": value["canonical_root"],
            "global_roots": list(value["global_roots"]),
            "evidence_status": value["evidence_status"],
            "connectable": value["evidence_status"] in CONNECTABLE,
            "detection_evidence": sorted(
                [f"config:{item}" for item in markers]
                + ([f"executable:{executable}"] if executable else [])),
        })
    return results
