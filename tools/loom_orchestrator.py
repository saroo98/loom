#!/usr/bin/env python3
"""Production bridge from one `/loom` request to gated host-agent work and a receipt."""

import sys
sys.dont_write_bytecode = True

import argparse
import contextlib
import datetime as dt
import fnmatch
import hashlib
import io
import json
import os
import re
import tempfile
import uuid
from pathlib import Path

import loom_gate
import loom_authority
import loom_crypto
import loom_domain
import loom_domain_bundle
import loom_domain_contract
import loom_domain_invariants
import loom_planning_intelligence
import loom_program
import loom_domain_learning
import loom_install
import loom_improvement
import loom_lifecycle
import loom_lint
import loom_adapter_protocol
import loom_memory
import loom_message
import loom_owner


TEST_LEGACY_BACKEND_MARKER = ".loom-test-legacy-backend-v1"
TEST_LEGACY_BACKEND_MARKER_BYTES = b"loom-disposable-test-backend-v1\n"
import loom_performance
import loom_project_inspection
import loom_reliability
import loom_runtime
import loom_session
import loom_survey
import loom_vault_adapter


SCHEMA_VERSION = 1
ACTION_SCHEMA_VERSION = 8
LEGACY_ACTION_SCHEMA_VERSION = 6
PRIOR_ACTION_SCHEMA_VERSION = 7
ACTION_FIELDS_V7 = {
    "schema_version", "action_id", "status", "instance_id", "project_id",
    "request", "invocation_id", "owner_home", "install_root", "cwd",
    "explicit_target", "intent", "tier", "domains", "survey_hash",
    "created_at", "expires_at", "attempts", "max_attempts", "session_id",
    "operation_id", "journal_path", "initial_pack_hash",
    "remove_pristine_pack", "work_order", "prepared", "context", "result",
    "repair_plan", "host_result", "plan_contract", "domain_contract", "context_manifest",
    "continuation_authority", "owner_message", "action_hash",
}
ACTION_FIELDS = ACTION_FIELDS_V7 | {"pack_seed", "recovery_receipt"}
ACTION_STATUSES = {
    "initializing", "pending", "completed", "cancelled", "expired", "failed",
    "abandoned", "superseded",
}
TERMINAL_ACTION_STATUSES = ACTION_STATUSES - {"initializing", "pending"}
PACK_SEED_STATES = {"not-applicable", "recorded", "prepared", "installed", "recovered"}
NONINTERFERING_ACTIVE_ACTION_INTENTS = {"status", "why", "remember", "forget", "undo"}
MAX_ORCHESTRATION_ACTIONS = 256
MAX_ORCHESTRATION_DIRECTORY_ENTRIES = 512
ACTIVE_POINTER_FILE = "active-action.json"
RECOVERY_DIRECTORY = "planning-recovery"
MAX_RECOVERY_FILES = 8
MAX_RECOVERY_FILE_BYTES = 256 * 1024
MAX_RECOVERY_TOTAL_BYTES = MAX_RECOVERY_FILES * MAX_RECOVERY_FILE_BYTES
MAX_ACTION_BYTES = 256 * 1024
MAX_ENCRYPTED_ACTION_BYTES = 384 * 1024
PLAN_CONTRACT_SCHEMA_VERSION = 4
ARTIFACT_ORDER = (
    "intake.md", "survey.md", "product.md", "architecture.md", "uiux.md",
    "contracts.md", "testing.md", "release-rollback.md", "security.md",
    "maintenance.md", "scaffold.md", "domain-discovery.md", "work orders",
    "routing", "project instructions",
)


class OrchestratorError(RuntimeError):
    def __init__(self, code, message, *, status="refused"):
        self.code = str(code)
        self.message = str(message)
        self.status = str(status)
        super().__init__(f"{self.code}: {self.message}")


def _canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _transport_invocation_id(envelope):
    """Bind duplicate delivery to one protocol operation without storing host text."""
    identity = _hash({
        "protocol": "adapter-request-envelope-v2",
        "request_id": envelope["request_id"],
        "request_identity": envelope["request_identity"],
        "cwd": envelope["cwd"],
        "host": envelope["host"],
    })
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "loom-transport:" + identity))


def _stamp(value=None):
    instant = loom_runtime._parse_time(value or dt.datetime.now(dt.timezone.utc))
    return loom_runtime._format_time(instant)


def _action_hash(value):
    body = dict(value)
    body.pop("action_hash", None)
    return _hash(body)


def _absolute(value, label, *, must_exist=True):
    try:
        path = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    except (TypeError, ValueError, OSError) as exc:
        raise OrchestratorError("INVALID_PATH", f"{label} is invalid: {exc}") from exc
    if not path.is_absolute() or (must_exist and not path.exists()):
        raise OrchestratorError("INVALID_PATH", f"{label} must be an existing absolute path")
    return path


def _action_path(owner_home, instance_id, project_id, action_id):
    return (Path(owner_home) / "instances" / instance_id / "runtime" /
            "projects" / project_id / "orchestrations" / f"{action_id}.json")


def _validate_seed_manifest(value):
    if value is None:
        return None
    if isinstance(value, dict) and value.get("schema_version") == 2:
        fields = {
            "schema_version", "policy", "platform", "entries", "file_count",
            "directory_count", "total_bytes", "root_sha256",
        }
        if set(value) != fields \
                or value.get("policy") != "exact-tree-no-extended-data-v1" \
                or value.get("platform") not in {"windows", "posix"} \
                or not isinstance(value.get("entries"), list) \
                or not 1 <= len(value["entries"]) <= 64 \
                or type(value.get("file_count")) is not int \
                or type(value.get("directory_count")) is not int \
                or type(value.get("total_bytes")) is not int \
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("root_sha256", ""))):
            raise OrchestratorError("ACTION_CORRUPT", "pack seed manifest v2 is invalid")
        seen = set()
        file_count = directory_count = total_bytes = 0
        previous = None
        for item in value["entries"]:
            if not isinstance(item, dict) or item.get("kind") not in {"directory", "file"}:
                raise OrchestratorError(
                    "ACTION_CORRUPT", "pack seed manifest v2 entry is invalid")
            path = item.get("path")
            common = {"path", "kind", "mode"}
            expected_fields = (common if item["kind"] == "directory" else
                               common | {"bytes", "sha256", "links"})
            if set(item) != expected_fields \
                    or not isinstance(path, str) \
                    or not (path == "." or re.fullmatch(
                        r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", path)) \
                    or path in seen \
                    or type(item.get("mode")) is not int \
                    or not 0 <= item["mode"] <= 0o7777 \
                    or (previous is not None and path <= previous):
                raise OrchestratorError(
                    "ACTION_CORRUPT", "pack seed manifest v2 entry is invalid")
            if item["kind"] == "directory":
                directory_count += 1
            else:
                if type(item.get("bytes")) is not int \
                        or not 0 <= item["bytes"] <= MAX_RECOVERY_FILE_BYTES \
                        or item.get("links") != 1 \
                        or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
                    raise OrchestratorError(
                        "ACTION_CORRUPT", "pack seed manifest v2 file is invalid")
                file_count += 1
                total_bytes += item["bytes"]
            seen.add(path)
            previous = path
        if not value["entries"] or value["entries"][0] != {
                "path": ".", "kind": "directory",
                "mode": value["entries"][0].get("mode")} \
                or value["file_count"] != file_count \
                or value["directory_count"] != directory_count \
                or value["total_bytes"] != total_bytes \
                or file_count > MAX_RECOVERY_FILES \
                or total_bytes > MAX_RECOVERY_TOTAL_BYTES:
            raise OrchestratorError("ACTION_CORRUPT", "pack seed manifest v2 totals are invalid")
        body = {key: value[key] for key in fields if key != "root_sha256"}
        if value["root_sha256"] != _hash(body):
            raise OrchestratorError("ACTION_CORRUPT", "pack seed manifest v2 digest is invalid")
        return value
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "files", "root_sha256"} \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("files"), list) \
            or not 1 <= len(value["files"]) <= 8 \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("root_sha256", ""))):
        raise OrchestratorError("ACTION_CORRUPT", "pack seed manifest is invalid")
    seen = set()
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} \
                or not isinstance(item["path"], str) \
                or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", item["path"]) \
                or item["path"].startswith(("/", "../")) \
                or "/../" in item["path"] \
                or item["path"] in seen \
                or type(item["bytes"]) is not int \
                or not 0 <= item["bytes"] <= 256 * 1024 \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            raise OrchestratorError("ACTION_CORRUPT", "pack seed file manifest is invalid")
        seen.add(item["path"])
    body = {"schema_version": 1, "files": value["files"]}
    if value["root_sha256"] != _hash(body):
        raise OrchestratorError("ACTION_CORRUPT", "pack seed manifest digest is invalid")
    return value


def _validate_pack_seed(value, *, intent, status, initial_pack_hash,
                        allow_unsealed_recovery=False):
    if not isinstance(value, dict) or set(value) != {
            "state", "created_pack", "kind", "manifest", "activation_atomic_rename"} \
            or value.get("state") not in PACK_SEED_STATES \
            or type(value.get("created_pack")) is not bool \
            or value.get("kind") not in {None, "small", "planned"}:
        raise OrchestratorError("ACTION_CORRUPT", "pack seed contract is invalid")
    manifest = _validate_seed_manifest(value.get("manifest"))
    rename_state = value.get("activation_atomic_rename")
    if rename_state is not None:
        try:
            loom_reliability.validate_atomic_rename_state(rename_state)
        except loom_reliability.ReliabilityError as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT", "pack seed activation state is invalid") from exc
    if intent != "plan":
        if value != {"state": "not-applicable", "created_pack": False,
                     "kind": None, "manifest": None,
                     "activation_atomic_rename": None}:
            raise OrchestratorError(
                "ACTION_CORRUPT", "non-planning action carries a pack seed")
        return value
    if value["kind"] not in {"small", "planned"} \
            or (value["state"] == "prepared" and manifest is None) \
            or (value["state"] in {"installed", "recovered"}
                and manifest is None and initial_pack_hash is None
                and not (value["state"] == "recovered" and allow_unsealed_recovery)) \
            or (value["state"] in {"recorded"} and manifest is not None) \
            or (value["state"] == "recorded" and rename_state is not None) \
            or (not value["created_pack"] and rename_state is not None) \
            or (status == "initializing" and value["state"] not in {
                "recorded", "prepared"}) \
            or (status == "pending" and value["state"] != "installed") \
            or (status in {"abandoned", "superseded"} and value["created_pack"]
                and value["state"] != "recovered"):
        raise OrchestratorError("ACTION_CORRUPT", "planning pack seed state is invalid")
    return value


def _validate_recovery_receipt(value, *, action):
    if value is None:
        if action["status"] in {"abandoned", "superseded"}:
            raise OrchestratorError(
                "ACTION_CORRUPT", "recovered action has no recovery receipt")
        return None
    if isinstance(value, dict) and value.get("schema_version") == 3:
        return _validate_recovery_receipt_v3(value, action=action)
    fields_v1 = {
        "schema_version", "recovery_id", "action_id", "project_id", "reason",
        "source_path", "quarantine_relative", "seed_manifest_sha256",
        "quarantined_manifest_sha256", "complete_seed", "changes_made",
        "reversible", "recovered_at", "receipt_hash",
    }
    fields_v2 = fields_v1 | {
        "manifest_schema_version", "source_disposition", "cleanup_phase",
        "preserved_relatives",
    }
    schema = value.get("schema_version") if isinstance(value, dict) else None
    fields = fields_v2 if schema == 2 else fields_v1
    reasons = {"interrupted-initialization", "expired", "superseded"}
    if schema == 2:
        reasons.add("cancelled")
    if not isinstance(value, dict) or set(value) != fields \
            or schema not in {1, 2} \
            or value.get("action_id") != action["action_id"] \
            or value.get("project_id") != action["project_id"] \
            or (schema == 1 and value.get("source_path") != "plans") \
            or (schema == 2 and value.get("source_path") not in {
                "plans", "install-stage", "owner-stage", "legacy-tombstone", "none"}) \
            or value.get("reason") not in reasons \
            or not re.fullmatch(r"recovery-[0-9a-f]{24}", str(value.get("recovery_id"))) \
            or (value.get("quarantine_relative") is not None and not re.fullmatch(
                r"instances/[0-9a-f-]{36}/runtime/projects/p-[0-9a-f]{32}/"
                r"planning-recovery/[0-9a-f-]{36}/plans",
                str(value["quarantine_relative"]))) \
            or (value.get("seed_manifest_sha256") is not None and not re.fullmatch(
                r"[0-9a-f]{64}", str(value["seed_manifest_sha256"]))) \
            or (value.get("quarantined_manifest_sha256") is not None and not re.fullmatch(
                r"[0-9a-f]{64}", str(value["quarantined_manifest_sha256"]))) \
            or type(value.get("complete_seed")) is not bool \
            or type(value.get("changes_made")) is not bool \
            or type(value.get("reversible")) is not bool:
        raise OrchestratorError("ACTION_CORRUPT", "recovery receipt contract is invalid")
    expected_status = {
        "interrupted-initialization": "abandoned", "expired": "expired",
        "superseded": "superseded", "cancelled": "cancelled",
    }[value["reason"]]
    expected_id = "recovery-" + hashlib.sha256(
        f"{action['action_id']}:{value['reason']}".encode()).hexdigest()[:24]
    expected_relative = (
        f"instances/{action['instance_id']}/runtime/projects/{action['project_id']}/"
        f"planning-recovery/{action['action_id']}/plans")
    expected_recovery_prefix = expected_relative.rsplit("/", 1)[0] + "/"
    if action["status"] != expected_status \
            or value["recovery_id"] != expected_id \
            or (value["quarantine_relative"] is not None
                and value["quarantine_relative"] != expected_relative) \
            or (value["complete_seed"] and (
                value["seed_manifest_sha256"] is None
                or value["seed_manifest_sha256"] !=
                value["quarantined_manifest_sha256"])):
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt is not semantically bound to the action")
    if schema == 2:
        disposition = value.get("source_disposition")
        phase = value.get("cleanup_phase")
        preserved = value.get("preserved_relatives")
        if value.get("manifest_schema_version") not in {None, 1, 2} \
                or disposition not in {
                    "not-present", "quarantined", "preserved-in-place"} \
                or phase not in {"gc-complete", "preserved-in-place"} \
                or not isinstance(preserved, list) or len(preserved) > 3 \
                or len(preserved) != len(set(preserved)) \
                or not all(isinstance(item, str) and re.fullmatch(
                    r"instances/[0-9a-f-]{36}/runtime/projects/p-[0-9a-f]{32}/"
                    r"planning-recovery/[0-9a-f-]{36}/[A-Za-z0-9._-]{1,64}", item)
                    and item.startswith(expected_recovery_prefix)
                    for item in preserved) \
                or (disposition == "quarantined" and (
                    value["quarantine_relative"] is None
                    or not value["changes_made"] or not value["reversible"]
                    or phase != "gc-complete")) \
                or (disposition == "not-present" and (
                    value["quarantine_relative"] is not None
                    or preserved or value["changes_made"] or value["reversible"]
                    or phase != "gc-complete")) \
                or (disposition == "preserved-in-place" and (
                    value["quarantine_relative"] is not None or preserved
                    or value["changes_made"] or value["reversible"]
                    or phase != "preserved-in-place")):
            raise OrchestratorError(
                "ACTION_CORRUPT", "recovery receipt disposition is invalid")
    try:
        loom_runtime._parse_time(value["recovered_at"])
    except (TypeError, ValueError, loom_runtime.RuntimeError) as exc:
        raise OrchestratorError("ACTION_CORRUPT", "recovery receipt time is invalid") from exc
    body = dict(value); claimed = body.pop("receipt_hash")
    if claimed != _hash(body) \
            or (schema == 1 and (
                value["changes_made"] != (value["quarantine_relative"] is not None)
                or value["reversible"] != value["changes_made"])):
        raise OrchestratorError("ACTION_CORRUPT", "recovery receipt digest is invalid")
    return value


def _validate_recovery_receipt_v3(value, *, action):
    """Validate the current receipt contract plus its action-bound semantics."""
    report = loom_lint.Report()
    loom_lint.validate_schema(
        report, "recovery-receipt", value, "recovery-receipt.schema.json")
    if report.errors:
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 schema is invalid")

    expected_status = {
        "interrupted-initialization": "abandoned", "expired": "expired",
        "superseded": "superseded", "cancelled": "cancelled",
    }[value["reason"]]
    expected_id = "recovery-" + hashlib.sha256(
        f"{action['action_id']}:{value['reason']}".encode()).hexdigest()[:24]
    expected_owner_relative = (
        f"instances/{action['instance_id']}/runtime/projects/{action['project_id']}/"
        f"planning-recovery/{action['action_id']}/plans")
    expected_owner_prefix = expected_owner_relative.rsplit("/", 1)[0] + "/"
    expected_project_relative = f".loom-recovery-{action['action_id']}"
    if action["status"] != expected_status \
            or value["action_id"] != action["action_id"] \
            or value["project_id"] != action["project_id"] \
            or value["recovery_id"] != expected_id:
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 is not bound to its action")

    activation = value["activation_atomic_rename"]
    quarantine = value["quarantine_atomic_rename"]
    for label, state, roles in (
            ("activation", activation, ("prepared_stage", "active_plan")),
            ("quarantine", quarantine,
             ("recovery_source", "quarantine_destination"))):
        if state is None:
            continue
        try:
            loom_reliability.validate_atomic_rename_state(state)
        except loom_reliability.ReliabilityError as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT", f"recovery receipt v3 {label} evidence is invalid") from exc
        if (state["source_role"], state["destination_role"]) != roles:
            raise OrchestratorError(
                "ACTION_CORRUPT", f"recovery receipt v3 {label} roles are invalid")
    if activation != action["pack_seed"].get("activation_atomic_rename"):
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 activation evidence differs from the action")

    disposition = value["source_disposition"]
    scope = value["quarantine_scope"]
    owner_relative = value["owner_quarantine_relative"]
    project_relative = value["project_quarantine_relative"]
    preserved_owner = value["preserved_relatives"]
    preserved_project = value["preserved_project_relatives"]
    source_path = value["source_path"]
    if len(preserved_owner) != len(set(preserved_owner)) \
            or len(preserved_project) != len(set(preserved_project)) \
            or (disposition == "quarantined"
                and not all(item.startswith(expected_owner_prefix)
                            for item in preserved_owner)):
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 preservation locators are invalid")

    if disposition == "quarantined":
        if value["changes_made"] is not True or value["reversible"] is not True \
                or (source_path == "owner-stage" and (
                    scope != "owner-home" or owner_relative != expected_owner_relative
                    or project_relative is not None
                    or value["project_namespace_changed"] is not False
                    or value["owner_control_changed"] is not True)) \
                or (source_path in {"plans", "install-stage", "legacy-tombstone"}
                    and scope == "owner-home" and (
                        owner_relative != expected_owner_relative
                        or project_relative is not None
                        or value["project_namespace_changed"] is not True
                        or value["owner_control_changed"] is not True)) \
                or (source_path in {"plans", "install-stage"}
                    and scope == "project-local" and (
                        owner_relative is not None
                        or project_relative != expected_project_relative
                        or value["project_namespace_changed"] is not True
                        or value["owner_control_changed"] is not False)) \
                or not ((source_path == "owner-stage" and scope == "owner-home")
                        or (source_path in {"plans", "install-stage", "legacy-tombstone"}
                            and scope == "owner-home")
                        or (source_path in {"plans", "install-stage"}
                            and scope == "project-local")):
            raise OrchestratorError(
                "ACTION_CORRUPT", "recovery receipt v3 quarantine scope is invalid")
    elif disposition == "preserved-in-place":
        expected_owner, expected_project = _recovery_preserved_locators(
            source_path, action)
        if scope is not None or owner_relative is not None or project_relative is not None \
                or quarantine is not None or value["quarantined_manifest_sha256"] is not None \
                or value["changes_made"] or value["reversible"] \
                or value["project_namespace_changed"] or value["owner_control_changed"] \
                or preserved_owner != expected_owner or preserved_project != expected_project:
            raise OrchestratorError(
                "ACTION_CORRUPT", "recovery receipt v3 preserved state is invalid")
    else:
        if source_path != "none" or scope is not None or owner_relative is not None \
                or project_relative is not None or preserved_owner or preserved_project \
                or quarantine is not None \
                or value["quarantined_manifest_sha256"] is not None \
                or value["changes_made"] or value["reversible"] \
                or value["project_namespace_changed"] or value["owner_control_changed"]:
            raise OrchestratorError(
                "ACTION_CORRUPT", "recovery receipt v3 absent state is invalid")

    if value["complete_seed"] and (
            value["seed_manifest_sha256"] is None
            or value["seed_manifest_sha256"] != value["quarantined_manifest_sha256"]):
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 complete-seed evidence is invalid")
    evidence = [state for state in (activation, quarantine) if state is not None]
    requires_reconciliation = (
        disposition == "quarantined" and quarantine is None) or any(
            state["namespace_state"] != "committed"
            or state["durability"] != "confirmed" for state in evidence)
    expected_phase = (
        "reconciliation-required" if requires_reconciliation else
        "preserved-in-place" if disposition == "preserved-in-place" else
        "gc-complete")
    if value["cleanup_phase"] != expected_phase:
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 cleanup phase is invalid")
    try:
        target = Path(action["explicit_target"] or action["cwd"])
        if disposition == "quarantined":
            artifact = (
                Path(action["owner_home"]) / owner_relative
                if scope == "owner-home" else target / project_relative)
            if not _path_present(artifact):
                raise ValueError("quarantine artifact is absent")
            observed = _recovery_manifest(artifact)
            if observed["root_sha256"] != value["quarantined_manifest_sha256"]:
                raise ValueError("quarantine artifact digest differs from receipt")
        elif disposition == "preserved-in-place":
            for relative in preserved_owner:
                if not _path_present(Path(action["owner_home"]) / relative):
                    raise ValueError("preserved owner artifact is absent")
            for relative in preserved_project:
                if not _path_present(target / relative):
                    raise ValueError("preserved project artifact is absent")
    except (ValueError, OrchestratorError) as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 artifact binding is invalid") from exc
    try:
        loom_runtime._parse_time(value["recovered_at"])
    except (TypeError, ValueError, loom_runtime.RuntimeError) as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 time is invalid") from exc
    body = dict(value)
    claimed = body.pop("receipt_hash")
    if claimed != _hash(body):
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt v3 digest is invalid")
    return value


def _legacy_pack_seed(value):
    if value.get("intent") != "plan":
        return {"state": "not-applicable", "created_pack": False,
                "kind": None, "manifest": None, "activation_atomic_rename": None}
    return {
        "state": "installed" if value.get("initial_pack_hash") else "recorded",
        "created_pack": bool(value.get("remove_pristine_pack")),
        "kind": "small" if value.get("tier") == "S" else "planned",
        "manifest": None,
        "activation_atomic_rename": None,
    }


def _validate_action(value, path):
    if not isinstance(value, dict):
        raise OrchestratorError("ACTION_CORRUPT", "action must be an object")
    if value.get("schema_version") == LEGACY_ACTION_SCHEMA_VERSION:
        if set(value) != ACTION_FIELDS_V7 \
                or value.get("action_hash") != _action_hash(value) \
                or value.get("status") not in {
                    "pending", "completed", "cancelled", "expired", "failed"}:
            raise OrchestratorError("ACTION_CORRUPT", "legacy action fields or hash are invalid")
        if value["status"] != "completed":
            raise OrchestratorError(
                "ACTION_REPREPARE_REQUIRED",
                "an open pre-inspection action cannot resume; invoke /loom again against "
                "the current project state",
                status="action-required")
        try:
            if str(uuid.UUID(value["action_id"])) != value["action_id"] \
                    or str(uuid.UUID(value["instance_id"])) != value["instance_id"] \
                    or not isinstance(value["result"], dict):
                raise ValueError
        except (ValueError, TypeError, KeyError) as exc:
            raise OrchestratorError("ACTION_CORRUPT", "legacy terminal action is invalid") \
                from exc
        expected = _action_path(
            value.get("owner_home"), value.get("instance_id"), value.get("project_id"),
            value.get("action_id"))
        if Path(path) != expected:
            raise OrchestratorError("ACTION_PATH_MISMATCH", "legacy action path is not scoped")
        return value
    if value.get("schema_version") == PRIOR_ACTION_SCHEMA_VERSION:
        if set(value) != ACTION_FIELDS_V7 \
                or value.get("action_hash") != _action_hash(value) \
                or value.get("status") not in {
                    "pending", "completed", "cancelled", "expired", "failed"}:
            raise OrchestratorError("ACTION_CORRUPT", "prior action fields or hash are invalid")
        value = {
            **value,
            "schema_version": ACTION_SCHEMA_VERSION,
            "pack_seed": _legacy_pack_seed(value),
            "recovery_receipt": None,
        }
        value["owner_message"] = loom_message.build(
            state="progress",
            consequence={"S": "ordinary", "M": "material", "L": "high",
                         "XL": "critical"}[value["tier"]],
            verification="pending", freshness="current",
            changes_made=False, undo_status="not-applicable",
            summary="Loom prepared the next safe frontier.",
            next_action="Complete and verify the sealed frontier.",
            receipt_id="action-" + value["action_id"])
        value["action_hash"] = _action_hash(value)
    if value.get("schema_version") != ACTION_SCHEMA_VERSION:
        raise OrchestratorError(
            "ACTION_VERSION_UNSUPPORTED", "action schema version is not supported")
    if set(value) != ACTION_FIELDS \
            or value.get("status") not in ACTION_STATUSES \
            or value.get("action_hash") != _action_hash(value):
        raise OrchestratorError("ACTION_CORRUPT", "action fields or hash are invalid")
    try:
        if str(uuid.UUID(value["action_id"])) != value["action_id"] \
                or str(uuid.UUID(value["invocation_id"])) != value["invocation_id"] \
                or str(uuid.UUID(value["instance_id"])) != value["instance_id"] \
                or str(uuid.UUID(value["session_id"])) != value["session_id"]:
            raise ValueError
        created = loom_runtime._parse_time(value["created_at"])
        expires = loom_runtime._parse_time(value["expires_at"])
    except (ValueError, TypeError, loom_runtime.RuntimeError) as exc:
        raise OrchestratorError("ACTION_CORRUPT", "action identity is invalid") from exc
    if not re.fullmatch(r"p-[0-9a-f]{32}", str(value["project_id"])) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value["survey_hash"])) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value["operation_id"])) \
            or value["intent"] not in loom_runtime.INTENTS \
            or value["tier"] not in {"S", "M", "L", "XL"} \
            or not isinstance(value["domains"], list) or not value["domains"] \
            or len(value["domains"]) > 16 \
            or len(value["domains"]) != len(set(value["domains"])) \
            or not all(isinstance(item, str) and re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", item) for item in value["domains"]) \
            or type(value["attempts"]) is not int \
            or not 0 <= value["attempts"] <= 3 \
            or value["max_attempts"] != 3 \
            or type(value["remove_pristine_pack"]) is not bool \
            or (value["work_order"] is not None and (
                not isinstance(value["work_order"], str)
                or not re.fullmatch(r"(?:work-orders/)?WO-[0-9]{3,}(?:-[A-Za-z0-9._-]+)?\.md",
                                    value["work_order"]))) \
            or not isinstance(value["prepared"], dict) \
            or not isinstance(value["context"], dict) \
            or (value["initial_pack_hash"] is not None and not re.fullmatch(
                r"[0-9a-f]{64}", str(value["initial_pack_hash"]))):
        raise OrchestratorError("ACTION_CORRUPT", "action contract is invalid")
    context = value["context"]
    if set(context) != {"memory", "preferences", "archived_count"} \
            or not isinstance(context["memory"], list) \
            or not isinstance(context["preferences"], list) \
            or len(context["memory"]) > 16 \
            or len(context["preferences"]) > 32 \
            or type(context["archived_count"]) is not int \
            or context["archived_count"] < 0 \
            or len(_canonical_bytes(context)) > 32 * 1024:
        raise OrchestratorError("ACTION_CORRUPT", "sealed context capsule is invalid")
    try:
        expected_manifest = loom_performance.production_context_manifest(
            value["install_root"])
    except loom_performance.PerformanceError as exc:
        raise OrchestratorError("ACTION_CORRUPT", "static context is unavailable") from exc
    if value["context_manifest"] != expected_manifest:
        raise OrchestratorError(
            "ACTION_CORRUPT", "sealed static context manifest is invalid or stale")
    try:
        loom_authority.validate(value["continuation_authority"])
    except loom_authority.AuthorityError as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", f"sealed continuation authority is invalid: {exc}") from exc
    try:
        loom_message.validate(value["owner_message"])
    except loom_message.MessageError as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", f"sealed owner message is invalid: {exc}") from exc
    message_builder = (loom_message.v2_build
                       if value["owner_message"].get("schema_version") == 2
                       else loom_message.build)
    expected_owner_message = message_builder(
        state="progress",
        consequence={"S": "ordinary", "M": "material", "L": "high",
                     "XL": "critical"}[value["tier"]],
        verification="pending", freshness="current",
        changes_made=False,
        undo_status=("not-needed" if message_builder is loom_message.v2_build
                     else "not-applicable"),
        summary="Loom prepared the next safe frontier.",
        next_action="Complete and verify the sealed frontier.",
        receipt_id="action-" + value["action_id"])
    if value["owner_message"] != expected_owner_message:
        raise OrchestratorError(
            "ACTION_CORRUPT", "sealed owner message does not match the action")
    try:
        prepared = loom_runtime.PreparedInvocation.from_dict(value["prepared"])
    except loom_runtime.RuntimeError as exc:
        raise OrchestratorError("ACTION_CORRUPT", "sealed preparation is invalid") from exc
    if prepared.instance_id != value["instance_id"] \
            or prepared.invocation_id != value["invocation_id"] \
            or prepared.project_id != value["project_id"] \
            or prepared.survey_hash != value["survey_hash"] \
            or prepared.intent != value["intent"] \
            or prepared.route_contract["tier"] != value["tier"] \
            or list(prepared.domains) != value["domains"] \
            or not isinstance(value["request"], str) \
            or not value["request"].strip() or len(value["request"]) > 20_000 \
            or prepared.request_hash != loom_runtime._sha(
                " ".join(value["request"].split())):
        raise OrchestratorError("ACTION_CORRUPT", "sealed preparation does not match action")
    try:
        loom_domain_contract.validate_route(value["domain_contract"])
    except loom_domain_contract.DomainContractError as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", f"sealed domain route is invalid: {exc}") from exc
    if value["domain_contract"]["active_task_domains"] != value["domains"] \
            and not (value["domains"] == ["unclassified"]
                     and value["domain_contract"]["active_task_domains"] == ["unclassified"]):
        raise OrchestratorError("ACTION_CORRUPT", "sealed domain route differs from action")
    recovery_receipt = _validate_recovery_receipt(value["recovery_receipt"], action=value)
    allow_unsealed_recovery = recovery_receipt is not None \
        and recovery_receipt["source_disposition"] in {"preserved-in-place", "not-present"} \
        and recovery_receipt["complete_seed"] is False
    _validate_pack_seed(
        value["pack_seed"], intent=value["intent"], status=value["status"],
        initial_pack_hash=value["initial_pack_hash"],
        allow_unsealed_recovery=allow_unsealed_recovery)
    if recovery_receipt is not None and value["pack_seed"]["created_pack"] \
            and value["pack_seed"]["state"] != "recovered":
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt requires a recovered pack seed state")
    contract_expected = value["intent"] == "plan" \
        and not prepared.route_contract["blocked"] \
        and value["initial_pack_hash"] is not None
    if contract_expected:
        schema_report = loom_lint.Report()
        loom_lint.validate_schema(
            schema_report, path, value["plan_contract"], "plan-contract.schema.json")
        if schema_report.errors \
                or value["plan_contract"] != _make_plan_contract(value, prepared):
            raise OrchestratorError(
                "ACTION_CORRUPT", "sealed plan contract is invalid or does not match action")
    elif value["plan_contract"] is not None:
        raise OrchestratorError(
            "ACTION_CORRUPT", "non-planning action carries a plan contract")
    repair_plan = value["repair_plan"]
    if value["intent"] == "repair" and not prepared.route_contract["blocked"]:
        repair_fields = {
            "changed_paths", "affected_plan_sections", "regate_scope",
            "prior_state_hash", "current_state_hash", "force_full"}
        if value["tier"] == "S":
            repair_fields.add("lifecycle_sha256")
        else:
            repair_fields.add("program_impact")
        if not isinstance(repair_plan, dict) or set(repair_plan) != repair_fields \
                or repair_plan["regate_scope"] not in {"selective", "full", "compact"} \
                or (repair_plan["regate_scope"] == "compact") != (value["tier"] == "S") \
                or type(repair_plan["force_full"]) is not bool \
                or not all(re.fullmatch(r"[0-9a-f]{64}", str(repair_plan[name]))
                           for name in ("prior_state_hash", "current_state_hash")) \
                or not isinstance(repair_plan["changed_paths"], list) \
                or not isinstance(repair_plan["affected_plan_sections"], list) \
                or not repair_plan["affected_plan_sections"]:
            raise OrchestratorError("ACTION_CORRUPT", "sealed repair plan is invalid")
        if value["tier"] == "S" and not re.fullmatch(
                r"[0-9a-f]{64}", str(repair_plan["lifecycle_sha256"])):
            raise OrchestratorError("ACTION_CORRUPT", "compact lifecycle binding is invalid")
        if value["tier"] != "S" and repair_plan["program_impact"] is not None:
            try:
                loom_program.validate_impact_receipt(repair_plan["program_impact"])
            except loom_program.ProgramError as exc:
                raise OrchestratorError(
                    "ACTION_CORRUPT", f"sealed program impact is invalid: {exc}") from exc
    elif repair_plan is not None:
        raise OrchestratorError("ACTION_CORRUPT", "non-repair action carries repair scope")
    if value["host_result"] is not None and not isinstance(value["host_result"], dict):
        raise OrchestratorError("ACTION_CORRUPT", "host result is invalid")
    if created >= expires \
            or any(not isinstance(value[field], str) or not Path(value[field]).is_absolute()
                   for field in ("owner_home", "install_root", "cwd", "journal_path")) \
            or (value["explicit_target"] is not None and (
                not isinstance(value["explicit_target"], str)
                or not Path(value["explicit_target"]).is_absolute())) \
            or (value["status"] in {"initializing", "pending"}
                and value["result"] is not None) \
            or (value["status"] == "completed" and not isinstance(value["result"], dict)):
        raise OrchestratorError("ACTION_CORRUPT", "action state is invalid")
    expected = _action_path(
        value["owner_home"], value["instance_id"], value["project_id"],
        value["action_id"])
    if Path(path) != expected:
        raise OrchestratorError("ACTION_PATH_MISMATCH", "action path is not owner-scoped")
    expected_journal = expected.parent.parent / loom_session.JOURNAL_FILE
    if Path(value["journal_path"]) != expected_journal:
        raise OrchestratorError("ACTION_PATH_MISMATCH", "session journal is not project-scoped")
    return value


def _read_action(path, *, owner_home=None, install_root=None):
    path = _absolute(path, "action")
    try:
        loom_memory._reject_link_ancestors(path, "orchestration action")
    except loom_memory.MemoryError as exc:
        raise OrchestratorError("ACTION_UNSAFE", str(exc)) from exc
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ENCRYPTED_ACTION_BYTES:
        raise OrchestratorError("ACTION_UNSAFE", "action must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("ACTION_CORRUPT", f"action cannot be read: {exc}") from exc
    security = None
    if isinstance(value, dict) and set(value) == {
            "schema_version", "kind", "action_id", "owner_vault_id", "ciphertext"} \
            and value.get("kind") == "loom-encrypted-action-v1":
        if owner_home is None or install_root is None:
            raise OrchestratorError(
                "ACTION_KEY_REQUIRED", "encrypted action requires the active owner vault")
        helper = _vault_helper(install_root)
        if helper is None:
            raise OrchestratorError("ACTION_KEY_REQUIRED", "active runtime has no vault helper")
        try:
            if str(uuid.UUID(value["action_id"])) != value["action_id"] \
                    or str(uuid.UUID(value["owner_vault_id"])) != value["owner_vault_id"]:
                raise ValueError("non-canonical action identity")
        except (ValueError, TypeError, AttributeError) as exc:
            raise OrchestratorError("ACTION_CORRUPT", "encrypted action identity is invalid") \
                from exc
        opened, crypto = loom_owner.open_owner_vault(owner_home, helper)
        if opened.identity()["owner_vault_id"] != value["owner_vault_id"]:
            raise OrchestratorError("ACTION_OWNER_MISMATCH", "action belongs to another vault")
        aad = f"action:{value['owner_vault_id']}:{value['action_id']}".encode()
        try:
            value = json.loads(crypto.open(value["ciphertext"].encode("ascii"), aad))
        except (loom_crypto.CryptoError, ValueError, UnicodeError,
                json.JSONDecodeError, AttributeError) as exc:
            raise OrchestratorError("ACTION_CORRUPT", "encrypted action authentication failed") \
                from exc
        if Path(owner_home).resolve() != Path(value.get("owner_home", "")).resolve() \
                or Path(install_root).resolve() != Path(value.get("install_root", "")).resolve():
            raise OrchestratorError(
                "ACTION_RUNTIME_MISMATCH", "action does not belong to this home and runtime")
        security = (crypto, opened.identity()["owner_vault_id"])
    return path, _validate_action(value, path), security


def _write_action(path, value, security=None):
    value = dict(value)
    value["action_hash"] = _action_hash(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_ACTION_BYTES:
        raise OrchestratorError("ACTION_CAPACITY", "action exceeds its plaintext bound")
    if security is None:
        loom_session._atomic_json(path, value)
    else:
        crypto, owner_vault_id = security
        aad = f"action:{owner_vault_id}:{value['action_id']}".encode()
        envelope = {"schema_version": 1, "kind": "loom-encrypted-action-v1",
                    "action_id": value["action_id"], "owner_vault_id": owner_vault_id,
                    "ciphertext": crypto.seal(raw, aad).decode("ascii")}
        loom_session._atomic_json(path, envelope)
    return value


def _orchestration_directory(owner_home, instance_id, project_id):
    return _action_path(
        owner_home, instance_id, project_id,
        "00000000-0000-4000-8000-000000000000").parent


def _orchestration_lock(directory):
    return Path(directory) / ".orchestration.lock"


def _active_pointer_path(directory):
    return Path(directory) / ACTIVE_POINTER_FILE


def _pointer_hash(value):
    body = dict(value); body.pop("pointer_hash", None)
    return _hash(body)


def _write_active_pointer(directory, *, action_id, project_id):
    value = {
        "schema_version": 1, "action_id": action_id, "project_id": project_id,
        "state": "active",
    }
    value["pointer_hash"] = _pointer_hash(value)
    loom_session._atomic_json(_active_pointer_path(directory), value)
    return value


def _read_active_pointer(directory):
    path = _active_pointer_path(directory)
    if not _path_present(path):
        return None
    try:
        loom_memory._reject_link_ancestors(path, "active action pointer")
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024:
            raise ValueError("pointer is not a bounded regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError,
            loom_memory.MemoryError, ValueError) as exc:
        raise OrchestratorError(
            "ACTION_POINTER_CORRUPT", f"active action pointer is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "action_id", "project_id", "state", "pointer_hash"} \
            or value.get("schema_version") != 1 \
            or value.get("state") != "active" \
            or not re.fullmatch(r"[0-9a-f-]{36}", str(value.get("action_id", ""))) \
            or not re.fullmatch(r"p-[0-9a-f]{32}", str(value.get("project_id", ""))) \
            or value.get("pointer_hash") != _pointer_hash(value):
        raise OrchestratorError("ACTION_POINTER_CORRUPT", "active action pointer is invalid")
    return value


def _clear_active_pointer(directory, action_id):
    path = _active_pointer_path(directory)
    pointer = _read_active_pointer(directory)
    if pointer is None:
        return False
    if pointer["action_id"] != action_id:
        raise OrchestratorError(
            "ACTION_POINTER_CONFLICT", "another action owns the active pointer")
    path.unlink()
    try:
        loom_reliability._sync_parent(path)
    except OSError as exc:
        raise OrchestratorError(
            "ACTION_POINTER_DURABILITY", "active action pointer removal was not durable") from exc
    return True


def _stage_path(action_path):
    """Return the legacy owner-home stage path for compatibility recovery."""
    return Path(action_path).parent / ".staging" / Path(action_path).stem / "plans"


def _project_stage_path(action):
    """Return the same-volume stage used by new atomic planning-pack installs."""
    target = Path(action["explicit_target"] or action["cwd"])
    return target / f".loom-plan-stage-{action['action_id']}"


def _manifest_for_tree(path):
    try:
        return loom_reliability.deterministic_manifest(path)
    except (OSError, loom_reliability.ReliabilityError) as exc:
        raise OrchestratorError("PACK_UNSAFE", f"planning tree is unsafe: {exc}") from exc


def _path_present(path):
    """Treat every redirect, including a broken link, as present and unsafe."""
    path = Path(path)
    try:
        return path.exists() or loom_reliability._is_redirect(path)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED", f"recovery path cannot be inspected: {exc}") from exc


def _recovery_manifest(path):
    """Return bounded exact-tree deletion authority or refuse all mutation."""
    try:
        return loom_reliability.exact_tree_manifest(
            path, max_entries=64, max_file_bytes=MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=MAX_RECOVERY_TOTAL_BYTES)
    except (OSError, loom_reliability.ReliabilityError) as exc:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED", f"recovery tree is unsafe: {exc}") from exc


def _seed_stage(action_path, action, prepared):
    stage = _project_stage_path(action)
    if _path_present(stage):
        raise OrchestratorError(
            "BASELINE_STAGING_CONFLICT", "planning seed staging path already exists")
    target = Path(action["explicit_target"] or action["cwd"])
    try:
        target_identity = loom_reliability.observe_root_identity(target)
        reserved = loom_reliability.reserve_directory_leaf(
            target, stage.name, mode=0o755)
        loom_reliability._validate_directory_object_continuity(
            target, target_identity)
        stage_identity = loom_reliability.observe_root_identity(reserved)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "BASELINE_STAGING_CONFLICT",
            f"planning seed stage could not be reserved safely: {exc}") from exc
    if reserved != stage:
        raise OrchestratorError(
            "BASELINE_STAGING_CONFLICT", "planning seed stage resolved unexpectedly")
    if action["tier"] == "S":
        record = stage / ".loom-small-lifecycle.json"
        work_order = stage / "WO-001.md"
        code, output = _capture(
            loom_gate.small_start, record, target, work_order,
            list(prepared.domains), prepared.prepared_at)
    else:
        _seed_manifest(
            stage, target, action["install_root"], prepared, action["request"])
        code, output = _capture(loom_gate.start, stage, target, "planned")
    if code:
        raise OrchestratorError("BASELINE_FAILED", output)
    try:
        loom_reliability._validate_directory_object_continuity(
            target, target_identity)
        loom_reliability._validate_directory_object_continuity(
            stage, stage_identity)
        manifest = loom_reliability.exact_tree_manifest(
            stage, max_entries=64, max_file_bytes=MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=MAX_RECOVERY_TOTAL_BYTES)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "BASELINE_STAGING_UNSAFE", f"planning seed cannot be sealed safely: {exc}") from exc
    _validate_seed_manifest(manifest)
    return stage, manifest, stage_identity


def _copy_seed_stage(stage, pack, expected, expected_source_identity):
    """Install a sealed same-volume stage with one atomic directory rename."""
    pack = Path(pack)
    stage = Path(stage)
    try:
        source_identity = loom_reliability._validate_directory_object_continuity(
            stage, expected_source_identity)
        actual = loom_reliability.exact_tree_manifest(
            stage, max_entries=64, max_file_bytes=MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=MAX_RECOVERY_TOTAL_BYTES)
        loom_reliability._validate_directory_object_continuity(stage, source_identity)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "BASELINE_STAGING_CHANGED", f"planning seed changed before installation: {exc}") \
            from exc
    if not loom_reliability.exact_tree_manifests_equal(
            actual, expected, max_entries=64,
            max_file_bytes=MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=MAX_RECOVERY_TOTAL_BYTES):
        raise OrchestratorError(
            "BASELINE_STAGING_CHANGED", "planning seed changed during installation")
    try:
        outcome = loom_reliability.atomic_rename_noreplace(
            stage, pack, expected_source_identity=source_identity,
            source_role="prepared_stage", destination_role="active_plan")
    except loom_reliability.AtomicRenameReconciliationRequired:
        raise
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "BASELINE_ATOMIC_INSTALL_FAILED", f"planning seed was not installed: {exc}") from exc
    try:
        installed = loom_reliability.exact_tree_manifest(
            pack, max_entries=64, max_file_bytes=MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=MAX_RECOVERY_TOTAL_BYTES)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "BASELINE_STAGING_CHANGED", f"installed planning seed is unsafe: {exc}") from exc
    if not loom_reliability.exact_tree_manifests_equal(
            installed, expected, max_entries=64,
            max_file_bytes=MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=MAX_RECOVERY_TOTAL_BYTES):
        raise OrchestratorError("BASELINE_STAGING_CHANGED", "installed planning seed differs")
    return outcome.state


def _manifest_is_seed_subset(actual, expected):
    if actual.get("schema_version") == expected.get("schema_version") == 2:
        try:
            return loom_reliability.exact_tree_manifest_is_subset(
                actual, expected, max_entries=64,
                max_file_bytes=MAX_RECOVERY_FILE_BYTES,
                max_total_bytes=MAX_RECOVERY_TOTAL_BYTES)
        except loom_reliability.ReliabilityError:
            return False
    if actual.get("schema_version") == expected.get("schema_version") == 1:
        expected_files = {item["path"]: item for item in expected["files"]}
        return all(expected_files.get(item["path"]) == item for item in actual["files"])
    return False


def _recovery_preserved_locators(source_path, action):
    """Return the only bounded locator permitted for an untouched recovery source."""
    action_id = action["action_id"]
    if source_path == "owner-stage":
        return ([
            f"instances/{action['instance_id']}/runtime/projects/{action['project_id']}/"
            f"orchestrations/.staging/{action_id}/plans"], [])
    project_relative = {
        "plans": "plans",
        "install-stage": f".loom-plan-stage-{action_id}",
        "legacy-tombstone": f".loom-recovery-{action_id}",
    }.get(source_path)
    if project_relative is None:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED", "recovery source has no bounded locator")
    return ([], [project_relative])


def _recovery_receipt(action, *, reason, source_path, owner_quarantine_relative,
                      project_quarantine_relative, preserved_relatives,
                      preserved_project_relatives, seed_sha256, quarantined_sha256,
                      manifest_schema_version, complete_seed, source_disposition,
                      activation_atomic_rename, quarantine_atomic_rename,
                      recovered_at):
    if owner_quarantine_relative is not None:
        quarantine_scope = "owner-home"
    elif project_quarantine_relative is not None:
        quarantine_scope = "project-local"
    else:
        quarantine_scope = None
    changes_made = source_disposition == "quarantined"
    project_namespace_changed = (
        source_disposition == "quarantined" and source_path != "owner-stage")
    owner_control_changed = (
        source_disposition == "quarantined" and quarantine_scope == "owner-home")
    uncertain = any(
        state is None or state["namespace_state"] != "committed"
        or state["durability"] != "confirmed"
        for state in (activation_atomic_rename, quarantine_atomic_rename)
        if state is not None)
    if source_disposition == "quarantined" and quarantine_atomic_rename is None:
        uncertain = True
    if source_disposition == "preserved-in-place":
        cleanup_phase = (
            "reconciliation-required" if uncertain else "preserved-in-place")
    elif source_disposition == "quarantined":
        cleanup_phase = "reconciliation-required" if uncertain else "gc-complete"
    else:
        cleanup_phase = "reconciliation-required" if uncertain else "gc-complete"
    body = {
        "schema_version": 3,
        "recovery_id": "recovery-" + hashlib.sha256(
            f"{action['action_id']}:{reason}".encode()).hexdigest()[:24],
        "action_id": action["action_id"], "project_id": action["project_id"],
        "reason": reason, "source_path": source_path,
        "quarantine_scope": quarantine_scope,
        "owner_quarantine_relative": owner_quarantine_relative,
        "project_quarantine_relative": project_quarantine_relative,
        "preserved_relatives": list(preserved_relatives),
        "preserved_project_relatives": list(preserved_project_relatives),
        "seed_manifest_sha256": seed_sha256,
        "quarantined_manifest_sha256": quarantined_sha256,
        "manifest_schema_version": manifest_schema_version,
        "complete_seed": bool(complete_seed),
        "changes_made": changes_made,
        "reversible": changes_made,
        "source_disposition": source_disposition,
        "cleanup_phase": cleanup_phase,
        "project_namespace_changed": project_namespace_changed,
        "owner_control_changed": owner_control_changed,
        "activation_atomic_rename": activation_atomic_rename,
        "quarantine_atomic_rename": quarantine_atomic_rename,
        "recovered_at": _stamp(recovered_at),
    }
    return {**body, "receipt_hash": _hash(body)}


def _atomic_quarantine_tree(source, destination, *, expected_source_identity):
    """Move one whole tree without traversing or deleting any of its entries."""
    source = Path(source)
    destination = Path(destination)
    try:
        if not _path_present(destination.parent):
            raise OrchestratorError(
                "RECOVERY_DECISION_REQUIRED",
                "recovery quarantine parent was not prepared safely")
        loom_reliability._absolute(
            destination.parent, "recovery quarantine parent", must_exist=True)
        outcome = loom_reliability.atomic_rename_noreplace(
            source, destination,
            expected_source_identity=expected_source_identity,
            source_role="recovery_source",
            destination_role="quarantine_destination")
        return outcome.state
    except loom_reliability.AtomicRenameReconciliationRequired:
        raise
    except OrchestratorError:
        raise
    except loom_reliability.ReliabilityError as exc:
        if "different filesystems" in str(exc) \
                or "unavailable" in str(exc):
            return False
        raise OrchestratorError(
            "RECOVERY_DURABILITY", f"whole-tree quarantine failed safely: {exc}") from exc


def _prepare_recovery_root(owner_root, recovery_root):
    """Create or validate one bounded owner-private quarantine directory."""
    try:
        owner_root = Path(owner_root)
        recovery_root = Path(recovery_root)
        recovery_root.relative_to(owner_root)
        project_state_root = recovery_root.parent.parent
        project_state_root.relative_to(owner_root)
        relative = recovery_root.relative_to(project_state_root)
        if len(relative.parts) != 2 or relative.parts[0] != RECOVERY_DIRECTORY:
            raise ValueError("recovery path is not action-scoped")
        return loom_reliability.ensure_private_directory(
            project_state_root, relative.parts)
    except (ValueError, loom_reliability.ReliabilityError) as exc:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            f"recovery quarantine parent cannot be prepared safely: {exc}") from exc


def _manifest_if_proven(path, expected, *, allow_subset=False):
    if not isinstance(expected, dict) or expected.get("schema_version") != 2:
        return None
    try:
        identity = loom_reliability.observe_root_identity(path)
        actual = _recovery_manifest(path)
        loom_reliability.validate_root_identity(path, identity)
        if loom_reliability.exact_tree_manifests_equal(
                actual, expected, max_entries=64,
                max_file_bytes=MAX_RECOVERY_FILE_BYTES,
                max_total_bytes=MAX_RECOVERY_TOTAL_BYTES):
            return {"manifest": actual, "identity": identity}
        if allow_subset and loom_reliability.exact_tree_manifest_is_subset(
                actual, expected, max_entries=64,
                max_file_bytes=MAX_RECOVERY_FILE_BYTES,
                max_total_bytes=MAX_RECOVERY_TOTAL_BYTES):
            return {"manifest": actual, "identity": identity}
    except (OrchestratorError, loom_reliability.ReliabilityError):
        pass
    return None


def _recover_plan_action(path, action, security, *, now, requested_reason=None):
    target = Path(action["explicit_target"] or action["cwd"])
    pack = target / "plans"
    project_stage = _project_stage_path(action)
    legacy_stage = _stage_path(path)
    legacy_tombstone = target / f".loom-recovery-{action['action_id']}"
    seed = action["pack_seed"]
    expected = seed.get("manifest")
    reason = requested_reason or (
              "interrupted-initialization" if action["status"] == "initializing"
              else "expired" if loom_runtime._parse_time(now) > loom_runtime._parse_time(
                  action["expires_at"])
              else "superseded")
    recovery_root = Path(path).parent.parent / RECOVERY_DIRECTORY / action["action_id"]
    try:
        owner_root = loom_reliability._absolute(
            action["owner_home"], "recovery owner root", must_exist=True)
        recovery_root = loom_reliability._absolute(recovery_root, "recovery destination")
        target_root = loom_reliability._absolute(target, "recovery project", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED", f"recovery location is unsafe: {exc}") from exc
    if not recovery_root.is_relative_to(owner_root) \
            or recovery_root == target_root or recovery_root.is_relative_to(target_root):
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED", "recovery destination is not owner-scoped")
    quarantine = recovery_root / "plans"
    present = [
        ("plans", pack) if _path_present(pack) else None,
        ("install-stage", project_stage) if _path_present(project_stage) else None,
        ("owner-stage", legacy_stage) if _path_present(legacy_stage) else None,
        ("legacy-tombstone", legacy_tombstone)
        if _path_present(legacy_tombstone) else None,
    ]
    present = [item for item in present if item is not None]
    quarantine_present = _path_present(quarantine)
    preserved_relatives = []
    preserved_project_relatives = []
    quarantine_atomic_rename = None
    quarantine_proof = (
        _manifest_if_proven(quarantine, expected) if quarantine_present else None)
    if quarantine_present and quarantine_proof is None:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            "the existing recovery quarantine cannot be proven exact; it was preserved")
    if quarantine_present and len(present) == 1 \
            and present[0][0] == "legacy-tombstone":
        tombstone_proof = _manifest_if_proven(
            present[0][1], expected, allow_subset=True)
        if tombstone_proof is None:
            raise OrchestratorError(
                "RECOVERY_DECISION_REQUIRED",
                "the legacy recovery tombstone cannot be proven from the sealed seed")
        _prepare_recovery_root(owner_root, recovery_root)
        auxiliary = recovery_root / "legacy-tombstone"
        auxiliary_state = _atomic_quarantine_tree(
                present[0][1], auxiliary,
                expected_source_identity=tombstone_proof["identity"])
        if not auxiliary_state:
            raise OrchestratorError(
                "RECOVERY_DECISION_REQUIRED",
                "a legacy recovery tombstone could not be moved atomically; it was preserved")
        preserved_relatives.append(
            auxiliary.relative_to(Path(action["owner_home"])).as_posix())
        present = []
    if quarantine_present and present:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            "both a recovery source and its quarantine exist; every artifact was preserved")
    if len(present) > 1:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            "multiple recovery sources exist; every source was preserved for inspection")
    elif quarantine_present:
        source_path, source = (
            ("install-stage", None) if action["status"] == "initializing"
            else ("plans", None))
        source_disposition = "quarantined"
        owner_quarantine_relative = quarantine.relative_to(
            Path(action["owner_home"])).as_posix()
        project_quarantine_relative = None
        actual = quarantine_proof["manifest"]
    elif present:
        source_path, source = present[0]
        source_proof = _manifest_if_proven(
            source, expected, allow_subset=source_path != "plans")
        actual = source_proof["manifest"] if source_proof is not None else None
        if source_proof is None:
            if requested_reason == "cancelled":
                source_disposition = "preserved-in-place"
                owner_quarantine_relative = None
                project_quarantine_relative = None
                moved = False
            else:
                raise OrchestratorError(
                    "RECOVERY_DECISION_REQUIRED",
                    f"{source_path} cannot be proven from the exact v2 seed; it was preserved")
        else:
            _prepare_recovery_root(owner_root, recovery_root)
            moved = _atomic_quarantine_tree(
                source, quarantine,
                expected_source_identity=source_proof["identity"])
            if not moved and requested_reason != "cancelled":
                raise OrchestratorError(
                    "RECOVERY_DECISION_REQUIRED",
                    f"{source_path} cannot move atomically to owner quarantine; it was preserved")
        if moved:
            quarantine_atomic_rename = moved
            source_disposition = "quarantined"
            owner_quarantine_relative = quarantine.relative_to(
                Path(action["owner_home"])).as_posix()
            project_quarantine_relative = None
            moved_proof = _manifest_if_proven(
                quarantine, expected, allow_subset=source_path != "plans")
            if moved_proof is None:
                raise OrchestratorError(
                    "RECOVERY_RACE",
                    "moved quarantine does not match the pre-move exact-tree proof")
            actual = moved_proof["manifest"]
        elif requested_reason == "cancelled":
            source_disposition = "preserved-in-place"
            owner_quarantine_relative = None
            project_quarantine_relative = None
            owner_locators, project_locators = _recovery_preserved_locators(
                source_path, action)
            preserved_relatives.extend(owner_locators)
            preserved_project_relatives.extend(project_locators)
    else:
        source_path, source = "none", None
        source_disposition = "not-present"
        owner_quarantine_relative = None
        project_quarantine_relative = None
        actual = None

    complete_seed = (
        source_disposition == "quarantined"
        and actual is not None and expected is not None and actual == expected)
    quarantined_sha = (
        actual["root_sha256"]
        if actual is not None and source_disposition == "quarantined" else None)

    receipt = _recovery_receipt(
        action, reason=reason, source_path=source_path,
        owner_quarantine_relative=owner_quarantine_relative,
        project_quarantine_relative=project_quarantine_relative,
        preserved_relatives=preserved_relatives,
        preserved_project_relatives=preserved_project_relatives,
        seed_sha256=(expected or {}).get("root_sha256") or action.get("initial_pack_hash"),
        quarantined_sha256=quarantined_sha,
        manifest_schema_version=(expected or {}).get("schema_version"),
        complete_seed=complete_seed, source_disposition=source_disposition,
        activation_atomic_rename=seed.get("activation_atomic_rename"),
        quarantine_atomic_rename=quarantine_atomic_rename,
        recovered_at=now)
    candidate = dict(action)
    candidate["schema_version"] = ACTION_SCHEMA_VERSION
    candidate["pack_seed"] = {
        **seed, "state": "recovered", "manifest": expected,
    }
    candidate["recovery_receipt"] = receipt
    candidate["remove_pristine_pack"] = False
    candidate["status"] = {
        "interrupted-initialization": "abandoned",
        "expired": "expired",
        "superseded": "superseded",
        "cancelled": "cancelled",
    }[reason]
    candidate["action_hash"] = _action_hash(candidate)
    _validate_action(candidate, path)
    _write_action(path, candidate, security)
    _clear_active_pointer(Path(path).parent, candidate["action_id"])
    return receipt


def _legacy_active_actions(directory, *, owner_home, install_root):
    candidates = []
    entries = []
    inspected = 0
    for entry in os.scandir(directory):
        inspected += 1
        if inspected > MAX_ORCHESTRATION_DIRECTORY_ENTRIES:
            raise OrchestratorError(
                "RECOVERY_CAPACITY",
                "orchestration directory exceeds its hard entry bound")
        if entry.name == ACTIVE_POINTER_FILE or not entry.name.endswith(".json"):
            continue
        if not re.fullmatch(r"[0-9a-f-]{36}\.json", entry.name):
            continue
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise OrchestratorError(
                "ACTION_UNSAFE", "orchestration history contains an unsafe action entry")
        entries.append(Path(entry.path))
        if len(entries) > MAX_ORCHESTRATION_ACTIONS:
            raise OrchestratorError(
                "RECOVERY_CAPACITY", "legacy active-action scan exceeds its hard bound")
    for path in sorted(entries, key=lambda item: item.name):
        _path, action, security = _read_action(
            path, owner_home=owner_home, install_root=install_root)
        if action["status"] in {"initializing", "pending"}:
            candidates.append((_path, action, security))
    return candidates


def _reconcile_active_action(*, owner_home, install_root, instance_id,
                             project_id, now, incoming_intent, request, cwd, target,
                             transport_invocation_id=None):
    directory = _orchestration_directory(owner_home, instance_id, project_id)
    directory.mkdir(parents=True, exist_ok=True)
    pointer = _read_active_pointer(directory)
    if pointer is not None:
        if pointer["project_id"] != project_id:
            raise OrchestratorError(
                "ACTION_POINTER_CONFLICT", "active action pointer belongs to another project")
        path = directory / f"{pointer['action_id']}.json"
        if not _path_present(path):
            raise OrchestratorError(
                "RECOVERY_DECISION_REQUIRED",
                "the active pointer names a missing action; its project effects cannot be "
                "proven absent, so the pointer and project were preserved")
        _path, action, security = _read_action(
            path, owner_home=owner_home, install_root=install_root)
        if action["status"] in TERMINAL_ACTION_STATUSES:
            _clear_active_pointer(directory, action["action_id"])
            return action.get("recovery_receipt"), None
        candidates = [(_path, action, security)]
    else:
        candidates = _legacy_active_actions(
            directory, owner_home=owner_home, install_root=install_root)
        if not candidates:
            return None, None
        if len(candidates) != 1:
            raise OrchestratorError(
                "RECOVERY_DECISION_REQUIRED", "multiple nonterminal actions require inspection")
    path, action, security = candidates[0]
    if incoming_intent is None \
            or incoming_intent in NONINTERFERING_ACTIVE_ACTION_INTENTS:
        return None, None
    if transport_invocation_id is not None \
            and action["invocation_id"] == transport_invocation_id \
            and action["status"] == "pending" \
            and loom_runtime._parse_time(now) <= loom_runtime._parse_time(
                action["expires_at"]):
        try:
            prepared = loom_runtime.prepare_invocation(
                request, instance_id=instance_id, invocation_id=str(uuid.uuid4()),
                cwd=cwd, explicit_target=target, owner_home=owner_home, now=now)
        except loom_runtime.RuntimeBlocked as exc:
            raise OrchestratorError(exc.code, exc.message) from exc
        sealed = action["prepared"]
        same_frontier = action["request"] == request \
                and action["cwd"] == str(cwd) \
                and action["explicit_target"] == str(target) \
                and action["project_id"] == prepared.project_id \
                and action["survey_hash"] == prepared.survey_hash \
                and sealed["request_hash"] == prepared.request_hash \
                and sealed["intent"] == prepared.intent \
                and sealed["domains"] == list(prepared.domains)
        unchanged_world = sealed["world_fingerprint"] == prepared.world_fingerprint
        current_pack_matches = action["initial_pack_hash"] is not None \
            and _pack_hash(Path(target) / "plans") == action["initial_pack_hash"]
        repair_record = Path(target) / "plans" / ".loom-small-lifecycle.json"
        tier_s_repair_current = False
        if action["intent"] == "repair" and action["tier"] == "S" \
                and isinstance(action["repair_plan"], dict) \
                and _path_present(repair_record):
            try:
                tier_s_repair_current = hashlib.sha256(
                    repair_record.read_bytes()).hexdigest() == \
                    action["repair_plan"].get("lifecycle_sha256")
            except OSError as exc:
                raise OrchestratorError(
                    "TARGET_INDETERMINATE",
                    "the repeated transport operation's Tier-S lifecycle is unreadable") \
                    from exc
        if action["intent"] == prepared.intent and same_frontier and (
                unchanged_world or current_pack_matches or tier_s_repair_current):
            return None, action
        raise OrchestratorError(
            "TARGET_DRIFT",
            "a repeated transport operation no longer matches its sealed target state")
    if action["intent"] != "plan" or not action["pack_seed"]["created_pack"]:
        raise OrchestratorError(
            "ACTION_IN_PROGRESS", "a non-planning action remains active for this project")
    if action["status"] == "pending" \
            and loom_runtime._parse_time(now) <= loom_runtime._parse_time(action["expires_at"]) \
            and incoming_intent != "plan":
        raise OrchestratorError(
            "ACTION_IN_PROGRESS",
            "the current planning action must complete or be cancelled before this request")
    return _recover_plan_action(path, action, security, now=now), None


def _capture(function, *args, **kwargs):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = function(*args, **kwargs)
    return code, (stdout.getvalue() + stderr.getvalue()).strip()


def _seed_manifest(pack, target, install_root, prepared, request):
    """Write only a valid draft shell; no semantic plan is claimed before the baseline."""
    version = (Path(install_root) / "VERSION").read_text(encoding="utf-8").strip()
    coverage = ("unknown" if prepared.route_contract["requires_domain_discovery"]
                else "adapter")
    quoted_request = "\n".join(
        "> " + line for line in request.replace("\r", "").split("\n"))
    text = f"""---
artifact: manifest
project: {json.dumps(Path(target).name)}
tier: {prepared.route_contract['tier']}
status: draft
last_verified: {dt.date.today().isoformat()}
loom_version: {json.dumps(version)}
plan_contract_version: 4
execution_mode: planned
domain_id: {prepared.domains[0]}
domain_ids: [{', '.join(prepared.domains)}]
domain_coverage: {coverage}
freshness_window_days: 14
---

# Planning pack — {Path(target).name}

Original request (verbatim, do not paraphrase):
{quoted_request}

## Artifacts

| Artifact | Action | Consumer | Decision | Why (one line) | Status | last_verified |
|---|---|---|---|---|---|---|

## Work order frontier

| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|---|
"""
    pack.mkdir(parents=True, exist_ok=True)
    loom_gate._atomic_write_text(pack / "MANIFEST.md", text)


def _artifact_contract(tier, domains, request, requires_discovery):
    domains = set(domains)
    whole = bool(re.search(
        r"(?i)\b(?:build|create|develop|design|implement|produce|write)\b", request))
    ui_domains = {
        "android", "desktop", "ios-macos", "mobile", "realtime-3d",
        "web-app", "website",
    }
    product_domains = ui_domains | {"accounting", "browser-extension", "cli", "llm-agent"}
    boundary_domains = {
        "accounting", "android", "cli", "data-etl", "desktop",
        "firmware-hardware", "ios-macos", "library-sdk", "ml", "mobile",
        "realtime-3d", "web-app",
    }
    sensitive_domains = {
        "accounting", "android", "automation", "browser-extension",
        "firmware-hardware", "high-risk", "ios-macos", "llm-agent", "mobile",
        "web-app",
    }
    produced = {"work orders"}
    if tier != "S":
        produced.update({"intake.md", "testing.md"})
    if requires_discovery:
        produced.add("domain-discovery.md")
    if tier in {"L", "XL"} or (tier == "M" and whole):
        if "research" not in domains:
            produced.add("architecture.md")
        if domains & product_domains:
            produced.add("product.md")
        if domains & boundary_domains:
            produced.add("contracts.md")
    if tier in {"L", "XL"}:
        produced.update({"release-rollback.md", "routing"})
        if "research" not in domains:
            produced.add("maintenance.md")
    if domains & ui_domains and tier != "S":
        produced.add("uiux.md")
    if domains & sensitive_domains and tier in {"L", "XL"}:
        produced.add("security.md")

    produced_cells = {
        "intake.md": ("planner", "scope and constraints", "establishes the contract"),
        "product.md": ("product owner", "outcomes and release scope",
                       "whole product decisions need an explicit consumer contract"),
        "architecture.md": ("implementer", "components and boundaries",
                            "whole-deliverable topology cannot remain implicit"),
        "uiux.md": ("interface implementer", "states, interaction, and accessibility",
                    "the selected domain has user-interface invariants"),
        "contracts.md": ("implementer", "boundary and compatibility contracts",
                         "the selected domain crosses durable interfaces"),
        "testing.md": ("verifier", "acceptance evidence", "invariants need tests"),
        "release-rollback.md": ("release owner", "release and rollback controls",
                                "release-pack depth requires an executable recovery route"),
        "security.md": ("security reviewer", "authority and abuse boundaries",
                        "the selected domain carries security-sensitive consequences"),
        "maintenance.md": ("operator", "ownership, observability, and upkeep",
                           "multi-subsystem work needs an operating contract"),
        "domain-discovery.md": ("G1 reviewer", "verified domain invariants",
                                "no shipped adapter covers this domain"),
        "work orders": ("implementer", "execution and acceptance", "executable frontier"),
        "routing": ("coordinator", "ordered ownership and integration",
                    "release-pack work has multiple atomic outcomes"),
    }
    skip_cells = {
        "intake.md": "Tier S carries scope in its compact work order",
        "survey.md": "the sealed machine survey supplies current world state",
        "product.md": "no independent product-policy consumer was selected",
        "architecture.md": "no multi-component architecture decision was observed",
        "uiux.md": "no interface-state consumer was selected",
        "contracts.md": "no durable external boundary was observed",
        "testing.md": "Tier S carries acceptance in its compact work order",
        "release-rollback.md": "release exposure does not require a separate artifact",
        "security.md": "no independent security-boundary consumer was selected",
        "maintenance.md": "no separate operator decision was observed",
        "scaffold.md": "scaffolding belongs in atomic work orders, not a planning essay",
        "domain-discovery.md": "shipped domain adapters cover the selected invariants",
        "work orders": "unreachable: every plan requires an executable frontier",
        "routing": "one ordered implementer frontier is sufficient",
        "project instructions": "no new repository instruction consumer was observed",
    }
    rows = []
    for artifact in ARTIFACT_ORDER:
        if artifact in produced:
            consumer, decision, reason = produced_cells[artifact]
            rows.append({"artifact": artifact, "action": "produce",
                         "consumer": consumer, "decision": decision, "reason": reason})
        else:
            rows.append({"artifact": artifact, "action": "skip", "consumer": "—",
                         "decision": "—", "reason": skip_cells[artifact]})
    return rows


def _make_plan_contract(action, prepared):
    tier = action["tier"]
    domains = list(action["domains"])
    required_invariants = []
    current_facts = []
    verification_media = []
    normalized_invariants = []
    route = action["domain_contract"]
    instant = loom_runtime._parse_time(action["created_at"])
    for domain_id in domains:
        adapter = loom_domain.CATALOG.get(domain_id)
        if adapter is None:
            continue
        guidance = loom_domain.GUIDANCE.get(domain_id, (
            ["domain-specific contract failure"],
            ["supported-environment acceptance"],
            ["domain-real-medium execution"],
        ))
        media = list(guidance[2])
        normalized_invariants.extend(loom_domain_invariants.compile_shipped(
            domain_id, adapter, guidance, now=instant))
        for index, invariant in enumerate(adapter["invariants"]):
            required_invariants.append({
                "domain": domain_id,
                "invariant": invariant,
                "evidence_target": "intake.md#domain-invariant-contract",
                "required_real_medium": media[index % len(media)],
            })
        for fact in (
                "current platform/tool versions and limits",
                "current governing policies, standards, or regulations",
                "current target environment and release channel"):
            current_facts.append({
                "domain": domain_id, "fact": fact,
                "evidence_target": "intake.md#current-facts-to-verify",
            })
        for medium in media:
            verification_media.append({
                "domain": domain_id, "medium": medium,
                "decision": "prove a release-relevant domain invariant",
            })
    ceilings = {
        "S": (3000, 900), "M": (30000, 9000),
        "L": (75000, 22000), "XL": (150000, 45000),
    }
    topology = {
        "S": (1, 1), "M": (1, 8), "L": (2, 24), "XL": (3, 64),
    }
    planning_intelligence = loom_planning_intelligence.compile_intelligence(
        action["request"], tier=tier, route=route)
    project_inspection = loom_runtime._thaw(prepared.project_inspection)
    inspection_capsule = loom_project_inspection.capsule(project_inspection)
    inspection_obligations = [
        {"path": item["path"], "reason": item["reason"],
         "potential_authorities": list(item["potential_authorities"])}
        for item in project_inspection["unresolved_roots"]]
    completion_gates = [
        "exact-artifact-matrix", "domain-invariant-contract",
        "current-fact-contract", "verification-media-contract",
        "planning-intelligence", "budget", "work-order-topology", "lint", "g1",
        "lifecycle",
    ]
    if not project_inspection["relevant_coverage_complete"]:
        completion_gates.insert(0, "project-inspection")
    body = {
        "schema_version": PLAN_CONTRACT_SCHEMA_VERSION,
        "request_hash": prepared.request_hash,
        "survey_hash": action["survey_hash"],
        "tier": tier,
        "domains": domains,
        "domain_route": route,
        "route_digest": route["route_digest"],
        "composition_graph_digest": route["graph_digest"],
        "target_fingerprint": action["survey_hash"],
        "project_inspection": inspection_capsule,
        "inspection_obligations": inspection_obligations,
        "pack_baseline_hash": action["initial_pack_hash"],
        "pack_root": "plans",
        "allowed_host_write_paths": ["plans/**"],
        "artifact_matrix": _artifact_contract(
            tier, domains, action["request"],
            prepared.route_contract["requires_domain_discovery"]),
        "required_domain_invariants": required_invariants,
        "domain_invariants": normalized_invariants,
        "domain_discovery": {
            "required": route["coverage_state"] != "known",
            "human_projection": "domain-discovery.md",
            "machine_bundle": "domain-discovery.json",
            "maximum_sources": 20, "maximum_invariants": 32,
            "maximum_retrieval_rounds": 2,
        },
        "planning_intelligence": planning_intelligence,
        "current_facts_to_verify": current_facts,
        "verification_media": verification_media,
        "budget": {
            "character_ceiling": ceilings[tier][0],
            "token_ceiling": ceilings[tier][1],
            "token_metric": "loom-lexical-v1",
        },
        "work_order_topology": {
            "minimum": topology[tier][0], "maximum": topology[tier][1],
            "dag_required": True, "atomic_outcomes_required": True,
            "acceptance_evidence_required": True,
        },
        "completion_gates": completion_gates,
    }
    return {**body, "contract_hash": _hash(body)}


def _tier_s_host_capsule(contract):
    """Project the full local contract into a bounded decision-only host capsule."""
    if contract.get("tier") != "S":
        return None
    body = {
        "schema_version": 1,
        "plan_contract_hash": contract["contract_hash"],
        "request_hash": contract["request_hash"],
        "project_inspection": contract["project_inspection"],
        "allowed_host_write_paths": contract["allowed_host_write_paths"],
        "work_order": {"count": 1, "path": "plans/WO-001.md",
                       "maximum_touches": 5, "maximum_outcomes": 1,
                       "maximum_characters": 3000, "maximum_lines": 40,
                       "maximum_lexical_tokens": 900,
                       "required_sections": ["Intent", "Context", "Preconditions", "Task",
                           "Acceptance criteria", "Out of scope", "Escalation triggers",
                           "Epistemic notes", "Close-out"]},
        "invariants": [{"id": item["invariant_id"], "statement": item["statement"],
                        "verification_medium": item["verification"]["required_real_medium"]}
                       for item in contract["domain_invariants"]],
        "current_facts": [{"domain": item["domain"], "fact": item["fact"]}
                          for item in contract["current_facts_to_verify"]],
        "verification_media": sorted({item["medium"]
                                      for item in contract["verification_media"]}),
        "planning_atoms": [{"id": item["atom_id"], "kind": item["kind"],
                             "statement": item["statement"],
                             "required_real_medium": item["required_real_medium"]}
                            for item in contract["planning_intelligence"]["atoms"]],
        "promotion_triggers": ["unknown-or-partial-coverage", "consequential-change",
            "new-boundary", "more-than-five-touches", "irreversible-action",
            "multiple-outcomes", "missing-real-medium", "budget-overflow"],
        "completion": "loom complete --action <action_path> [--usage <usage-v3.json>]",
    }
    capsule = {**body, "capsule_hash": _hash(body)}
    if len(_canonical_bytes(capsule)) > 4096:
        raise OrchestratorError(
            "TIER_PROMOTION_REQUIRED",
            "complete Tier S decision context exceeds the 4096-byte host capsule bound")
    return capsule


def _validate_planning_assignments(pack, contract, work_orders):
    intelligence = contract["planning_intelligence"]
    required_atoms = {
        item["atom_id"]: item for item in intelligence["atoms"]
        if item["gate_effect"] != "none"}
    work_order_records = {}
    for path in work_orders:
        try:
            frontmatter, _ = loom_lint.parse_frontmatter(
                path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", f"{path.name} cannot be read: {exc}") from exc
        if not isinstance(frontmatter, dict) or not frontmatter.get("id"):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", f"{path.name} has no valid work-order identity")
        work_order_records[frontmatter["id"]] = (path, frontmatter)
    program = intelligence["program"]
    if program is None:
        allowed_milestones = {"delivery"}
    else:
        try:
            loom_program.validate_program(program)
        except loom_program.ProgramError as exc:
            raise OrchestratorError("PLAN_CONTRACT_MISMATCH", str(exc)) from exc
        allowed_milestones = {
            item["id"] for item in program["milestone_graph"]["milestones"]}
    if contract["tier"] == "S":
        if set(work_order_records) != {"WO-001"}:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "Tier-S planning assignments require WO-001")
        frontmatter = work_order_records["WO-001"][1]
        if frontmatter.get("milestone") != "delivery" \
                or sorted(frontmatter.get("planning_obligations", [])) != sorted(required_atoms):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH",
                "Tier-S work order does not bind every sealed planning obligation")
        return

    path = pack / "planning-obligations.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", f"planning obligation assignments are invalid: {exc}") \
            from exc
    fields = {"schema_version", "plan_contract_hash", "planning_intelligence_digest",
              "program_digest", "assignments", "assignment_digest"}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1:
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", "planning obligation assignment fields are invalid")
    body = dict(value); claimed = body.pop("assignment_digest")
    if claimed != loom_domain_contract.digest("planning-obligation-assignments-v1", body) \
            or value["plan_contract_hash"] != contract["contract_hash"] \
            or value["planning_intelligence_digest"] != intelligence["intelligence_digest"] \
            or value["program_digest"] != (program or {}).get("program_digest"):
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", "planning obligation assignments are stale or mutated")
    assignments = value.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != len(required_atoms) \
            or assignments != sorted(assignments, key=lambda item: item.get("atom_id", "")):
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", "planning obligations are incomplete or noncanonical")
    seen = set(); milestone_use = set(); by_work_order = {
        identity: [] for identity in work_order_records}
    for assignment in assignments:
        if not isinstance(assignment, dict) or set(assignment) != {
                "atom_id", "work_order", "milestone", "verification"}:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "planning obligation assignment is invalid")
        atom_id = assignment["atom_id"]
        if atom_id in seen or atom_id not in required_atoms \
                or assignment["work_order"] not in work_order_records \
                or assignment["milestone"] not in allowed_milestones \
                or assignment["verification"] != loom_planning_intelligence.expanded_verification(
                    intelligence, required_atoms[atom_id]):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH",
                "planning obligation assignment changes scope, evidence, or verification")
        seen.add(atom_id); milestone_use.add(assignment["milestone"])
        by_work_order[assignment["work_order"]].append(atom_id)
    if seen != set(required_atoms) or (program is not None and milestone_use != allowed_milestones):
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH",
            "planning obligations or program milestones are not fully assigned")
    for identity, (_path, frontmatter) in work_order_records.items():
        assigned = sorted(by_work_order[identity])
        if sorted(frontmatter.get("planning_obligations", [])) != assigned \
                or frontmatter.get("milestone") not in allowed_milestones:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH",
                f"{identity} frontmatter diverges from sealed planning assignments")


def _validate_authored_plan(action):
    contract = action["plan_contract"]
    root = Path(action["explicit_target"] or action["cwd"])
    pack = root / contract["pack_root"]
    if not pack.is_dir() or pack.is_symlink():
        raise OrchestratorError("PLAN_CONTRACT_MISMATCH", "planning pack is missing or unsafe")
    if action["tier"] != "S":
        contract_path = pack / "plan-contract.json"
        try:
            persisted_contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", f"persisted plan contract is invalid: {exc}") from exc
        if persisted_contract != contract:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH",
                "persisted plan contract differs from the sealed action contract")
    text_files = []
    for path in sorted(pack.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "planning pack contains an unsafe entry")
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
                if path.suffix.casefold() == ".md":
                    text_files.append(text)
            except (OSError, UnicodeError) as exc:
                raise OrchestratorError(
                    "PLAN_CONTRACT_MISMATCH", f"planning artifact is not UTF-8 text: {exc}") \
                    from exc
    combined = "\n".join(text_files)
    lexical_tokens = len(re.findall(r"\w+|[^\s\w]", combined, re.UNICODE))
    if len(combined) > contract["budget"]["character_ceiling"] \
            or lexical_tokens > contract["budget"]["token_ceiling"]:
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", "authored plan exceeds its sealed planning budget")
    missing_inspection_obligations = [
        item["path"] for item in contract["inspection_obligations"]
        if item["path"] not in combined]
    if missing_inspection_obligations:
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH",
            "authored plan omits sealed project-inspection obligations: "
            + ", ".join(missing_inspection_obligations[:8]))

    work_orders = ([pack / "WO-001.md"] if action["tier"] == "S" else
                   sorted((pack / "work-orders").glob("WO-*.md")))
    minimum = contract["work_order_topology"]["minimum"]
    maximum = contract["work_order_topology"]["maximum"]
    if not minimum <= len([item for item in work_orders if item.is_file()]) <= maximum:
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", "work-order count is outside the sealed topology")
    _validate_planning_assignments(pack, contract, work_orders)
    if action["tier"] == "S":
        return None

    manifest = pack / "MANIFEST.md"
    try:
        manifest_text = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OrchestratorError(
            "PLAN_CONTRACT_MISMATCH", f"manifest cannot be read: {exc}") from exc
    actual_rows = loom_lint.parse_markdown_table(manifest_text, "Artifacts")
    actual = {}
    for row in actual_rows:
        key = loom_lint.artifact_matrix_key(row.get("artifact", ""))
        if key in actual:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", f"duplicate artifact row: {key}")
        actual[key] = {
            "artifact": key,
            "action": row.get("action", "").strip().lower(),
            "consumer": row.get("consumer", "").strip(),
            "decision": row.get("decision", "").strip(),
            "reason": row.get("why (one line)", "").strip(),
        }
    expected = {item["artifact"]: item for item in contract["artifact_matrix"]}
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        detail = f"missing={missing}; extra={extra}"
        if not missing and not extra:
            detail = "one or more artifact decisions differ from the sealed contract"
        raise OrchestratorError("PLAN_CONTRACT_MISMATCH", detail)

    def table(path, heading):
        try:
            return loom_lint.parse_markdown_table(
                path.read_text(encoding="utf-8"), heading)
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", f"{path.name} cannot be read: {exc}") from exc

    if contract["required_domain_invariants"]:
        rows = table(pack / "intake.md", "Domain invariant contract")
        observed = {(row.get("domain", "").strip(), row.get("invariant", "").strip())
                    for row in rows
                    if row.get("evidence target", "").strip()
                    and row.get("required real medium", "").strip()
                    and row.get("status", "").strip().lower() == "verified"}
        required = {(item["domain"], item["invariant"])
                    for item in contract["required_domain_invariants"]}
        if not required.issubset(observed):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "required domain invariants are not verified")

    validated_domain_bundle = None
    if contract["domain_discovery"]["required"]:
        bundle_path = pack / contract["domain_discovery"]["machine_bundle"]
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            validated_domain_bundle = loom_domain_bundle.validate(bundle)
        except (OSError, UnicodeError, json.JSONDecodeError,
                loom_domain_bundle.DomainBundleError) as exc:
            raise OrchestratorError(
                "DOMAIN_EVIDENCE_NOT_READY", f"domain discovery bundle is invalid: {exc}") \
                from exc
        if bundle["route"] != contract["domain_route"] \
                or bundle["target_fingerprint"] != contract["target_fingerprint"]:
            raise OrchestratorError(
                "DOMAIN_EVIDENCE_CHANGED",
                "domain evidence is bound to another route or target state")
        try:
            projection = (pack / contract["domain_discovery"]["human_projection"]).read_text(
                encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "DOMAIN_PROJECTION_MISSING", f"domain projection cannot be read: {exc}") from exc
        missing_bindings = [
            item["invariant_id"] for item in bundle["invariants"]
            if item["invariant_id"] not in projection
            or item["canonical_digest"] not in projection]
        if missing_bindings:
            raise OrchestratorError(
                "DOMAIN_PROJECTION_DIVERGED",
                "domain projection omits sealed invariant IDs or digests: "
                + ", ".join(missing_bindings[:8]))

    if contract["current_facts_to_verify"]:
        rows = table(pack / "intake.md", "Current facts to verify")
        observed = {(row.get("domain", "").strip(), row.get("fact", "").strip())
                    for row in rows if row.get("source", "").strip()
                    and row.get("status", "").strip().lower() == "verified"}
        required = {(item["domain"], item["fact"])
                    for item in contract["current_facts_to_verify"]}
        if not required.issubset(observed):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "required current facts are not verified")

    if contract["verification_media"]:
        rows = table(pack / "testing.md", "Verification media contract")
        observed = {(row.get("domain", "").strip(), row.get("medium", "").strip())
                    for row in rows if row.get("target", "").strip()
                    and row.get("status", "").strip().lower() == "planned"}
        required = {(item["domain"], item["medium"])
                    for item in contract["verification_media"]}
        if not required.issubset(observed):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "required verification media are not planned")
    return validated_domain_bundle


def _store_domain_bundle(memory, bundle):
    if bundle is None or not isinstance(memory, loom_vault_adapter.VaultMemoryAdapter):
        return []
    stored = []
    sequence = 1
    for kind, values in (("source", bundle["sources"]),
                         ("applicability", bundle["applicability"]),
                         ("invariant", bundle["invariants"])):
        for value in values:
            stored.append(loom_domain_learning.store(
                memory.vault, kind, value, source_sequence=sequence))
            sequence += 1
    adapter = {
        "id": "adapter-" + bundle["bundle_digest"][7:31],
        "domain_ids": bundle["route"]["active_task_domains"],
        "invariant_ids": [item["invariant_id"] for item in bundle["invariants"]],
        "status": "active",
        "revalidate_by": min(
            item["freshness"]["revalidate_by"] for item in bundle["invariants"]),
    }
    stored.append(loom_domain_learning.store(
        memory.vault, "adapter", adapter, source_sequence=sequence))
    return stored


def _pack_hash(pack):
    return loom_runtime._hash_frontier(pack)


def _repair_force_full(pack, instant):
    try:
        frontmatter, _ = loom_lint.parse_frontmatter(
            (Path(pack) / "MANIFEST.md").read_text(encoding="utf-8"))
        verified = dt.date.fromisoformat(str(frontmatter["last_verified"]))
        window = int(frontmatter["freshness_window_days"])
    except (OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        raise OrchestratorError(
            "REPAIR_SCOPE_INDETERMINATE", f"cannot establish freshness scope: {exc}") from exc
    return (instant.date() - verified).days > window


def _program_impact(pack, changed_paths, *, force_full=False):
    """Bind repository drift to the sealed milestone dependency closure."""
    pack = Path(pack)
    contract_path = pack / "plan-contract.json"
    assignment_path = pack / "planning-obligations.json"
    if not contract_path.is_file() or not assignment_path.is_file():
        return None
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        assignments = json.loads(assignment_path.read_text(encoding="utf-8"))
        program = contract["planning_intelligence"]["program"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as exc:
        raise OrchestratorError(
            "REPAIR_SCOPE_INDETERMINATE", f"cannot load sealed planning program: {exc}") \
            from exc
    if program is None:
        return None
    try:
        loom_program.validate_program(program)
    except loom_program.ProgramError as exc:
        raise OrchestratorError("REPAIR_SCOPE_INDETERMINATE", str(exc)) from exc
    milestone_by_wo = {
        item["work_order"]: item["milestone"] for item in assignments.get("assignments", [])
        if isinstance(item, dict) and item.get("work_order") and item.get("milestone")}
    seeds = set()
    for path in sorted((pack / "work-orders").glob("WO-*.md")):
        try:
            frontmatter, _ = loom_lint.parse_frontmatter(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "REPAIR_SCOPE_INDETERMINATE", f"cannot inspect program work order: {exc}") \
                from exc
        identity = (frontmatter or {}).get("id")
        patterns = (frontmatter or {}).get("touches", [])
        if isinstance(patterns, str):
            patterns = [patterns]
        if force_full or any(fnmatch.fnmatchcase(changed, pattern)
                             for changed in changed_paths for pattern in patterns):
            if identity in milestone_by_wo:
                seeds.add(milestone_by_wo[identity])
    graph = program["milestone_graph"]
    if not seeds:
        seeds = {item["id"] for item in graph["milestones"]}
    try:
        return loom_program.affected_milestones(graph, sorted(seeds))
    except loom_program.ProgramError as exc:
        raise OrchestratorError("REPAIR_SCOPE_INDETERMINATE", str(exc)) from exc


def _read_repair_result(result_path, action):
    if result_path is None:
        raise OrchestratorError(
            "REPAIR_EVIDENCE_REQUIRED",
            "repair completion requires content-bound real-medium evidence")
    path = _absolute(result_path, "repair result")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair result is not a bounded file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", str(exc)) from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "repair_verification"} \
            or value["schema_version"] != 2 \
            or not isinstance(value["repair_verification"], list) \
            or not 1 <= len(value["repair_verification"]) <= 32:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair result fields are invalid")
    expected = action["repair_plan"]["affected_plan_sections"]
    entries, seen = [], set()
    root = Path(action["explicit_target"] or action["cwd"])
    pack = root / "plans"
    action_file = _action_path(
        action["owner_home"], action["instance_id"], action["project_id"],
        action["action_id"])
    receipt_root = action_file.parent / f"{action['action_id']}.evidence"
    for item in value["repair_verification"]:
        if not isinstance(item, dict) or set(item) != {
                "section", "medium", "command", "timeout_seconds"} \
                or item["section"] not in expected or item["section"] in seen \
                or not isinstance(item["medium"], str) \
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item["medium"]) \
                or not isinstance(item["command"], list) \
                or not 1 <= len(item["command"]) <= 32 \
                or not all(isinstance(part, str) and 0 < len(part) <= 1000
                           and "\x00" not in part for part in item["command"]) \
                or type(item["timeout_seconds"]) is not int \
                or not 1 <= item["timeout_seconds"] <= 300:
            raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair evidence entry is invalid")
        try:
            receipt = loom_lifecycle.capture_repair_verification(
                pack, root, item["section"], medium=item["medium"],
                command=item["command"], timeout=item["timeout_seconds"])
            receipt_path = receipt_root / f"{item['section']}.json"
            loom_memory._atomic_json(receipt_path, receipt)
        except (OSError, loom_lifecycle.LifecycleError,
                loom_memory.MemoryError) as exc:
            raise OrchestratorError(
                "REPAIR_VERIFICATION_FAILED", f"{item['section']}: {exc}") from exc
        seen.add(item["section"])
        entries.append({
            "section": item["section"], "passed": True,
            "medium": receipt["medium"],
            "evidence_id": receipt["evidence_id"],
            "evidence_hash": receipt["evidence_hash"],
            "attestation_status": "loom-executed-local",
            "receipt_path": receipt_path.relative_to(action_file.parent).as_posix(),
        })
    if sorted(seen) != sorted(expected):
        raise OrchestratorError(
            "REPAIR_EVIDENCE_INVALID", "repair evidence does not cover the sealed scope exactly")
    return {"schema_version": 2, "repair_verification": entries}


def _read_host_outcome(result_path, action):
    if result_path is None:
        return None
    path = _absolute(result_path, "host outcome")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise OrchestratorError("HOST_OUTCOME_INVALID", "host outcome is not a bounded file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("HOST_OUTCOME_INVALID", str(exc)) from exc
    fields = {
        "schema_version", "applied_memory_ids", "verified_memory_ids",
        "rejected_memory_ids", "memory_effects", "metrics", "preference_observations",
        "artifact_usage",
    }
    if not isinstance(value, dict) or frozenset(value) not in {frozenset(fields),
            frozenset(fields | {"replay_pair"})} or value["schema_version"] != 1:
        raise OrchestratorError("HOST_OUTCOME_INVALID", "host outcome fields are invalid")
    evidence_id = "host-outcome-" + _hash(value)
    candidate = {
        "status": "completed", "code": "host-outcome", "success": True,
        "metrics": value["metrics"], "evidence_ids": [evidence_id],
        "reversible_action_ids": [],
        "applied_memory_ids": value["applied_memory_ids"],
        "verified_memory_ids": value["verified_memory_ids"],
        "rejected_memory_ids": value["rejected_memory_ids"],
        "memory_effects": value["memory_effects"],
        "preference_observations": value["preference_observations"],
        "artifact_usage": value["artifact_usage"],
    }
    try:
        normalized = loom_session._validate_handler_result(candidate)
    except loom_session.SessionBlocked as exc:
        raise OrchestratorError("HOST_OUTCOME_INVALID", str(exc)) from exc
    active_domains = set(action["domains"])
    for observation in normalized["preference_observations"]:
        if observation["key"] != "stack":
            continue
        observed_domain = observation.get("domain")
        if observed_domain is None and len(active_domains) == 1:
            continue
        if observed_domain not in active_domains:
            raise OrchestratorError(
                "HOST_OUTCOME_INVALID",
                "stack preference observation must name one active domain")
    selected = {item.get("id") for item in action["context"]["memory"]
                if isinstance(item, dict)}
    referenced = set(normalized["applied_memory_ids"]) \
        | set(normalized["verified_memory_ids"]) \
        | set(normalized["rejected_memory_ids"]) \
        | {item["memory_id"] for item in normalized["memory_effects"]}
    if not referenced.issubset(selected):
        raise OrchestratorError(
            "HOST_OUTCOME_INVALID", "host outcome references memory outside sealed context")
    if not (referenced or normalized["metrics"] or normalized["preference_observations"]
            or normalized["artifact_usage"]):
        raise OrchestratorError("HOST_OUTCOME_INVALID", "empty host outcome has no learning value")
    result = {"schema_version": 1, "learning": {
        key: normalized[key] for key in (
            "metrics", "evidence_ids", "applied_memory_ids", "verified_memory_ids",
            "rejected_memory_ids", "memory_effects", "preference_observations",
            "artifact_usage")}}
    if "replay_pair" in value:
        result["replay_pair"] = _validated_replay_pair(
            value["replay_pair"], action, normalized["applied_memory_ids"])
    return result


def _validated_replay_pair(value, action, applied_memory_ids):
    fields = {
        "schema_version", "replay_id", "metric", "domain", "request_hash",
        "world_fingerprint", "evaluator_id", "production", "simulation",
        "enabled", "disabled",
    }
    cohort_fields = {
        "value", "memory_ids", "outcome_evidence_path", "outcome_evidence_sha256",
        "provider_receipt",
    }
    receipt_fields = {
        "source", "provider", "model", "response_id", "captured_at",
        "raw_response_sha256", "usage",
    }
    prepared = action["prepared"]
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("replay_id"), str) \
            or loom_improvement.EVIDENCE_RE.fullmatch(value["replay_id"]) is None \
            or value.get("metric") not in loom_improvement.METRICS \
            or value.get("domain") not in (set(action["domains"]) | {"general"}) \
            or value.get("request_hash") != prepared["request_hash"] \
            or value.get("world_fingerprint") != prepared["world_fingerprint"] \
            or not isinstance(value.get("evaluator_id"), str) \
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
                            value["evaluator_id"]) is None \
            or value.get("production") is not True \
            or value.get("simulation") is not False:
        raise OrchestratorError(
            "HOST_OUTCOME_INVALID", "production replay identity is invalid")
    selected = {item.get("id") for item in action["context"]["memory"]
                if isinstance(item, dict)}
    pack = Path(action["explicit_target"] or action["cwd"]) / "plans"
    created = loom_runtime._parse_time(action["created_at"])
    expires = loom_runtime._parse_time(action["expires_at"])
    normalized = {}
    for cohort_name in ("enabled", "disabled"):
        cohort = value.get(cohort_name)
        if not isinstance(cohort, dict) or set(cohort) != cohort_fields \
                or not loom_improvement._valid_value(value["metric"], cohort.get("value")) \
                or not isinstance(cohort.get("memory_ids"), list) \
                or len(cohort["memory_ids"]) != len(set(cohort["memory_ids"])) \
                or not all(isinstance(item, str) for item in cohort["memory_ids"]):
            raise OrchestratorError(
                "HOST_OUTCOME_INVALID", "production replay cohort is invalid")
        memory_ids = set(cohort["memory_ids"])
        if cohort_name == "enabled":
            if not memory_ids or memory_ids != set(applied_memory_ids) \
                    or not memory_ids.issubset(selected):
                raise OrchestratorError(
                    "HOST_OUTCOME_INVALID",
                    "enabled replay cohort does not match applied sealed memory")
        elif memory_ids:
            raise OrchestratorError(
                "HOST_OUTCOME_INVALID", "disabled replay cohort contains memory")
        relative = cohort.get("outcome_evidence_path")
        digest = cohort.get("outcome_evidence_sha256")
        if not isinstance(relative, str) \
                or not re.fullmatch(r"evidence/[A-Za-z0-9][A-Za-z0-9._/-]{0,247}", relative) \
                or ".." in relative.split("/") \
                or not isinstance(digest, str) \
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise OrchestratorError(
                "HOST_OUTCOME_INVALID", "production replay evidence binding is invalid")
        evidence = pack / Path(*relative.split("/"))
        try:
            loom_memory._reject_link_ancestors(evidence, "production replay evidence")
            if evidence.is_symlink() or not evidence.is_file() \
                    or evidence.stat().st_size > 8 * 1024 * 1024 \
                    or hashlib.sha256(evidence.read_bytes()).hexdigest() != digest:
                raise OrchestratorError(
                    "HOST_OUTCOME_INVALID", "production replay evidence does not match")
        except (OSError, loom_memory.MemoryError) as exc:
            raise OrchestratorError("HOST_OUTCOME_INVALID", str(exc)) from exc
        receipt = cohort.get("provider_receipt")
        if not isinstance(receipt, dict) or set(receipt) != receipt_fields \
                or receipt.get("source") != "provider-response" \
                or any(not isinstance(receipt.get(field), str)
                       or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                                       receipt[field]) is None
                       for field in ("provider", "model", "response_id")) \
                or not isinstance(receipt.get("raw_response_sha256"), str) \
                or re.fullmatch(r"[0-9a-f]{64}", receipt["raw_response_sha256"]) is None:
            raise OrchestratorError(
                "HOST_OUTCOME_INVALID", "provider replay receipt is invalid")
        try:
            captured = loom_runtime._parse_time(receipt.get("captured_at"))
            usage = loom_performance.normalize_usage(receipt.get("usage"))
        except (loom_runtime.RuntimeError, loom_performance.PerformanceError) as exc:
            raise OrchestratorError("HOST_OUTCOME_INVALID", str(exc)) from exc
        if not created <= captured <= expires \
                or usage["measurement_status"] not in {
                    "provider-complete", "legacy-ambiguous"}:
            raise OrchestratorError(
                "HOST_OUTCOME_INVALID", "provider replay receipt is outside the action")
        normalized[cohort_name] = {
            **cohort,
            "value": float(cohort["value"]),
            "evidence_id": f"provider-{cohort_name}-" + _hash({
                "cohort": cohort_name, "replay_id": value["replay_id"],
                "receipt": receipt, "outcome_evidence_sha256": digest,
                "value": float(cohort["value"]),
            })[:32],
        }
    enabled_receipt = normalized["enabled"]["provider_receipt"]
    disabled_receipt = normalized["disabled"]["provider_receipt"]
    if enabled_receipt["provider"] != disabled_receipt["provider"] \
            or enabled_receipt["model"] != disabled_receipt["model"] \
            or enabled_receipt["response_id"] == disabled_receipt["response_id"] \
            or enabled_receipt["raw_response_sha256"] == \
            disabled_receipt["raw_response_sha256"] \
            or normalized["enabled"]["outcome_evidence_path"] == \
            normalized["disabled"]["outcome_evidence_path"] \
            or normalized["enabled"]["outcome_evidence_sha256"] == \
            normalized["disabled"]["outcome_evidence_sha256"]:
        raise OrchestratorError(
            "HOST_OUTCOME_INVALID", "production replay cohorts are not independent runs")
    return {**value, **normalized, "attestation_status": "local-receipts-only"}


def _record_production_replay(action, memory=None):
    replay = (action.get("host_result") or {}).get("replay_pair")
    if replay is None:
        return None
    if memory is not None and hasattr(memory, "record_replay"):
        record_ids = memory.record_replay(replay, action["project_id"])
    else:
        records = loom_improvement.ImprovementTracker(
            Path(action["owner_home"]), action["instance_id"]).record_replay_pair(
                metric=replay["metric"], domain=replay["domain"],
                replay_id=replay["replay_id"],
                enabled_value=replay["enabled"]["value"],
                disabled_value=replay["disabled"]["value"],
                project_id=action["project_id"],
                evidence_ids=[replay["enabled"]["evidence_id"],
                              replay["disabled"]["evidence_id"]],
                recorded_at=replay["enabled"]["provider_receipt"]["captured_at"])
        record_ids = [item["id"] for item in records]
    return {
        "status": "recorded", "replay_id": replay["replay_id"],
        "metric": replay["metric"], "domain": replay["domain"],
        "record_ids": record_ids,
        "source": "production-provider-response",
        "certification_status": "requires-independent-attestation",
    }


def _merge_host_outcome(result, host_result):
    if not host_result or "learning" not in host_result or result["status"] != "completed":
        return result
    merged = dict(result)
    learning = host_result["learning"]
    merged["metrics"] = dict(learning["metrics"])
    merged["evidence_ids"] = list(dict.fromkeys(
        list(result["evidence_ids"]) + list(learning["evidence_ids"])))
    for field in (
            "applied_memory_ids", "verified_memory_ids", "rejected_memory_ids",
            "preference_observations", "artifact_usage"):
        merged[field] = list(learning[field])
    return merged


def _restamp_verified_pack(pack, repo, verified_at, *, full):
    """Update only verification stamps after a successful sealed regate."""
    pack = Path(pack)
    state = loom_gate._state(repo, pack)
    manifest, rendered = loom_gate._render_manifest(pack, state, "planned")
    stamp = loom_runtime._parse_time(verified_at).date().isoformat()
    rendered = re.sub(
        r"(?m)^last_verified\s*:.*$", f"last_verified: {stamp}", rendered, count=1)
    updates = {manifest: rendered}
    if full:
        for path in pack.rglob("*.md"):
            if path == manifest or path.is_symlink() or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            close = text.find("\n---", 4) if text.startswith("---\n") else -1
            if close < 0 or not re.search(r"(?m)^last_verified\s*:.*$", text[:close]):
                continue
            updates[path] = re.sub(
                r"(?m)^last_verified\s*:.*$", f"last_verified: {stamp}", text, count=1)
    originals = {path: path.read_text(encoding="utf-8") for path in updates}
    try:
        for path, text in updates.items():
            loom_gate._atomic_write_text(path, text)
    except BaseException:
        for path, text in originals.items():
            loom_gate._atomic_write_text(path, text)
        raise
    return originals


def _active_work_order(pack, tier):
    pack = Path(pack)
    candidates = []
    paths = [pack / "WO-001.md"] if tier == "S" \
        else sorted((pack / "work-orders").glob("WO-*.md"))
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        frontmatter, _ = loom_lint.parse_frontmatter(path.read_text(encoding="utf-8"))
        if frontmatter and frontmatter.get("status") in {"ready", "in-progress"}:
            candidates.append((str(frontmatter.get("id", "")), path))
    if len(candidates) != 1 or not re.fullmatch(r"WO-[0-9]{3,}", candidates[0][0]):
        raise OrchestratorError(
            "WORK_ORDER_AMBIGUOUS",
            "execution requires exactly one ready or in-progress work order")
    work_order, path = candidates[0]
    return work_order, path.relative_to(pack).as_posix()


def _handler_result(context, root, owner_home, usage, work_order=None,
                    repair_plan=None, host_result=None, memory_adapter=None):
    pack = root / "plans"
    tier = context.prepared.route_contract["tier"]
    intent = context.intent
    logs = []
    if intent == "plan":
        if tier == "S":
            record, work_order = pack / ".loom-small-lifecycle.json", pack / "WO-001.md"
            findings = []
            try:
                data = json.loads(record.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                findings = [f"Tier-S lifecycle is unreadable: {exc}"]
            if not findings and [event.get("event") for event in data.get("events", [])] \
                    == ["small-planning-started"]:
                code, output = _capture(
                    loom_gate.small_authorize, record, root, work_order,
                    context.prepared.prepared_at)
                logs.append(output)
                if code:
                    findings = ["Tier-S authorization failed: " + output]
            findings = loom_gate.verify_small(record) if not findings else findings
        else:
            report = loom_lint.lint(
                pack, repo_path=root, enforce_lifecycle=False,
                check_repo_state=False)
            findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
            if not findings:
                lifecycle = json.loads((pack / loom_gate.LIFECYCLE_FILE).read_text(
                    encoding="utf-8"))
                events = [event["event"] for event in lifecycle["events"]]
                if events == ["planning-started"]:
                    review = pack / "reviews" / "G1-plan-review.md"
                    code, output = _capture(loom_gate.seal_g1, pack, root, review)
                    logs.append(output)
                    if not code:
                        code, output = _capture(loom_gate.authorize, pack, root)
                        logs.append(output)
                    if code:
                        findings = ["G1 sealing or authorization failed"]
                if not findings:
                    findings = loom_gate.verify(pack, root, require_authorized=True)
        if findings:
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": "plan-not-release-ready",
                "success": False, "metrics": {},
                "evidence_ids": [failure_evidence],
                "reversible_action_ids": [], "usage": usage,
                "user_message": "Plan validation blocked: " + "; ".join(findings[:8]),
            }
        evidence = "pack-" + _pack_hash(pack)[:24]
        return {
            "status": "completed", "code": "plan-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [], "usage": usage,
            "user_message": (
                "Release-ready plan validated and implementation authorized. "
                f"Lifecycle evidence: {evidence}."),
        }

    if intent == "execute":
        if not work_order:
            findings = ["execution action is not bound to one work order"]
        else:
            work_order_path = pack / work_order
            if tier == "S":
                code, output = _capture(
                    loom_gate.small_close,
                    pack / ".loom-small-lifecycle.json", root, work_order_path,
                    context.prepared.prepared_at)
            else:
                code, output = _capture(
                    loom_gate.close_wo, pack, root, work_order_path)
            logs.append(output)
            findings = (["work-order completion failed: " + output] if code else [])
        if not findings:
            findings.extend(
                loom_gate.verify_small(pack / ".loom-small-lifecycle.json")
                if tier == "S" else
                loom_gate.verify(pack, root, require_authorized=True))
        if findings:
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": "execute-not-ready", "success": False,
                "metrics": {}, "evidence_ids": [failure_evidence],
                "reversible_action_ids": [],
                "usage": usage,
                "user_message": "Execute blocked: " + "; ".join(findings[:8]),
            }
        evidence = "execute-" + _pack_hash(pack)[:24]
        return {
            "status": "completed", "code": "execute-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [], "usage": usage,
            "user_message": (
                "Execution completion was causally sealed against the declared "
                f"work order ({evidence})."),
        }

    if intent == "repair":
        if tier == "S":
            record, compact_wo = (
                pack / ".loom-small-lifecycle.json", pack / "WO-001.md")
            if repair_plan is None or host_result is None:
                raise OrchestratorError(
                    "REPAIR_EVIDENCE_REQUIRED", "sealed compact-plan evidence is missing")
            code, output = _capture(
                loom_gate.small_authorize, record, root, compact_wo,
                context.prepared.prepared_at)
            findings = (["Tier-S reauthorization failed: " + output] if code else [])
            if not findings:
                findings = loom_gate.verify_small(record)
            if findings:
                failure_evidence = "gate-" + _hash(findings)[:24]
                return {
                    "status": "blocked", "code": "small-repair-not-ready",
                    "success": False, "metrics": {},
                    "evidence_ids": [failure_evidence],
                    "reversible_action_ids": [], "usage": usage,
                    "user_message": "Compact-plan repair blocked: "
                    + "; ".join(findings[:8]),
                }
            evidence = "repair-" + _hash({
                "pack": _pack_hash(pack),
                "verification": host_result["repair_verification"],
            })[:24]
            return {
                "status": "completed", "code": "repair-complete", "success": True,
                "metrics": {"drift-caught-before-execution": 1},
                "evidence_ids": [evidence], "reversible_action_ids": [],
                "usage": usage,
                "user_message": (
                    "Compact plan revalidated and reauthorized against the current target "
                    f"({evidence})."),
            }
        if repair_plan is None or host_result is None:
            raise OrchestratorError(
                "REPAIR_EVIDENCE_REQUIRED", "sealed repair evidence is missing")
        by_section = {
            item["section"]: item for item in host_result["repair_verification"]}

        def verifier(section, _changed_paths):
            item = by_section[section]
            return {"passed": True, "medium": item["medium"],
                    "evidence_id": item["evidence_id"]}

        regate = pack / loom_lifecycle.REGATE_FILE
        regate_before = regate.read_bytes() if regate.is_file() else None
        originals = {}
        try:
            outcome = loom_lifecycle.reconcile(
                pack, root, verifier,
                now=loom_runtime._parse_time(context.prepared.prepared_at),
                force_full=repair_plan["force_full"],
                expected_plan={key: repair_plan[key] for key in (
                    "changed_paths", "affected_plan_sections", "regate_scope",
                    "prior_state_hash", "current_state_hash")})
            originals = _restamp_verified_pack(
                pack, root, context.prepared.prepared_at,
                full=repair_plan["force_full"])
            report = loom_lint.lint(pack, repo_path=root, strict_staleness=True)
            findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
            findings.extend(loom_gate.verify(pack, root, require_authorized=True))
            if findings:
                raise OrchestratorError("REPAIR_POSTCHECK_FAILED", "; ".join(findings[:8]))
        except BaseException:
            for path, text in originals.items():
                loom_gate._atomic_write_text(path, text)
            if regate_before is None:
                if regate.exists() and not regate.is_symlink():
                    regate.unlink()
            else:
                loom_lifecycle._atomic_json(regate, json.loads(regate_before))
            raise
        evidence = "repair-" + outcome["receipt_hash"][:24]
        return {
            "status": "completed", "code": "repair-complete", "success": True,
            "metrics": {"drift-caught-before-execution": 1},
            "evidence_ids": [evidence], "reversible_action_ids": [], "usage": usage,
            "user_message": (
                f"Repair sealed for {outcome['regate_scope']} scope ({evidence})."),
        }

    if intent in {"resume", "review", "close"}:
        report = loom_lint.lint(
            pack, repo_path=root, strict_staleness=intent in {"resume", "repair"})
        findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
        findings.extend(loom_gate.verify(
            pack, root, require_authorized=intent in {"resume", "repair", "execute"}))
        if intent == "close" and not findings:
            lifecycle = json.loads((pack / loom_gate.LIFECYCLE_FILE).read_text(
                encoding="utf-8"))
            work_orders = list((pack / "work-orders").glob("WO-*.md"))
            if len(lifecycle.get("work_order_completions", [])) != len(work_orders):
                findings.append("not every work order has a sealed completion")
        if findings:
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": f"{intent}-not-ready", "success": False,
                "metrics": {}, "evidence_ids": [failure_evidence],
                "reversible_action_ids": [],
                "usage": usage,
                "user_message": f"{intent.title()} blocked: " + "; ".join(findings[:8]),
            }
        evidence = f"{intent}-" + _pack_hash(pack)[:24]
        return {
            "status": "completed", "code": f"{intent}-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [], "usage": usage,
            "user_message": f"{intent.title()} validation completed ({evidence}).",
        }

    if intent == "remember":
        statement = re.sub(
            r"(?is)^.*?\bremember(?:\s+that)?\s+", "", context.request_text).strip()
        if not statement or len(statement) > 280:
            return {
                "status": "blocked", "code": "memory-statement-invalid",
                "success": False, "metrics": {}, "evidence_ids": [],
                "reversible_action_ids": [], "usage": usage,
                "user_message": "State one memory item of at most 280 characters.",
            }
        if memory_adapter is not None and hasattr(memory_adapter, "remember"):
            record = memory_adapter.remember(context, statement)
        else:
            record = loom_memory.add_record(
                owner_home, context.prepared.instance_id, scope="project",
                category="process", statement=statement, provenance="stated",
                evidence_count=1, domain=context.prepared.domains[0],
                project_id=context.project_id, confidence=1.0)
        return {
            "status": "completed", "code": "remember-complete", "success": True,
            "metrics": {}, "evidence_ids": ["memory-" + record["id"]],
            "reversible_action_ids": [], "usage": usage,
            "user_message": f"Remembered for this project as {record['id']}.",
        }
    return {
        "status": "blocked", "code": "intent-needs-no-host-action", "success": False,
        "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
        "usage": usage, "user_message": "Use the built-in transparency handler.",
    }


def default_handlers(*, root, owner_home, usage=None, work_order=None,
                     repair_plan=None, host_result=None, memory_adapter=None):
    """Return the complete audited production handler registry."""
    root, owner_home = Path(root), Path(owner_home)
    normalized = loom_performance.normalize_usage(usage)
    usage_payload = loom_performance.measured_usage_payload(normalized)
    return {
        intent: (lambda context, _intent=intent: _merge_host_outcome(
            _handler_result(context, root, owner_home, usage_payload, work_order,
                            repair_plan, host_result, memory_adapter), host_result))
        for intent in {
            "plan", "resume", "execute", "review", "repair", "close", "remember"
        }
    }


def _vault_helper(install_root):
    root = Path(install_root)
    names = ("loom-vault.exe", "loom-vault") if os.name == "nt" else ("loom-vault",)
    for name in names:
        candidate = root / "bin" / name
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def _disposable_test_legacy_backend_allowed(home):
    """Keep the legacy test adapter unavailable outside an explicit temp fixture."""
    if os.environ.get("LOOM_TEST_ALLOW_LEGACY_BACKEND") != "1":
        return False
    try:
        temporary = Path(tempfile.gettempdir()).resolve(strict=True)
        # Canonicalize both sides before containment. Hosted runners may expose the
        # same temporary directory through an OS alias (for example macOS /var and
        # /private/var) or a Windows short/redirected path. Comparing one canonical
        # path with one lexical path incorrectly disabled the explicitly marked
        # disposable test backend on those hosts.
        candidate = Path(os.path.abspath(os.fspath(home))).resolve(strict=True)
        candidate.relative_to(temporary)
        marker = candidate / TEST_LEGACY_BACKEND_MARKER
        return marker.is_file() and not marker.is_symlink() \
            and marker.read_bytes() == TEST_LEGACY_BACKEND_MARKER_BYTES \
            and not (candidate / "vault" / "owner.sqlite3").exists()
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _memory_backend(home, install_root, project_root=None):
    if _disposable_test_legacy_backend_allowed(home):
        instance_id = loom_memory.initialize(home, install_root)
        return instance_id, loom_session.LocalMemoryAdapter(
            owner_home=home, instance_id=instance_id)
    helper = _vault_helper(install_root)
    if helper is None:
        raise OrchestratorError(
            "OWNER_VAULT_BACKEND_UNAVAILABLE",
            "the verified owner-vault helper is unavailable; Loom refused to create a second "
            "legacy learning authority")
    opened = loom_owner.initialize_owner_vault(home, helper)
    adapter = loom_vault_adapter.VaultMemoryAdapter(
        owner_home=home, vault=opened["vault"], project_root=project_root)
    return adapter.instance_id, adapter


def _controller(action, *, usage=None):
    home = Path(action["owner_home"])
    root = Path(action["explicit_target"] or action["cwd"])
    instance_id, memory = _memory_backend(home, action["install_root"], root)
    if instance_id != action["instance_id"]:
        raise OrchestratorError(
            "OWNER_VAULT_CHANGED", "the action owner vault no longer matches the active vault")
    handlers = default_handlers(
        root=root, owner_home=home, usage=usage,
        work_order=action.get("work_order"),
        repair_plan=action.get("repair_plan"), host_result=action.get("host_result"),
        memory_adapter=memory)
    return loom_session.SessionController(
        owner_home=home, instance_id=instance_id,
        handlers=handlers, memory=memory)


def invoke(*, request, cwd, home, install_root, explicit_target=None,
           timeout_seconds=900, now=None, transport_invocation_id=None):
    if type(timeout_seconds) is not int or not 60 <= timeout_seconds <= 3600:
        raise OrchestratorError("INVALID_TIMEOUT", "timeout must be between 60 and 3600 seconds")
    if transport_invocation_id is not None:
        try:
            if str(uuid.UUID(transport_invocation_id)) != transport_invocation_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise OrchestratorError(
                "REQUEST_IDENTITY_INVALID",
                "transport invocation identity is not a canonical UUID") from exc
    cwd = _absolute(cwd, "cwd")
    home = _absolute(home, "owner home", must_exist=False)
    install_root = _absolute(install_root, "installation root")
    target = _absolute(explicit_target, "target") if explicit_target else cwd
    try:
        loom_install.check(install_root)
    except loom_install.InstallError as exc:
        raise OrchestratorError(
            "INSTALL_UNVERIFIED", f"installation receipt check failed: {exc}") from exc
    instance_id, memory = _memory_backend(home, install_root, target)
    try:
        project = loom_runtime.resolve_project(
            instance_id, explicit_target=target, cwd=cwd)
    except loom_runtime.RuntimeBlocked as exc:
        raise OrchestratorError(exc.code, exc.message) from exc
    directory = _orchestration_directory(home, instance_id, project.project_id)
    instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
    intent_decision = loom_runtime.resolve_intent(request)
    incoming_intent = (
        None if intent_decision["blocked"] else intent_decision["intent"])
    try:
        with loom_reliability.exclusive_file_lock(_orchestration_lock(directory)):
            recovery, reused_action = _reconcile_active_action(
                owner_home=home, install_root=install_root, instance_id=instance_id,
                project_id=project.project_id, now=instant,
                incoming_intent=incoming_intent, request=request, cwd=cwd,
                target=target, transport_invocation_id=transport_invocation_id)
            if reused_action is not None:
                result = _pending_action_result(reused_action)
            else:
                result = _invoke_under_lock(
                    request=request, cwd=cwd, home=home, install_root=install_root,
                    target=target, timeout_seconds=timeout_seconds, now=instant,
                    instance_id=instance_id, memory=memory,
                    transport_invocation_id=transport_invocation_id)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc
    if recovery is not None and isinstance(result, dict):
        result = {**result, "prior_recovery": recovery}
    return result


def _pending_action_result(action, *, resolved_terminal_block=None,
                           session_environment=None, work_order=None):
    """Return the bounded public frontier for a new or idempotently reused action."""
    if session_environment is None:
        session_environment = {
            "LOOM_SESSION_JOURNAL": action["journal_path"],
            "LOOM_SESSION_ID": action["session_id"],
            "LOOM_SESSION_OPERATION_ID": action["operation_id"],
            "LOOM_SESSION_DOMAIN": action["domains"][0],
        }
    if work_order is None and action["work_order"] is not None:
        work_order_path = (Path(action["explicit_target"]) / "plans" /
                           action["work_order"])
        try:
            frontmatter, _ = loom_lint.parse_frontmatter(
                work_order_path.read_text(encoding="utf-8"))
            work_order = frontmatter.get("id") if frontmatter else None
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT", "pending work-order identity is unreadable") from exc
        if not isinstance(work_order, str) \
                or not re.fullmatch(r"WO-[0-9]{3,}", work_order):
            raise OrchestratorError(
                "ACTION_CORRUPT", "pending work-order identity is invalid")
    return {
        "schema_version": SCHEMA_VERSION, "status": "action-required",
        "action_id": action["action_id"],
        "action_path": str(_action_path(
            action["owner_home"], action["instance_id"],
            action["project_id"], action["action_id"])),
        "intent": action["intent"], "tier": action["tier"],
        "domains": action["domains"], "expires_at": action["expires_at"],
        "work_order": work_order,
        "repair_plan": action["repair_plan"],
        "plan_contract": (_tier_s_host_capsule(action["plan_contract"])
                          if action["tier"] == "S" and action["plan_contract"] is not None
                          else action["plan_contract"]),
        "context_manifest": action["context_manifest"],
        "continuation_authority": action["continuation_authority"],
        "resolved_terminal_block": resolved_terminal_block,
        "owner_message": action["owner_message"],
        "context": {
            "memory": action["context"]["memory"],
            "preferences": action["context"]["preferences"],
        },
        "attempts_remaining": action["max_attempts"] - action["attempts"],
        "session_environment": session_environment,
        "required_outcome": (
            "The sealed plan_contract and bounded context capsule are complete; do not reload "
            "static Loom guidance. For plan, author the exact plan_contract; otherwise perform "
            "only the routed intent. Do not mutate undeclared target paths. Then call complete "
            "with all five measured token categories. The orchestrator owns validation, gates, "
            "learning, and the final receipt. A prior terminal block never authorizes fallback "
            "work; only this fresh sealed action can authorize its declared frontier."),
    }


def _invoke_under_lock(*, request, cwd, home, install_root, target,
                       timeout_seconds, now, instance_id, memory,
                       transport_invocation_id=None):
    action_security = ((memory.vault.crypto, instance_id)
                       if isinstance(memory, loom_vault_adapter.VaultMemoryAdapter) else None)
    invocation_id = transport_invocation_id or str(uuid.uuid4())
    controller = loom_session.SessionController(
        owner_home=home, instance_id=instance_id, handlers={},
        memory=memory)
    opened = controller.open(
        request, invocation_id=invocation_id, cwd=cwd,
        explicit_target=target, now=now)
    if opened.terminal_receipt is not None:
        return opened.terminal_receipt.to_dict()
    prepared = opened.prepared
    conflict_selector = getattr(memory, "relevant_preference_conflicts", None)
    conflicts = (conflict_selector(
        domains=prepared.domains, project_id=prepared.project_id)
        if conflict_selector is not None else [])
    if conflicts:
        keys = sorted({item["preference_key"] for item in conflicts})
        controller.handlers[prepared.intent] = lambda _context: {
            "status": "blocked", "code": "preference-conflict",
            "success": False, "metrics": {}, "evidence_ids": [],
            "reversible_action_ids": [],
            "user_message": (
                "One owner choice is required for: " + ", ".join(keys))}
        return controller.run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared).to_dict()
    context_capsule = controller.prepare_context(opened, request)
    created_at = _stamp(now)
    expires_at = _stamp(
        loom_runtime._parse_time(created_at) + dt.timedelta(seconds=timeout_seconds))
    action_id = invocation_id
    path = _action_path(home, instance_id, prepared.project_id, action_id)
    pack_present_at_start = _path_present(target / "plans")
    action = {
        "schema_version": ACTION_SCHEMA_VERSION, "action_id": action_id,
        "status": "initializing" if prepared.intent == "plan" else "pending",
        "instance_id": instance_id,
        "project_id": prepared.project_id, "request": request,
        "invocation_id": invocation_id, "owner_home": str(home),
        "install_root": str(install_root), "cwd": str(cwd),
        "explicit_target": str(target), "intent": prepared.intent,
        "tier": prepared.route_contract["tier"],
        "domains": list(prepared.domains), "survey_hash": prepared.survey_hash,
        "created_at": created_at, "expires_at": expires_at,
        "attempts": 0, "max_attempts": 3, "session_id": opened.session_id,
        "operation_id": opened.operation_id, "journal_path": opened.journal_path,
        "initial_pack_hash": None, "remove_pristine_pack": False,
        "work_order": None, "prepared": prepared.to_dict(),
        "context": context_capsule,
        "repair_plan": None, "host_result": None, "plan_contract": None,
        "domain_contract": loom_domain.select_domains(
            request, explicit=list(prepared.domains),
            project_facts=loom_project_inspection.facts(
                loom_runtime._thaw(prepared.project_inspection)),
            project_inspection=loom_runtime._thaw(prepared.project_inspection)
        )["domain_contract"],
        "context_manifest": loom_performance.production_context_manifest(install_root),
        "continuation_authority": loom_authority.decide(
            loom_authority.facts_for_intent(prepared.intent),
            owner_authorized=prepared.intent in {
                "execute", "close", "remember", "forget", "undo"}),
        "owner_message": loom_message.build(
            state="progress",
            consequence={"S": "ordinary", "M": "material", "L": "high",
                         "XL": "critical"}[prepared.route_contract["tier"]],
            verification="pending", freshness="current",
            changes_made=False, undo_status="not-applicable",
            summary="Loom prepared the next safe frontier.",
            next_action="Complete and verify the sealed frontier.",
            receipt_id="action-" + action_id),
        "result": None,
        "pack_seed": ({
            "state": "recorded",
            "created_pack": not pack_present_at_start,
            "kind": "small" if prepared.route_contract["tier"] == "S" else "planned",
            "manifest": None,
            "activation_atomic_rename": None,
        } if prepared.intent == "plan" else {
            "state": "not-applicable", "created_pack": False,
            "kind": None, "manifest": None, "activation_atomic_rename": None,
        }),
        "recovery_receipt": None,
    }
    if prepared.route_contract["blocked"]:
        receipt = controller.run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared, selected_context=context_capsule)
        action["status"], action["result"] = "completed", receipt.to_dict()
        _write_action(path, action, action_security)
        return receipt.to_dict()
    if prepared.intent in {"status", "why", "undo", "forget", "remember"}:
        immediate = _controller(action).run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared, selected_context=context_capsule)
        action["status"], action["result"] = "completed", immediate.to_dict()
        _write_action(path, action, action_security)
        return immediate.to_dict()
    if prepared.intent == "plan":
        pack = target / "plans"
        if not action["pack_seed"]["created_pack"]:
            raise OrchestratorError(
                "PLAN_PACK_EXISTS",
                "a planning pack already exists; use resume or repair instead of mutating it")
        directory = path.parent
        action = _write_action(path, action, action_security)
        _write_active_pointer(
            directory, action_id=action_id, project_id=prepared.project_id)
        stage, manifest, stage_identity = _seed_stage(path, action, prepared)
        action["pack_seed"] = {**action["pack_seed"], "state": "prepared",
                               "manifest": manifest}
        action = _write_action(path, action, action_security)
        try:
            activation_state = _copy_seed_stage(
                stage, pack, manifest, stage_identity)
        except loom_reliability.AtomicRenameReconciliationRequired as exc:
            action["pack_seed"] = {
                **action["pack_seed"],
                "activation_atomic_rename": exc.state,
            }
            _write_action(path, action, action_security)
            raise OrchestratorError(
                "DURABILITY_INDETERMINATE",
                "planning-pack activation changed the namespace but requires reconciliation") \
                from exc
        action["initial_pack_hash"] = _pack_hash(pack)
        action["remove_pristine_pack"] = True
        action["pack_seed"] = {
            **action["pack_seed"], "state": "installed",
            "activation_atomic_rename": activation_state,
        }
        action["plan_contract"] = _make_plan_contract(action, prepared)
        action["status"] = "pending"
        action = _write_action(path, action, action_security)
    elif prepared.intent == "execute":
        work_order_id, work_order_path = _active_work_order(
            target / "plans", action["tier"])
        if action["tier"] == "S":
            findings = loom_gate.verify_small(
                target / "plans" / ".loom-small-lifecycle.json")
        else:
            report = loom_lint.lint(
                target / "plans", repo_path=target, strict_staleness=True)
            findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
            findings.extend(loom_gate.verify(
                target / "plans", target, require_authorized=True))
        if findings:
            raise OrchestratorError(
                "EXECUTION_NOT_READY", "; ".join(findings[:8]))
        action["work_order"] = work_order_path
    elif prepared.intent == "repair":
        if action["tier"] == "S":
            record = target / "plans" / ".loom-small-lifecycle.json"
            work_order = target / "plans" / "WO-001.md"
            before = json.loads(record.read_text(encoding="utf-8"))
            reason = ("freshness-expired"
                      if "elapsed-time-drift" in prepared.route_contract["evidence"]
                      else "target-drifted")
            code, output = _capture(
                loom_gate.small_rebaseline, record, target, work_order,
                reason=reason, event_at=prepared.prepared_at)
            if code:
                raise OrchestratorError("SMALL_REBASELINE_FAILED", output)
            after = json.loads(record.read_text(encoding="utf-8"))
            action["repair_plan"] = {
                "force_full": True,
                "changed_paths": [],
                "affected_plan_sections": ["compact-plan"],
                "regate_scope": "compact",
                "prior_state_hash": before["events"][-1]["repo_state_hash"],
                "current_state_hash": after["events"][0]["repo_state_hash"],
                "lifecycle_sha256": hashlib.sha256(record.read_bytes()).hexdigest(),
            }
        else:
            force_full = _repair_force_full(
                target / "plans", loom_runtime._parse_time(created_at))
            preview = loom_lifecycle.preview_regate(
                target / "plans", target, force_full=force_full)
            if preview["regate_scope"] == "none":
                raise OrchestratorError(
                    "REPAIR_SCOPE_INDETERMINATE",
                    "repair route has no verifiable affected scope")
            program_impact = _program_impact(
                target / "plans", preview["changed_paths"], force_full=force_full)
            action["repair_plan"] = {
                **preview, "force_full": force_full, "program_impact": program_impact}
    if prepared.intent != "plan":
        action["initial_pack_hash"] = _pack_hash(Path(target) / "plans")
    action = _write_action(path, action, action_security)
    if prepared.intent != "plan":
        _write_active_pointer(
            path.parent, action_id=action_id, project_id=prepared.project_id)
    return _pending_action_result(
        action,
        resolved_terminal_block=loom_runtime._thaw(opened.resolved_terminal_block),
        session_environment=opened.environment(),
        work_order=work_order_id if prepared.intent == "execute" else None)


def _reopen(action, *, controller=None):
    controller = controller or _controller(action)
    sealed = loom_runtime.PreparedInvocation.from_dict(action["prepared"])
    try:
        opened = controller.reopen_sealed(
            sealed, session_id=action["session_id"],
            operation_id=action["operation_id"], journal_path=action["journal_path"])
    except loom_session.SessionBlocked as exc:
        raise OrchestratorError("ACTION_IDENTITY_CHANGED", str(exc)) from exc
    return controller, opened


def complete(action_path, usage_path=None, *, result_path=None, now=None,
             owner_home=None, install_root=None):
    action_path = _absolute(action_path, "action")
    try:
        with loom_reliability.exclusive_file_lock(
                _orchestration_lock(action_path.parent)):
            return _complete_under_lock(
                action_path, usage_path, result_path=result_path, now=now,
                owner_home=owner_home, install_root=install_root)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc


def _complete_under_lock(action_path, usage_path=None, *, result_path=None, now=None,
                         owner_home=None, install_root=None):
    path, action, action_security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    try:
        checked = loom_install.check(action["install_root"])
    except loom_install.InstallError as exc:
        raise OrchestratorError("INSTALL_CHANGED", str(exc)) from exc
    helper = _vault_helper(action["install_root"])
    if helper is None:
        marker = Path(action["install_root"]) / loom_install.INSTANCE_MARKER
        identity_valid = marker.read_text(encoding="utf-8").strip() == action["instance_id"]
    else:
        vault, _crypto = loom_owner.open_owner_vault(action["owner_home"], helper)
        identity_valid = vault.identity()["owner_vault_id"] == action["instance_id"]
    if not identity_valid or checked["status"] != "installed":
        raise OrchestratorError("INSTALL_CHANGED", "installation identity changed")
    if action["status"] != "pending":
        raise OrchestratorError(
            "ACTION_TERMINAL", f"action is already {action['status']}",
            status=action["status"])
    instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
    if instant > loom_runtime._parse_time(action["expires_at"]):
        controller, opened = _reopen(action)
        controller.interrupt(opened, code="orchestration-timeout", now=instant)
        if action["intent"] == "plan" and action["pack_seed"]["created_pack"]:
            _recover_plan_action(
                path, action, action_security, now=instant, requested_reason="expired")
        else:
            action["status"] = "expired"
            _write_action(path, action, action_security)
            _clear_active_pointer(path.parent, action["action_id"])
        raise OrchestratorError("ACTION_TIMEOUT", "action deadline expired", status="expired")
    if usage_path is None:
        usage = None
        normalized = loom_performance.normalize_usage(None)
    else:
        try:
            usage = json.loads(_absolute(usage_path, "usage").read_text(encoding="utf-8"))
            normalized = loom_performance.normalize_usage(usage)
        except (OSError, UnicodeError, json.JSONDecodeError,
                loom_performance.PerformanceError) as exc:
            raise OrchestratorError("USAGE_INVALID", str(exc)) from exc
        if normalized["measurement_status"] == "invalid":
            raise OrchestratorError("USAGE_INVALID", normalized["normalization_reason"])
    if action["intent"] == "repair":
        action["host_result"] = _read_repair_result(result_path, action)
    elif result_path is not None:
        action["host_result"] = _read_host_outcome(result_path, action)
    sealed = loom_runtime.PreparedInvocation.from_dict(action["prepared"])
    if action["intent"] == "repair" and action["tier"] == "S":
        project = loom_runtime.resolve_project(
            action["instance_id"], explicit_target=action["explicit_target"],
            cwd=action["cwd"])
        root = Path(action["explicit_target"] or action["cwd"])
        pack = root / "plans"
        record = pack / ".loom-small-lifecycle.json"
        try:
            state = loom_gate._stable_state(root, pack)
            lifecycle_hash = hashlib.sha256(record.read_bytes()).hexdigest()
            lifecycle_findings = loom_gate.verify_small(record)
            lifecycle = json.loads(record.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError,
                loom_survey.SurveyError) as exc:
            raise OrchestratorError(
                "TARGET_DRIFT", f"compact rebaseline cannot be verified: {exc}") from exc
        if project.project_id != action["project_id"] \
                or project.canonical_target_identity != sealed.canonical_target_identity \
                or state.state_hash != action["repair_plan"]["current_state_hash"] \
                or lifecycle_hash != action["repair_plan"]["lifecycle_sha256"] \
                or lifecycle_findings \
                or [event.get("event") for event in lifecycle.get("events", [])] != \
                ["small-planning-started"]:
            raise OrchestratorError(
                "TARGET_DRIFT",
                "target or compact rebaseline changed during delegated review")
    elif action["intent"] == "execute":
        project = loom_runtime.resolve_project(
            action["instance_id"], explicit_target=action["explicit_target"],
            cwd=action["cwd"])
        if project.project_id != action["project_id"] \
                or project.canonical_target_identity != sealed.canonical_target_identity:
            raise OrchestratorError(
                "TARGET_DRIFT", "delegated target identity changed")
    else:
        current = loom_runtime.prepare_invocation(
            action["request"], instance_id=action["instance_id"],
            invocation_id=action["invocation_id"], cwd=action["cwd"],
            explicit_target=action["explicit_target"], owner_home=action["owner_home"],
            now=instant)
        if current.survey_hash != action["survey_hash"] \
                or current.project_id != action["project_id"] \
                or current.intent != action["intent"]:
            raise OrchestratorError(
                "TARGET_DRIFT",
                "target, project, or routed intent changed during delegated work")
        if action["intent"] == "plan" and not current.project_inspection[
                "g1_eligible"]:
            unresolved = [item["path"] for item in
                          current.project_inspection["unresolved_roots"]]
            raise OrchestratorError(
                "PROJECT_INSPECTION_INCOMPLETE",
                "G1 remains blocked until relevant project coverage is complete: "
                + ", ".join(unresolved[:8]), status="action-required")
    validated_domain_bundle = None
    if action["intent"] == "plan":
        validated_domain_bundle = _validate_authored_plan(action)
    controller = _controller(action, usage=usage)
    try:
        controller, opened = _reopen(action, controller=controller)
        receipt = controller.seal(
            opened, action["request"], now=instant,
            selected_context=action["context"])
    except loom_session.SessionInterrupted as exc:
        action["attempts"] += 1
        if action["attempts"] >= action["max_attempts"]:
            action["status"] = "failed"
        _write_action(path, action, action_security)
        if action["status"] == "failed":
            _clear_active_pointer(path.parent, action["action_id"])
        raise OrchestratorError(
            "HANDLER_INTERRUPTED", str(exc), status=action["status"]) from exc
    result = receipt.to_dict()
    if result.get("status") == "completed":
        stored_domain_records = _store_domain_bundle(
            controller.memory, validated_domain_bundle)
        if stored_domain_records:
            result["domain_learning"] = {
                "bundle_digest": validated_domain_bundle["bundle_digest"],
                "stored_records": len(stored_domain_records),
            }
    production_replay = _record_production_replay(action, controller.memory)
    if production_replay is not None:
        result["production_replay"] = production_replay
    action["status"], action["result"] = "completed", result
    _write_action(path, action, action_security)
    _clear_active_pointer(path.parent, action["action_id"])
    return result


def cancel(action_path, *, now=None, owner_home=None, install_root=None):
    action_path = _absolute(action_path, "action")
    try:
        with loom_reliability.exclusive_file_lock(
                _orchestration_lock(action_path.parent)):
            return _cancel_under_lock(
                action_path, now=now, owner_home=owner_home,
                install_root=install_root)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc


def _cancel_under_lock(action_path, *, now=None, owner_home=None, install_root=None):
    path, action, action_security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    try:
        loom_install.check(action["install_root"])
    except loom_install.InstallError as exc:
        raise OrchestratorError("INSTALL_CHANGED", str(exc)) from exc
    if action["status"] not in {"initializing", "pending"}:
        raise OrchestratorError(
            "ACTION_TERMINAL", f"action is already {action['status']}",
            status=action["status"])
    if action["status"] == "pending":
        controller, opened = _reopen(action)
        controller.interrupt(opened, code="owner-cancelled", now=now)
    instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
    if action["intent"] == "plan" and action["pack_seed"]["created_pack"]:
        receipt = _recover_plan_action(
            path, action, action_security, now=instant, requested_reason="cancelled")
    else:
        action["status"] = "cancelled"
        _write_action(path, action, action_security)
        _clear_active_pointer(path.parent, action["action_id"])
        receipt = None
    return {"status": "cancelled", "action_id": action["action_id"],
            "session_id": action["session_id"], "recovery_receipt": receipt}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    invoke_parser = commands.add_parser("invoke-stdio")
    invoke_parser.add_argument("--home", required=True)
    invoke_parser.add_argument("--install-root", required=True)
    invoke_parser.add_argument("--target")
    invoke_parser.add_argument("--timeout-seconds", type=int, default=900)
    complete_parser = commands.add_parser("complete")
    complete_parser.add_argument("--action", required=True)
    complete_parser.add_argument("--usage")
    complete_parser.add_argument("--result")
    complete_parser.add_argument("--home")
    complete_parser.add_argument("--install-root")
    cancel_parser = commands.add_parser("cancel")
    cancel_parser.add_argument("--action", required=True)
    cancel_parser.add_argument("--home")
    cancel_parser.add_argument("--install-root")
    args = parser.parse_args(argv)
    try:
        if args.command == "invoke-stdio":
            envelope = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type="request-envelope")
            result = invoke(
                request=envelope["request"], cwd=envelope["cwd"], home=args.home,
                install_root=args.install_root, explicit_target=args.target,
                timeout_seconds=args.timeout_seconds,
                transport_invocation_id=_transport_invocation_id(envelope))
        elif args.command == "complete":
            result = complete(
                args.action, args.usage, result_path=args.result,
                owner_home=args.home, install_root=args.install_root)
        else:
            result = cancel(
                args.action, owner_home=args.home, install_root=args.install_root)
    except OrchestratorError as exc:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": exc.status,
            "code": exc.code, "error": exc.message,
        }, sort_keys=True))
        return 2
    except loom_adapter_protocol.ProtocolError as exc:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": "blocked",
            "code": exc.code, "error": str(exc),
        }, sort_keys=True))
        return 2
    except (loom_memory.MemoryError, loom_crypto.CryptoError, loom_owner.OwnerError,
            loom_vault_adapter.VaultAdapterError, loom_runtime.RuntimeError,
            loom_session.SessionError, loom_install.InstallError) as exc:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": "blocked",
            "code": "RUNTIME_BLOCKED", "error": str(exc),
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
