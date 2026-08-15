#!/usr/bin/env python3
"""Production bridge from one `/loom` request to gated host-agent work and a receipt."""

import sys
sys.dont_write_bytecode = True

import argparse
import base64
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
from pathlib import Path, PurePosixPath

import loom_gate
import loom_authority
import loom_block_reason
import loom_crypto
import loom_domain
import loom_domain_bundle
import loom_domain_contract
import loom_domain_discovery
import loom_domain_invariants
import loom_planning_intelligence
import loom_program
import loom_domain_learning
import loom_install
import loom_improvement
import loom_lifecycle
import loom_lifecycle_kernel
import loom_lifecycle_transition
import loom_lint
import loom_adapter_protocol
import loom_contract_rebase
import loom_memory
import loom_message
import loom_owner
import loom_plan_author
import loom_plan_presentation
import loom_plan_store
import loom_privacy
import loom_proofline
import loom_proofline_completion
import loom_proofline_ux
import loom_verification_recipe


TEST_LEGACY_BACKEND_MARKER = ".loom-test-legacy-backend-v1"
TEST_LEGACY_BACKEND_MARKER_BYTES = b"loom-disposable-test-backend-v1\n"
import loom_performance
import loom_preferences
import loom_project_inspection
import loom_reliability
import loom_runtime
import loom_session
import loom_survey
import loom_transparency
import loom_vault_adapter
import loom_execution_chain


SCHEMA_VERSION = 1
MAX_PLAN_REVISION_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_PLAN_REVISION_FILES = 512
MAX_PLAN_GENERATION_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_PLAN_GENERATION_FILES = 512
ACTION_SCHEMA_VERSION = 11
PREVIOUS_ACTION_SCHEMA_VERSION = 10
LEGACY_ACTION_SCHEMA_VERSION = 6
INTERMEDIATE_ACTION_SCHEMA_VERSION = 7
PRIOR_ACTION_SCHEMA_VERSION = 8
OWNER_MESSAGE_ACTION_SCHEMA_VERSION = 9
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
ACTION_FIELDS_V8 = ACTION_FIELDS_V7 | {"pack_seed", "recovery_receipt"}
ACTION_FIELDS_V10 = ACTION_FIELDS_V8 | {"assurance"}
ACTION_FIELDS = ACTION_FIELDS_V10 | {
    "generation_id", "request_control", "lifecycle_transition",
}
ACTION_STATUSES = {
    "initializing", "pending", "completed", "cancelled", "expired", "failed",
    "abandoned", "superseded",
}
TERMINAL_ACTION_STATUSES = ACTION_STATUSES - {"initializing", "pending"}
PACK_SEED_STATES = {"not-applicable", "recorded", "prepared", "installed", "recovered"}
NONINTERFERING_ACTIVE_ACTION_INTENTS = {
    "status", "why", "remember", "forget", "undo",
}
MAX_ORCHESTRATION_ACTIONS = 256
MAX_ORCHESTRATION_DIRECTORY_ENTRIES = 512
ACTIVE_POINTER_FILE = "active-action.json"
RECOVERY_DIRECTORY = "planning-recovery"
MAX_RECOVERY_FILES = 8
MAX_RECOVERY_FILE_BYTES = 256 * 1024
MAX_RECOVERY_TOTAL_BYTES = MAX_RECOVERY_FILES * MAX_RECOVERY_FILE_BYTES
MAX_ACTION_BYTES = 256 * 1024
MAX_ENCRYPTED_ACTION_BYTES = 384 * 1024
MAX_LIFECYCLE_PRIVATE_PROJECTION_BYTES = 1024 * 1024
LEGACY_PLAN_CONTRACT_SCHEMA_VERSION = 4
PLAN_CONTRACT_SCHEMA_VERSION = 5
LEGACY_PLAN_CONTRACT_FIELDS_V4 = {
    "schema_version", "request_hash", "survey_hash", "tier", "domains",
    "domain_route", "route_digest", "composition_graph_digest",
    "target_fingerprint", "project_inspection", "inspection_obligations",
    "pack_baseline_hash", "pack_root", "allowed_host_write_paths",
    "artifact_matrix", "required_domain_invariants", "domain_invariants",
    "domain_discovery", "planning_intelligence", "current_facts_to_verify",
    "verification_media", "budget", "work_order_topology",
    "completion_gates", "contract_hash",
}
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


def _action_consequence(action, *, use_domain_contract):
    if use_domain_contract:
        value = action.get("domain_contract", {}).get("consequence", {}).get("class")
        if value in {"ordinary", "material", "high", "critical"}:
            return value
    return {"S": "ordinary", "M": "material", "L": "high",
            "XL": "critical"}[action["tier"]]


def _domain_authority_facts(intent, domain_contract):
    consequence = domain_contract.get("consequence", {})
    categories = consequence.get("categories", [])
    subject_consequence = consequence.get("class")
    if subject_consequence not in {"ordinary", "material", "high", "critical"}:
        raise OrchestratorError(
            "DOMAIN_CONTRACT_INVALID", "domain consequence is unavailable")
    legal_or_safety = bool(set(categories) & {
        "human-safety", "physical-safety", "regulated-or-financial"})
    return loom_authority.facts_for_intent(
        intent, consequence=subject_consequence,
        legal_or_safety_judgment=legal_or_safety)


def _transport_invocation_id(envelope):
    """Bind duplicate delivery to one protocol operation without storing host text."""
    identity = _hash({
        "protocol": "adapter-request-envelope-v2",
        "request_id": envelope["request_id"],
        "request_identity": envelope["request_identity"],
        "cwd": envelope["cwd"],
        "host": envelope["host"],
        "assurance": envelope["assurance"],
    })
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "loom-transport:" + identity))


def _stamp(value=None):
    instant = loom_runtime._parse_time(value or dt.datetime.now(dt.timezone.utc))
    return loom_runtime._format_time(instant)


def _action_hash(value):
    body = dict(value)
    body.pop("action_hash", None)
    return _hash(body)


def _legacy_assurance(request):
    raw = request.encode("utf-8")
    return {
        "mode": "legacy-unclassified", "ingress": "legacy-v1",
        "request_identity_scope": "legacy-unknown",
        "request_utf8_bytes": len(raw),
        "request_sha256": hashlib.sha256(raw).hexdigest(),
        "host_id": "legacy", "host_version": "unclassified",
        "capability_receipt_sha256": "0" * 64,
        "lifecycle_capabilities": {
            "session_start": False, "pre_tool_guard": False,
            "post_tool_freshness": False, "compaction_resume": False,
            "automatic_learning": False, "subagent_propagation": False,
        },
    }


def _default_assurance(request):
    raw = request.encode("utf-8")
    capabilities = {
        "session_start": False, "pre_tool_guard": False,
        "post_tool_freshness": False, "compaction_resume": False,
        "automatic_learning": False, "subagent_propagation": False,
    }
    body = {"host_id": "direct-python", "host_version": "unattested",
            "lifecycle_capabilities": capabilities}
    return {
        "mode": "standard", "ingress": "codex-local-tool-v1",
        "request_identity_scope": "tool-argument",
        "request_utf8_bytes": len(raw),
        "request_sha256": hashlib.sha256(raw).hexdigest(),
        "host_id": "direct-python", "host_version": "unattested",
        "capability_receipt_sha256": _hash(body),
        "lifecycle_capabilities": capabilities,
    }


def _validate_assurance(value, request, *, allow_legacy=True):
    fields = {
        "mode", "ingress", "request_identity_scope", "request_utf8_bytes",
        "request_sha256", "host_id", "host_version",
        "capability_receipt_sha256", "lifecycle_capabilities",
    }
    lifecycle_fields = {
        "session_start", "pre_tool_guard", "post_tool_freshness",
        "compaction_resume", "automatic_learning", "subagent_propagation",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or not isinstance(value.get("lifecycle_capabilities"), dict) \
            or set(value["lifecycle_capabilities"]) != lifecycle_fields \
            or any(type(item) is not bool
                   for item in value["lifecycle_capabilities"].values()):
        raise OrchestratorError("ACTION_CORRUPT", "action assurance fields are invalid")
    mode = value["mode"]
    expected = {
        "standard": ("codex-local-tool-v1", "tool-argument"),
        "verified": ("codex-user-prompt-hook-v2", "host-prompt"),
        "legacy-unclassified": ("legacy-v1", "legacy-unknown"),
    }
    if mode not in expected or (mode == "legacy-unclassified" and not allow_legacy) \
            or (value["ingress"], value["request_identity_scope"]) != expected[mode]:
        raise OrchestratorError("ACTION_CORRUPT", "action assurance identity is invalid")
    raw = request.encode("utf-8")
    if value["request_utf8_bytes"] != len(raw) \
            or value["request_sha256"] != hashlib.sha256(raw).hexdigest() \
            or not isinstance(value["host_id"], str) or not value["host_id"] \
            or not isinstance(value["host_version"], str) or not value["host_version"] \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value["capability_receipt_sha256"])):
        raise OrchestratorError("ACTION_CORRUPT", "action assurance digest is invalid")
    return value


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


def _validate_action_path_authority(path, owner_home):
    """Reject non-owner action paths before any caller-selected file is accessed."""
    path = _absolute(path, "action", must_exist=False)
    owner_home = _absolute(owner_home, "owner home", must_exist=False)
    try:
        relative = path.relative_to(owner_home)
    except ValueError as exc:
        raise OrchestratorError(
            "ACTION_PATH_MISMATCH", "action path is not owner-scoped") from exc
    parts = relative.parts
    if len(parts) != 7 or parts[0] != "instances" or parts[2] != "runtime" \
            or parts[3] != "projects" or parts[5] != "orchestrations" \
            or not loom_runtime.PROJECT_RE.fullmatch(parts[4]) \
            or not re.fullmatch(r"[0-9a-f-]{36}\.json", parts[6]):
        raise OrchestratorError(
            "ACTION_PATH_MISMATCH", "action path is not owner-project scoped")
    try:
        if str(uuid.UUID(parts[1])) != parts[1] \
                or str(uuid.UUID(parts[6][:-5])) != parts[6][:-5]:
            raise ValueError
    except (TypeError, ValueError, AttributeError) as exc:
        raise OrchestratorError(
            "ACTION_PATH_MISMATCH", "action path identity is malformed") from exc
    return path


def _plan_author_transaction_path(action):
    root = Path(action["explicit_target"] or action["cwd"]).resolve()
    return root / f".loom-plan-transaction-{action['action_id']}.json"


def _reconcile_plan_authoring(action):
    if action["intent"] != "plan" or not action["pack_seed"]["created_pack"]:
        return {"status": "clean"}
    transaction_path = _plan_author_transaction_path(action)
    if not os.path.lexists(transaction_path):
        return {"status": "clean"}
    try:
        return loom_plan_author.reconcile(
            _action_pack_root(action), transaction_path)
    except loom_plan_author.PlanAuthorError as exc:
        raise OrchestratorError(
            exc.code, exc.message, status="action-required") from exc


def _validate_plan_author_record(value, *, action):
    if value is None:
        return None
    fields = {
        "schema_version", "action_id", "state", "manifest",
        "archive_path", "completed_at", "undone_at",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("action_id") != action.get("action_id") \
            or value.get("state") not in {"active", "undone"}:
        raise OrchestratorError(
            "ACTION_CORRUPT", "plan-author reversibility record is invalid")
    try:
        loom_reliability.validate_exact_tree_manifest(value["manifest"])
        loom_runtime._parse_time(value["completed_at"])
    except (loom_reliability.ReliabilityError, loom_runtime.RuntimeError,
            TypeError, ValueError) as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", "plan-author reversibility evidence is invalid") from exc
    expected_archive = f".loom-history/undone-plan-{action['action_id']}"
    if value["state"] == "active":
        if value["archive_path"] is not None or value["undone_at"] is not None:
            raise OrchestratorError(
                "ACTION_CORRUPT", "active plan-author record carries undo state")
    else:
        try:
            loom_runtime._parse_time(value["undone_at"])
        except (loom_runtime.RuntimeError, TypeError, ValueError) as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT", "plan-author undo time is invalid") from exc
        if value["archive_path"] != expected_archive:
            raise OrchestratorError(
                "ACTION_CORRUPT", "plan-author archive path is not action-bound")
    return value


def _validate_plan_review_record(value, *, action):
    fields = {"schema_version", "state", "revision", "semantics"}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("state") not in {"authored", "completed"} \
            or type(value.get("revision")) is not int \
            or not 1 <= value["revision"] <= 1_000_000:
        raise OrchestratorError(
            "ACTION_CORRUPT", "plan-review state is invalid")
    if action.get("intent") != "plan":
        raise OrchestratorError(
            "ACTION_CORRUPT", "non-planning action carries plan-review state")
    try:
        loom_plan_presentation.validate_semantics(value["semantics"])
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", f"plan-review semantics are invalid: {exc}") from exc
    return value


def _validate_plan_decision_record(value):
    fields_v1 = {
        "schema_version", "presentation_sha256", "plan_action_id",
        "project_id", "revision", "pack_sha256",
    }
    fields_v2 = fields_v1 | {
        "generation_id", "active_index_sha256", "plan_semantics_sha256",
        "execution_sequence_sha256", "reviewed_world_sha256",
        "reviewed_world_observation_sha256",
    }
    fields_v3 = fields_v1 | {
        "generation_id", "plan_semantics_sha256",
        "execution_sequence_sha256", "reviewed_world_sha256",
        "reviewed_world_observation_sha256", "source_lifecycle_name",
        "source_lifecycle_sha256",
    }
    version = value.get("schema_version") if isinstance(value, dict) else None
    expected = fields_v2 if version == 2 else fields_v3 if version == 3 else fields_v1
    if not isinstance(value, dict) or set(value) != expected \
            or version not in {1, 2, 3} \
            or not isinstance(value.get("presentation_sha256"), str) \
            or re.fullmatch(r"[0-9a-f]{64}", value["presentation_sha256"]) is None \
            or not isinstance(value.get("pack_sha256"), str) \
            or re.fullmatch(r"[0-9a-f]{64}", value["pack_sha256"]) is None \
            or not isinstance(value.get("plan_action_id"), str) \
            or not isinstance(value.get("project_id"), str) \
            or type(value.get("revision")) is not int \
            or not 1 <= value["revision"] <= 1_000_000:
        raise OrchestratorError(
            "ACTION_CORRUPT", "exact-plan decision binding is invalid")
    if version in {2, 3} and (
            not isinstance(value.get("generation_id"), str)
            or loom_lifecycle_kernel.SAFE_ID.fullmatch(
                value["generation_id"]) is None
            or any(
                not isinstance(value.get(key), str)
                or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
                for key in (
                    *(("active_index_sha256",) if version == 2 else ()),
                    "plan_semantics_sha256",
                    "execution_sequence_sha256", "reviewed_world_sha256",
                    "reviewed_world_observation_sha256"))):
        raise OrchestratorError(
            "ACTION_CORRUPT", "exact-plan generation binding is invalid")
    if version == 3 and (
            value.get("source_lifecycle_name") not in {
                "lifecycle.json", ".loom-small-lifecycle.json"}
            or not isinstance(value.get("source_lifecycle_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", value["source_lifecycle_sha256"]) is None):
        raise OrchestratorError(
            "ACTION_CORRUPT", "exact-plan legacy-adoption binding is invalid")
    return value


def _validate_plan_revision_record(value, *, action):
    fields_v1 = {
        "schema_version", "parent_action_id", "parent_presentation_sha256",
        "parent_pack_sha256", "revision", "request", "prior_semantics",
        "archive_sha256", "archive_record_id", "project_state_hash",
    }
    fields_v2 = fields_v1 | {
        "generation_id", "source_active_index_sha256",
        "source_plan_semantics_sha256", "source_lifecycle_sha256",
        "source_witness_sha256", "source_reviewed_world_sha256",
        "source_reviewed_world_observation_sha256",
    }
    version = value.get("schema_version") if isinstance(value, dict) else None
    fields = fields_v2 if version == 2 else fields_v1
    try:
        archive_record_id_valid = (
            isinstance(value, dict)
            and isinstance(value.get("archive_record_id"), str)
            and str(uuid.UUID(value["archive_record_id"]))
            == value["archive_record_id"])
    except (ValueError, TypeError, AttributeError):
        archive_record_id_valid = False
    if not isinstance(value, dict) or set(value) != fields \
            or version not in {1, 2} \
            or action.get("intent") != "plan" \
            or not isinstance(value.get("parent_action_id"), str) \
            or not isinstance(value.get("request"), str) \
            or not 1 <= len(value["request"]) <= \
            loom_adapter_protocol.MAX_REQUEST_CHARACTERS \
            or type(value.get("revision")) is not int \
            or not 2 <= value["revision"] <= 1_000_000 \
            or not archive_record_id_valid \
            or any(
                not isinstance(value.get(key), str)
                or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
                for key in (
                    "parent_presentation_sha256", "parent_pack_sha256",
                    "archive_sha256", "project_state_hash")):
        raise OrchestratorError(
            "ACTION_CORRUPT", "plan revision binding is invalid")
    if version == 2 and (
            not isinstance(value.get("generation_id"), str)
            or loom_lifecycle_kernel.SAFE_ID.fullmatch(
                value["generation_id"]) is None
            or any(
                not isinstance(value.get(key), str)
                or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
                for key in (
                    "source_active_index_sha256",
                    "source_plan_semantics_sha256",
                    "source_lifecycle_sha256", "source_witness_sha256",
                    "source_reviewed_world_sha256",
                    "source_reviewed_world_observation_sha256"))):
        raise OrchestratorError(
            "ACTION_CORRUPT", "plan revision generation binding is invalid")
    try:
        loom_plan_presentation.validate_semantics(value["prior_semantics"])
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "ACTION_CORRUPT", f"prior plan semantics are invalid: {exc}") from exc
    return value


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
                        allow_unsealed_recovery=False,
                        allow_pending_prepared=False):
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
            or (status == "pending" and value["state"] != "installed"
                and not (allow_pending_prepared
                         and value["state"] == "prepared")) \
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


def _validate_legacy_plan_contract_v4(contract, *, action, prepared):
    """Validate a terminal v4 plan contract without executing it under v5 rules."""
    if not isinstance(contract, dict) or set(contract) != LEGACY_PLAN_CONTRACT_FIELDS_V4:
        raise OrchestratorError(
            "ACTION_CORRUPT", "legacy plan contract fields are invalid")
    body = {key: value for key, value in contract.items() if key != "contract_hash"}
    if contract.get("schema_version") != LEGACY_PLAN_CONTRACT_SCHEMA_VERSION \
            or not re.fullmatch(r"[0-9a-f]{64}", str(contract.get("contract_hash", ""))) \
            or contract["contract_hash"] != _hash(body):
        raise OrchestratorError(
            "ACTION_CORRUPT", "legacy plan contract digest is invalid")
    project_inspection = loom_runtime._thaw(prepared.project_inspection)
    inspection_obligations = [
        {"path": item["path"], "reason": item["reason"],
         "potential_authorities": list(item["potential_authorities"])}
        for item in project_inspection["unresolved_roots"]]
    if contract["request_hash"] != prepared.request_hash \
            or contract["survey_hash"] != action["survey_hash"] \
            or contract["tier"] != action["tier"] \
            or contract["domains"] != action["domains"] \
            or contract["domain_route"] != action["domain_contract"] \
            or contract["route_digest"] != action["domain_contract"]["route_digest"] \
            or contract["composition_graph_digest"] \
            != action["domain_contract"]["graph_digest"] \
            or contract["target_fingerprint"] != action["survey_hash"] \
            or contract["project_inspection"] \
            != loom_project_inspection.capsule(project_inspection) \
            or contract["inspection_obligations"] != inspection_obligations \
            or contract["pack_baseline_hash"] != action["initial_pack_hash"] \
            or contract["pack_root"] != "plans" \
            or contract["allowed_host_write_paths"] != ["plans/**"]:
        raise OrchestratorError(
            "ACTION_CORRUPT", "legacy plan contract does not match its sealed action")
    if action["status"] not in TERMINAL_ACTION_STATUSES:
        raise OrchestratorError(
            "ACTION_REPREPARE_REQUIRED",
            "an open plan-contract-v4 action cannot resume under plan-contract-v5; "
            "invoke /loom again against the current project state",
            status="action-required")
    return contract


def _validate_action(value, path):
    if not isinstance(value, dict):
        raise OrchestratorError("ACTION_CORRUPT", "action must be an object")
    original_schema_version = value.get("schema_version")
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
    if value.get("schema_version") == INTERMEDIATE_ACTION_SCHEMA_VERSION:
        if set(value) != ACTION_FIELDS_V7 \
                or value.get("action_hash") != _action_hash(value) \
                or value.get("status") not in {
                    "pending", "completed", "cancelled", "expired", "failed"}:
            raise OrchestratorError("ACTION_CORRUPT", "prior action fields or hash are invalid")
        value = {
            **value,
            "schema_version": PRIOR_ACTION_SCHEMA_VERSION,
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
    if value.get("schema_version") == PRIOR_ACTION_SCHEMA_VERSION:
        if set(value) != ACTION_FIELDS_V8 \
                or value.get("action_hash") != _action_hash(value) \
                or value.get("status") not in ACTION_STATUSES:
            raise OrchestratorError("ACTION_CORRUPT", "prior action fields or hash are invalid")
        value = {
            **value,
            "schema_version": PREVIOUS_ACTION_SCHEMA_VERSION,
            "assurance": _legacy_assurance(value.get("request", "")),
        }
        value["action_hash"] = _action_hash(value)
    if value.get("schema_version") == OWNER_MESSAGE_ACTION_SCHEMA_VERSION:
        if set(value) != ACTION_FIELDS_V10 \
                or value.get("status") not in ACTION_STATUSES \
                or value.get("action_hash") != _action_hash(value):
            raise OrchestratorError(
                "ACTION_CORRUPT", "prior owner-message action fields or hash are invalid")
        value = {
            **value,
            "schema_version": PREVIOUS_ACTION_SCHEMA_VERSION,
        }
        value["action_hash"] = _action_hash(value)
    if value.get("schema_version") == PREVIOUS_ACTION_SCHEMA_VERSION:
        if set(value) != ACTION_FIELDS_V10 \
                or value.get("status") not in ACTION_STATUSES \
                or value.get("action_hash") != _action_hash(value):
            raise OrchestratorError(
                "ACTION_CORRUPT", "prior lifecycle action fields or hash are invalid")
        value = {
            **value,
            "schema_version": ACTION_SCHEMA_VERSION,
            "generation_id": None,
            "request_control": None,
            "lifecycle_transition": None,
        }
        value["action_hash"] = _action_hash(value)
    if value.get("schema_version") != ACTION_SCHEMA_VERSION:
        raise OrchestratorError(
            "ACTION_VERSION_UNSUPPORTED", "action schema version is not supported")
    if set(value) != ACTION_FIELDS \
            or value.get("status") not in ACTION_STATUSES \
            or value.get("action_hash") != _action_hash(value):
        raise OrchestratorError("ACTION_CORRUPT", "action fields or hash are invalid")
    _validate_assurance(value["assurance"], value.get("request", ""))
    if original_schema_version == ACTION_SCHEMA_VERSION:
        try:
            loom_runtime.validate_request_control(value["request_control"])
        except loom_runtime.RuntimeError as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT", f"sealed request control is invalid: {exc}") from exc
    elif value["request_control"] is not None:
        raise OrchestratorError(
            "ACTION_CORRUPT", "historical action unexpectedly carries request control")
    if value["generation_id"] is not None and (
            not isinstance(value["generation_id"], str)
            or loom_lifecycle_kernel.SAFE_ID.fullmatch(
                value["generation_id"]) is None):
        raise OrchestratorError(
            "ACTION_CORRUPT", "sealed lifecycle generation identity is invalid")
    if value["lifecycle_transition"] is not None:
        try:
            loom_lifecycle_transition.validate_receipt(
                value["lifecycle_transition"])
        except loom_lifecycle_transition.LifecycleTransitionError as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT", f"sealed lifecycle transition is invalid: {exc}") from exc
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
    message_version = value["owner_message"].get("schema_version")
    message_builder = (
        loom_message.v2_build if message_version == 2 else
        loom_message.v3_build if message_version == 3 else
        loom_message.v4_build if message_version == 4 else
        loom_message.build)
    current_owner_message_contract = (
        original_schema_version in {
            PREVIOUS_ACTION_SCHEMA_VERSION, ACTION_SCHEMA_VERSION}
        and message_builder is loom_message.build)
    planning_metadata_changed = (
        current_owner_message_contract and value["intent"] == "plan")
    expected_owner_message = message_builder(
        state="progress",
        consequence=_action_consequence(
            value, use_domain_contract=current_owner_message_contract),
        verification="pending", freshness="current",
        changes_made=planning_metadata_changed,
        undo_status=("unavailable" if planning_metadata_changed else
                     "not-needed" if message_builder is loom_message.v2_build
                     else "not-applicable"),
        summary=(
            _planning_seed_summary(value["tier"])
            if planning_metadata_changed
            else "Loom prepared the next safe frontier."),
        next_action=(
            "Have the agent finish the plan, then review it before any project work starts."
            if planning_metadata_changed
            else "Complete and verify the sealed frontier."),
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
        allow_unsealed_recovery=allow_unsealed_recovery,
        allow_pending_prepared=original_schema_version == ACTION_SCHEMA_VERSION)
    if recovery_receipt is not None and value["pack_seed"]["created_pack"] \
            and value["pack_seed"]["state"] != "recovered":
        raise OrchestratorError(
            "ACTION_CORRUPT", "recovery receipt requires a recovered pack seed state")
    contract_expected = value["intent"] == "plan" \
        and not prepared.route_contract["blocked"] \
        and value["initial_pack_hash"] is not None
    if contract_expected:
        contract_version = (
            value["plan_contract"].get("schema_version")
            if isinstance(value["plan_contract"], dict) else None)
        if contract_version == LEGACY_PLAN_CONTRACT_SCHEMA_VERSION:
            _validate_legacy_plan_contract_v4(
                value["plan_contract"], action=value, prepared=prepared)
        elif contract_version == PLAN_CONTRACT_SCHEMA_VERSION:
            schema_report = loom_lint.Report()
            loom_lint.validate_schema(
                schema_report, path, value["plan_contract"], "plan-contract.schema.json")
            if schema_report.errors \
                    or value["plan_contract"] != _make_plan_contract(value, prepared):
                raise OrchestratorError(
                    "ACTION_CORRUPT",
                    "sealed plan contract is invalid or does not match action")
        else:
            raise OrchestratorError(
                "ACTION_VERSION_UNSUPPORTED",
                "sealed plan contract schema version is not supported")
    elif value["plan_contract"] is not None:
        raise OrchestratorError(
            "ACTION_CORRUPT", "non-planning action carries a plan contract")
    repair_plan = value["repair_plan"]
    if value["intent"] == "repair" and not prepared.route_contract["blocked"]:
        v3_repair = value.get("generation_id") is not None
        repair_fields = {
            "changed_paths", "affected_plan_sections", "regate_scope",
            "prior_state_hash", "current_state_hash", "force_full"}
        if value["tier"] == "S" and not v3_repair:
            repair_fields.add("lifecycle_sha256")
        else:
            repair_fields.add("program_impact")
        if not isinstance(repair_plan, dict) or set(repair_plan) != repair_fields \
                or repair_plan["regate_scope"] not in {"selective", "full", "compact"} \
                or (repair_plan["regate_scope"] == "compact") != \
                (value["tier"] == "S" and not v3_repair) \
                or type(repair_plan["force_full"]) is not bool \
                or not all(re.fullmatch(r"[0-9a-f]{64}", str(repair_plan[name]))
                           for name in ("prior_state_hash", "current_state_hash")) \
                or not isinstance(repair_plan["changed_paths"], list) \
                or not isinstance(repair_plan["affected_plan_sections"], list) \
                or not repair_plan["affected_plan_sections"]:
            raise OrchestratorError("ACTION_CORRUPT", "sealed repair plan is invalid")
        if value["tier"] == "S" and not v3_repair and not re.fullmatch(
                r"[0-9a-f]{64}", str(repair_plan["lifecycle_sha256"])):
            raise OrchestratorError("ACTION_CORRUPT", "compact lifecycle binding is invalid")
        if (value["tier"] != "S" or v3_repair) \
                and repair_plan["program_impact"] is not None:
            try:
                loom_program.validate_impact_receipt(repair_plan["program_impact"])
            except loom_program.ProgramError as exc:
                raise OrchestratorError(
                    "ACTION_CORRUPT", f"sealed program impact is invalid: {exc}") from exc
    elif repair_plan is not None:
        raise OrchestratorError("ACTION_CORRUPT", "non-repair action carries repair scope")
    if value["host_result"] is not None and not isinstance(value["host_result"], dict):
        raise OrchestratorError("ACTION_CORRUPT", "host result is invalid")
    if isinstance(value["host_result"], dict) and "plan_author" in value["host_result"]:
        if value["intent"] != "plan":
            raise OrchestratorError(
                "ACTION_CORRUPT", "non-planning action carries plan-author state")
        _validate_plan_author_record(
            value["host_result"]["plan_author"], action=value)
    if isinstance(value["host_result"], dict) and "plan_review" in value["host_result"]:
        _validate_plan_review_record(
            value["host_result"]["plan_review"], action=value)
    if isinstance(value["host_result"], dict) and "plan_decision" in value["host_result"]:
        decision = _validate_plan_decision_record(
            value["host_result"]["plan_decision"])
        if value["intent"] != "execute" \
                or decision["project_id"] != value["project_id"]:
            raise OrchestratorError(
                "ACTION_CORRUPT", "exact-plan decision belongs to another action")
    if isinstance(value["host_result"], dict) and "plan_revision" in value["host_result"]:
        _validate_plan_revision_record(
            value["host_result"]["plan_revision"], action=value)
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
    path = (_validate_action_path_authority(path, owner_home)
            if owner_home is not None else _absolute(path, "action"))
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


def _lifecycle_private_projection(action, *, operation, memory, completion=None):
    """Seal restart material without exposing action text in the journal."""
    if operation not in {"start", "complete", "repair", "repair-complete"}:
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "private lifecycle projection operation is unsupported")
    action_value = dict(action)
    action_value.pop("action_hash", None)
    payload = {
        "schema_version": 1,
        "operation": operation,
        "action": action_value,
        "completion": completion,
    }
    raw = _canonical_bytes(payload)
    if not raw or len(raw) > MAX_LIFECYCLE_PRIVATE_PROJECTION_BYTES:
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "private lifecycle projection exceeds its bound")
    encrypted = isinstance(memory, loom_vault_adapter.VaultMemoryAdapter)
    owner_vault_id = action["instance_id"] if encrypted else None
    aad = (
        f"lifecycle-projection:{owner_vault_id}:{action['project_id']}:"
        f"{action['action_id']}:{operation}").encode("utf-8")
    stored_payload = (
        memory.vault.crypto.seal(raw, aad).decode("ascii")
        if encrypted else payload)
    value = {
        "schema_version": 1,
        "kind": "orchestration-action-transition-v1",
        "encoding": (
            "owner-vault-encrypted-v1" if encrypted else "plaintext-v1"),
        "owner_vault_id": owner_vault_id,
        "project_id": action["project_id"],
        "action_id": action["action_id"],
        "operation": operation,
        "payload": stored_payload,
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
    }
    value["projection_sha256"] = _hash(value)
    return value


def _open_lifecycle_private_projection(value, *, memory):
    fields = {
        "schema_version", "kind", "encoding", "owner_vault_id",
        "project_id", "action_id", "operation", "payload",
        "payload_sha256", "projection_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("kind") != "orchestration-action-transition-v1" \
            or value.get("operation") not in {
                "start", "complete", "repair", "repair-complete"} \
            or not re.fullmatch(r"p-[0-9a-f]{32}", str(value.get("project_id", ""))) \
            or not re.fullmatch(r"[0-9a-f-]{36}", str(value.get("action_id", ""))) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("payload_sha256", ""))) \
            or value.get("projection_sha256") != _hash({
                key: item for key, item in value.items()
                if key != "projection_sha256"}):
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "private lifecycle projection is invalid")
    encoding = value["encoding"]
    if encoding == "owner-vault-encrypted-v1":
        if not isinstance(memory, loom_vault_adapter.VaultMemoryAdapter) \
                or value["owner_vault_id"] != memory.vault.identity()[
                    "owner_vault_id"] \
                or not isinstance(value["payload"], str):
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "private lifecycle projection owner identity is invalid")
        aad = (
            f"lifecycle-projection:{value['owner_vault_id']}:"
            f"{value['project_id']}:{value['action_id']}:"
            f"{value['operation']}").encode("utf-8")
        try:
            raw = memory.vault.crypto.open(
                value["payload"].encode("ascii"), aad)
        except (loom_crypto.CryptoError, UnicodeError, ValueError) as exc:
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "private lifecycle projection authentication failed") from exc
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object)
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "private lifecycle projection payload is invalid") from exc
    elif encoding == "plaintext-v1":
        if value["owner_vault_id"] is not None \
                or not isinstance(value["payload"], dict):
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "plaintext lifecycle projection is invalid")
        payload = value["payload"]
        raw = _canonical_bytes(payload)
    else:
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "private lifecycle projection encoding is unsupported")
    if not raw or len(raw) > MAX_LIFECYCLE_PRIVATE_PROJECTION_BYTES \
            or hashlib.sha256(raw).hexdigest() != value["payload_sha256"] \
            or not isinstance(payload, dict) \
            or set(payload) != {
                "schema_version", "operation", "action", "completion"} \
            or payload.get("schema_version") != 1 \
            or payload.get("operation") != value["operation"] \
            or not isinstance(payload.get("action"), dict):
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "private lifecycle projection payload does not match")
    action = dict(payload["action"])
    if "action_hash" in action or set(action) != ACTION_FIELDS - {"action_hash"} \
            or action.get("action_id") != value["action_id"] \
            or action.get("project_id") != value["project_id"]:
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "private lifecycle action projection does not match")
    action["action_hash"] = _action_hash(action)
    expected_path = _action_path(
        action["owner_home"], action["instance_id"],
        action["project_id"], action["action_id"])
    _validate_action(action, expected_path)
    completion = payload["completion"]
    if value["operation"] == "complete":
        try:
            loom_gate.validate_work_order_completion_evidence(completion)
        except (TypeError, ValueError) as exc:
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "private completion projection is invalid") from exc
    elif completion is not None:
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "start projection unexpectedly carries completion evidence")
    return action, completion


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


def _active_action_for_status(directory, *, owner_home, install_root):
    pointer = _read_active_pointer(directory)
    if pointer is None:
        return None
    path = Path(directory) / f"{pointer['action_id']}.json"
    if not _path_present(path):
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            "the active pointer names a missing action; status is indeterminate")
    _path, action, _security = _read_action(
        path, owner_home=owner_home, install_root=install_root)
    if action["project_id"] != pointer["project_id"] \
            or action["action_id"] != pointer["action_id"]:
        raise OrchestratorError(
            "ACTION_POINTER_CONFLICT", "active action and pointer disagree")
    return None if action["status"] in TERMINAL_ACTION_STATUSES else action


def _active_action_transparency(action, *, explain):
    labels = {
        "plan": "A project plan is waiting to be finished and reviewed.",
        "resume": "A paused project plan is waiting to continue.",
        "execute": "The next approved work item is waiting to run.",
        "review": "A project review is waiting to finish.",
        "repair": "A plan repair is waiting to finish.",
        "close": "Project closeout is waiting to finish.",
    }
    summary = labels.get(
        action["intent"], "A Loom action is waiting to finish.")
    if action["intent"] == "plan":
        summary += " Coding has not started."
    if explain:
        summary += (
            " Loom stopped at this step because only this action is currently authorized.")
    return {
        "status": "completed",
        "code": "active-action-reason" if explain else "active-action-status",
        "success": True,
        "metrics": {},
        "evidence_ids": [],
        "reversible_action_ids": [],
        "user_message": summary,
    }


def _generation_transparency(state, *, explain):
    """Render only closed reducer axes when no attempt pointer is authoritative."""
    if not isinstance(state, loom_lifecycle_kernel.LifecycleState):
        raise OrchestratorError(
            "INVALID_LIFECYCLE", "canonical generation status is unavailable")
    fields = [
        f"generation_phase={state.generation_phase}",
        f"transition_observation={state.transition_observation}",
        f"authority_validity={state.authority_validity}",
        f"work_order_frontier={state.frontier}",
    ]
    if state.selected_work_order_id is not None:
        fields.append(f"selected_work_order={state.selected_work_order_id}")
    if state.blocked_work_order_id is not None:
        fields.append(f"blocked_work_order={state.blocked_work_order_id}")
    message = "Canonical Loom generation status: " + "; ".join(fields) + "."
    if explain:
        message += (
            " The generation ledger remains authoritative independently of any "
            "cleared or terminal action-attempt pointer.")
    return {
        "status": "completed",
        "code": "generation-reason" if explain else "status-complete",
        "success": True,
        "metrics": {},
        "evidence_ids": ["generation-" + state.state_sha256[:24]],
        "reversible_action_ids": [],
        "user_message": message,
    }


def _generation_status_projection_requested(request):
    """Keep established status subcommands distinct from lifecycle status."""
    return re.search(
        r"\btoken usage\b|\bperformance report\b|\bcost report\b|"
        r"\bloom health\b|\bremember(?:ed)? preferences?\b|"
        r"\bwhat you learned\b",
        request, re.I) is None


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


def _action_pack_root(action):
    """Resolve the exact plan projection owned by one action."""
    root = Path(action["explicit_target"] or action["cwd"])
    seed = action.get("pack_seed") or {}
    if action.get("intent") == "plan" and seed.get("created_pack") \
            and seed.get("state") in {"recorded", "prepared"}:
        stage = _project_stage_path(action)
        if _path_present(stage):
            return stage
    plans = root / "plans"
    if _path_present(plans / loom_plan_store.INDEX_NAME):
        try:
            return loom_plan_store.resolve(root).generation_root
        except loom_plan_store.PlanStoreError as exc:
            raise OrchestratorError(
                "PLAN_STORE_INVALID",
                f"the active plan generation cannot be resolved: {exc}") from exc
    return plans


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
    revision_record = (action.get("host_result") or {}).get("plan_revision")
    immutable_revision_stage = (
        isinstance(revision_record, dict)
        and revision_record.get("schema_version") == 2)
    if immutable_revision_stage and not _v3_revision_source_is_current(
            action, target):
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            "the active revision source changed; the stage and active generation "
            "were preserved")
    present = [
        ("plans", pack)
        if not immutable_revision_stage and _path_present(pack) else None,
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


def _completed_plan_replay(directory, prepared, target, *, request, cwd,
                           owner_home, install_root):
    """Return one completed plan only when its exact post-plan world still exists."""
    target = Path(target)
    plans = target / "plans"
    if not plans.is_dir():
        return None
    try:
        pack = (
            loom_plan_store.resolve(target).generation_root
            if os.path.lexists(plans / loom_plan_store.INDEX_NAME)
            else plans)
        current_manifest = loom_reliability.exact_tree_manifest(pack)
        loom_reliability.validate_exact_tree_manifest(current_manifest)
    except (loom_plan_store.PlanStoreError,
            loom_reliability.ReliabilityError) as exc:
        raise OrchestratorError(
            "TARGET_INDETERMINATE",
            f"the existing planning pack cannot be proven unchanged: {exc}") from exc
    try:
        current_survey_hash = loom_survey.workspace_snapshot(
            target, exclude_prefixes=("plans",)).state.state_hash
    except loom_survey.SurveyError as exc:
        raise OrchestratorError(
            "TARGET_INDETERMINATE",
            f"the current project world cannot be proven unchanged: {exc}") from exc
    entries = []
    inspected = 0
    for entry in os.scandir(directory):
        inspected += 1
        if inspected > MAX_ORCHESTRATION_DIRECTORY_ENTRIES:
            raise OrchestratorError(
                "RECOVERY_CAPACITY",
                "completed-action replay scan exceeds its directory-entry bound")
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            continue
        if not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{12}\.json", entry.name):
            continue
        entries.append(Path(entry.path))
        if len(entries) > MAX_ORCHESTRATION_ACTIONS:
            raise OrchestratorError(
                "RECOVERY_CAPACITY",
                "completed-action replay scan exceeds its action bound")
    matches = []
    for path in sorted(entries, key=lambda item: item.name):
        _path, action, _security = _read_action(
            path, owner_home=owner_home, install_root=install_root)
        plan_author = (action.get("host_result") or {}).get("plan_author")
        result = action.get("result")
        sealed = action.get("prepared") or {}
        if action.get("status") != "completed" \
                or action.get("intent") != "plan" \
                or not isinstance(result, dict) \
                or result.get("status") != "completed" \
                or action.get("request") != request \
                or action.get("cwd") != str(cwd) \
                or action.get("explicit_target") != str(target) \
                or action.get("project_id") != prepared.project_id \
                or action.get("survey_hash") != current_survey_hash \
                or sealed.get("request_hash") != prepared.request_hash \
                or sealed.get("intent") != prepared.intent \
                or sealed.get("domains") != list(prepared.domains) \
                or not isinstance(plan_author, dict) \
                or plan_author.get("state") != "active" \
                or plan_author.get("manifest") != current_manifest:
            continue
        matches.append((
            str(plan_author.get("completed_at", "")),
            action["action_id"],
            action,
            result,
        ))
    if not matches:
        return None
    _completed_at, _action_id, action, result = max(
        matches, key=lambda item: (item[0], item[1]))
    presentation = result.get("plan_presentation")
    if presentation is None:
        return result
    try:
        host_projection = loom_plan_presentation.project_for_host(
            presentation, project_root=target,
            host_id=action["assurance"]["host_id"])
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "PLAN_PRESENTATION_INVALID",
            f"the unchanged completed plan cannot be presented safely: {exc}") from exc
    return {**result, "plan_host_projection": host_projection}


def _v3_revision_source_is_current(action, target):
    revision = (action.get("host_result") or {}).get("plan_revision")
    if not isinstance(revision, dict) or revision.get("schema_version") != 2:
        return False
    try:
        resolved = loom_plan_store.resolve(target)
        semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
            json.loads(
                (resolved.generation_root / "plan-semantics.json").read_text(
                    encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object))
        ledger = loom_lifecycle_kernel.validate_lifecycle_ledger(
            json.loads(
                (resolved.generation_root / "lifecycle.json").read_text(
                    encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object))
        world = _staged_plan_world(action)
    except (
            OSError, UnicodeError, json.JSONDecodeError, ValueError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError) as exc:
        raise OrchestratorError(
            "TARGET_INDETERMINATE",
            f"the revision source cannot be proven unchanged: {exc}") from exc
    return resolved.index is not None \
        and resolved.index.index_sha256 == \
        revision["source_active_index_sha256"] \
        and resolved.index.generation_id == revision["generation_id"] \
        and semantics.plan_semantics_sha256 == \
        revision["source_plan_semantics_sha256"] \
        and ledger.lifecycle_sha256 == revision["source_lifecycle_sha256"] \
        and world["state_sha256"] == revision["project_state_hash"] \
        and world["observation_sha256"] == \
        revision["source_reviewed_world_observation_sha256"]


def _committed_v3_action_matches_current_frontier(action, target):
    """Recognize the exact lifecycle mutation made by one pending action.

    A successful v3 start or continue necessarily changes the lifecycle digest
    that was observed before the action was created.  Transport replay must not
    mistake that action's own sealed transition for product-world drift.
    """
    receipt = action.get("lifecycle_transition")
    if action.get("schema_version") != ACTION_SCHEMA_VERSION \
            or action.get("intent") != "execute" \
            or action.get("status") != "pending" \
            or not isinstance(action.get("work_order"), str) \
            or not isinstance(receipt, dict):
        return False
    try:
        loom_lifecycle_transition.validate_receipt(receipt)
        if receipt["status"] != "completed" \
                or receipt["observation"] != "target" \
                or receipt["projection_status"] != "verified" \
                or receipt["findings"] \
                or receipt["project_id"] != action["project_id"] \
                or receipt["generation_id"] != action["generation_id"] \
                or receipt["command_id"] not in {
                    "start-" + action["action_id"],
                    "continue-" + action["action_id"],
                }:
            return False
        resolved = loom_plan_store.resolve(target)
        if resolved.index is None \
                or resolved.index.project_id != action["project_id"] \
                or resolved.index.generation_id != action["generation_id"]:
            return False
        semantics_value = json.loads(
            (resolved.generation_root / "plan-semantics.json").read_text(
                encoding="utf-8"),
            object_pairs_hook=loom_lifecycle._strict_object)
        ledger_value = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"),
            object_pairs_hook=loom_lifecycle._strict_object)
        if ledger_value.get("lifecycle_sha256") != \
                receipt["target_authority_sha256"]:
            return False
        witness_value = {
            "schema_version": 1,
            "project_id": receipt["project_id"],
            "generation_id": receipt["generation_id"],
            "transition_id": receipt["transition_id"],
            "authoritative_sha256": receipt["target_authority_sha256"],
            "predecessor_witness_sha256": receipt["source_witness_sha256"],
        }
        witness_value["witness_sha256"] = loom_lifecycle_kernel.digest(
            witness_value)
        if witness_value["witness_sha256"] != receipt["target_witness_sha256"]:
            return False
        ledger = loom_lifecycle_kernel.validate_lifecycle_ledger(ledger_value)
        state = loom_lifecycle_kernel.fold({
            "schema_version": 1,
            "project_id": resolved.index.project_id,
            "generation_id": resolved.index.generation_id,
            "storage_kind": resolved.index.storage_kind,
            "generation_path": resolved.index.generation_path,
            "index_sha256": resolved.index.index_sha256,
        }, semantics_value, ledger_value, witness_value)
        work_order_path = resolved.generation_root / action["work_order"]
        frontmatter, _body = loom_lint.parse_frontmatter(
            work_order_path.read_text(encoding="utf-8"))
        work_order_id = (frontmatter or {}).get("id")
        current_world = _reviewed_world_observation(
            Path(target), project_id=action["project_id"],
            generation_id=action["generation_id"],
            excluded_paths=(Path(target) / "plans",))
        return state.generation_phase == "active" \
            and state.in_progress_work_order_id == work_order_id \
            and current_world["state_sha256"] == state.expected_world_sha256 \
            and any(
                event.transition_id == receipt["transition_id"]
                and event.command_id == receipt["command_id"]
                for event in ledger.events)
    except (
            OSError, UnicodeError, json.JSONDecodeError, ValueError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_lifecycle_transition.LifecycleTransitionError):
        return False


def _action_matches_current_frontier(action, prepared, target, *, request, cwd):
    """Prove that one pending action still names the current target frontier."""
    sealed = action["prepared"]
    revision = (action.get("host_result") or {}).get("plan_revision")
    seed = action.get("pack_seed") or {}
    if action["intent"] == "plan" and revision is None \
            and action["status"] == "pending" \
            and seed.get("created_pack") \
            and seed.get("state") == "prepared":
        try:
            current_world = _staged_plan_world(action)
        except OrchestratorError:
            return False
        return action["request"] == request \
            and action["cwd"] == str(cwd) \
            and action["explicit_target"] == str(target) \
            and action["project_id"] == prepared.project_id \
            and sealed["request_hash"] == prepared.request_hash \
            and prepared.intent == "plan" \
            and sealed["domains"] == list(prepared.domains) \
            and current_world["state_sha256"] == action["survey_hash"] \
            and action["initial_pack_hash"] is not None \
            and _pack_hash(_action_pack_root(action)) == \
            action["initial_pack_hash"]
    if action["intent"] == "plan" and isinstance(revision, dict) \
            and action["status"] == "pending":
        if revision.get("schema_version") == 2:
            stage = _project_stage_path(action)
            if not _v3_revision_source_is_current(action, target) \
                    or not _path_present(stage):
                return False
            authored = isinstance(
                (action.get("host_result") or {}).get("plan_review"), dict)
            if authored:
                try:
                    _validate_authored_plan(action)
                except OrchestratorError:
                    return False
                stage_current = True
            else:
                stage_current = action["initial_pack_hash"] is not None \
                    and _pack_hash(stage) == action["initial_pack_hash"]
            return action["request"] == request \
                and action["cwd"] == str(cwd) \
                and action["explicit_target"] == str(target) \
                and action["project_id"] == prepared.project_id \
                and sealed["request_hash"] == prepared.request_hash \
                and prepared.intent == "plan" \
                and stage_current
        try:
            revision_state = loom_gate._stable_state(
                Path(target), Path(target) / "plans").state_hash
        except loom_survey.SurveyError as exc:
            raise OrchestratorError(
                "TARGET_INDETERMINATE",
                f"the pending revision world cannot be proven unchanged: {exc}") from exc
        return action["request"] == request \
            and action["cwd"] == str(cwd) \
            and action["explicit_target"] == str(target) \
            and action["project_id"] == prepared.project_id \
            and sealed["request_hash"] == prepared.request_hash \
            and prepared.intent == "plan" \
            and revision_state == revision["project_state_hash"] \
            and action["initial_pack_hash"] is not None \
            and _pack_hash(Path(target) / "plans") == action["initial_pack_hash"]
    same_identity = action["request"] == request \
            and action["cwd"] == str(cwd) \
            and action["explicit_target"] == str(target) \
            and action["project_id"] == prepared.project_id \
            and sealed["request_hash"] == prepared.request_hash \
            and sealed["intent"] == prepared.intent \
            and sealed["domains"] == list(prepared.domains)
    same_frontier = same_identity \
            and action["survey_hash"] == prepared.survey_hash
    unchanged_world = sealed["world_fingerprint"] == prepared.world_fingerprint
    current_pack_matches = action["initial_pack_hash"] is not None \
        and _pack_hash(_action_pack_root(action)) == action["initial_pack_hash"]
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
                "the repeated transport operation's Tier-S lifecycle is unreadable") from exc
    return action["intent"] == prepared.intent and (
        same_frontier and (
            unchanged_world or current_pack_matches or tier_s_repair_current)
        or same_identity
        and _committed_v3_action_matches_current_frontier(action, target))


def _reconcile_active_action(*, owner_home, install_root, instance_id,
                             project_id, now, incoming_intent, request, cwd, target,
                             memory, transport_invocation_id=None):
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
    _reconcile_plan_authoring(action)
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
                cwd=cwd, explicit_target=target, owner_home=owner_home, now=now,
                lifecycle_witness_reader=_lifecycle_witness_reader(
                    memory, directory, project_id))
        except loom_runtime.RuntimeBlocked as exc:
            raise OrchestratorError(exc.code, exc.message) from exc
        if _action_matches_current_frontier(
                action, prepared, target, request=request, cwd=cwd):
            return None, action
        raise OrchestratorError(
            "TARGET_DRIFT",
            "a repeated transport operation no longer matches its sealed target state")
    if incoming_intent == "plan" \
            and action["intent"] == "plan" \
            and action["status"] == "pending" \
            and action["request"] == request \
            and loom_runtime._parse_time(now) <= loom_runtime._parse_time(
                action["expires_at"]):
        try:
            prepared = loom_runtime.prepare_invocation(
                request, instance_id=instance_id, invocation_id=str(uuid.uuid4()),
                cwd=cwd, explicit_target=target, owner_home=owner_home, now=now,
                lifecycle_witness_reader=_lifecycle_witness_reader(
                    memory, directory, project_id))
        except loom_runtime.RuntimeBlocked as exc:
            raise OrchestratorError(exc.code, exc.message) from exc
        if _action_matches_current_frontier(
                action, prepared, target, request=request, cwd=cwd):
            # Host retries commonly carry a new transport request ID. Request,
            # project, and exact world identity are the idempotency authority.
            return None, action
    if incoming_intent == "repair" \
            and action["intent"] == "execute" \
            and action["status"] == "pending" \
            and action.get("generation_id") is not None:
        # Prove the active v3 generation has one bounded repair scope before
        # retiring the stale execution attempt.  The lifecycle ledger remains
        # authoritative and is changed only by the subsequent repair command.
        _observe_v3_repair_scope(
            action, path, memory, require_action_world=False)
        controller, opened = _reopen(action)
        controller.interrupt(opened, code="repair-superseded", now=now)
        action["status"] = "cancelled"
        _write_action(path, action, security)
        _clear_active_pointer(directory, action["action_id"])
        return None, None
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


def _cancel_active_request(*, directory, request, owner_home, install_root, now):
    """Cancel only the uniquely active action named by an owner request."""
    pointer = _read_active_pointer(directory)
    if pointer is not None:
        path = directory / f"{pointer['action_id']}.json"
        if not _path_present(path):
            raise OrchestratorError(
                "RECOVERY_DECISION_REQUIRED",
                "the active pointer names a missing action; nothing was cancelled")
        candidates = [_read_action(
            path, owner_home=owner_home, install_root=install_root)]
    else:
        candidates = _legacy_active_actions(
            directory, owner_home=owner_home, install_root=install_root)
    if not candidates:
        raise OrchestratorError(
            "NO_ACTIVE_ACTION", "No pending Loom action exists for this project.")
    if len(candidates) != 1:
        raise OrchestratorError(
            "RECOVERY_DECISION_REQUIRED",
            "multiple nonterminal actions require inspection; nothing was cancelled")
    path, action, _security = candidates[0]
    requested_ids = set(re.findall(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        request, re.I))
    if len(requested_ids) > 1 or (
            requested_ids and action["action_id"] not in requested_ids):
        raise OrchestratorError(
            "ACTION_IDENTITY_CHANGED",
            "The named action is not the pending action for this project; nothing was cancelled.")
    result = _cancel_under_lock(
        path, now=now, owner_home=owner_home, install_root=install_root)
    return {
        **result,
        "success": True,
        "user_message": (
            "Cancelled the pending Loom action. "
            "No project implementation was performed."),
    }


def _transition_project_generation_terminal(
        *, directory, target, memory, project_id, relation, command_id,
        successor_generation_id=None, owner_home, install_root):
    """Commit an explicit v3 cancel/supersede even without an active action."""
    if relation not in {"cancel-generation", "supersede-generation"}:
        raise OrchestratorError(
            "REQUEST_CONTROL_INVALID", "generation terminal relation is invalid")
    witness_store = _lifecycle_witness_store(memory, directory, project_id)
    try:
        resolved, semantics, _ledger, _witness, state = \
            loom_lifecycle_transition.observe(
                target, witness_store=witness_store)
    except loom_lifecycle_transition.LifecycleTransitionError as exc:
        raise OrchestratorError(
            "INVALID_LIFECYCLE",
            f"indexed lifecycle authority cannot be observed safely: {exc}") from exc
    if state.project_id != project_id:
        raise OrchestratorError(
            "PROJECT_CHANGED", "the active generation belongs to another project")

    def project_terminal(_source_state, _decision, target_ledger):
        current = loom_plan_store.resolve(target)
        target_state = loom_lifecycle_kernel.fold(
            current.index, semantics, target_ledger, witness_store.read())
        _write_v3_pack_projection(current.generation_root, target_state)
        pointer = _read_active_pointer(directory)
        if pointer is None:
            return
        action_path = Path(directory) / f"{pointer['action_id']}.json"
        path, action, security = _read_action(
            action_path, owner_home=owner_home, install_root=install_root)
        if action["project_id"] != project_id \
                or action.get("generation_id") != state.generation_id:
            raise OrchestratorError(
                "ACTION_POINTER_CONFLICT",
                "the active action does not belong to the generation being retired")
        if action["status"] not in TERMINAL_ACTION_STATUSES:
            action["status"] = "cancelled"
            _write_action(path, action, security)
        _clear_active_pointer(directory, action["action_id"])

    command = {
        "schema_version": 1,
        "command_id": command_id,
        "relation": relation,
        "project_id": project_id,
        "generation_id": state.generation_id,
        "plan_semantics_sha256": state.plan_semantics_sha256,
        "observed_world_sha256": None,
        "action_id": None,
        "work_order_id": None,
        "evidence_sha256": None,
        "affected_scope_sha256": None,
        "successor_generation_id": successor_generation_id,
        "reason_code": (
            "owner-cancelled" if relation == "cancel-generation"
            else "owner-superseded"),
    }
    try:
        result = loom_lifecycle_transition.transition(
            target, command, witness_store=witness_store,
            envelope_root=Path(directory) / "lifecycle-transitions",
            project_projection=project_terminal,
            lock_path=_orchestration_lock(directory), _lock_held=True)
    except (
            loom_lifecycle_transition.LifecycleTransitionError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_plan_store.PlanStoreError) as exc:
        raise OrchestratorError(
            "LIFECYCLE_TRANSITION_FAILED",
            f"generation terminal transition failed safely: {exc}") from exc
    if not result["accepted"] or result["status"] != "completed" \
            or not isinstance(result["receipt"], dict):
        raise OrchestratorError(
            result["primary_code"],
            "the requested generation transition was rejected without mutation")
    code = (
        "generation-cancelled" if relation == "cancel-generation"
        else "generation-superseded")
    return {
        "status": "completed", "code": code, "success": True,
        "project_id": project_id, "generation_id": state.generation_id,
        "successor_generation_id": successor_generation_id,
        "transition_receipt": result["receipt"],
        "user_message": (
            "Cancelled the reviewed Loom generation. No new work was started."
            if relation == "cancel-generation" else
            "Superseded the active Loom generation before preparing standalone work."),
    }


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
plan_contract_version: {PLAN_CONTRACT_SCHEMA_VERSION}
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


def _artifact_contract(
        tier, domains, request, requires_discovery, active_specialists=()):
    domains = set(domains)
    task_text = loom_domain.task_language(request)
    research_deliverable = domains == {"research"} and bool(re.search(
        r"(?i)\b(?:do not (?:build|implement)|research (?:write[- ]?up|report|"
        r"comparison|paper|memo)|research\s+and\s+(?:write|produce|deliver|"
        r"synthesize)|write (?:a |the )?(?:report|paper|memo)|"
        r"produce (?:a |the )?(?:markdown )?(?:report|paper|memo))\b",
        task_text))
    whole = bool(re.search(
        r"(?i)\b(?:build|create|develop|design|implement|produce|write)\b",
        task_text)) or bool(re.search(
            r"(?i)\bplan\s+(?:(?:a|an|the|new|small|simple|minimal|desktop|mobile|"
            r"offline[- ]first|cross[- ]platform|real[- ]time|3d|accounting|"
            r"bookkeeping)\s+){0,7}(?:software|app(?:lication)?|system|product|"
            r"service|platform|tool|pipeline|website|firmware|library|sdk)\b",
            task_text))
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
    controlled_exposure = bool(re.search(
        r"(?i)\b(?:data|database|schema|storage|state)\b[^.!?;\n]{0,96}"
        r"\bmigrat(?:e|es|ed|ing|ion)\b"
        r"|\bmigrat(?:e|es|ed|ing|ion)\b[^.!?;\n]{0,96}"
        r"\b(?:data|database|schema|storage|state)\b"
        r"|\birreversible\b|\bregulated\b", task_text))
    produced = {"work orders"}
    if tier != "S":
        produced.add("intake.md")
        if not research_deliverable:
            produced.add("testing.md")
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
    elif tier != "S" and controlled_exposure:
        produced.add("release-rollback.md")
    if domains & ui_domains and tier != "S":
        produced.add("uiux.md")
    security_consumer = any(
        isinstance(item, dict)
        and item.get("id") == "security-privacy-safety"
        and any(str(evidence).startswith("request:")
                for evidence in item.get("evidence", ()))
        for item in active_specialists)
    if tier != "S" and (
            security_consumer or (
                domains & sensitive_domains
                and (tier in {"L", "XL"} or (tier == "M" and whole)))):
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
    if research_deliverable:
        produced_cells["work orders"] = (
            "researcher", "research tasks and report acceptance",
            "reviewable evidence and report frontier")
        skip_cells["testing.md"] = (
            "research verification belongs in source, method, citation, and report "
            "acceptance tasks rather than a separate test artifact")
        skip_cells["routing"] = "one ordered research frontier is sufficient"
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


def _semantic_draft_limits(tier):
    """Return the one machine-enforced semantic budget for this tier."""
    by_tier = {
        "S": {
            "assumptions": (2, 180), "decisions": (2, 180),
            "tasks": (3, 180), "acceptance": (3, 220),
            "negative_acceptance": (2, 180), "out_of_scope": (2, 180),
            "escalation": (2, 180), "touches": (5, 300),
        },
        "M": {
            "assumptions": (4, 300), "decisions": (4, 300),
            "tasks": (5, 300), "acceptance": (5, 360),
            "negative_acceptance": (3, 300), "out_of_scope": (3, 300),
            "escalation": (3, 300), "touches": (8, 300),
        },
        "L": {
            "assumptions": (8, 400), "decisions": (8, 400),
            "tasks": (8, 400), "acceptance": (8, 450),
            "negative_acceptance": (5, 400), "out_of_scope": (5, 400),
            "escalation": (5, 400), "touches": (16, 300),
        },
        "XL": {
            "assumptions": (12, 500), "decisions": (12, 500),
            "tasks": (12, 500), "acceptance": (12, 500),
            "negative_acceptance": (8, 500), "out_of_scope": (8, 500),
            "escalation": (8, 500), "touches": (24, 300),
        },
    }
    body = {
        "schema": "schemas/plan-draft.schema.json",
        "copy_current_facts_exactly": True,
    }
    minimum_items = {
        "tasks": 1,
        "acceptance": 1,
        "negative_acceptance": 1,
        "out_of_scope": 1,
        "escalation": 1,
        "touches": 1,
    }
    for field, (items, characters) in by_tier[tier].items():
        body[field] = {
            "minimum_items": minimum_items.get(field, 0),
            "maximum_items": items,
            "maximum_item_characters": characters,
        }
    return body


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
        compiled_invariants = loom_domain_invariants.compile_shipped(
            domain_id, adapter, guidance, now=instant)
        normalized_invariants.extend(compiled_invariants)
        compiled_by_statement = {
            item["statement"]: item for item in compiled_invariants
        }
        for index, invariant in enumerate(adapter["invariants"]):
            required_invariants.append({
                "domain": domain_id,
                "invariant": invariant,
                "evidence_target": "intake.md#domain-invariant-contract",
                "required_real_medium": compiled_by_statement[invariant][
                    "verification"]["required_real_medium"],
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
        "lifecycle", "proofline",
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
        "project_id": action["project_id"],
        "allowed_host_write_paths": ["plans/**"],
        "artifact_matrix": _artifact_contract(
            tier, domains, action["request"],
            prepared.route_contract["requires_domain_discovery"],
            planning_intelligence["active_modules"]),
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
        "semantic_draft_limits": _semantic_draft_limits(tier),
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
        "semantic_draft_limits": contract["semantic_draft_limits"],
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


def _validate_authored_plan(action, *, pack_override=None):
    contract = action["plan_contract"]
    root = Path(action["explicit_target"] or action["cwd"])
    pack = (
        Path(pack_override).resolve()
        if pack_override is not None else _action_pack_root(action))
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
    proofline_required = "proofline" in contract.get("completion_gates", [])
    proofline_present = (
        pack / "proofline" / "material-intent-ledger.json").is_file() \
        or (pack / "proofline" / "proof-graph.json").is_file()
    if proofline_required or proofline_present:
        try:
            material_ledger = json.loads(
                (pack / "proofline" / "material-intent-ledger.json").read_text(
                    encoding="utf-8"))
            proof_graph = json.loads(
                (pack / "proofline" / "proof-graph.json").read_text(
                    encoding="utf-8"))
            loom_proofline.validate_material_ledger(
                material_ledger, request=action["request"])
            loom_proofline.validate_graph(proof_graph)
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                loom_proofline.ProoflineError) as exc:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH",
                f"derived Proofline projection is invalid: {exc}") from exc
        if material_ledger["plan_contract_sha256"] != contract["contract_hash"] \
                or proof_graph["ledger_sha256"] != material_ledger["ledger_sha256"] \
                or proof_graph["plan_contract_sha256"] != contract["contract_hash"]:
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH",
                "derived Proofline projection is bound to another plan")
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
                    and row.get("status", "").strip().lower()
                    in {"required", "verified"}}
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
                    and row.get("status", "").strip().lower()
                    in {"unverified", "verified"}}
        required = {(item["domain"], item["fact"])
                    for item in contract["current_facts_to_verify"]}
        if not required.issubset(observed):
            raise OrchestratorError(
                "PLAN_CONTRACT_MISMATCH", "required current facts are not verified")

    testing_artifact = next(
        (item for item in contract["artifact_matrix"]
         if item["artifact"] == "testing.md"),
        None)
    if contract["verification_media"] \
            and testing_artifact is not None \
            and testing_artifact["action"] == "produce":
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


def _generation_archive_payload(resolved, state):
    """Build one bounded, content-bound private terminal-generation archive."""
    if not state.generation_phase.startswith("terminal-") \
            or resolved.index is None \
            or resolved.generation_id != state.generation_id:
        raise OrchestratorError(
            "GENERATION_ARCHIVE_FAILED",
            "only the exact active terminal generation can be archived")
    try:
        manifest = loom_reliability.exact_tree_manifest(
            resolved.generation_root, max_entries=1024,
            max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=MAX_PLAN_GENERATION_ARCHIVE_BYTES)
        files = []
        total = 0
        for entry in manifest["entries"]:
            if entry["kind"] != "file":
                continue
            path = resolved.generation_root.joinpath(
                *PurePosixPath(entry["path"]).parts)
            raw = path.read_bytes()
            total += len(raw)
            if len(files) >= MAX_PLAN_GENERATION_FILES \
                    or total > MAX_PLAN_GENERATION_ARCHIVE_BYTES \
                    or len(raw) != entry["bytes"] \
                    or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                raise OrchestratorError(
                    "GENERATION_ARCHIVE_FAILED",
                    "terminal generation changed or exceeds its archive bound")
            files.append({
                "path": entry["path"],
                "sha256": entry["sha256"],
                "size": entry["bytes"],
                "content_base64": base64.b64encode(raw).decode("ascii"),
            })
        after = loom_reliability.exact_tree_manifest(
            resolved.generation_root, max_entries=1024,
            max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=MAX_PLAN_GENERATION_ARCHIVE_BYTES)
        if not loom_reliability.exact_tree_manifests_equal(
                after, manifest, max_entries=1024,
                max_file_bytes=4 * 1024 * 1024,
                max_total_bytes=MAX_PLAN_GENERATION_ARCHIVE_BYTES):
            raise OrchestratorError(
                "GENERATION_ARCHIVE_FAILED",
                "terminal generation changed during archive capture")
    except (OSError, loom_reliability.ReliabilityError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "GENERATION_ARCHIVE_FAILED",
            f"terminal generation cannot be archived safely: {exc}") from exc
    value = {
        "schema_version": 1,
        "project_id": state.project_id,
        "generation_id": state.generation_id,
        "terminal_phase": state.generation_phase,
        "active_index_sha256": resolved.index.index_sha256,
        "lifecycle_sha256": state.lifecycle_sha256,
        "plan_semantics_sha256": state.plan_semantics_sha256,
        "tree_sha256": manifest["root_sha256"],
        "tree_manifest": manifest,
        "files": files,
    }
    value["archive_sha256"] = hashlib.sha256(_canonical_bytes(value)).hexdigest()
    report = loom_lint.Report()
    loom_lint.validate_schema(
        report, "plan generation archive", value,
        "plan-generation-archive-v1.schema.json")
    if report.errors:
        raise OrchestratorError(
            "GENERATION_ARCHIVE_FAILED",
            "terminal generation archive schema is invalid")
    return value


def _generation_archive_record_id(action, payload):
    try:
        namespace = uuid.UUID(action["instance_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise OrchestratorError(
            "GENERATION_ARCHIVE_FAILED",
            "owner identity cannot bind generation history") from exc
    return str(uuid.uuid5(
        namespace,
        "plan-generation:"
        f"{action['project_id']}:{payload['generation_id']}:"
        f"{payload['archive_sha256']}"))


def _persist_generation_archive(memory, action_path, action, payload):
    record_id = _generation_archive_record_id(action, payload)
    writer = getattr(memory, "archive_plan_generation", None)
    if writer is not None:
        try:
            stored = writer(
                record_id=record_id, project_id=action["project_id"],
                payload=payload, created_at=action["created_at"])
        except loom_vault_adapter.VaultAdapterError as exc:
            raise OrchestratorError(
                "GENERATION_ARCHIVE_FAILED", str(exc)) from exc
        if stored.get("forgotten") \
                or stored.get("record_id") != record_id \
                or stored.get("archive_sha256") != payload["archive_sha256"]:
            raise OrchestratorError(
                "GENERATION_ARCHIVE_FAILED",
                "owner-vault generation archive identity changed")
        return payload["archive_sha256"]
    directory = Path(action_path).parent / "plan-generations"
    if os.path.lexists(directory) and (
            directory.is_symlink() or not directory.is_dir()):
        raise OrchestratorError(
            "GENERATION_ARCHIVE_FAILED",
            "private generation archive namespace is unsafe")
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / f"{record_id}-{payload['archive_sha256']}.json"
    if os.path.lexists(path):
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise OrchestratorError(
                "GENERATION_ARCHIVE_FAILED",
                "existing generation archive is corrupt") from exc
        if existing != payload:
            raise OrchestratorError(
                "GENERATION_ARCHIVE_FAILED",
                "immutable generation archive identity conflicts")
    else:
        loom_session._atomic_json(path, payload)
    return payload["archive_sha256"]


def _reviewed_world_observation(
        root, *, project_id, generation_id, excluded_paths=()):
    """Observe immutable product bytes while excluding Loom control projections."""
    root = Path(root).resolve(strict=True)
    prefixes = []
    for item in excluded_paths:
        try:
            relative = Path(item).resolve(strict=True).relative_to(root).as_posix()
        except (OSError, RuntimeError, ValueError) as exc:
            raise OrchestratorError(
                "REVIEWED_WORLD_INVALID",
                "a reviewed-world exclusion is outside the project or unavailable") from exc
        if not relative or relative == ".":
            raise OrchestratorError(
                "REVIEWED_WORLD_INVALID",
                "the project root cannot be excluded from reviewed-world evidence")
        prefixes.append(relative)
    prefixes = tuple(sorted(set(prefixes), key=os.fsencode))
    try:
        before = loom_survey.workspace_snapshot(
            root, exclude_prefixes=prefixes)
        files = loom_gate._snapshot_files(
            root, exclude_prefixes=prefixes)
        after = loom_survey.workspace_snapshot(
            root, exclude_prefixes=prefixes,
            state_mode=before.state.mode)
    except loom_survey.SurveyError as exc:
        raise OrchestratorError(
            "REVIEWED_WORLD_INVALID",
            f"the reviewed product world could not be observed safely: {exc}") from exc
    if before.state != after.state \
            or before.content_hash_complete != after.content_hash_complete \
            or not before.content_hash_complete:
        raise OrchestratorError(
            "REVIEWED_WORLD_CHANGED",
            "the product world changed while review evidence was collected")
    value = {
        "schema_version": 1,
        "project_id": project_id,
        "generation_id": generation_id,
        "state_mode": before.state.mode,
        "state_sha256": before.state.state_hash,
        "repo_head": before.state.head or None,
        "files": {key: files[key] for key in sorted(files, key=os.fsencode)},
    }
    value["observation_sha256"] = loom_lifecycle_kernel.digest(value)
    try:
        loom_lifecycle_kernel.validate_reviewed_world_observation(value)
    except loom_lifecycle_kernel.LifecycleKernelError as exc:
        raise OrchestratorError(
            "REVIEWED_WORLD_INVALID",
            f"the reviewed-world evidence is invalid: {exc}") from exc
    return value


def _staged_plan_world(action):
    root = Path(action["explicit_target"] or action["cwd"])
    stage = _project_stage_path(action)
    excluded = [stage]
    plans = root / "plans"
    if _path_present(plans):
        excluded.append(plans)
    return _reviewed_world_observation(
        root, project_id=action["project_id"],
        generation_id=action["generation_id"],
        excluded_paths=tuple(excluded))


def _lifecycle_witness_store(memory, directory, project_id):
    if isinstance(memory, loom_vault_adapter.VaultMemoryAdapter):
        return loom_lifecycle_transition.VaultWitnessStore(
            memory.vault, project_id)
    return loom_lifecycle_transition.FileWitnessStore(
        Path(directory) / "lifecycle-head-witness.json")


def _lifecycle_witness_reader(memory, directory, project_id):
    store = _lifecycle_witness_store(memory, directory, project_id)

    def read(requested_project_id):
        if requested_project_id != project_id:
            raise loom_runtime.RuntimeError(
                "lifecycle witness request belongs to another project")
        try:
            return store.read_optional()
        except loom_lifecycle_transition.LifecycleTransitionError as exc:
            raise loom_runtime.RuntimeError(
                "lifecycle witness cannot be read safely") from exc

    return read


def _action_lifecycle_witness_reader(action, directory):
    root = Path(action["explicit_target"] or action["cwd"])
    instance_id, memory = _memory_backend(
        Path(action["owner_home"]), Path(action["install_root"]), root)
    if instance_id != action["instance_id"]:
        raise OrchestratorError(
            "OWNER_VAULT_CHANGED",
            "the action owner vault no longer matches the active vault")
    try:
        project = loom_runtime.resolve_project(
            instance_id, explicit_target=root, cwd=root)
    except loom_runtime.RuntimeBlocked as exc:
        raise OrchestratorError(exc.code, exc.message) from exc
    if project.project_id != action["project_id"]:
        raise OrchestratorError(
            "PROJECT_CHANGED",
            "the action project identity no longer matches the active target")
    _bind_memory_project(memory, project)
    return _lifecycle_witness_reader(
        memory, directory, action["project_id"])


def _verify_v3_pack_projection(pack, state):
    try:
        pack = Path(pack)
        projection = loom_lifecycle_kernel.project(state)
        observed = {}
        compact = pack / "WO-001.md"
        if compact.is_file() and not compact.is_symlink():
            frontmatter, _ = loom_lint.parse_frontmatter(
                compact.read_text(encoding="utf-8"))
            observed[(frontmatter or {}).get("id")] = (
                frontmatter or {}).get("status")
        else:
            manifest_frontmatter, _ = loom_lint.parse_frontmatter(
                (pack / "MANIFEST.md").read_text(encoding="utf-8"))
            if not isinstance(manifest_frontmatter, dict) \
                    or manifest_frontmatter.get("execution_policy") != \
                    "strict-serial-sequence-v1" \
                    or manifest_frontmatter.get("execution_sequence") != \
                    list(state.graph.execution_sequence) \
                    or manifest_frontmatter.get("execution_policy_sha256") != \
                    loom_plan_author._execution_policy().policy_sha256:
                raise OrchestratorError(
                    "PLAN_PROJECTION_INVALID",
                    "manifest execution projection does not match lifecycle authority")
        for path in sorted((pack / "work-orders").glob("WO-*.md")):
            frontmatter, _ = loom_lint.parse_frontmatter(
                path.read_text(encoding="utf-8"))
            identifier = (frontmatter or {}).get("id")
            if identifier in observed:
                raise OrchestratorError(
                    "PLAN_PROJECTION_INVALID",
                    "work-order projection repeats an identity")
            observed[identifier] = (frontmatter or {}).get("status")
        if observed != projection["work_order_statuses"]:
            raise OrchestratorError(
                "PLAN_PROJECTION_INVALID",
                "work-order statuses do not match lifecycle authority")
    except (OSError, UnicodeError, loom_lifecycle_kernel.LifecycleKernelError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "PLAN_PROJECTION_INVALID",
            f"the plan projection cannot be verified: {exc}") from exc
    return projection


def _replace_frontmatter_status(text, status, *, label):
    if status not in {"ready", "blocked", "in-progress", "done", "cancelled",
                      "gated", "active", "archived"}:
        raise OrchestratorError(
            "PLAN_PROJECTION_INVALID", f"{label} status is invalid")
    pattern = re.compile(r"(?m)^status\s*:.*$")
    matches = list(pattern.finditer(text))
    if len(matches) != 1 or not text.startswith("---\n"):
        raise OrchestratorError(
            "PLAN_PROJECTION_INVALID",
            f"{label} must contain exactly one status projection")
    return pattern.sub(f"status: {status}", text, count=1)


def _ensure_manifest_execution_projection(text, state):
    """Add only a fully derived v3 sequence to a verified historical manifest."""
    frontmatter, _body = loom_lint.parse_frontmatter(text)
    if not isinstance(frontmatter, dict):
        raise OrchestratorError(
            "PLAN_PROJECTION_INVALID", "manifest frontmatter is invalid")
    policy = loom_plan_author._execution_policy()
    expected = {
        "execution_policy": policy.execution_policy,
        "execution_sequence": list(state.graph.execution_sequence),
        "execution_policy_sha256": policy.policy_sha256,
    }
    present = {key for key in expected if key in frontmatter}
    if present:
        if present != set(expected) \
                or any(frontmatter[key] != value
                       for key, value in expected.items()):
            raise OrchestratorError(
                "PLAN_PROJECTION_INVALID",
                "manifest execution projection conflicts with lifecycle authority")
        return text
    close = text.find("\n---", 4) if text.startswith("---\n") else -1
    if close < 0:
        raise OrchestratorError(
            "PLAN_PROJECTION_INVALID", "manifest frontmatter is not closed")
    insertion = (
        "\nexecution_policy: " + policy.execution_policy
        + "\nexecution_sequence: "
        + json.dumps(list(state.graph.execution_sequence), separators=(",", ":"))
        + "\nexecution_policy_sha256: " + policy.policy_sha256)
    return text[:close] + insertion + text[close:]


def _write_v3_pack_projection(pack, state):
    """Apply one reducer-derived projection after the v3 ledger commit."""
    pack = Path(pack)
    projection = loom_lifecycle_kernel.project(state)
    statuses = projection["work_order_statuses"]
    work_order_writes = []
    observed = set()
    try:
        compact = pack / "WO-001.md"
        paths = ([compact] if compact.is_file() and not compact.is_symlink()
                 else sorted((pack / "work-orders").glob("WO-*.md")))
        for path in paths:
            if not path.is_file() or path.is_symlink():
                raise OrchestratorError(
                    "PLAN_PROJECTION_INVALID",
                    "a work-order projection is missing or redirected")
            text = path.read_text(encoding="utf-8")
            frontmatter, _ = loom_lint.parse_frontmatter(text)
            identifier = (frontmatter or {}).get("id")
            if identifier not in statuses or identifier in observed:
                raise OrchestratorError(
                    "PLAN_PROJECTION_INVALID",
                    "work-order projection inventory is inconsistent")
            observed.add(identifier)
            work_order_writes.append((
                path, _replace_frontmatter_status(
                    text, statuses[identifier], label=identifier)))
        if observed != set(statuses):
            raise OrchestratorError(
                "PLAN_PROJECTION_INVALID",
                "work-order projection inventory is incomplete")
        if compact in paths:
            for path, text in work_order_writes:
                loom_gate._atomic_write_text(path, text)
            _verify_v3_pack_projection(pack, state)
            return projection
        manifest_path = pack / "MANIFEST.md"
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest_text = _ensure_manifest_execution_projection(
            manifest_text, state)
        phase_status = (
            "gated" if state.generation_phase == "reviewable" else
            "active" if state.generation_phase == "active" else "archived")
        manifest_text = _replace_frontmatter_status(
            manifest_text, phase_status, label="manifest")
        for identifier, status in statuses.items():
            row = re.compile(
                rf"(?m)^\|\s*{re.escape(identifier)}\s*\|\s*[^|\r\n]+\|")
            rows = list(row.finditer(manifest_text))
            if len(rows) != 1:
                raise OrchestratorError(
                    "PLAN_PROJECTION_INVALID",
                    f"manifest frontier does not contain exactly one {identifier}")
            manifest_text = row.sub(
                f"| {identifier} | {status} |", manifest_text, count=1)
        for path, text in work_order_writes:
            loom_gate._atomic_write_text(path, text)
        loom_gate._atomic_write_text(manifest_path, manifest_text)
    except (OSError, UnicodeError) as exc:
        raise OrchestratorError(
            "PLAN_PROJECTION_INVALID",
            f"the plan projection could not be written safely: {exc}") from exc
    _verify_v3_pack_projection(pack, state)
    return projection


def _ensure_recovered_action_projection(
        action, *, directory, memory, work_order, receipt,
        recoverable_fields=()):
    candidate = dict(action)
    candidate["work_order"] = work_order
    candidate["lifecycle_transition"] = receipt
    if candidate["intent"] != "plan" and candidate["initial_pack_hash"] is None:
        root = Path(candidate["explicit_target"] or candidate["cwd"])
        candidate["initial_pack_hash"] = _pack_hash(root / "plans")
    candidate["action_hash"] = _action_hash(candidate)
    path = _action_path(
        candidate["owner_home"], candidate["instance_id"],
        candidate["project_id"], candidate["action_id"])
    if path.parent != Path(directory):
        raise OrchestratorError(
            "LIFECYCLE_PROJECTION_INVALID",
            "recovered action does not belong to the transition namespace")
    security = (
        (memory.vault.crypto, candidate["instance_id"])
        if isinstance(memory, loom_vault_adapter.VaultMemoryAdapter) else None)
    if _path_present(path):
        _path, existing, _existing_security = _read_action(
            path, owner_home=candidate["owner_home"],
            install_root=candidate["install_root"])
        mutable_recovery_fields = {
            "action_hash", "attempts", "lifecycle_transition",
            *recoverable_fields}
        differing = sorted(
            key for key in set(existing) | set(candidate)
            if existing.get(key) != candidate.get(key))
        if any(key not in mutable_recovery_fields for key in differing) \
                or not candidate["attempts"] <= existing["attempts"] <= \
                candidate["max_attempts"]:
            differing = sorted(
                key for key in set(existing) | set(candidate)
                if existing.get(key) != candidate.get(key))
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "recovered action target contains different authenticated fields: "
                + ", ".join(differing[:16]))
        candidate["attempts"] = existing["attempts"]
        candidate["action_hash"] = _action_hash(candidate)
        if existing != candidate:
            _write_action(path, candidate, security)
            _path, existing, _existing_security = _read_action(
                path, owner_home=candidate["owner_home"],
                install_root=candidate["install_root"])
            if existing != candidate:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered action update could not be verified")
    else:
        _write_action(path, candidate, security)
        _path, existing, _existing_security = _read_action(
            path, owner_home=candidate["owner_home"],
            install_root=candidate["install_root"])
        if existing != candidate:
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "recovered action could not be verified after write")
    pointer = _read_active_pointer(directory)
    expected_pointer = {
        "action_id": candidate["action_id"],
        "project_id": candidate["project_id"],
    }
    if pointer is None:
        _write_active_pointer(
            directory, action_id=candidate["action_id"],
            project_id=candidate["project_id"])
    elif any(pointer[key] != value for key, value in expected_pointer.items()):
        raise OrchestratorError(
            "ACTION_POINTER_CONFLICT",
            "recovered lifecycle action conflicts with the active pointer")
    return candidate


def _recover_pending_v3_lifecycle(
        *, target, directory, memory, project_id, owner_home, install_root):
    """Reconcile every prepared v3 transition before observing a new command."""
    envelope_root = Path(directory) / "lifecycle-transitions"
    if not os.path.lexists(envelope_root):
        return []
    witness_store = _lifecycle_witness_store(memory, directory, project_id)

    def project_generation(prepared):
        resolved = loom_plan_store.resolve(target)
        state = loom_lifecycle_kernel.fold(
            prepared["index"], prepared["semantics"], prepared["ledger"],
            witness_store.read())
        _write_v3_pack_projection(resolved.generation_root, state)

    def recover_projection(envelope, source_state, decision, target_ledger, receipt):
        command = loom_lifecycle_kernel.lifecycle_command(envelope["command"])
        resolved = loom_plan_store.resolve(target)
        semantics = json.loads(
            (resolved.generation_root / "plan-semantics.json").read_text(
                encoding="utf-8"),
            object_pairs_hook=loom_lifecycle._strict_object)
        target_state = loom_lifecycle_kernel.fold(
            resolved.index, semantics, target_ledger, witness_store.read())
        if target_state.project_id != project_id \
                or command.project_id != project_id \
                or receipt["target_authority_sha256"] != \
                target_ledger["lifecycle_sha256"]:
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "recovered lifecycle authority belongs to another project")
        private = envelope["private_projection"]
        relation = command.relation
        if relation in {"start-exact", "continue-active"}:
            action, completion = _open_lifecycle_private_projection(
                private, memory=memory)
            if completion is not None \
                    or private["operation"] != "start" \
                    or action["intent"] != "execute" \
                    or action["action_id"] != command.action_id \
                    or action.get("generation_id") != command.generation_id \
                    or target_state.in_progress_work_order_id is None:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered start projection does not match the committed command")
            expected_event_type = (
                "work-order-resumed"
                if relation == "continue-active"
                and source_state.in_progress_work_order_id is not None
                else "work-order-started")
            started = [
                event for event in target_ledger["events"]
                if event["transition_id"] == receipt["transition_id"]
                and event["event_type"] == expected_event_type]
            if len(started) != 1 \
                    or started[0]["payload"] != {
                        "work_order_id": target_state.in_progress_work_order_id,
                        "action_id": action["action_id"]}:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered start event does not match its action")
            _write_v3_pack_projection(resolved.generation_root, target_state)
            work_order_id, work_order = _active_work_order(
                resolved.generation_root, action["tier"])
            if work_order_id != target_state.in_progress_work_order_id:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered work-order projection does not match lifecycle authority")
            _ensure_recovered_action_projection(
                action, directory=directory, memory=memory,
                work_order=work_order, receipt=receipt)
            return
        if relation == "repair-active":
            action, completion = _open_lifecycle_private_projection(
                private, memory=memory)
            repaired = [
                event for event in target_ledger["events"]
                if event["transition_id"] == receipt["transition_id"]
                and event["event_type"] == "repair-authorized"]
            if completion is not None \
                    or private["operation"] != "repair" \
                    or action["intent"] != "repair" \
                    or action["action_id"] != command.action_id \
                    or action.get("generation_id") != command.generation_id \
                    or len(repaired) != 1 \
                    or repaired[0]["payload"]["action_id"] != action["action_id"] \
                    or repaired[0]["payload"]["affected_scope_sha256"] != \
                    command.affected_scope_sha256:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered repair projection does not match the committed command")
            _write_v3_pack_projection(resolved.generation_root, target_state)
            _ensure_recovered_action_projection(
                action, directory=directory, memory=memory,
                work_order=None, receipt=receipt)
            return
        if relation == "repair-complete":
            action, completion = _open_lifecycle_private_projection(
                private, memory=memory)
            evidence_sha256 = loom_lifecycle_kernel.digest({
                "action_id": action["action_id"],
                "repair_plan": action["repair_plan"],
                "repair_verification": action["host_result"],
                "repaired_world_sha256": command.observed_world_sha256,
            })
            if completion is not None \
                    or private["operation"] != "repair-complete" \
                    or action["intent"] != "repair" \
                    or action["action_id"] != command.action_id \
                    or action.get("generation_id") != command.generation_id \
                    or evidence_sha256 != command.evidence_sha256:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered repair completion owner state does not match")
            repaired = [
                event for event in target_ledger["events"]
                if event["transition_id"] == receipt["transition_id"]
                and event["event_type"] == "repair-completed"]
            if len(repaired) != 1 \
                    or repaired[0]["payload"] != {
                        "work_order_id": command.work_order_id,
                        "action_id": action["action_id"],
                        "repair_evidence_sha256": command.evidence_sha256,
                        "repaired_world_sha256": command.observed_world_sha256,
                    }:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered repair completion does not match its action")
            _write_v3_pack_projection(resolved.generation_root, target_state)
            _ensure_recovered_action_projection(
                action, directory=directory, memory=memory,
                work_order=None, receipt=receipt,
                recoverable_fields={"host_result"})
            return
        if relation == "complete-active":
            action, completion = _open_lifecycle_private_projection(
                private, memory=memory)
            if private["operation"] != "complete" \
                    or action["intent"] != "execute" \
                    or action["action_id"] != command.action_id \
                    or action.get("generation_id") != command.generation_id \
                    or completion["work_order_id"] != command.work_order_id \
                    or completion["completion_sha256"] != command.evidence_sha256 \
                    or completion["completed_world_sha256"] != \
                    command.observed_world_sha256:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered completion projection does not match the committed command")
            completed = [
                event for event in target_ledger["events"]
                if event["transition_id"] == receipt["transition_id"]
                and event["event_type"] == "work-order-completed"]
            if len(completed) != 1 \
                    or completed[0]["payload"] != {
                        "work_order_id": completion["work_order_id"],
                        "completion_sha256": completion["completion_sha256"],
                        "completed_world_sha256": completion[
                            "completed_world_sha256"]}:
                raise OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "recovered completion event does not match its evidence")
            evidence_root = resolved.generation_root / "completion-evidence"
            if os.path.lexists(evidence_root) and (
                    evidence_root.is_symlink() or not evidence_root.is_dir()):
                raise OrchestratorError(
                    "COMPLETION_EVIDENCE_INVALID",
                    "completion evidence namespace is unsafe")
            evidence_root.mkdir(exist_ok=True)
            evidence_path = evidence_root / (
                completion["work_order_id"] + ".json")
            if _path_present(evidence_path):
                existing = json.loads(
                    evidence_path.read_text(encoding="utf-8"),
                    object_pairs_hook=loom_lifecycle._strict_object)
                if existing != completion:
                    raise OrchestratorError(
                        "COMPLETION_EVIDENCE_INVALID",
                        "completion evidence target contains different bytes")
            else:
                loom_reliability.atomic_write_json(evidence_path, completion)
            _write_v3_pack_projection(resolved.generation_root, target_state)
            _ensure_recovered_action_projection(
                action, directory=directory, memory=memory,
                work_order=action["work_order"], receipt=receipt)
            return
        if private is not None:
            raise OrchestratorError(
                "LIFECYCLE_PROJECTION_INVALID",
                "non-action lifecycle transition carries private action state")
        _write_v3_pack_projection(resolved.generation_root, target_state)
        if relation in {"cancel-generation", "supersede-generation"}:
            pointer = _read_active_pointer(directory)
            if pointer is None:
                return
            action_path = Path(directory) / f"{pointer['action_id']}.json"
            path, action, security = _read_action(
                action_path, owner_home=owner_home, install_root=install_root)
            if action["project_id"] != project_id \
                    or action.get("generation_id") != source_state.generation_id:
                raise OrchestratorError(
                    "ACTION_POINTER_CONFLICT",
                    "active action does not belong to the recovered generation")
            if action["status"] not in TERMINAL_ACTION_STATUSES:
                action["status"] = (
                    "superseded" if relation == "supersede-generation"
                    else "cancelled")
                _write_action(path, action, security)
            _clear_active_pointer(directory, action["action_id"])

    try:
        return loom_lifecycle_transition.recover_pending(
            target, witness_store=witness_store,
            envelope_root=envelope_root,
            lock_path=_orchestration_lock(directory),
            activation_projection=project_generation,
            legacy_projection=project_generation,
            recovery_projection=recover_projection,
            _lock_held=True)
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_lifecycle_transition.LifecycleTransitionError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_plan_store.PlanStoreError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "LIFECYCLE_RECOVERY_INDETERMINATE",
            f"pending lifecycle transition cannot be reconciled safely: {exc}") from exc


def _v3_completion_records(pack, state, reviewed_world):
    directory = Path(pack) / "completion-evidence"
    records = []
    for identifier in state.completed_work_orders:
        path = directory / f"{identifier}.json"
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object)
            loom_gate.validate_work_order_completion_evidence(value)
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                ValueError, loom_lifecycle.LifecycleError) as exc:
            raise OrchestratorError(
                "COMPLETION_EVIDENCE_INVALID",
                f"prior completion evidence is missing or invalid: {exc}") from exc
        if value["work_order_id"] != identifier \
                or value["project_id"] != state.project_id \
                or value["generation_id"] != state.generation_id \
                or value["reviewed_world_observation_sha256"] != \
                reviewed_world["observation_sha256"]:
            raise OrchestratorError(
                "COMPLETION_EVIDENCE_INVALID",
                "prior completion evidence does not match lifecycle authority")
        records.append(value)
    if directory.exists():
        try:
            observed = sorted(
                path.name for path in directory.iterdir()
                if path.is_file() and not path.is_symlink())
        except OSError as exc:
            raise OrchestratorError(
                "COMPLETION_EVIDENCE_INVALID",
                f"completion evidence inventory is unavailable: {exc}") from exc
        expected = sorted(f"{identifier}.json"
                          for identifier in state.completed_work_orders)
        if observed != expected:
            raise OrchestratorError(
                "COMPLETION_EVIDENCE_INVALID",
                "completion evidence inventory is unexpected or incomplete")
    return records


def _v3_repair_scope(action, resolved, state, semantics, reviewed_world):
    expected_files = dict(reviewed_world["files"])
    for completion in _v3_completion_records(
            resolved.generation_root, state, reviewed_world):
        for path, digest in completion["after_hashes"].items():
            if digest is None:
                expected_files.pop(path, None)
            else:
                expected_files[path] = digest
    current = _reviewed_world_observation(
        Path(action["explicit_target"] or action["cwd"]),
        project_id=action["project_id"],
        generation_id=action["generation_id"],
        excluded_paths=(
            Path(action["explicit_target"] or action["cwd"]) / "plans",))
    changed_paths = sorted(
        (
            path for path in set(expected_files) | set(current["files"])
            if expected_files.get(path) != current["files"].get(path)
        ),
        key=os.fsencode)
    selected = state.in_progress_work_order_id or state.selected_work_order_id
    work_orders = {
        dict(item)["id"]: dict(item) for item in semantics.work_orders}
    touches = tuple(work_orders.get(selected, {}).get("touches", ()))
    outside = [
        path for path in changed_paths
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in touches)]
    if not changed_paths:
        raise OrchestratorError(
            "REPAIR_SCOPE_INDETERMINATE",
            "the active generation has no exact product-world difference to repair")
    if selected is None or not touches or outside:
        raise OrchestratorError(
            "REPAIR_REPLAN_REQUIRED",
            "changed product paths escape the active reviewed work order; "
            "supersede and review a new plan")
    plan = {
        "changed_paths": changed_paths,
        "affected_plan_sections": ["active-work-order"],
        "regate_scope": "selective",
        "prior_state_hash": state.expected_world_sha256,
        "current_state_hash": current["state_sha256"],
        "force_full": False,
        "program_impact": None,
    }
    scope_sha256 = loom_lifecycle_kernel.digest({
        "changed_paths": changed_paths,
        "prior_state_hash": plan["prior_state_hash"],
        "current_state_hash": plan["current_state_hash"],
        "work_order_id": selected,
    })
    return plan, scope_sha256, current


def _observe_v3_repair_scope(
        action, action_path, memory, *, require_action_world=True):
    """Preflight an exact active-generation repair without mutating authority."""
    root = Path(action["explicit_target"] or action["cwd"])
    witness_store = _lifecycle_witness_store(
        memory, Path(action_path).parent, action["project_id"])
    try:
        resolved, semantics_value, _ledger, _witness, state = \
            loom_lifecycle_transition.observe(
                root, witness_store=witness_store)
        semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
            semantics_value)
        reviewed_world = loom_lifecycle_kernel.validate_reviewed_world_observation(
            json.loads(
                (resolved.generation_root / "reviewed-world.json").read_text(
                    encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object))
        if state.generation_phase != "active" \
                or state.repair_action_id is not None \
                or resolved.generation_id != action.get("generation_id"):
            raise OrchestratorError(
                "REPAIR_SCOPE_INDETERMINATE",
                "the exact active generation cannot accept a repair attempt")
        repair_plan, affected_scope_sha256, current = _v3_repair_scope(
            action, resolved, state, semantics, reviewed_world)
        if require_action_world \
                and current["state_sha256"] != action["survey_hash"]:
            raise OrchestratorError(
                "TARGET_DRIFT",
                "the product world changed while the repair action was prepared")
        return {
            "root": root,
            "witness_store": witness_store,
            "resolved": resolved,
            "semantics_value": semantics_value,
            "state": state,
            "repair_plan": repair_plan,
            "affected_scope_sha256": affected_scope_sha256,
            "current": current,
        }
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_lifecycle_transition.LifecycleTransitionError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "REPAIR_SCOPE_INDETERMINATE",
            f"v3 repair scope cannot be established safely: {exc}") from exc


def _prepare_v3_repair_action(action, action_path, memory):
    observed = _observe_v3_repair_scope(action, action_path, memory)
    root = observed["root"]
    witness_store = observed["witness_store"]
    semantics_value = observed["semantics_value"]
    state = observed["state"]
    repair_plan = observed["repair_plan"]
    affected_scope_sha256 = observed["affected_scope_sha256"]
    current = observed["current"]
    action["repair_plan"] = repair_plan
    try:

        def project_repair(_source_state, _decision, target_ledger):
            current_resolved = loom_plan_store.resolve(root)
            target_state = loom_lifecycle_kernel.fold(
                current_resolved.index, semantics_value, target_ledger,
                witness_store.read())
            _write_v3_pack_projection(
                current_resolved.generation_root, target_state)

        command = {
            "schema_version": 1,
            "command_id": "repair-" + action["action_id"],
            "relation": "repair-active",
            "project_id": action["project_id"],
            "generation_id": action["generation_id"],
            "plan_semantics_sha256": state.plan_semantics_sha256,
            "observed_world_sha256": current["state_sha256"],
            "action_id": action["action_id"],
            "work_order_id": None,
            "evidence_sha256": None,
            "affected_scope_sha256": affected_scope_sha256,
            "successor_generation_id": None,
            "reason_code": None,
        }
        result = loom_lifecycle_transition.transition(
            root, command, witness_store=witness_store,
            envelope_root=Path(action_path).parent / "lifecycle-transitions",
            project_projection=project_repair,
            lock_path=_orchestration_lock(Path(action_path).parent),
            private_projection=_lifecycle_private_projection(
                action, operation="repair", memory=memory),
            _lock_held=True)
        if not result["accepted"] or result["status"] != "completed" \
                or not isinstance(result["receipt"], dict):
            raise OrchestratorError(
                result["primary_code"],
                "the v3 repair attempt was rejected without mutation")
        action["lifecycle_transition"] = result["receipt"]
        return repair_plan
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_lifecycle_transition.LifecycleTransitionError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "REPAIR_SCOPE_INDETERMINATE",
            f"v3 repair scope cannot be sealed safely: {exc}") from exc


def _seal_v3_execution_completion(action, action_path, memory):
    root = Path(action["explicit_target"] or action["cwd"])
    try:
        resolved = loom_plan_store.resolve(root)
        if resolved.index is None or resolved.index.generation_id != \
                action.get("generation_id"):
            raise OrchestratorError(
                "COMPLETION_NOT_AUTHORIZED",
                "the action generation is no longer active")
        semantics_value = json.loads(
            (resolved.generation_root / "plan-semantics.json").read_text(
                encoding="utf-8"))
        reviewed_world = loom_lifecycle_kernel.validate_reviewed_world_observation(
            json.loads(
                (resolved.generation_root / "reviewed-world.json").read_text(
                    encoding="utf-8")))
        witness_store = _lifecycle_witness_store(
            memory, Path(action_path).parent, action["project_id"])
        ledger_value = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        index_value = {
            "schema_version": 1,
            "project_id": resolved.index.project_id,
            "generation_id": resolved.index.generation_id,
            "storage_kind": resolved.index.storage_kind,
            "generation_path": resolved.index.generation_path,
            "index_sha256": resolved.index.index_sha256,
        }
        state = loom_lifecycle_kernel.fold(
            index_value, semantics_value, ledger_value, witness_store.read())
        work_order_path = resolved.generation_root / action["work_order"]
        frontmatter, _ = loom_lint.parse_frontmatter(
            work_order_path.read_text(encoding="utf-8"))
        work_order_id = (frontmatter or {}).get("id")
        prior = _v3_completion_records(
            resolved.generation_root, state, reviewed_world)
        if state.in_progress_work_order_id != work_order_id:
            receipt = action.get("lifecycle_transition")
            completed = next(
                (item for item in prior
                 if item["work_order_id"] == work_order_id), None)
            events = [
                event for event in ledger_value["events"]
                if isinstance(receipt, dict)
                and event["transition_id"] == receipt.get("transition_id")
                and event["event_type"] == "work-order-completed"]
            if completed is not None \
                    and isinstance(receipt, dict) \
                    and receipt.get("status") == "completed" \
                    and receipt.get("command_id") == \
                    "complete-" + action["action_id"] \
                    and receipt.get("project_id") == action["project_id"] \
                    and receipt.get("generation_id") == action["generation_id"] \
                    and receipt.get("target_authority_sha256") == \
                    ledger_value["lifecycle_sha256"] \
                    and len(events) == 1 \
                    and events[0]["payload"] == {
                        "work_order_id": work_order_id,
                        "completion_sha256": completed["completion_sha256"],
                        "completed_world_sha256": completed[
                            "completed_world_sha256"]}:
                return {
                    "completion": completed,
                    "transition": {
                        "accepted": True,
                        "primary_code": "COMPLETION_ACCEPTED",
                        "status": "completed",
                        "transition_id": receipt["transition_id"],
                        "receipt": receipt,
                    },
                }
            raise OrchestratorError(
                "COMPLETION_NOT_AUTHORIZED",
                "the action does not own the canonical in-progress work order")
        try:
            completion = loom_gate.evaluate_work_order_completion(
                resolved.generation_root, root, work_order_path,
                project_id=action["project_id"],
                generation_id=action["generation_id"],
                reviewed_world_observation_sha256=reviewed_world[
                    "observation_sha256"],
                baseline_files=reviewed_world["files"],
                prior_completions=prior)
        except (ValueError, loom_lifecycle.LifecycleError) as exc:
            return {
                "completion": None,
                "transition": None,
                "blocked_message": loom_block_reason.safe_text(
                    " ".join(str(exc).split())[:320],
                    "completion evidence was rejected and unsafe detail was withheld"),
            }

        def project_completion(_source_state, _decision, target_ledger):
            current = loom_plan_store.resolve(root)
            target_state = loom_lifecycle_kernel.fold(
                index_value, semantics_value, target_ledger,
                witness_store.read())
            directory = current.generation_root / "completion-evidence"
            if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
                raise OrchestratorError(
                    "COMPLETION_EVIDENCE_INVALID",
                    "completion evidence namespace is unsafe")
            directory.mkdir(exist_ok=True)
            evidence_path = directory / f"{work_order_id}.json"
            if os.path.lexists(evidence_path):
                if evidence_path.is_symlink() or not evidence_path.is_file():
                    raise OrchestratorError(
                        "COMPLETION_EVIDENCE_INVALID",
                        "completion evidence target is unsafe")
                existing = json.loads(
                    evidence_path.read_text(encoding="utf-8"),
                    object_pairs_hook=loom_lifecycle._strict_object)
                if existing != completion:
                    raise OrchestratorError(
                        "COMPLETION_EVIDENCE_INVALID",
                        "completion evidence target already contains different bytes")
            else:
                loom_reliability.atomic_write_json(evidence_path, completion)
            _write_v3_pack_projection(current.generation_root, target_state)

        command = {
            "schema_version": 1,
            "command_id": "complete-" + action["action_id"],
            "relation": "complete-active",
            "project_id": action["project_id"],
            "generation_id": action["generation_id"],
            "plan_semantics_sha256": state.plan_semantics_sha256,
            "observed_world_sha256": completion["completed_world_sha256"],
            "action_id": action["action_id"],
            "work_order_id": work_order_id,
            "evidence_sha256": completion["completion_sha256"],
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        }
        result = loom_lifecycle_transition.transition(
            root, command, witness_store=witness_store,
            envelope_root=Path(action_path).parent / "lifecycle-transitions",
            project_projection=project_completion,
            lock_path=_orchestration_lock(Path(action_path).parent),
            private_projection=_lifecycle_private_projection(
                action, operation="complete", memory=memory,
                completion=completion),
            _lock_held=True)
        if not result["accepted"] or result["status"] != "completed" \
                or not isinstance(result["receipt"], dict):
            raise OrchestratorError(
                "COMPLETION_NOT_AUTHORIZED",
                "v3 completion was rejected: " + result["primary_code"])
        action["lifecycle_transition"] = result["receipt"]
        return {"completion": completion, "transition": result}
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_lifecycle_transition.LifecycleTransitionError,
            loom_lifecycle.LifecycleError, ValueError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "COMPLETION_NOT_AUTHORIZED",
            f"v3 completion could not be sealed safely: {exc}") from exc


def _seal_v3_repair_completion(action, action_path, memory):
    root = Path(action["explicit_target"] or action["cwd"])
    try:
        resolved = loom_plan_store.resolve(root)
        if resolved.index is None \
                or resolved.index.generation_id != action.get("generation_id"):
            raise OrchestratorError(
                "REPAIR_COMPLETION_NOT_AUTHORIZED",
                "the repair generation is no longer active")
        semantics_value = json.loads(
            (resolved.generation_root / "plan-semantics.json").read_text(
                encoding="utf-8"),
            object_pairs_hook=loom_lifecycle._strict_object)
        witness_store = _lifecycle_witness_store(
            memory, Path(action_path).parent, action["project_id"])
        ledger_value = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"),
            object_pairs_hook=loom_lifecycle._strict_object)
        state = loom_lifecycle_kernel.fold(
            resolved.index, semantics_value, ledger_value,
            witness_store.read())
        current = _reviewed_world_observation(
            root, project_id=action["project_id"],
            generation_id=action["generation_id"],
            excluded_paths=(root / "plans",))
        if current["state_sha256"] != action["survey_hash"]:
            raise OrchestratorError(
                "TARGET_DRIFT",
                "the product world changed during repair verification")
        evidence_sha256 = loom_lifecycle_kernel.digest({
            "action_id": action["action_id"],
            "repair_plan": action["repair_plan"],
            "repair_verification": action["host_result"],
            "repaired_world_sha256": current["state_sha256"],
        })
        receipt = action.get("lifecycle_transition")
        completed_events = [
            event for event in ledger_value["events"]
            if isinstance(receipt, dict)
            and event["transition_id"] == receipt.get("transition_id")
            and event["event_type"] == "repair-completed"]
        if state.repair_action_id is None and len(completed_events) == 1 \
                and isinstance(receipt, dict) \
                and receipt.get("status") == "completed" \
                and receipt.get("command_id") == \
                "repair-complete-" + action["action_id"] \
                and receipt.get("target_authority_sha256") == \
                ledger_value["lifecycle_sha256"] \
                and completed_events[0]["payload"][
                    "repair_evidence_sha256"] == evidence_sha256 \
                and completed_events[0]["payload"][
                    "repaired_world_sha256"] == current["state_sha256"]:
            return {
                "evidence_sha256": evidence_sha256,
                "transition": {
                    "accepted": True,
                    "primary_code": "REPAIR_COMPLETION_ACCEPTED",
                    "status": "completed",
                    "transition_id": receipt["transition_id"],
                    "receipt": receipt,
                },
            }
        scope_sha256 = loom_lifecycle_kernel.digest({
            "changed_paths": action["repair_plan"]["changed_paths"],
            "prior_state_hash": action["repair_plan"]["prior_state_hash"],
            "current_state_hash": action["repair_plan"]["current_state_hash"],
            "work_order_id": state.repair_work_order_id,
        })

        def project_repair_completion(_source_state, _decision, target_ledger):
            current_resolved = loom_plan_store.resolve(root)
            target_state = loom_lifecycle_kernel.fold(
                current_resolved.index, semantics_value, target_ledger,
                witness_store.read())
            _write_v3_pack_projection(
                current_resolved.generation_root, target_state)

        command = {
            "schema_version": 1,
            "command_id": "repair-complete-" + action["action_id"],
            "relation": "repair-complete",
            "project_id": action["project_id"],
            "generation_id": action["generation_id"],
            "plan_semantics_sha256": state.plan_semantics_sha256,
            "observed_world_sha256": current["state_sha256"],
            "action_id": action["action_id"],
            "work_order_id": state.repair_work_order_id,
            "evidence_sha256": evidence_sha256,
            "affected_scope_sha256": scope_sha256,
            "successor_generation_id": None,
            "reason_code": None,
        }
        result = loom_lifecycle_transition.transition(
            root, command, witness_store=witness_store,
            envelope_root=Path(action_path).parent / "lifecycle-transitions",
            project_projection=project_repair_completion,
            lock_path=_orchestration_lock(Path(action_path).parent),
            private_projection=_lifecycle_private_projection(
                action, operation="repair-complete", memory=memory),
            _lock_held=True)
        if not result["accepted"] or result["status"] != "completed" \
                or not isinstance(result["receipt"], dict):
            raise OrchestratorError(
                "REPAIR_COMPLETION_NOT_AUTHORIZED",
                "v3 repair completion was rejected: "
                + result["primary_code"])
        action["lifecycle_transition"] = result["receipt"]
        return {"evidence_sha256": evidence_sha256, "transition": result}
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_lifecycle_transition.LifecycleTransitionError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "REPAIR_COMPLETION_NOT_AUTHORIZED",
            f"v3 repair completion could not be sealed safely: {exc}") from exc


def _activate_reviewed_generation(action, action_path, memory, instant):
    root = Path(action["explicit_target"] or action["cwd"])
    stage = _action_pack_root(action)
    if stage != _project_stage_path(action):
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            "only the exact non-authoritative plan stage can be activated")
    review = (action.get("host_result") or {}).get("plan_review")
    _validate_plan_review_record(review, action=action)
    reviewed_world = _staged_plan_world(action)
    if reviewed_world["state_sha256"] != action["survey_hash"]:
        raise OrchestratorError(
            "TARGET_DRIFT", "product bytes changed before generation activation")
    try:
        semantics = loom_plan_presentation.compile_reviewed_semantics(
            review["semantics"], project_id=action["project_id"],
            generation_id=action["generation_id"],
            revision=review["revision"],
            reviewed_world_sha256=reviewed_world["state_sha256"],
            reviewed_world_observation_sha256=reviewed_world[
                "observation_sha256"],
            plan_contract_sha256=action["plan_contract"]["contract_hash"],
            domain_bindings_sha256=action["domain_contract"][
                "route_digest"].removeprefix("sha256:"),
        )
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            f"reviewed plan semantics cannot be sealed: {exc}") from exc
    index = {
        "schema_version": 1,
        "project_id": action["project_id"],
        "generation_id": action["generation_id"],
        "storage_kind": "generation-dir",
        "generation_path": (
            f"plans/generations/{action['generation_id']}"),
    }
    index["index_sha256"] = loom_lifecycle_kernel.digest(index)
    legacy_lifecycle_name = (
        ".loom-small-lifecycle.json"
        if action["tier"] == "S" else loom_gate.LIFECYCLE_FILE)
    legacy_lifecycle = stage / legacy_lifecycle_name
    witness_store = _lifecycle_witness_store(
        memory, Path(action_path).parent, action["project_id"])
    predecessor_generation_id = None
    predecessor_witness_sha256 = None
    generation_archive_sha256 = None
    if os.path.lexists(root / "plans" / loom_plan_store.INDEX_NAME):
        try:
            (source_resolved, _source_semantics, _source_ledger,
             source_witness, source_state) = loom_lifecycle_transition.observe(
                 root, witness_store=witness_store)
        except loom_lifecycle_transition.LifecycleTransitionError as exc:
            raise OrchestratorError(
                "GENERATION_ACTIVATION_INVALID",
                f"generation predecessor cannot be observed safely: {exc}") from exc
        if not source_state.generation_phase.startswith("terminal-") \
                or action.get("request_control", {}).get("relation") != "new":
            raise OrchestratorError(
                "GENERATION_ACTIVATION_INVALID",
                "a successor generation requires exact terminal new-work authority")
        archive_payload = _generation_archive_payload(
            source_resolved, source_state)
        generation_archive_sha256 = _persist_generation_archive(
            memory, action_path, action, archive_payload)
        predecessor_generation_id = source_state.generation_id
        predecessor_witness_sha256 = source_witness["witness_sha256"]
    try:
        legacy_sha256 = hashlib.sha256(legacy_lifecycle.read_bytes()).hexdigest()
        prepared = loom_lifecycle_transition.prepare_generation_authority(
            stage, index_value=index, semantics_value=semantics,
            reviewed_world_value=reviewed_world,
            command_id="review-generation-" + action["action_id"],
            relation="new",
            predecessor_generation_id=predecessor_generation_id,
            predecessor_witness_sha256=predecessor_witness_sha256,
            replace_lifecycle_sha256=legacy_sha256,
            replace_lifecycle_name=legacy_lifecycle_name)
    except (OSError, loom_lifecycle_transition.LifecycleTransitionError) as exc:
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            f"reviewed generation preparation failed: {exc}") from exc
    def verify_projection(prepared_value):
        resolved = loom_plan_store.resolve(root)
        observed_witness = witness_store.read()
        state = loom_lifecycle_kernel.fold(
            prepared_value["index"], prepared_value["semantics"],
            prepared_value["ledger"], observed_witness)
        _verify_v3_pack_projection(resolved.generation_root, state)

    try:
        result = loom_lifecycle_transition.activate_generation(
            root, stage, prepared, witness_store=witness_store,
            envelope_root=Path(action_path).parent / "lifecycle-transitions",
            lock_path=_orchestration_lock(Path(action_path).parent),
            project_projection=verify_projection, _lock_held=True)
        resolved = loom_plan_store.resolve(root)
        manifest = loom_reliability.exact_tree_manifest(
            resolved.generation_root)
        loom_reliability.validate_exact_tree_manifest(manifest)
    except (
            loom_lifecycle_transition.LifecycleTransitionError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_reliability.ReliabilityError) as exc:
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            f"reviewed generation activation failed: {exc}") from exc
    return {
        "receipt": result["receipt"],
        "manifest": manifest,
        "semantics": semantics,
        "reviewed_world": reviewed_world,
        "generation_root": resolved.generation_root,
        "generation_archive_sha256": generation_archive_sha256,
    }


def _activate_reviewed_revision(action, action_path, memory, instant):
    """Activate one immutable pre-start revision by replacing only the index."""
    root = Path(action["explicit_target"] or action["cwd"])
    stage = _action_pack_root(action)
    if stage != _project_stage_path(action):
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            "only the exact non-authoritative revision stage can be activated")
    revision = (action.get("host_result") or {}).get("plan_revision")
    _validate_plan_revision_record(revision, action=action)
    if revision["schema_version"] != 2:
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            "immutable revision activation requires a v3 generation binding")
    review = (action.get("host_result") or {}).get("plan_review")
    _validate_plan_review_record(review, action=action)
    reviewed_world = _staged_plan_world(action)
    if reviewed_world["state_sha256"] != action["survey_hash"]:
        raise OrchestratorError(
            "TARGET_DRIFT", "product bytes changed before revision activation")
    witness_store = _lifecycle_witness_store(
        memory, Path(action_path).parent, action["project_id"])
    try:
        resolved, source_semantics_value, source_ledger_value, \
            source_witness_value, source_state = \
            loom_lifecycle_transition._observe(root, witness_store)
        source_semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
            source_semantics_value)
        source_world = loom_lifecycle_kernel.validate_reviewed_world_observation(
            json.loads(
                (resolved.generation_root / "reviewed-world.json").read_text(
                    encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object))
        if source_state.generation_phase != "reviewable" \
                or resolved.index.index_sha256 != \
                revision["source_active_index_sha256"] \
                or source_state.generation_id != revision["generation_id"] \
                or source_semantics.plan_semantics_sha256 != \
                revision["source_plan_semantics_sha256"] \
                or source_ledger_value["lifecycle_sha256"] != \
                revision["source_lifecycle_sha256"] \
                or source_witness_value["witness_sha256"] != \
                revision["source_witness_sha256"] \
                or source_semantics.reviewed_world_sha256 != \
                revision["source_reviewed_world_sha256"] \
                or source_world["observation_sha256"] != revision[
                    "source_reviewed_world_observation_sha256"]:
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                "the exact reviewed generation changed before revision activation")
        semantics = loom_plan_presentation.compile_reviewed_semantics(
            review["semantics"], project_id=action["project_id"],
            generation_id=revision["generation_id"],
            revision=revision["revision"],
            reviewed_world_sha256=reviewed_world["state_sha256"],
            reviewed_world_observation_sha256=reviewed_world[
                "observation_sha256"],
            plan_contract_sha256=action["plan_contract"]["contract_hash"],
            domain_bindings_sha256=action["domain_contract"][
                "route_digest"].removeprefix("sha256:"),
        )
        generation_path = (
            f"plans/generations/revisions/{revision['generation_id']}/"
            f"r{revision['revision']:06d}-{semantics['plan_semantics_sha256']}")
        index = {
            "schema_version": 1,
            "project_id": action["project_id"],
            "generation_id": revision["generation_id"],
            "storage_kind": "generation-dir",
            "generation_path": generation_path,
        }
        index["index_sha256"] = loom_lifecycle_kernel.digest(index)
        legacy_lifecycle_name = (
            ".loom-small-lifecycle.json"
            if action["tier"] == "S" else loom_gate.LIFECYCLE_FILE)
        legacy_lifecycle = stage / legacy_lifecycle_name
        legacy_sha256 = hashlib.sha256(legacy_lifecycle.read_bytes()).hexdigest()
        source_index_value = {
            "schema_version": 1,
            "project_id": resolved.index.project_id,
            "generation_id": resolved.index.generation_id,
            "storage_kind": resolved.index.storage_kind,
            "generation_path": resolved.index.generation_path,
            "index_sha256": resolved.index.index_sha256,
        }
        prepared = loom_lifecycle_transition.prepare_revision_authority(
            stage, index_value=index, semantics_value=semantics,
            reviewed_world_value=reviewed_world,
            source_index=source_index_value,
            source_semantics=source_semantics_value,
            source_ledger=source_ledger_value,
            source_witness=source_witness_value,
            command_id="review-revision-" + action["action_id"],
            replace_lifecycle_sha256=legacy_sha256,
            replace_lifecycle_name=legacy_lifecycle_name)
    except (
            OSError, UnicodeError, json.JSONDecodeError, ValueError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_lifecycle_transition.LifecycleTransitionError,
            loom_plan_presentation.PresentationError) as exc:
        if isinstance(exc, OrchestratorError):
            raise
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            f"reviewed revision preparation failed: {exc}") from exc

    def verify_projection(prepared_value):
        current = loom_plan_store.resolve(root)
        state = loom_lifecycle_kernel.fold(
            prepared_value["index"], prepared_value["semantics"],
            prepared_value["ledger"], witness_store.read())
        _verify_v3_pack_projection(current.generation_root, state)

    try:
        result = loom_lifecycle_transition.activate_generation(
            root, stage, prepared, witness_store=witness_store,
            envelope_root=Path(action_path).parent / "lifecycle-transitions",
            lock_path=_orchestration_lock(Path(action_path).parent),
            project_projection=verify_projection, _lock_held=True)
        current = loom_plan_store.resolve(root)
        manifest = loom_reliability.exact_tree_manifest(
            current.generation_root)
        loom_reliability.validate_exact_tree_manifest(manifest)
    except (
            loom_lifecycle_transition.LifecycleTransitionError,
            loom_plan_store.PlanStoreError,
            loom_lifecycle_kernel.LifecycleKernelError,
            loom_reliability.ReliabilityError) as exc:
        raise OrchestratorError(
            "GENERATION_ACTIVATION_INVALID",
            f"reviewed revision activation failed: {exc}") from exc
    return {
        "receipt": result["receipt"], "manifest": manifest,
        "semantics": semantics, "reviewed_world": reviewed_world,
        "generation_root": current.generation_root,
    }


def _completed_plan_review(action, root):
    record = (action.get("host_result") or {}).get("plan_review")
    if record is None:
        return None, None
    _validate_plan_review_record(record, action=action)
    tier = action["tier"]
    if action.get("generation_id") is not None:
        try:
            resolved = loom_plan_store.resolve(root)
            if resolved.index is None \
                    or resolved.index.generation_id != action["generation_id"]:
                raise OrchestratorError(
                    "PLAN_PRESENTATION_INVALID",
                    "the reviewed generation is not the active generation")
            semantics_value = json.loads(
                (resolved.generation_root / "plan-semantics.json").read_text(
                    encoding="utf-8"))
            semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
                semantics_value)
            reviewed_world = loom_lifecycle_kernel.validate_reviewed_world_observation(
                json.loads(
                    (resolved.generation_root / "reviewed-world.json").read_text(
                        encoding="utf-8")))
            relative_path = (
                resolved.generation_root
                / ("WO-001.md" if tier == "S" else "MANIFEST.md")
            ).relative_to(Path(root)).as_posix()
            plan_file = Path(root) / relative_path
            binding = {
                "action_id": action["action_id"],
                "project_id": action["project_id"],
                "world_fingerprint": semantics.reviewed_world_sha256,
                "plan_contract_hash": semantics.plan_contract_sha256,
                "pack_sha256": _pack_hash(resolved.generation_root),
                "revision": semantics.revision_number,
                "relative_path": relative_path,
                "manifest_sha256": hashlib.sha256(
                    plan_file.read_bytes()).hexdigest(),
                "generation_id": semantics.generation_id,
                "plan_semantics_sha256": semantics.plan_semantics_sha256,
                "execution_policy": semantics.execution_policy,
                "execution_sequence_sha256": loom_lifecycle_kernel.digest(
                    semantics.graph.execution_sequence),
                "domain_bindings_sha256": semantics.domain_bindings_sha256,
                "reviewed_world_observation_sha256": reviewed_world[
                    "observation_sha256"],
            }
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                loom_plan_store.PlanStoreError,
                loom_lifecycle_kernel.LifecycleKernelError) as exc:
            if isinstance(exc, OrchestratorError):
                raise
            raise OrchestratorError(
                "PLAN_PRESENTATION_INVALID",
                f"the completed generation cannot be presented safely: {exc}") from exc
    else:
        relative_path = (
            "plans/WO-001.md" if tier == "S" else "plans/MANIFEST.md")
        plan_file = Path(root) / relative_path
        binding = {
            "action_id": action["action_id"],
            "project_id": action["project_id"],
            "world_fingerprint": action["prepared"]["world_fingerprint"],
            "plan_contract_hash": action["plan_contract"]["contract_hash"],
            "pack_sha256": _pack_hash(Path(root) / "plans"),
            "revision": record["revision"],
            "relative_path": relative_path,
            "manifest_sha256": hashlib.sha256(plan_file.read_bytes()).hexdigest(),
        }
    if not plan_file.is_file() or plan_file.is_symlink():
        raise OrchestratorError(
            "PLAN_PRESENTATION_INVALID",
            "the completed plan file is unavailable for review")
    try:
        presentation = loom_plan_presentation.compile_presentation(
            record["semantics"], tier=tier, binding=binding)
        host_projection = loom_plan_presentation.project_for_host(
            presentation, project_root=root,
            host_id=action["assurance"]["host_id"])
    except (OSError, loom_plan_presentation.PresentationError) as exc:
        raise OrchestratorError(
            "PLAN_PRESENTATION_INVALID",
            f"the completed plan could not be presented safely: {exc}") from exc
    record["state"] = "completed"
    return presentation, host_projection


def _completed_plan_revision(action):
    revision = (action.get("host_result") or {}).get("plan_revision")
    if revision is None:
        return None
    _validate_plan_revision_record(revision, action=action)
    current = (action.get("host_result") or {}).get("plan_review")
    _validate_plan_review_record(current, action=action)
    changed = sorted(
        key for key in (
            "title", "summary", "assumptions", "decisions", "work_orders")
        if revision["prior_semantics"][key] != current["semantics"][key])
    if not changed:
        raise OrchestratorError(
            "PLAN_REVISION_EMPTY",
            "the revised plan is semantically identical to the displayed plan")
    return {
        "schema_version": 1,
        "parent_action_id": revision["parent_action_id"],
        "parent_presentation_sha256": revision[
            "parent_presentation_sha256"],
        "parent_pack_sha256": revision["parent_pack_sha256"],
        "revision": revision["revision"],
        "archive_sha256": revision["archive_sha256"],
        "changed_sections": changed,
    }


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
    if not isinstance(value, dict) or value.get("schema_version") not in {2, 3}:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair result fields are invalid")
    expected = action["repair_plan"]["affected_plan_sections"]
    root = Path(action["explicit_target"] or action["cwd"])
    pack = _action_pack_root(action)
    action_file = _action_path(
        action["owner_home"], action["instance_id"], action["project_id"],
        action["action_id"])
    receipt_root = action_file.parent / f"{action['action_id']}.evidence"
    if value["schema_version"] == 3:
        if set(value) != {
                "schema_version", "risk", "verification_requests"} \
                or value["risk"] not in {
                    "low", "medium", "high", "critical"} \
                or not isinstance(value["verification_requests"], list) \
                or not 1 <= len(value["verification_requests"]) <= 32:
            raise OrchestratorError(
                "REPAIR_EVIDENCE_INVALID",
                "compiled repair recipe request fields are invalid")
        try:
            registry = loom_verification_recipe.load_registry(
                Path(action["install_root"]) / "contracts"
                / "verification-recipes-v1.json")
            recipe = loom_verification_recipe.compile_recipe(
                root=root, pack=pack,
                requests=value["verification_requests"],
                expected_sections=expected, risk=value["risk"],
                registry=registry)
            loom_memory._atomic_json(
                receipt_root / "compiled-recipe.json", recipe)
            entries = loom_verification_recipe.execute_recipe(
                recipe=recipe, registry=registry, root=root, pack=pack,
                evidence_root=receipt_root)
        except loom_verification_recipe.RecipeError as exc:
            code = (
                "REPAIR_VERIFICATION_UNSUPPORTED"
                if "unsupported" in str(exc)
                else "REPAIR_VERIFICATION_FAILED")
            raise OrchestratorError(code, str(exc)) from exc
        except (OSError, loom_memory.MemoryError) as exc:
            raise OrchestratorError(
                "REPAIR_VERIFICATION_FAILED", str(exc)) from exc
        return {"schema_version": 3, "repair_verification": entries}
    if set(value) != {"schema_version", "repair_verification"} \
            or not isinstance(value["repair_verification"], list) \
            or not 1 <= len(value["repair_verification"]) <= 32:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair result fields are invalid")
    entries, seen = [], set()
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
    pack = _action_pack_root(action)
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
    if tier != "S":
        manifest = pack / "MANIFEST.md"
        try:
            manifest_frontmatter, _ = loom_lint.parse_frontmatter(
                manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "WORK_ORDER_PROJECTION_INVALID",
                f"reviewed execution sequence is unavailable: {exc}") from exc
        if isinstance(manifest_frontmatter, dict) \
                and manifest_frontmatter.get("execution_policy") is not None:
            records = []
            observed = {}
            paths_by_id = {}
            try:
                paths = sorted((pack / "work-orders").glob("WO-*.md"))
                for path in paths:
                    if not path.is_file() or path.is_symlink():
                        continue
                    frontmatter, _ = loom_lint.parse_frontmatter(
                        path.read_text(encoding="utf-8"))
                    if not isinstance(frontmatter, dict):
                        raise loom_lifecycle_kernel.LifecycleKernelError(
                            "work-order frontmatter is invalid")
                    identifier = frontmatter.get("id")
                    if identifier in observed:
                        raise loom_lifecycle_kernel.LifecycleKernelError(
                            "work-order identities must be unique")
                    records.append({
                        "id": identifier,
                        "depends_on": frontmatter.get("depends_on", []),
                    })
                    observed[identifier] = frontmatter.get("status")
                    paths_by_id[identifier] = path
                graph = loom_lifecycle_kernel.validate_work_order_graph(
                    records, manifest_frontmatter.get("execution_sequence"))
                completed = {
                    identifier for identifier, status in observed.items()
                    if status == "done"}
                in_progress = [
                    identifier for identifier, status in observed.items()
                    if status == "in-progress"]
                if len(in_progress) > 1:
                    raise loom_lifecycle_kernel.LifecycleKernelError(
                        "more than one work order is in progress")
                expected = loom_lifecycle_kernel.project_work_order_statuses(
                    graph, completed=completed,
                    in_progress=(in_progress[0] if in_progress else None))
                if observed != expected:
                    raise loom_lifecycle_kernel.LifecycleKernelError(
                        "work-order statuses do not match the reviewed sequence")
                selection = loom_lifecycle_kernel.select_work_order(
                    graph, completed=completed,
                    in_progress=(in_progress[0] if in_progress else None))
            except (OSError, UnicodeError,
                    loom_lifecycle_kernel.LifecycleKernelError) as exc:
                raise OrchestratorError(
                    "WORK_ORDER_PROJECTION_INVALID",
                    f"reviewed execution sequence is invalid: {exc}") from exc
            if selection.work_order_id is None:
                raise OrchestratorError(
                    "WORK_ORDER_AMBIGUOUS",
                    "reviewed execution sequence has no executable work order")
            path = paths_by_id[selection.work_order_id]
            return selection.work_order_id, path.relative_to(pack).as_posix()
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


def _prepare_execution_pack(
        pack, target, tier, event_at, *, action=None, action_path=None,
        memory=None, plan_decision=None):
    """Preflight executable work before recording legacy-v2 authorization."""
    pack = Path(pack)
    target = Path(target)
    request_relation = (
        (action or {}).get("request_control", {}).get("relation")
        if isinstance(action, dict) else None)
    legacy_adoption = (
        isinstance(plan_decision, dict)
        and plan_decision.get("schema_version") == 3)
    if legacy_adoption:
        if action is None or action_path is None or memory is None:
            raise OrchestratorError(
                "EXECUTION_NOT_READY",
                "historical adoption requires its exact action and witness authority")
        plan_action_path = (
            Path(action_path).parent
            / f"{plan_decision['plan_action_id']}.json")
        try:
            _prior_path, prior_action, _prior_security = _read_action(
                plan_action_path, owner_home=action["owner_home"],
                install_root=action["install_root"])
            presentation = prior_action["result"]["plan_presentation"]
            _validate_authored_plan(
                prior_action, pack_override=target / "plans")
            exact_decision = _exact_plan_decision(
                plan_action_path, plan_decision["presentation_sha256"],
                owner_home=action["owner_home"],
                install_root=action["install_root"], target=target)
            if exact_decision != plan_decision:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "the historical adoption decision changed before execution")
            semantic_draft = _verified_historical_plan_semantics(
                prior_action, presentation)
            reviewed_world = _reviewed_world_observation(
                target, project_id=action["project_id"],
                generation_id=plan_decision["generation_id"],
                excluded_paths=(target / "plans",))
            route_digest = (
                prior_action.get("domain_contract") or {}).get("route_digest")
            domain_digest = (
                route_digest.removeprefix("sha256:")
                if isinstance(route_digest, str)
                and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", route_digest)
                else None)
            semantics = loom_plan_presentation.compile_reviewed_semantics(
                semantic_draft, project_id=action["project_id"],
                generation_id=plan_decision["generation_id"],
                revision=plan_decision["revision"],
                reviewed_world_sha256=reviewed_world["state_sha256"],
                reviewed_world_observation_sha256=reviewed_world[
                    "observation_sha256"],
                plan_contract_sha256=presentation["binding"][
                    "plan_contract_hash"],
                domain_bindings_sha256=domain_digest)
            if semantics["plan_semantics_sha256"] != \
                    plan_decision["plan_semantics_sha256"] \
                    or loom_lifecycle_kernel.digest(
                        semantics["execution_sequence"]) != \
                    plan_decision["execution_sequence_sha256"] \
                    or reviewed_world["state_sha256"] != \
                    plan_decision["reviewed_world_sha256"] \
                    or reviewed_world["observation_sha256"] != \
                    plan_decision["reviewed_world_observation_sha256"]:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "historical adoption material no longer matches its exact decision")
            index = {
                "schema_version": 1,
                "project_id": action["project_id"],
                "generation_id": plan_decision["generation_id"],
                "storage_kind": "legacy-root",
                "generation_path": "plans",
            }
            index["index_sha256"] = loom_lifecycle_kernel.digest(index)
            prepared_adoption = \
                loom_lifecycle_transition.prepare_legacy_adoption(
                    target, index_value=index, semantics_value=semantics,
                    reviewed_world_value=reviewed_world,
                    command_id="adopt-" + action["action_id"],
                    source_lifecycle_name=plan_decision[
                        "source_lifecycle_name"])
            if prepared_adoption["source_lifecycle_sha256"] != \
                    plan_decision["source_lifecycle_sha256"]:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "historical lifecycle bytes changed before adoption")
            witness_store = _lifecycle_witness_store(
                memory, Path(action_path).parent, action["project_id"])

            def project_adoption(prepared_value):
                state = loom_lifecycle_kernel.fold(
                    prepared_value["index"], prepared_value["semantics"],
                    prepared_value["ledger"], witness_store.read())
                _write_v3_pack_projection(target / "plans", state)

            adoption = loom_lifecycle_transition.adopt_legacy_root(
                target, prepared_adoption, witness_store=witness_store,
                envelope_root=Path(action_path).parent / "lifecycle-transitions",
                lock_path=_orchestration_lock(Path(action_path).parent),
                project_projection=project_adoption, _lock_held=True)
            if adoption["status"] != "completed":
                raise OrchestratorError(
                    "EXECUTION_NOT_READY",
                    "historical generation adoption did not commit")
            action["generation_id"] = plan_decision["generation_id"]
        except (
                OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError,
                loom_plan_presentation.PresentationError,
                loom_lifecycle_transition.LifecycleTransitionError) as exc:
            if isinstance(exc, OrchestratorError):
                raise
            raise OrchestratorError(
                "EXECUTION_NOT_READY",
                f"historical generation could not be adopted safely: {exc}") from exc
    v3_start = (
        isinstance(plan_decision, dict)
        and plan_decision.get("schema_version") in {2, 3})
    v3_continue = (
        request_relation == "continue-active"
        and os.path.lexists(pack / loom_plan_store.INDEX_NAME))
    if v3_start or v3_continue:
        if action is None or action_path is None or memory is None:
            raise OrchestratorError(
                "EXECUTION_NOT_READY",
                "v3 execution requires its exact action and witness authority")
        try:
            resolved = loom_plan_store.resolve(target)
            expected_generation_id = (
                plan_decision["generation_id"] if v3_start
                else action.get("generation_id"))
            if resolved.index is None \
                    or resolved.index.generation_id != expected_generation_id:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "the reviewed generation is no longer active")
            witness_store = _lifecycle_witness_store(
                memory, Path(action_path).parent, action["project_id"])
            (_observed, _semantics_value, _ledger_value, _witness_value,
             source_state) = loom_lifecycle_transition.observe(
                 target, witness_store=witness_store)
            transition_relation = (
                "start-exact"
                if v3_start or source_state.generation_phase == "reviewable"
                else "continue-active")
            current_world = _reviewed_world_observation(
                target, project_id=action["project_id"],
                generation_id=expected_generation_id,
                excluded_paths=(target / "plans",))
            if current_world["state_sha256"] != source_state.expected_world_sha256 \
                    or v3_start and (
                        current_world["state_sha256"] != plan_decision[
                            "reviewed_world_sha256"]
                        or current_world["observation_sha256"] != plan_decision[
                            "reviewed_world_observation_sha256"]):
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "the project world changed before reviewed execution")

            def project_start(_source_state, _decision, target_ledger):
                current = loom_plan_store.resolve(target)
                semantics_value = json.loads(
                    (current.generation_root / "plan-semantics.json").read_text(
                        encoding="utf-8"))
                target_state = loom_lifecycle_kernel.fold(
                    {
                        "schema_version": 1,
                        "project_id": current.index.project_id,
                        "generation_id": current.index.generation_id,
                        "storage_kind": current.index.storage_kind,
                        "generation_path": current.index.generation_path,
                        "index_sha256": current.index.index_sha256,
                    },
                    semantics_value, target_ledger, witness_store.read())
                _write_v3_pack_projection(current.generation_root, target_state)

            command = {
                "schema_version": 1,
                "command_id": (
                    "start-" if transition_relation == "start-exact" else "continue-"
                ) + action["action_id"],
                "relation": transition_relation,
                "project_id": action["project_id"],
                "generation_id": expected_generation_id,
                "plan_semantics_sha256": (
                    plan_decision["plan_semantics_sha256"]
                    if v3_start else source_state.plan_semantics_sha256),
                "observed_world_sha256": current_world["state_sha256"],
                "action_id": action["action_id"],
                "work_order_id": None,
                "evidence_sha256": None,
                "affected_scope_sha256": None,
                "successor_generation_id": None,
                "reason_code": None,
            }
            transition_result = loom_lifecycle_transition.transition(
                target, command, witness_store=witness_store,
                envelope_root=Path(action_path).parent / "lifecycle-transitions",
                project_projection=project_start,
                lock_path=_orchestration_lock(Path(action_path).parent),
                private_projection=_lifecycle_private_projection(
                    action, operation="start", memory=memory),
                _lock_held=True)
            if not transition_result["accepted"] \
                    or transition_result["status"] != "completed" \
                    or not isinstance(transition_result["receipt"], dict):
                raise OrchestratorError(
                    "EXECUTION_NOT_READY",
                    "v3 reviewed execution was rejected: "
                    + transition_result["primary_code"])
            action["lifecycle_transition"] = transition_result["receipt"]
            post = loom_plan_store.resolve(target)
            work_order_id, work_order_path = _active_work_order(
                post.generation_root, tier)
            return work_order_id, work_order_path
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                loom_plan_store.PlanStoreError,
                loom_lifecycle_kernel.LifecycleKernelError,
                loom_lifecycle_transition.LifecycleTransitionError) as exc:
            if isinstance(exc, OrchestratorError):
                raise
            raise OrchestratorError(
                "EXECUTION_NOT_READY",
                f"v3 reviewed execution could not be sealed safely: {exc}") from exc
    work_order_id, work_order_path = _active_work_order(pack, tier)
    if tier == "S":
        record = pack / ".loom-small-lifecycle.json"
        lifecycle = json.loads(record.read_text(encoding="utf-8"))
        if [event["event"] for event in lifecycle["events"]] \
                == loom_gate.SMALL_EVENT_ORDER[:2]:
            code, output = _capture(
                loom_gate.small_authorize, record, target,
                pack / "WO-001.md", event_at)
            if code:
                raise OrchestratorError("EXECUTION_NOT_READY", output)
        findings = loom_gate.verify_small(record, require_authorized=True)
    else:
        lifecycle = json.loads(
            (pack / loom_gate.LIFECYCLE_FILE).read_text(encoding="utf-8"))
        if [event["event"] for event in lifecycle["events"]] \
                == loom_gate.EVENT_ORDER[:2]:
            code, output = _capture(
                loom_gate.authorize, pack, target, event_at)
            if code:
                raise OrchestratorError("EXECUTION_NOT_READY", output)
        report = loom_lint.lint(
            pack, repo_path=target, strict_staleness=True)
        findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
        findings.extend(loom_gate.verify(
            pack, target, require_authorized=True))
    if findings:
        raise OrchestratorError(
            "EXECUTION_NOT_READY", "; ".join(findings[:8]))
    return work_order_id, work_order_path


def _refresh_proofline_completion(pack, root, policy_path):
    proofline = pack / "proofline"
    if not (proofline / "material-intent-ledger.json").is_file() \
            and not (proofline / "proof-graph.json").is_file():
        return None
    try:
        report = loom_proofline_completion.evaluate_pack(
            pack, root, policy_path=policy_path)
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_lifecycle.LifecycleError,
            loom_proofline.ProoflineError,
            loom_proofline_completion.CompletionError) as exc:
        raise OrchestratorError(
            "PROOFLINE_COMPLETION_INVALID",
            f"Proofline completion could not be derived safely: {exc}") from exc
    if report["gate"]["state"] == "failed":
        raise OrchestratorError(
            "PROOFLINE_ORPHAN_CHANGE",
            "changed project paths fall outside the declared work-order scope: "
            + ", ".join(report["gate"]["orphan_paths"][:8]))
    loom_reliability.atomic_write_json(
        proofline / "completion-report.json", report)
    return report


def _write_contract_rebase(
        pack, prepared, changed_paths, install_root, *, current_consequence):
    proofline = pack / "proofline"
    ledger_path = proofline / "material-intent-ledger.json"
    graph_path = proofline / "proof-graph.json"
    if not ledger_path.is_file() and not graph_path.is_file():
        return None
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        consequences = sorted({
            atom["consequence"] for atom in ledger["atoms"]})
        if len(consequences) != 1:
            raise loom_contract_rebase.RebaseError(
                "prior consequence is not singular")
        report = loom_contract_rebase.evaluate(
            ledger=ledger, graph=graph,
            work_orders=loom_contract_rebase.work_orders_from_pack(pack),
            changed_paths=changed_paths,
            prior_consequence=consequences[0],
            current_consequence=current_consequence,
            world_coverage_complete=prepared.project_inspection[
                "relevant_coverage_complete"],
            domain_state=(
                "unknown" if prepared.route_contract["needs_owner"]
                else "consistent"),
            policy=loom_contract_rebase.load_policy(
                Path(install_root) / "contracts"
                / "contract-rebase-policy-v1.json"))
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            KeyError, loom_proofline.ProoflineError,
            loom_contract_rebase.RebaseError) as exc:
        raise OrchestratorError(
            "CONTRACT_REBASE_INDETERMINATE",
            f"drift preservation could not be derived safely: {exc}") from exc
    loom_reliability.atomic_write_json(
        proofline / "contract-rebase.json", report)
    return report


def _handler_result(context, root, owner_home, usage, work_order=None,
                    repair_plan=None, host_result=None, memory_adapter=None,
                    seal_plan_author=None, proofline_policy=None,
                    pack_root=None, seal_execution_completion=None,
                    seal_repair_completion=None):
    pack = Path(pack_root) if pack_root is not None else root / "plans"
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
                    loom_gate.small_seal, record, root, work_order,
                    context.prepared.prepared_at)
                logs.append(output)
                if code:
                    findings = ["Tier-S plan sealing failed: " + output]
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
                    if code:
                        findings = ["G1 sealing failed"]
                if not findings:
                    findings = loom_gate.verify(pack, root)
        if findings:
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": "plan-not-release-ready",
                "success": False, "metrics": {},
                "evidence_ids": [failure_evidence],
                "reversible_action_ids": [], "usage": usage,
                "user_message": "Plan validation blocked: " + "; ".join(findings[:8]),
            }
        if proofline_policy is not None:
            _refresh_proofline_completion(pack, root, proofline_policy)
        evidence = "pack-" + _pack_hash(pack)[:24]
        reversible_action_ids = []
        presented_plan = pack / ("WO-001.md" if tier == "S" else "MANIFEST.md")
        if seal_plan_author is not None:
            reversible_action_ids = [seal_plan_author(memory_adapter)]
            try:
                presented_plan = loom_plan_store.resolve(root).generation_root / (
                    "WO-001.md" if tier == "S" else "MANIFEST.md")
            except loom_plan_store.PlanStoreError as exc:
                raise OrchestratorError(
                    "PLAN_STORE_INVALID",
                    f"activated plan cannot be resolved: {exc}") from exc
        return {
            "status": "completed", "code": "plan-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": reversible_action_ids, "usage": usage,
            "user_message": (
                "LOOM_RESULT "
                f"{presented_plan.relative_to(root).as_posix()}"
                " | The plan is validated and ready for review."),
        }

    if intent == "execute":
        if seal_execution_completion is not None:
            sealed = seal_execution_completion(memory_adapter)
            completion = sealed["completion"]
            if completion is None:
                findings = [sealed["blocked_message"]]
                return {
                    "status": "blocked", "code": "execute-not-ready",
                    "success": False, "metrics": {},
                    "evidence_ids": ["gate-" + _hash(findings)[:24]],
                    "reversible_action_ids": [], "usage": usage,
                    "user_message": "Execute blocked: " + findings[0],
                }
            evidence = "execute-" + completion["completion_sha256"][:24]
            return {
                "status": "completed", "code": "execute-complete",
                "success": True, "metrics": {},
                "evidence_ids": [evidence],
                "reversible_action_ids": [], "usage": usage,
                "result_path": (
                    f"{pack.relative_to(root).as_posix()}/completion-evidence/"
                    f"{completion['work_order_id']}.json"),
                "user_message": (
                    "Execution completion was causally sealed against the "
                    f"declared work order ({evidence})."),
            }
        lifecycle_path = (
            pack / ".loom-small-lifecycle.json"
            if tier == "S" else pack / loom_gate.LIFECYCLE_FILE)
        rollback_paths = [lifecycle_path]
        if tier != "S":
            rollback_paths.append(pack / "MANIFEST.md")
        try:
            rollback_text = {
                path: path.read_text(encoding="utf-8")
                for path in rollback_paths
            }
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "PROOFLINE_COMPLETION_INVALID",
                f"lifecycle rollback evidence is unavailable: {exc}") from exc
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
        if not findings and proofline_policy is not None:
            try:
                _refresh_proofline_completion(pack, root, proofline_policy)
            except BaseException:
                for path, text in rollback_text.items():
                    loom_gate._atomic_write_text(path, text)
                raise
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
            "result_path": "plans/proofline/trust-card.json",
            "user_message": (
                "Execution completion was causally sealed against the declared "
                f"work order ({evidence})."),
        }

    if intent == "repair":
        if seal_repair_completion is not None:
            sealed = seal_repair_completion(memory_adapter)
            evidence = "repair-" + sealed["evidence_sha256"][:24]
            return {
                "status": "completed", "code": "repair-complete",
                "success": True,
                "metrics": {"drift-caught-before-execution": 1},
                "evidence_ids": [evidence],
                "reversible_action_ids": [], "usage": usage,
                "user_message": (
                    "Repair was verified and sealed against the active "
                    f"generation ({evidence})."),
            }
        if tier == "S":
            record, compact_wo = (
                pack / ".loom-small-lifecycle.json", pack / "WO-001.md")
            if repair_plan is None or host_result is None:
                raise OrchestratorError(
                    "REPAIR_EVIDENCE_REQUIRED", "sealed compact-plan evidence is missing")
            code, output = _capture(
                loom_gate.small_seal, record, root, compact_wo,
                context.prepared.prepared_at)
            findings = (["Tier-S repair plan sealing failed: " + output] if code else [])
            if not findings:
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
            lifecycle = json.loads(
                (pack / loom_gate.LIFECYCLE_FILE).read_text(encoding="utf-8"))
            event_names = [event["event"] for event in lifecycle["events"]]
            if event_names == loom_gate.EVENT_ORDER[:2]:
                code, output = _capture(
                    loom_gate.authorize, pack, root,
                    context.prepared.prepared_at)
                if code:
                    raise OrchestratorError(
                        "REPAIR_REAUTHORIZATION_FAILED", output)
            elif event_names != loom_gate.EVENT_ORDER:
                raise OrchestratorError(
                    "REPAIR_REAUTHORIZATION_FAILED",
                    "repair produced an invalid lifecycle authorization state")
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
        if record.get("status") == "forgotten":
            return {
                "status": "blocked", "code": "memory-remains-forgotten",
                "success": False, "metrics": {},
                "evidence_ids": ["memory-tombstone-" + record["id"]],
                "reversible_action_ids": [], "usage": usage,
                "user_message": (
                    "Not remembered. This information remains permanently forgotten."),
            }
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
                     repair_plan=None, host_result=None, memory_adapter=None,
                     seal_plan_author=None, proofline_policy=None,
                     pack_root=None, seal_execution_completion=None,
                     seal_repair_completion=None):
    """Return the complete audited production handler registry."""
    root, owner_home = Path(root), Path(owner_home)
    normalized = loom_performance.normalize_usage(usage)
    usage_payload = loom_performance.measured_usage_payload(normalized)
    return {
        intent: (lambda context, _intent=intent: _merge_host_outcome(
            _handler_result(context, root, owner_home, usage_payload, work_order,
                            repair_plan, host_result, memory_adapter,
                            seal_plan_author, proofline_policy,
                            pack_root, seal_execution_completion,
                            seal_repair_completion), host_result))
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
            and not loom_owner.owner_vault_path(candidate).exists()
    except (OSError, RuntimeError, TypeError, ValueError, loom_owner.OwnerError):
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


def _bind_memory_project(memory, project):
    binder = getattr(memory, "bind_project_state", None)
    if binder is None:
        return
    try:
        binder(project.project_id, project.state_mode)
    except loom_vault_adapter.VaultAdapterError as exc:
        raise OrchestratorError(
            "PROJECT_INDETERMINATE",
            f"owner memory could not bind the resolved project state: {exc}") from exc


def _controller(
        action, *, usage=None, seal_plan_author=None,
        seal_execution_completion=None, seal_repair_completion=None):
    home = Path(action["owner_home"])
    root = Path(action["explicit_target"] or action["cwd"])
    instance_id, memory = _memory_backend(home, action["install_root"], root)
    if instance_id != action["instance_id"]:
        raise OrchestratorError(
            "OWNER_VAULT_CHANGED", "the action owner vault no longer matches the active vault")
    try:
        project = loom_runtime.resolve_project(
            instance_id, explicit_target=root, cwd=root)
    except loom_runtime.RuntimeBlocked as exc:
        raise OrchestratorError(exc.code, exc.message) from exc
    if project.project_id != action["project_id"]:
        raise OrchestratorError(
            "PROJECT_CHANGED",
            "the action project identity no longer matches the active target")
    _bind_memory_project(memory, project)
    handlers = default_handlers(
        root=root, owner_home=home, usage=usage,
        work_order=action.get("work_order"),
        repair_plan=action.get("repair_plan"), host_result=action.get("host_result"),
        memory_adapter=memory, seal_plan_author=seal_plan_author,
        pack_root=_action_pack_root(action),
        seal_execution_completion=seal_execution_completion,
        seal_repair_completion=seal_repair_completion,
        proofline_policy=(
            Path(action["install_root"]) / "contracts"
            / "proofline-policy-v1.json"))
    pack = root / "plans"
    receipt_observer = None
    if (pack / "proofline" / "material-intent-ledger.json").is_file():
        def receipt_observer(receipt):
            if (pack / "proofline" / "completion-report.json").is_file():
                loom_proofline_ux.record_receipt(pack, receipt)
    return loom_session.SessionController(
        owner_home=home, instance_id=instance_id,
        handlers=handlers, memory=memory,
        receipt_observer=receipt_observer)


def _plan_undo_handler(action, memory, *, now):
    """Undo the latest exact, unchanged plan pack before falling back to memory undo."""
    directory = _orchestration_directory(
        action["owner_home"], action["instance_id"], action["project_id"])
    candidates = []
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise OrchestratorError(
            "PLAN_UNDO_INDETERMINATE",
            f"plan history cannot be inspected safely: {exc}") from exc
    action_paths = [
        path for path in entries
        if re.fullmatch(r"[0-9a-f-]{36}\.json", path.name)
    ]
    if len(action_paths) > MAX_ORCHESTRATION_ACTIONS:
        raise OrchestratorError(
            "PLAN_UNDO_INDETERMINATE", "plan history exceeds its bounded action inventory")
    for candidate_path in action_paths:
        _candidate_path, candidate, security = _read_action(
            candidate_path, owner_home=action["owner_home"],
            install_root=action["install_root"])
        record = (
            (candidate.get("host_result") or {}).get("plan_author")
            if candidate.get("intent") == "plan"
            and candidate.get("status") == "completed" else None)
        if record is not None and record["state"] == "active" \
                and candidate["project_id"] == action["project_id"] \
                and candidate["explicit_target"] == action["explicit_target"]:
            candidates.append((candidate["created_at"], candidate_path,
                               candidate, security, record))
    if not candidates:
        undo = getattr(memory, "undo_latest", None)
        if undo is None:
            return {
                "status": "blocked", "code": "nothing-to-undo", "success": False,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
                "user_message": "No reversible Loom change is available.",
            }
        try:
            result = undo()
        except (loom_vault_adapter.VaultAdapterError,
                loom_transparency.TransparencyError,
                loom_preferences.PreferenceError) as exc:
            return {
                "status": "blocked", "code": "nothing-to-undo", "success": False,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
                "user_message": str(exc),
            }
        return {
            "status": "completed", "code": "undo-complete", "success": True,
            "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            "user_message": result["message"],
        }
    _created_at, prior_path, prior, prior_security, record = max(
        candidates, key=lambda item: item[0])
    root = Path(prior["explicit_target"] or prior["cwd"]).resolve()
    pack = root / "plans"
    if os.path.lexists(pack / loom_plan_store.INDEX_NAME):
        witness_store = _lifecycle_witness_store(
            memory, directory, prior["project_id"])
        try:
            resolved, _semantics, _ledger, _witness, state = \
                loom_lifecycle_transition.observe(
                    root, witness_store=witness_store)
            current = loom_reliability.exact_tree_manifest(
                resolved.generation_root)
        except (
                loom_lifecycle_transition.LifecycleTransitionError,
                loom_reliability.ReliabilityError) as exc:
            raise OrchestratorError(
                "PLAN_UNDO_INDETERMINATE",
                f"the indexed generation cannot be verified for undo: {exc}") from exc
        if state.generation_phase != "reviewable":
            raise OrchestratorError(
                "PLAN_UNDO_NOT_REVIEWABLE",
                "only an unchanged reviewable generation can be undone; use the "
                "explicit active-generation cancellation flow after execution starts")
        if not loom_reliability.exact_tree_manifests_equal(
                current, record["manifest"]):
            raise OrchestratorError(
                "PLAN_UNDO_CHANGED",
                "the reviewed generation changed after Loom created it; undo refused")
        transition = _transition_project_generation_terminal(
            directory=directory, target=root, memory=memory,
            project_id=prior["project_id"], relation="cancel-generation",
            command_id="undo-generation:" + action["action_id"],
            owner_home=action["owner_home"],
            install_root=action["install_root"])
        evidence = "undo-" + transition["transition_receipt"][
            "transition_id"][:24]
        return {
            "status": "completed", "code": "undo-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [],
            "user_message": (
                "The unchanged reviewable generation was cancelled through its "
                f"canonical lifecycle transition ({evidence})."),
        }
    history = root / ".loom-history"
    archive = history / f"undone-plan-{prior['action_id']}"
    expected_relative = archive.relative_to(root).as_posix()
    if history.exists() and (history.is_symlink() or not history.is_dir()):
        raise OrchestratorError(
            "PLAN_UNDO_UNSAFE", "project-local Loom history is not a regular directory")
    pack_present = _path_present(pack)
    archive_present = _path_present(archive)
    if pack_present and archive_present:
        raise OrchestratorError(
            "PLAN_UNDO_CONFLICT",
            "both the active plan and its undo archive exist; neither was changed")
    if pack_present:
        if pack.is_symlink() or not pack.is_dir():
            raise OrchestratorError(
                "PLAN_UNDO_UNSAFE", "active plan is not a regular project directory")
        try:
            current = loom_reliability.exact_tree_manifest(pack)
        except loom_reliability.ReliabilityError as exc:
            raise OrchestratorError(
                "PLAN_UNDO_INDETERMINATE",
                f"active plan cannot be inventoried safely: {exc}") from exc
        if not loom_reliability.exact_tree_manifests_equal(
                current, record["manifest"]):
            raise OrchestratorError(
                "PLAN_UNDO_CHANGED",
                "the plan changed after Loom created it; undo refused without moving anything")
        history.mkdir(parents=False, exist_ok=True)
        if history.is_symlink() or not history.is_dir():
            raise OrchestratorError(
                "PLAN_UNDO_UNSAFE", "project-local Loom history is unsafe")
        try:
            source_identity = loom_reliability.observe_root_identity(pack)
            loom_reliability.atomic_rename_noreplace(
                pack, archive, expected_source_identity=source_identity,
                source_role="active-plan", destination_role="undo-archive")
        except loom_reliability.AtomicRenameReconciliationRequired as exc:
            raise OrchestratorError(
                "PLAN_UNDO_RECONCILIATION_REQUIRED",
                "the atomic plan archive changed namespace but durability or final state "
                "requires a fresh Loom undo check before any claim: "
                + json.dumps(exc.state, sort_keys=True, separators=(",", ":")),
                status="action-required") from exc
        except OSError as exc:
            raise OrchestratorError(
                "PLAN_UNDO_FAILED",
                f"same-project atomic plan archive failed: {exc}") from exc
        except loom_reliability.ReliabilityError as exc:
            raise OrchestratorError(
                "PLAN_UNDO_FAILED",
                f"same-project atomic no-replace plan archive failed: {exc}") from exc
        archive_present = True
    if not archive_present or archive.is_symlink() or not archive.is_dir():
        raise OrchestratorError(
            "PLAN_UNDO_INDETERMINATE",
            "neither the exact active plan nor its exact undo archive is available")
    try:
        archived = loom_reliability.exact_tree_manifest(archive)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "PLAN_UNDO_INDETERMINATE",
            f"plan undo archive cannot be verified: {exc}") from exc
    if not loom_reliability.exact_tree_manifests_equal(
            archived, record["manifest"]):
        raise OrchestratorError(
            "PLAN_UNDO_INDETERMINATE",
            "plan undo archive differs from its sealed manifest")
    record = {
        **record,
        "state": "undone",
        "archive_path": expected_relative,
        "undone_at": _stamp(now),
    }
    prior["host_result"] = {
        **(prior.get("host_result") or {}),
        "plan_author": record,
    }
    _write_action(prior_path, prior, prior_security)
    evidence = "undo-" + record["manifest"]["root_sha256"][:24]
    return {
        "status": "completed", "code": "undo-complete", "success": True,
        "metrics": {}, "evidence_ids": [evidence],
        "reversible_action_ids": [],
        "user_message": (
            f"The unchanged Loom plan was archived to {expected_relative} "
            f"and removed from the active project ({evidence})."),
    }


def _safe_plan_undo_handler(action, memory, *, now):
    try:
        return _plan_undo_handler(action, memory, now=now)
    except OrchestratorError as exc:
        return {
            "status": "blocked",
            "code": exc.code.lower().replace("_", "-"),
            "success": False,
            "metrics": {},
            "evidence_ids": [],
            "reversible_action_ids": [],
            "user_message": exc.message,
        }


def _verified_historical_plan_semantics(action, presentation):
    """Recover only plan meaning that the exact v1 presentation actually seals."""
    review = (action.get("host_result") or {}).get("plan_review")
    if isinstance(review, dict):
        _validate_plan_review_record(review, action=action)
        semantics = review["semantics"]
    elif presentation.get("omitted_step_count") == 0 \
            and isinstance(presentation.get("steps"), list) \
            and len(presentation["steps"]) == 1:
        semantics = {
            "schema_version": 1,
            "title": presentation["title"],
            "summary": presentation["summary"],
            "assumptions": presentation["assumptions"],
            "decisions": presentation["decisions"],
            "work_orders": presentation["steps"],
        }
        try:
            loom_plan_presentation.validate_semantics(semantics)
        except loom_plan_presentation.PresentationError as exc:
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                f"historical one-work-order semantics are invalid: {exc}") from exc
    else:
        raise OrchestratorError(
            "PLAN_REVIEW_SEQUENCE_REQUIRED",
            "the historical multi-work-order plan has no exact verified presentation "
            "order; create and review a v3 revision before execution")
    try:
        reproduced = loom_plan_presentation.compile_presentation(
            semantics, tier=action["tier"], binding=presentation["binding"])
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            f"historical presentation semantics cannot be reproduced: {exc}") from exc
    if reproduced != presentation:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            "historical presentation order or semantics no longer match its sealed bytes")
    return semantics


def _v1_generation_decision(action, presentation, expected_root, current_pack):
    """Bind a v1 presentation to current v3 authority or an exact adoption target."""
    semantic_draft = _verified_historical_plan_semantics(action, presentation)
    try:
        resolved = loom_plan_store.resolve(expected_root)
    except loom_plan_store.PlanStoreError as exc:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            f"the historical plan store cannot be resolved safely: {exc}") from exc
    generation_id = (
        resolved.generation_id if resolved.authority_version == "v3"
        else _derived_generation_id(action["project_id"], action["action_id"]))
    try:
        reviewed_world = _reviewed_world_observation(
            expected_root, project_id=action["project_id"],
            generation_id=generation_id,
            excluded_paths=(expected_root / "plans",))
    except OrchestratorError:
        raise
    binding = presentation["binding"]
    if reviewed_world["state_sha256"] != binding["world_fingerprint"] \
            or reviewed_world["state_sha256"] != action["survey_hash"]:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            "the project world changed after the historical plan was reviewed")
    route_digest = (action.get("domain_contract") or {}).get("route_digest")
    domain_bindings_sha256 = (
        route_digest.removeprefix("sha256:")
        if isinstance(route_digest, str)
        and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", route_digest)
        else None)
    try:
        semantics = loom_plan_presentation.compile_reviewed_semantics(
            semantic_draft, project_id=action["project_id"],
            generation_id=generation_id, revision=binding["revision"],
            reviewed_world_sha256=reviewed_world["state_sha256"],
            reviewed_world_observation_sha256=reviewed_world[
                "observation_sha256"],
            plan_contract_sha256=binding["plan_contract_hash"],
            domain_bindings_sha256=domain_bindings_sha256)
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "PLAN_REVIEW_SEQUENCE_REQUIRED",
            f"historical execution order cannot be adopted safely: {exc}") from exc
    common = {
        "presentation_sha256": presentation["presentation_sha256"],
        "plan_action_id": action["action_id"],
        "project_id": action["project_id"],
        "generation_id": generation_id,
        "revision": binding["revision"],
        "pack_sha256": current_pack,
        "plan_semantics_sha256": semantics["plan_semantics_sha256"],
        "execution_sequence_sha256": loom_lifecycle_kernel.digest(
            semantics["execution_sequence"]),
        "reviewed_world_sha256": reviewed_world["state_sha256"],
        "reviewed_world_observation_sha256": reviewed_world[
            "observation_sha256"],
    }
    if resolved.authority_version == "v3":
        try:
            stored_semantics = json.loads(
                (resolved.generation_root / "plan-semantics.json").read_text(
                    encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object)
            stored_world = json.loads(
                (resolved.generation_root / "reviewed-world.json").read_text(
                    encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object)
            loom_lifecycle_kernel.validate_reviewed_plan_semantics(
                stored_semantics)
            loom_lifecycle_kernel.validate_reviewed_world_observation(
                stored_world)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError,
                loom_lifecycle_kernel.LifecycleKernelError) as exc:
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                f"the active reviewed generation is invalid: {exc}") from exc
        if stored_semantics != semantics or stored_world != reviewed_world:
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                "the v1 display no longer reproduces the active reviewed generation")
        return {
            "schema_version": 2,
            **common,
            "active_index_sha256": resolved.index.index_sha256,
        }
    source_lifecycle_name = (
        ".loom-small-lifecycle.json"
        if action["tier"] == "S" else loom_gate.LIFECYCLE_FILE)
    source_lifecycle = expected_root / "plans" / source_lifecycle_name
    try:
        if source_lifecycle.is_symlink() or not source_lifecycle.is_file():
            raise OSError("legacy lifecycle is missing or redirected")
        source_lifecycle_sha256 = hashlib.sha256(
            source_lifecycle.read_bytes()).hexdigest()
    except OSError as exc:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            f"the historical lifecycle is unavailable: {exc}") from exc
    return {
        "schema_version": 3,
        **common,
        "source_lifecycle_name": source_lifecycle_name,
        "source_lifecycle_sha256": source_lifecycle_sha256,
    }


def _exact_plan_decision(
        action_path, presentation_sha256, *, owner_home, install_root, target):
    if not isinstance(presentation_sha256, str) \
            or re.fullmatch(r"[0-9a-f]{64}", presentation_sha256) is None:
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH", "displayed-plan reference is invalid")
    _path, action, _security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    if action["status"] != "completed" or action["intent"] != "plan" \
            or not isinstance(action.get("result"), dict):
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            "the displayed plan action is not a completed planning action")
    presentation = action["result"].get("plan_presentation")
    try:
        loom_plan_presentation.validate(presentation)
    except loom_plan_presentation.PresentationError as exc:
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            f"the displayed plan binding is invalid: {exc}") from exc
    if presentation["presentation_sha256"] != presentation_sha256 \
            or presentation["binding"]["action_id"] != action["action_id"] \
            or presentation["binding"]["project_id"] != action["project_id"]:
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            "the decision does not name the exact displayed plan")
    expected_root = Path(action["explicit_target"] or action["cwd"]).resolve()
    if Path(target).resolve() != expected_root:
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH", "the displayed plan belongs to another project")
    if presentation["schema_version"] == 2:
        binding = presentation["binding"]
        try:
            resolved = loom_plan_store.resolve(expected_root)
            if resolved.index is None \
                    or resolved.index.generation_id != binding["generation_id"]:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "the displayed generation is no longer active")
            semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
                json.loads(
                    (resolved.generation_root / "plan-semantics.json").read_text(
                        encoding="utf-8")))
            reviewed_world = loom_lifecycle_kernel.validate_reviewed_world_observation(
                json.loads(
                    (resolved.generation_root / "reviewed-world.json").read_text(
                        encoding="utf-8")))
            plan_file = expected_root.joinpath(
                *PurePosixPath(presentation["full_plan"]["relative_path"]).parts)
            plan_file.resolve(strict=True).relative_to(
                resolved.generation_root.resolve(strict=True))
            current_file = hashlib.sha256(plan_file.read_bytes()).hexdigest()
            current_pack = _pack_hash(resolved.generation_root)
            current_world = _reviewed_world_observation(
                expected_root, project_id=action["project_id"],
                generation_id=binding["generation_id"],
                excluded_paths=(expected_root / "plans",))
        except (
                OSError, RuntimeError, ValueError, UnicodeError,
                json.JSONDecodeError, loom_plan_store.PlanStoreError,
                loom_lifecycle_kernel.LifecycleKernelError) as exc:
            if isinstance(exc, OrchestratorError):
                raise
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                f"the displayed generation is unavailable: {exc}") from exc
        expected_binding = {
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
            "execution_policy": semantics.execution_policy,
            "execution_sequence_sha256": loom_lifecycle_kernel.digest(
                semantics.graph.execution_sequence),
            "domain_bindings_sha256": semantics.domain_bindings_sha256,
            "reviewed_world_observation_sha256": reviewed_world[
                "observation_sha256"],
            "world_fingerprint": semantics.reviewed_world_sha256,
            "plan_contract_hash": semantics.plan_contract_sha256,
            "revision": semantics.revision_number,
        }
        if any(binding[key] != expected for key, expected in expected_binding.items()) \
                or binding["pack_sha256"] != current_pack \
                or current_file != presentation["full_plan"]["sha256"] \
                or current_world != reviewed_world:
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                "the reviewed plan semantics, projection, or project world changed")
        return {
            "schema_version": 2,
            "presentation_sha256": presentation_sha256,
            "plan_action_id": action["action_id"],
            "project_id": action["project_id"],
            "generation_id": semantics.generation_id,
            "revision": semantics.revision_number,
            "pack_sha256": current_pack,
            "active_index_sha256": resolved.index.index_sha256,
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
            "execution_sequence_sha256": loom_lifecycle_kernel.digest(
                semantics.graph.execution_sequence),
            "reviewed_world_sha256": semantics.reviewed_world_sha256,
            "reviewed_world_observation_sha256": reviewed_world[
                "observation_sha256"],
        }
    pack = expected_root / "plans"
    relative = presentation["full_plan"]["relative_path"]
    plan_file = expected_root.joinpath(*PurePosixPath(relative).parts)
    try:
        current_pack = _pack_hash(pack)
        current_file = hashlib.sha256(plan_file.read_bytes()).hexdigest()
    except OSError as exc:
        raise OrchestratorError(
            "PLAN_DECISION_STALE", f"the displayed plan is unavailable: {exc}") from exc
    if current_pack != presentation["binding"]["pack_sha256"] \
            or current_file != presentation["full_plan"]["sha256"]:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            "the plan changed after it was displayed; review a fresh plan before continuing")
    return _v1_generation_decision(
        action, presentation, expected_root, current_pack)


def _revision_archive_payload(action, presentation, pack):
    files = []
    total = 0
    try:
        pack = loom_privacy._safe_absolute(
            pack, "prior plan archive", must_exist=True)
        paths = sorted(
            loom_privacy._iter_regular_files(pack),
            key=lambda item: item.relative_to(pack).as_posix())
    except loom_privacy.PrivacyError as exc:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            f"the prior plan cannot be archived safely: {exc}") from exc
    for path in paths:
        if len(files) >= MAX_PLAN_REVISION_FILES:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the prior plan exceeds the private revision file bound")
        relative = path.relative_to(pack).as_posix()
        raw = path.read_bytes()
        total += len(raw)
        if total > MAX_PLAN_REVISION_ARCHIVE_BYTES:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the prior plan exceeds the private revision byte bound")
        files.append({
            "path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "content_base64": base64.b64encode(raw).decode("ascii"),
        })
    if not files:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED", "the prior plan is empty")
    payload = {
        "schema_version": 1,
        "kind": "loom-plan-revision-archive-v1",
        "project_id": action["project_id"],
        "action_id": action["action_id"],
        "revision": presentation["binding"]["revision"],
        "presentation_sha256": presentation["presentation_sha256"],
        "pack_sha256": presentation["binding"]["pack_sha256"],
        "files": files,
    }
    payload["archive_sha256"] = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    _validate_revision_archive_payload(payload)
    return payload


def _validate_revision_archive_payload(payload):
    expected = {
        "schema_version", "kind", "project_id", "action_id", "revision",
        "presentation_sha256", "pack_sha256", "files", "archive_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != expected \
            or payload.get("schema_version") != 1 \
            or payload.get("kind") != "loom-plan-revision-archive-v1":
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the private revision archive fields are invalid")
    identity = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    digest = re.compile(r"^[0-9a-f]{64}$")
    if any(not isinstance(payload.get(key), str)
           or identity.fullmatch(payload[key]) is None
           for key in ("project_id", "action_id")) \
            or type(payload.get("revision")) is not int \
            or not 1 <= payload["revision"] <= 1000000 \
            or any(not isinstance(payload.get(key), str)
                   or digest.fullmatch(payload[key]) is None
                   for key in (
                       "presentation_sha256", "pack_sha256",
                       "archive_sha256")):
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the private revision archive identity is invalid")
    files = payload.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_PLAN_REVISION_FILES:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the private revision archive file inventory is invalid")
    total = 0
    seen = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {
                "path", "sha256", "content_base64"}:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "a private revision archive file record is invalid")
        relative = item.get("path")
        try:
            pure = PurePosixPath(relative)
        except (TypeError, ValueError) as exc:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "a private revision archive path is invalid") from exc
        if not relative or len(relative) > 300 or pure.is_absolute() \
                or relative != pure.as_posix() or any(
                    part in {"", ".", ".."} for part in pure.parts) \
                or relative in seen:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "a private revision archive path is unsafe or duplicated")
        seen.add(relative)
        if not isinstance(item.get("sha256"), str) \
                or digest.fullmatch(item["sha256"]) is None \
                or not isinstance(item.get("content_base64"), str):
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "a private revision archive file identity is invalid")
        try:
            raw = base64.b64decode(item["content_base64"], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "a private revision archive file is not valid base64") from exc
        total += len(raw)
        if total > MAX_PLAN_REVISION_ARCHIVE_BYTES \
                or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "a private revision archive file changed or exceeds its bound")
    claimed = payload["archive_sha256"]
    unsigned = dict(payload)
    del unsigned["archive_sha256"]
    if hashlib.sha256(_canonical_bytes(unsigned)).hexdigest() != claimed:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the private revision archive digest is invalid")


def _validate_revision_archive_envelope(envelope):
    expected = {
        "schema_version", "kind", "owner_vault_id", "project_id",
        "action_id", "revision", "archive_sha256", "ciphertext",
    }
    identity = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    if not isinstance(envelope, dict) or set(envelope) != expected \
            or envelope.get("schema_version") != 1 \
            or envelope.get("kind") != "loom-encrypted-plan-revision-v1" \
            or any(not isinstance(envelope.get(key), str)
                   or identity.fullmatch(envelope[key]) is None
                   for key in ("owner_vault_id", "project_id", "action_id")) \
            or type(envelope.get("revision")) is not int \
            or not 1 <= envelope["revision"] <= 1000000 \
            or not isinstance(envelope.get("archive_sha256"), str) \
            or re.fullmatch(r"[0-9a-f]{64}", envelope["archive_sha256"]) is None \
            or not isinstance(envelope.get("ciphertext"), str):
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the encrypted revision archive envelope is invalid")
    try:
        raw = base64.b64decode(envelope["ciphertext"], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the encrypted revision archive ciphertext is invalid") from exc
    if not raw or len(raw) > MAX_PLAN_REVISION_ARCHIVE_BYTES + 4096:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the encrypted revision archive exceeds its bound")


def _write_revision_archive(
        action_path, action, security, presentation, pack, *, payload=None):
    payload = (
        _revision_archive_payload(action, presentation, pack)
        if payload is None else payload)
    _validate_revision_archive_payload(payload)
    directory = Path(action_path).parent / "plan-revisions"
    if os.path.lexists(directory) and (
            directory.is_symlink() or not directory.is_dir()):
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "private revision namespace is not a safe directory")
    directory.mkdir(mode=0o700, exist_ok=True)
    name = (
        f"{action['action_id']}-r{presentation['binding']['revision']:06d}-"
        f"{payload['archive_sha256']}.json")
    path = directory / name
    if os.path.lexists(path):
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if security is None:
                _validate_revision_archive_payload(existing)
                restored = existing
            else:
                _validate_revision_archive_envelope(existing)
                crypto, owner_vault_id = security
                aad = (
                    f"plan-revision:{owner_vault_id}:{action['project_id']}:"
                    f"{action['action_id']}:{presentation['binding']['revision']}"
                ).encode("utf-8")
                restored = json.loads(crypto.open(
                    existing["ciphertext"].encode("ascii"), aad).decode("utf-8"))
                _validate_revision_archive_payload(restored)
        except (OSError, ValueError, TypeError, UnicodeError,
                json.JSONDecodeError, loom_crypto.CryptoError) as exc:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the existing private revision archive is corrupt") from exc
        if restored != payload:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the immutable private revision archive identity conflicts")
        return payload["archive_sha256"]
    if security is None:
        loom_session._atomic_json(path, payload)
    else:
        crypto, owner_vault_id = security
        aad = (
            f"plan-revision:{owner_vault_id}:{action['project_id']}:"
            f"{action['action_id']}:{presentation['binding']['revision']}"
        ).encode("utf-8")
        raw = _canonical_bytes(payload)
        envelope = {
            "schema_version": 1,
            "kind": "loom-encrypted-plan-revision-v1",
            "owner_vault_id": owner_vault_id,
            "project_id": action["project_id"],
            "action_id": action["action_id"],
            "revision": presentation["binding"]["revision"],
            "archive_sha256": payload["archive_sha256"],
            "ciphertext": crypto.seal(raw, aad).decode("ascii"),
        }
        _validate_revision_archive_envelope(envelope)
        loom_session._atomic_json(path, envelope)
    return payload["archive_sha256"]


def _revision_archive_record_id(action, presentation):
    try:
        namespace = uuid.UUID(action["instance_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise OrchestratorError(
            "PLAN_REVISION_ARCHIVE_FAILED",
            "the owner-vault identity cannot bind revision history") from exc
    return str(uuid.uuid5(
        namespace,
        "plan-revision:"
        f"{action['project_id']}:{action['action_id']}:"
        f"{presentation['presentation_sha256']}:"
        f"{presentation['binding']['revision']}"))


def _persist_revision_archive(memory, archive):
    action = archive["action"]
    presentation = archive["presentation"]
    payload = archive["payload"]
    writer = getattr(memory, "archive_plan_revision", None)
    if writer is not None:
        try:
            stored = writer(
                record_id=archive["record_id"],
                project_id=action["project_id"],
                payload=payload,
                created_at=action["created_at"])
        except loom_vault_adapter.VaultAdapterError as exc:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED", str(exc)) from exc
        if stored.get("forgotten"):
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the owner previously forgot this private plan revision")
        if stored.get("record_id") != archive["record_id"] \
                or stored.get("archive_sha256") != payload["archive_sha256"]:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the owner-vault revision archive identity changed")
        return payload["archive_sha256"]
    return _write_revision_archive(
        archive["action_path"], action, archive["security"],
        presentation, archive["pack"], payload=payload)


def _prepare_revision_context(
        action_path, presentation_sha256, request, *,
        owner_home, install_root, target):
    decision = _exact_plan_decision(
        action_path, presentation_sha256, owner_home=owner_home,
        install_root=install_root, target=target)
    path, action, security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    prior = action["result"]["plan_presentation"]
    prior_record = (action.get("host_result") or {}).get("plan_review")
    _validate_plan_review_record(prior_record, action=action)
    archive_pack = Path(target) / "plans"
    source_binding = {}
    if decision["schema_version"] == 2:
        try:
            resolved = loom_plan_store.resolve(target)
            if resolved.index is None \
                    or resolved.index.index_sha256 != \
                    decision["active_index_sha256"]:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "the displayed plan generation changed before revision")
            source_semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
                json.loads(
                    (resolved.generation_root / "plan-semantics.json").read_text(
                        encoding="utf-8"),
                    object_pairs_hook=loom_lifecycle._strict_object))
            source_ledger = loom_lifecycle_kernel.validate_lifecycle_ledger(
                json.loads(
                    (resolved.generation_root / "lifecycle.json").read_text(
                        encoding="utf-8"),
                    object_pairs_hook=loom_lifecycle._strict_object))
            transition = action.get("lifecycle_transition")
            if not isinstance(transition, dict) \
                    or transition.get("target_witness_sha256") is None:
                raise OrchestratorError(
                    "PLAN_DECISION_STALE",
                    "the displayed plan has no sealed lifecycle-head binding")
            archive_pack = resolved.generation_root
            source_binding = {
                "generation_id": decision["generation_id"],
                "source_active_index_sha256": decision[
                    "active_index_sha256"],
                "source_plan_semantics_sha256":
                source_semantics.plan_semantics_sha256,
                "source_lifecycle_sha256": source_ledger.lifecycle_sha256,
                "source_witness_sha256": transition[
                    "target_witness_sha256"],
                "source_reviewed_world_sha256": decision[
                    "reviewed_world_sha256"],
                "source_reviewed_world_observation_sha256": decision[
                    "reviewed_world_observation_sha256"],
            }
        except (
                OSError, UnicodeError, json.JSONDecodeError, ValueError,
                loom_plan_store.PlanStoreError,
                loom_lifecycle_kernel.LifecycleKernelError) as exc:
            if isinstance(exc, OrchestratorError):
                raise
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                f"the displayed generation cannot be revised safely: {exc}") from exc
    archive_payload = _revision_archive_payload(
        action, prior, archive_pack)
    archive_record_id = _revision_archive_record_id(action, prior)
    if decision["schema_version"] == 2:
        project_state_hash = decision["reviewed_world_sha256"]
    else:
        try:
            project_state_hash = loom_gate._stable_state(
                Path(target), Path(target) / "plans").state_hash
        except loom_survey.SurveyError as exc:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                f"the revision baseline could not be observed safely: {exc}") from exc
    return {
        "schema_version": decision["schema_version"],
        "parent_action_id": action["action_id"],
        "parent_presentation_sha256": presentation_sha256,
        "parent_pack_sha256": decision["pack_sha256"],
        "revision": decision["revision"] + 1,
        "request": request,
        "prior_semantics": prior_record["semantics"],
        "archive_sha256": archive_payload["archive_sha256"],
        "archive_record_id": archive_record_id,
        "project_state_hash": project_state_hash,
        **source_binding,
    }, action, {
        "action_path": path,
        "action": action,
        "security": security,
        "presentation": prior,
        "pack": archive_pack,
        "payload": archive_payload,
        "record_id": archive_record_id,
    }


def _rebind_revision_prepared(prepared, prior_action):
    """Preserve the sealed plan's domains while observing the current world."""
    prior_domains = list(prior_action["domains"])
    prior_route = prior_action["prepared"]["route_contract"]
    values = prepared.to_dict()
    values.pop("prepared_hash")
    route = values["route_contract"]
    values["domains"] = prior_domains
    route["requires_domain_discovery"] = bool(
        prior_route["requires_domain_discovery"]
        or not values["project_inspection"]["relevant_coverage_complete"])
    route["evidence"] = list(dict.fromkeys([
        *route["evidence"][:15], "bound-plan-revision",
    ]))
    values["route_contract"] = route
    return loom_runtime.PreparedInvocation.build(
        **values, operation_fingerprint=prepared.operation_fingerprint)


def _rebind_status_prepared(prepared, subject_action):
    """Bind status receipt domains to the exact action being inspected."""
    if subject_action["project_id"] != prepared.project_id:
        raise OrchestratorError(
            "ACTION_POINTER_CONFLICT",
            "status subject belongs to a different project")
    values = prepared.to_dict()
    values.pop("prepared_hash")
    route = values["route_contract"]
    values["domains"] = list(subject_action["domains"])
    route["evidence"] = list(dict.fromkeys([
        *route["evidence"][:15], "active-action-status-subject",
    ]))
    values["route_contract"] = route
    return loom_runtime.PreparedInvocation.build(
        **values, operation_fingerprint=prepared.operation_fingerprint)


def invoke(*, request, cwd, home, install_root, explicit_target=None,
           timeout_seconds=900, now=None, transport_invocation_id=None,
           assurance=None, expected_plan_decision=None,
           revision_context=None, bound_intent=None):
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
    assurance = _default_assurance(request) if assurance is None else assurance
    _validate_assurance(assurance, request, allow_legacy=False)
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
    _bind_memory_project(memory, project)
    directory = _orchestration_directory(home, instance_id, project.project_id)
    instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
    if bound_intent not in {None, "plan", "execute"} \
            or bound_intent == "plan" and revision_context is None \
            or bound_intent == "execute" and expected_plan_decision is None:
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH", "bound intent is invalid")
    if revision_context is not None and bound_intent != "plan":
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            "plan revision requires its bound planning intent")
    intent_decision = loom_runtime.resolve_intent(request)
    incoming_intent = (
        bound_intent if bound_intent is not None else
        None if intent_decision["blocked"] else intent_decision["intent"])
    unobserved_control = _sealed_request_control(request)
    quarantine_requested = (
        unobserved_control["relation"] == "quarantine-generation"
        and not unobserved_control["blocked"])
    if quarantine_requested and any(item is not None for item in (
            expected_plan_decision, revision_context, bound_intent)):
        raise OrchestratorError(
            "REQUEST_CONTROL_INVALID",
            "plan-store quarantine cannot share exact plan or revision authority")
    effective_transport_invocation_id = transport_invocation_id
    prior_generation_transition = None
    lifecycle_recovery = []
    try:
        with loom_reliability.exclusive_file_lock(_orchestration_lock(directory)):
            lifecycle_recovery = _recover_pending_v3_lifecycle(
                target=target, directory=directory, memory=memory,
                project_id=project.project_id, owner_home=home,
                install_root=install_root)
            if quarantine_requested:
                command_identity = (
                    transport_invocation_id or str(uuid.uuid4()))
                try:
                    quarantine = loom_lifecycle_transition.quarantine_invalid_store(
                        target, project_id=project.project_id,
                        command_id="quarantine-generation:" + command_identity,
                        reason_code="invalid-plan-store",
                        quarantine_root=directory,
                        lock_path=_orchestration_lock(directory),
                        _lock_held=True)
                except loom_lifecycle_transition.LifecycleTransitionError as exc:
                    raise OrchestratorError(
                        "GENERATION_QUARANTINE_FAILED",
                        f"invalid plan authority was preserved in place: {exc}") from exc
                return {
                    "schema_version": SCHEMA_VERSION,
                    "status": "completed",
                    "code": "generation-quarantined",
                    "success": True,
                    "assurance": assurance,
                    "quarantine_receipt": quarantine,
                }
            recovery = None
            lifecycle_state = None
            lifecycle_control = None
            if os.path.lexists(target / "plans" / loom_plan_store.INDEX_NAME):
                witness_store = _lifecycle_witness_store(
                    memory, directory, project.project_id)
                try:
                    (_resolved, _semantics, _ledger, _witness,
                     lifecycle_state) = loom_lifecycle_transition.observe(
                        target, witness_store=witness_store)
                except loom_lifecycle_transition.LifecycleTransitionError as exc:
                    raise OrchestratorError(
                        "INVALID_LIFECYCLE",
                        f"indexed lifecycle authority cannot be observed safely: {exc}") \
                        from exc
                lifecycle_control = _sealed_request_control(
                    request,
                    lifecycle_state=loom_lifecycle_kernel.project(lifecycle_state))
            if incoming_intent == "cancel":
                if lifecycle_state is not None \
                        and lifecycle_control["relation"] == "cancel-generation":
                    command_identity = (
                        transport_invocation_id or str(uuid.uuid4()))
                    result = _transition_project_generation_terminal(
                        directory=directory, target=target, memory=memory,
                        project_id=project.project_id,
                        relation="cancel-generation",
                        command_id="cancel-generation:" + command_identity,
                        owner_home=home, install_root=install_root)
                else:
                    result = _cancel_active_request(
                        directory=directory, request=request, owner_home=home,
                        install_root=install_root, now=instant)
            else:
                if lifecycle_state is not None \
                        and not lifecycle_state.generation_phase.startswith("terminal-") \
                        and lifecycle_control["relation"] == "supersede-generation":
                    effective_transport_invocation_id = (
                        transport_invocation_id or str(uuid.uuid4()))
                    successor_generation_id = _derived_generation_id(
                        project.project_id, effective_transport_invocation_id)
                    prior_generation_transition = \
                        _transition_project_generation_terminal(
                            directory=directory, target=target, memory=memory,
                            project_id=project.project_id,
                            relation="supersede-generation",
                            command_id=(
                                "supersede-generation:"
                                + effective_transport_invocation_id),
                            successor_generation_id=successor_generation_id,
                            owner_home=home, install_root=install_root)
                recovery, reused_action = _reconcile_active_action(
                    owner_home=home, install_root=install_root, instance_id=instance_id,
                    project_id=project.project_id, now=instant,
                    incoming_intent=incoming_intent, request=request, cwd=cwd,
                    target=target, memory=memory,
                    transport_invocation_id=transport_invocation_id)
                if reused_action is not None:
                    result = _pending_action_result(reused_action)
                else:
                    replay = None
                    if incoming_intent == "plan" and revision_context is None:
                        try:
                            prepared = loom_runtime.prepare_invocation(
                                request, instance_id=instance_id,
                                invocation_id=str(uuid.uuid4()), cwd=cwd,
                                explicit_target=target, owner_home=home, now=instant,
                                lifecycle_witness_reader=_lifecycle_witness_reader(
                                    memory, directory, project.project_id))
                        except loom_runtime.RuntimeBlocked as exc:
                            raise OrchestratorError(exc.code, exc.message) from exc
                        replay = _completed_plan_replay(
                            directory, prepared, target, request=request, cwd=cwd,
                            owner_home=home, install_root=install_root)
                    if replay is not None:
                        result = replay
                    else:
                        result = _invoke_under_lock(
                            request=request, cwd=cwd, home=home,
                            install_root=install_root, target=target,
                            timeout_seconds=timeout_seconds, now=instant,
                            instance_id=instance_id, memory=memory,
                            transport_invocation_id=effective_transport_invocation_id,
                            assurance=assurance,
                            expected_plan_decision=expected_plan_decision,
                            revision_context=revision_context,
                            bound_intent=bound_intent)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc
    if recovery is not None and isinstance(result, dict):
        result = {**result, "prior_recovery": recovery}
    if prior_generation_transition is not None and isinstance(result, dict):
        result = {
            **result,
            "prior_generation_transition": prior_generation_transition,
        }
    if lifecycle_recovery and isinstance(result, dict):
        result = {
            **result,
            "prior_lifecycle_recovery": lifecycle_recovery,
        }
    if isinstance(result, dict) and "assurance" not in result:
        result = {**result, "assurance": assurance}
    return result


def _recover_plan_decision(cwd, *, owner_home, install_root):
    """Recover one exact, unchanged displayed plan for a project-local host turn."""
    target = _absolute(cwd, "cwd")
    home = _absolute(owner_home, "owner home", must_exist=False)
    install_root = _absolute(install_root, "installation root")
    try:
        loom_install.check(install_root)
    except loom_install.InstallError as exc:
        raise OrchestratorError(
            "INSTALL_UNVERIFIED", f"installation receipt check failed: {exc}") from exc
    instance_id, memory = _memory_backend(home, install_root, target)
    try:
        project = loom_runtime.resolve_project(
            instance_id, explicit_target=target, cwd=target)
    except loom_runtime.RuntimeBlocked as exc:
        raise OrchestratorError(exc.code, exc.message) from exc
    _bind_memory_project(memory, project)
    directory = _orchestration_directory(home, instance_id, project.project_id)
    if not directory.is_dir():
        raise OrchestratorError(
            "PLAN_DECISION_UNAVAILABLE",
            "no completed displayed plan is available for this project")
    entries = []
    inspected = 0
    for entry in os.scandir(directory):
        inspected += 1
        if inspected > MAX_ORCHESTRATION_DIRECTORY_ENTRIES:
            raise OrchestratorError(
                "RECOVERY_CAPACITY",
                "reviewable-plan scan exceeds its directory-entry bound")
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            continue
        if not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{12}\.json", entry.name):
            continue
        entries.append(Path(entry.path))
        if len(entries) > MAX_ORCHESTRATION_ACTIONS:
            raise OrchestratorError(
                "RECOVERY_CAPACITY", "reviewable-plan scan exceeds its action bound")
    candidates = []
    stale = False
    for path in sorted(entries, key=lambda item: item.name):
        _path, action, _security = _read_action(
            path, owner_home=home, install_root=install_root)
        result = action.get("result")
        presentation = result.get("plan_presentation") if isinstance(result, dict) else None
        action_target = Path(action.get("explicit_target") or action.get("cwd", ""))
        if action.get("status") != "completed" \
                or action.get("intent") != "plan" \
                or action.get("project_id") != project.project_id \
                or not isinstance(presentation, dict):
            continue
        try:
            if action_target.resolve() != target:
                continue
        except (OSError, RuntimeError):
            continue
        digest = presentation.get("presentation_sha256")
        try:
            decision = _exact_plan_decision(
                _path, digest, owner_home=home,
                install_root=install_root, target=target)
        except OrchestratorError as exc:
            if exc.code == "PLAN_DECISION_STALE":
                stale = True
                continue
            if exc.code == "PLAN_DECISION_MISMATCH":
                continue
            raise
        candidates.append((_path, decision))
    if len(candidates) > 1:
        raise OrchestratorError(
            "PLAN_DECISION_AMBIGUOUS",
            "more than one unchanged displayed plan is reviewable for this project")
    if not candidates:
        if stale:
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                "the displayed plan no longer matches the current project; review a fresh plan")
        raise OrchestratorError(
            "PLAN_DECISION_UNAVAILABLE",
            "no completed displayed plan is available for this project")
    path, decision = candidates[0]
    return {
        "action_path": str(path),
        "presentation_sha256": decision["presentation_sha256"],
    }


def _decision_reference(
        action_path, presentation_sha256, cwd, *, owner_home, install_root):
    has_action = action_path is not None
    has_digest = presentation_sha256 is not None
    if cwd is not None:
        if has_action or has_digest:
            raise OrchestratorError(
                "PLAN_DECISION_MISMATCH",
                "name either one exact displayed-plan reference or its project directory")
        return _recover_plan_decision(
            cwd, owner_home=owner_home, install_root=install_root)
    if not has_action or not has_digest:
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            "name either one exact displayed-plan reference or its project directory")
    return {
        "action_path": action_path,
        "presentation_sha256": presentation_sha256,
    }


def start(
        action_path=None, *, presentation_sha256=None, cwd=None,
        owner_home, install_root, now=None):
    """Start only the exact completed plan that was displayed to the owner."""
    reference = _decision_reference(
        action_path, presentation_sha256, cwd,
        owner_home=owner_home, install_root=install_root)
    action_path = reference["action_path"]
    presentation_sha256 = reference["presentation_sha256"]
    path, action, _security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    if action["status"] != "completed" or action["intent"] != "plan":
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            "only a completed displayed plan can be started")
    result = invoke(
        request="Continue", cwd=action["cwd"], home=owner_home,
        install_root=install_root, explicit_target=action["explicit_target"],
        now=now, expected_plan_decision={
            "action_path": str(path),
            "presentation_sha256": presentation_sha256,
        }, bound_intent="execute")
    if not isinstance(result, dict) or result.get("intent") != "execute" \
            or result.get("plan_decision", {}).get(
                "presentation_sha256") != presentation_sha256:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            "the exact displayed plan could not enter its existing execution authority")
    return result


def revise(
        action_path=None, *, presentation_sha256=None, cwd=None, request,
        owner_home, install_root, now=None):
    """Open a fresh planning action bound to one exact displayed plan revision."""
    try:
        loom_adapter_protocol.request_identity(request)
    except loom_adapter_protocol.ProtocolError as exc:
        raise OrchestratorError(exc.code, str(exc)) from exc
    reference = _decision_reference(
        action_path, presentation_sha256, cwd,
        owner_home=owner_home, install_root=install_root)
    action_path = reference["action_path"]
    presentation_sha256 = reference["presentation_sha256"]
    path, action, _security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    if action["status"] != "completed" or action["intent"] != "plan":
        raise OrchestratorError(
            "PLAN_DECISION_MISMATCH",
            "only a completed displayed plan can be revised")
    result = invoke(
        request=request, cwd=action["cwd"], home=owner_home,
        install_root=install_root, explicit_target=action["explicit_target"],
        now=now, revision_context={
            "action_path": str(path),
            "presentation_sha256": presentation_sha256,
        }, bound_intent="plan")
    context = result.get("revision_context") if isinstance(result, dict) else None
    if result.get("intent") != "plan" or not isinstance(context, dict) \
            or context.get("parent_presentation_sha256") != presentation_sha256:
        raise OrchestratorError(
            "PLAN_DECISION_STALE",
            "the displayed plan could not enter a fresh bound revision")
    return result


def resolve(*, request, cwd, action_path, action_sha256, home, install_root, now=None):
    """Resolve one hook-created verified action without creating a second action."""
    try:
        loom_adapter_protocol.request_identity(request)
    except loom_adapter_protocol.ProtocolError as exc:
        raise OrchestratorError(exc.code, str(exc)) from exc
    if not isinstance(action_sha256, str) \
            or not re.fullmatch(r"[0-9a-f]{64}", action_sha256):
        raise OrchestratorError(
            "REQUEST_IDENTITY_INVALID", "verified action digest is invalid")
    cwd = _absolute(cwd, "cwd")
    home = _absolute(home, "owner home", must_exist=False)
    install_root = _absolute(install_root, "installation root")
    path = _absolute(action_path, "action")
    try:
        relative = path.relative_to(home)
    except ValueError as exc:
        raise OrchestratorError(
            "ACTION_PATH_MISMATCH", "verified action escapes the owner home") from exc
    parts = relative.parts
    if len(parts) != 7 or parts[0] != "instances" or parts[2] != "runtime" \
            or parts[3] != "projects" or parts[5] != "orchestrations" \
            or not loom_runtime.PROJECT_RE.fullmatch(parts[4]) \
            or not re.fullmatch(r"[0-9a-f-]{36}\.json", parts[6]):
        raise OrchestratorError(
            "ACTION_PATH_MISMATCH", "verified action path is not owner-project scoped")
    try:
        if str(uuid.UUID(parts[1])) != parts[1] \
                or str(uuid.UUID(parts[6][:-5])) != parts[6][:-5]:
            raise ValueError
        loom_memory._reject_link_ancestors(path, "verified action")
    except (ValueError, loom_memory.MemoryError) as exc:
        raise OrchestratorError(
            "ACTION_UNSAFE", "verified action path is redirected or malformed") from exc
    try:
        loom_install.check(install_root)
    except loom_install.InstallError as exc:
        raise OrchestratorError(
            "INSTALL_UNVERIFIED", f"installation receipt check failed: {exc}") from exc
    instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
    try:
        with loom_reliability.exclusive_file_lock(_orchestration_lock(path.parent)):
            try:
                before = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                raise OrchestratorError(
                    "ACTION_UNSAFE", "verified action cannot be read") from exc
            if before != action_sha256:
                raise OrchestratorError(
                    "ACTION_CORRUPT", "verified action digest does not match the hook receipt")
            _path, action, _security = _read_action(
                path, owner_home=home, install_root=install_root)
            try:
                after = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                raise OrchestratorError(
                    "ACTION_UNSAFE", "verified action cannot be reread") from exc
            if after != before:
                raise OrchestratorError(
                    "ACTION_CORRUPT", "verified action changed while it was being resolved")
            if Path(action["owner_home"]) != home \
                    or Path(action["install_root"]) != install_root:
                raise OrchestratorError(
                    "ACTION_RUNTIME_MISMATCH",
                    "verified action belongs to another owner home or runtime")
            if action["status"] != "pending":
                raise OrchestratorError(
                    "ACTION_TERMINAL",
                    f"verified action is {action['status']}",
                    status=action["status"])
            if instant > loom_runtime._parse_time(action["expires_at"]):
                raise OrchestratorError(
                    "ACTION_EXPIRED", "verified action expired before it was resolved")
            if action["request"] != request or action["cwd"] != str(cwd):
                raise OrchestratorError(
                    "REQUEST_IDENTITY_INVALID",
                    "verified action does not match this request and working directory")
            assurance = action["assurance"]
            _validate_assurance(assurance, request, allow_legacy=False)
            if assurance["mode"] != "verified" \
                    or assurance["ingress"] != "codex-user-prompt-hook-v2":
                raise OrchestratorError(
                    "HOST_UNVERIFIED", "action was not created by the verified Codex hook")
            _reconcile_plan_authoring(action)
            pointer = _read_active_pointer(path.parent)
            if pointer is None \
                    or pointer["action_id"] != action["action_id"] \
                    or pointer["project_id"] != action["project_id"]:
                raise OrchestratorError(
                    "ACTION_POINTER_CONFLICT",
                    "verified action is not the active action for this project")
            target = _absolute(
                action["explicit_target"] or action["cwd"], "target")
            witness_reader = _action_lifecycle_witness_reader(
                action, path.parent)
            try:
                prepared = loom_runtime.prepare_invocation(
                    request, instance_id=action["instance_id"],
                    invocation_id=str(uuid.uuid4()), cwd=cwd,
                    explicit_target=target, owner_home=home, now=instant,
                    lifecycle_witness_reader=witness_reader)
            except loom_runtime.RuntimeBlocked as exc:
                raise OrchestratorError(exc.code, exc.message) from exc
            if not _action_matches_current_frontier(
                    action, prepared, target, request=request, cwd=cwd):
                raise OrchestratorError(
                    "TARGET_DRIFT",
                    "verified action no longer matches the current target state")
            try:
                final_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                raise OrchestratorError(
                    "ACTION_UNSAFE", "verified action cannot be read after resolution") from exc
            if final_digest != action_sha256:
                raise OrchestratorError(
                    "ACTION_CORRUPT", "verified action changed before resolution completed")
            return _pending_action_result(action)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc


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
    project_root = Path(action["explicit_target"] or action["cwd"])
    action_pack = _action_pack_root(action)
    if work_order is None and action["work_order"] is not None:
        work_order_path = action_pack / action["work_order"]
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
    semantic_draft_shape = None
    if action["intent"] == "plan" and action["plan_contract"] is not None:
        semantic_draft_shape = {
            "schema": "schemas/plan-draft.schema.json",
            "top_level_fields": sorted(loom_plan_author.TOP_FIELDS),
            "current_fact_fields": sorted(loom_plan_author.FACT_FIELDS),
            "release_exposure_fields": sorted(loom_plan_author.EXPOSURE_FIELDS),
            "work_order_fields": sorted(loom_plan_author.WORK_ORDER_FIELDS),
            "routing_values": sorted(loom_plan_author.ROUTING),
            "size_values": sorted(loom_plan_author.SIZE),
            "domain_evidence_fields": sorted(
                loom_plan_author.DOMAIN_EVIDENCE_FIELDS),
            "domain_evidence_required": bool(
                (action["plan_contract"].get("domain_discovery") or {}).get(
                    "required")),
            "domain_answer_fields": [
                key for key, _question in loom_domain_discovery.QUESTIONS],
            "domain_source_fields": sorted(
                loom_plan_author.DOMAIN_SOURCE_FIELDS),
            "domain_invariant_fields": sorted(
                loom_plan_author.DOMAIN_INVARIANT_FIELDS),
            "domain_scope_fields": sorted(
                loom_plan_author.DOMAIN_SCOPE_FIELDS),
            "domain_source_key_pattern": loom_plan_author.SOURCE_KEY_PATTERN,
            "domain_source_class_values": sorted(
                loom_plan_author.SOURCE_CLASSES),
            "domain_locator_visibility_values": sorted(
                loom_plan_author.LOCATOR_VISIBILITY),
            "domain_currentness_values": sorted(
                loom_plan_author.CURRENTNESS),
            "domain_invariant_type_values": sorted(
                loom_plan_author.INVARIANT_TYPES),
            "domain_invariant_type_guidance": dict(
                loom_plan_author.INVARIANT_TYPE_GUIDANCE),
            "domain_consequence_values": sorted(
                loom_plan_author.CONSEQUENCE_CLASSES),
            "domain_authority_requirement_values": sorted(
                loom_plan_author.AUTHORITY_REQUIREMENTS),
            "domain_authority_availability": {
                "semantic_source_supported": [
                    "owner-authority", "repository-evidence"],
                "receipt_required": sorted(
                    loom_plan_author.AUTHORITY_REQUIREMENTS - {
                        "owner-authority", "repository-evidence"}),
            },
            "domain_limits": loom_plan_author.DOMAIN_DRAFT_LIMITS,
            "active_domain_values": list(
                (action["plan_contract"].get("domain_route") or {}).get(
                    "active_task_domains") or action["domains"]),
            "timestamp_contract": (
                "RFC3339 date-time such as 2026-07-24T00:00:00Z, or null where "
                "the field is nullable; date-only and prose values are invalid."),
            "collection_contracts": {
                "answers": "object keyed by every domain_answer_fields value",
                "applicability_evidence": "array of concrete evidence strings",
                "authority_requirements": (
                    "non-empty unique array from domain_authority_requirement_values"),
                "contradicting_source_keys": (
                    "unique array of domain source keys; empty is allowed"),
                "depends_on": (
                    "unique array of earlier WO-### IDs, never work-order titles"),
                "domain_ids": (
                    "non-empty unique array using active_domain_values exactly"),
                "supporting_source_keys": (
                    "non-empty unique array of declared domain source keys"),
            },
            "rules": [
                "Use exactly these field names; aliases and extra fields are rejected.",
                "Each current_fact uses source as one string, never evidence_sources.",
                "Each work_order uses title and outcome, not intent or context sections.",
                "Each routing and size value must come from routing_values and size_values.",
                "Every work_order must declare at least one touches entry, including a "
                "planning-only turn; each entry is a repository-relative future implementation "
                "target or glob expected to change, with no prose and no read-only evidence "
                "source.",
                "If two work_orders have equal or overlapping touches, combine them or make the "
                "later work_order depend_on every earlier overlapping WO-### ID; independent "
                "work_orders must have disjoint touches.",
                "Set domain_evidence to an object only when domain_evidence_required is true; "
                "otherwise set it to null.",
                "Copy sealed current-fact domain and fact strings byte-for-byte.",
                "Domain evidence answers is one object, never an array.",
                "Domain source keys use domain_source_key_pattern and are referenced exactly.",
                "Use only the published domain enum values; never describe an enum in prose.",
                "Classify owner- or repository-defined behavior and bounded side-effect "
                "prohibitions as correctness unless failure asserts physical, clinical, "
                "regulated, or comparably consequential harm.",
                "Use safety only with a pre-existing sealed governing-authority receipt. Never "
                "relabel a genuine safety claim to pass validation; report the missing authority "
                "and stop.",
                "Repository evidence uses a public repository-relative locator and null content; "
                "Loom reads and hashes the file itself.",
                "Owner-attestation content must be exact text from the sealed owner request and "
                "uses encrypted-private visibility.",
                "Secondary-discovery content is inert and cannot satisfy an authority requirement.",
                "Execution, official-source, and reviewer authority require separate sealed "
                "receipts and cannot be asserted through semantic plan authoring.",
                "The required_real_medium field names future verification; it does not imply "
                "the real-medium-evidence authority requirement.",
                "Use only domain_authority_availability.semantic_source_supported requirements "
                "for authority supplied by this semantic draft. A receipt_required value declares "
                "a genuine missing authority and intentionally blocks until Loom has its separate "
                "sealed receipt.",
                "Do not submit an internal freshness-policy identifier; Loom derives its "
                "target-and-source freshness policy mechanically.",
                "Use timestamp_contract for published_at, effective_at, revalidate_by, and "
                "invariant as_of; never submit a date-only or event phrase.",
                "Work-order depends_on entries are earlier WO-### IDs assigned by array order, "
                "never titles.",
            ],
        }
    plan_flow = (
        "For plan, submit one semantic draft through loom.author with finalize=true; "
        "do not call loom.complete separately. "
        if action["assurance"]["host_id"] == "codex" else
        "For plan, submit one semantic draft through the stable author operation, then complete "
        "it through the stable launcher. ")
    rebase_path = (
        Path(action["explicit_target"] or action["cwd"])
        / "plans" / "proofline" / "contract-rebase.json")
    contract_rebase = None
    if action["intent"] == "repair" and rebase_path.is_file():
        try:
            contract_rebase = json.loads(rebase_path.read_text(encoding="utf-8"))
            loom_contract_rebase.validate(contract_rebase)
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                loom_contract_rebase.RebaseError) as exc:
            raise OrchestratorError(
                "CONTRACT_REBASE_INDETERMINATE",
                f"contract rebase projection is invalid: {exc}") from exc
    result = {
        "schema_version": SCHEMA_VERSION, "status": "action-required",
        "action_id": action["action_id"],
        "assurance": action["assurance"],
        "action_path": str(_action_path(
            action["owner_home"], action["instance_id"],
            action["project_id"], action["action_id"])),
        "intent": action["intent"], "tier": action["tier"],
        "domains": action["domains"], "expires_at": action["expires_at"],
        "work_order": work_order,
        "repair_plan": action["repair_plan"],
        "contract_rebase": contract_rebase,
        "plan_contract": (_tier_s_host_capsule(action["plan_contract"])
                          if action["tier"] == "S" and action["plan_contract"] is not None
                          else action["plan_contract"]),
        "semantic_draft_shape": semantic_draft_shape,
        "context_manifest": action["context_manifest"],
        "world_fingerprint": action["prepared"]["world_fingerprint"],
        "continuation_authority": action["continuation_authority"],
        "plan_decision": (
            (action.get("host_result") or {}).get("plan_decision")),
        "revision_context": (
            (action.get("host_result") or {}).get("plan_revision")),
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
            "static Loom guidance. " + plan_flow +
            "Use only semantic_draft_shape field names, copying sealed current facts exactly, "
            "and honoring both semantic_draft_limits and "
            "semantic_draft_shape.domain_limits; otherwise "
            "perform only the routed intent. Do not mutate undeclared target paths. "
            "Attach usage only when the host exposes genuine provider counters. "
            "The orchestrator owns validation, gates, learning, and the final receipt. A prior "
            "terminal block never authorizes fallback work; only this fresh sealed action can "
            "authorize its declared frontier."),
    }
    revision = (action.get("host_result") or {}).get("plan_revision")
    if isinstance(revision, dict):
        result["prepared_intent_authority"] = "bound-plan-revision"
    if action["intent"] == "execute" and action.get("work_order") is not None:
        work_order_path = action_pack / action["work_order"]
        try:
            work_order_relative = work_order_path.relative_to(
                project_root).as_posix()
        except ValueError as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT",
                "execution work order escapes its project") from exc
        try:
            work_order_text = work_order_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise OrchestratorError(
                "ACTION_CORRUPT",
                "execution completion contract cannot read its work order") from exc
        pending_markers = [
            marker for marker in (
                "Pending real implementation evidence.",
                "Pending implementation evidence.",
            )
            if marker in work_order_text
        ]
        if len(pending_markers) != 1:
            raise OrchestratorError(
                "ACTION_CORRUPT",
                "execution completion evidence marker is missing or ambiguous")
        result["execution_completion_contract"] = {
            "schema_version": 1,
            "work_order_path": work_order_relative,
            "work_order_id": work_order,
            "required_status": "done",
            "acceptance_marker": "- [x]",
            "pending_evidence_text": pending_markers[0],
            "evidence_capture": {
                "schema_version": 1,
                "method": "loom-lifecycle-capture-v1",
                "tool_path": str(
                    Path(action["install_root"]) / "tools" / "loom_lifecycle.py"),
                "repo_path": str(Path(
                    action["explicit_target"] or action["cwd"])),
                "pack_path": str(action_pack),
                "argv_prefix": [
                    sys.executable, "-B",
                    str(Path(action["install_root"]) / "tools"
                        / "loom_lifecycle.py"),
                    "capture",
                    "--repo", str(Path(
                        action["explicit_target"] or action["cwd"])),
                    "--pack", str(action_pack),
                    "--wo", work_order,
                    "--medium",
                ],
                "verification_argv_separator": "--",
                "required_medium": "the real verification medium actually used",
                "required_command": "the exact verification command that passed",
            },
            "completion_operation": "loom.complete",
        }
    return result


_ZERO_PROJECT_WRITE_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    r"\bdo\s+not\s+"
    r"(?:(?:implement|execute|apply)(?:\s+(?:it|this|the\s+(?:plan|changes?|work)))?"
    r"\s*(?:,|\band\b|\bor\b)\s*)?"
    r"(?:modify|change|write|create|touch)\s+(?:any\s+)?(?:the\s+)?"
    r"(?:project(?:-local)?\s+)?files?\b",
    r"\bdo\s+not\s+(?:modify|change|write|create|touch)\s+(?:the\s+)?project\b",
    r"\bno\s+(?:project(?:-local)?\s+)?(?:file\s+)?writes?\b",
    r"\bwithout\s+(?:modifying|changing|writing|creating|touching)\s+"
    r"(?:any\s+)?files?\b",
    r"\bleave\s+(?:the\s+)?project\s+(?:byte[- ]for[- ]byte\s+)?unchanged\b",
))


def _explicit_zero_project_write_requested(request):
    """Return true only for an explicit owner prohibition on project-local writes."""
    if not isinstance(request, str):
        return False
    return any(pattern.search(request) for pattern in _ZERO_PROJECT_WRITE_PATTERNS)


def _planning_seed_summary(tier):
    if tier == "S":
        return (
            "Loom created plans/.loom-small-lifecycle.json in the project; "
            "no implementation file was changed.")
    return (
        "Loom created plans/MANIFEST.md and plans/lifecycle.json in the project; "
        "no implementation file was changed.")


def _derived_generation_id(project_id, action_id):
    return "generation-" + hashlib.sha256(
        f"{project_id}:{action_id}".encode("utf-8")).hexdigest()[:32]


def _sealed_request_control(
        request, *, expected_plan_decision=None, revision_context=None,
        lifecycle_state=None):
    host_control = None
    if expected_plan_decision is not None:
        host_control = {
            "primary_operation": "execute", "relation": "start-exact"}
    elif revision_context is not None:
        host_control = {
            "primary_operation": "plan", "relation": "revise-exact"}
    try:
        value = loom_runtime.request_control(
            request, state=(lifecycle_state or {}), host_control=host_control)
        return loom_runtime.validate_request_control(value)
    except loom_runtime.RuntimeError as exc:
        raise OrchestratorError(
            "REQUEST_CONTROL_INVALID",
            f"the lifecycle request control is invalid: {exc}") from exc


def _invoke_under_lock(*, request, cwd, home, install_root, target,
                       timeout_seconds, now, instance_id, memory,
                       transport_invocation_id=None, assurance=None,
                       expected_plan_decision=None, revision_context=None,
                       bound_intent=None):
    action_security = ((memory.vault.crypto, instance_id)
                       if isinstance(memory, loom_vault_adapter.VaultMemoryAdapter) else None)
    invocation_id = transport_invocation_id or str(uuid.uuid4())
    controller = loom_session.SessionController(
        owner_home=home, instance_id=instance_id, handlers={},
        memory=memory)
    opened = controller.open(
        request, invocation_id=invocation_id, cwd=cwd,
        explicit_target=target, now=now, bound_intent=bound_intent)
    if opened.terminal_receipt is not None:
        return opened.terminal_receipt.to_dict()
    prepared = opened.prepared
    plan_decision = None
    plan_revision = None
    revision_archive = None
    if expected_plan_decision is not None:
        if not isinstance(expected_plan_decision, dict) \
                or set(expected_plan_decision) != {
                    "action_path", "presentation_sha256"}:
            raise OrchestratorError(
                "PLAN_DECISION_MISMATCH",
                "exact-plan decision fields are unknown or missing")
        plan_decision = _exact_plan_decision(
            expected_plan_decision["action_path"],
            expected_plan_decision["presentation_sha256"],
            owner_home=home, install_root=install_root, target=target)
        if prepared.intent != "execute":
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                "the project changed after the plan was displayed; review the refreshed "
                "plan before starting")
    if revision_context is not None:
        if not isinstance(revision_context, dict) or set(revision_context) != {
                "action_path", "presentation_sha256"}:
            raise OrchestratorError(
                "PLAN_DECISION_MISMATCH",
                "plan revision fields are unknown or missing")
        if prepared.intent != "plan":
            raise OrchestratorError(
                "PLAN_DECISION_STALE",
                "the revision request no longer routes to a fresh planning action")
        plan_revision, prior_plan_action, revision_archive = (
            _prepare_revision_context(
            revision_context["action_path"],
            revision_context["presentation_sha256"], request,
            owner_home=home, install_root=install_root, target=target))
        prepared = _rebind_revision_prepared(prepared, prior_plan_action)
    status_subject_action = None
    if prepared.intent in {"status", "why"} \
            and _generation_status_projection_requested(request):
        status_subject_action = _active_action_for_status(
            _orchestration_directory(home, instance_id, prepared.project_id),
            owner_home=home, install_root=install_root)
        if status_subject_action is not None:
            prepared = _rebind_status_prepared(
                prepared, status_subject_action)
            opened = loom_session.OpenSession(
                prepared=prepared,
                session_id=opened.session_id,
                operation_id=opened.operation_id,
                journal_path=opened.journal_path,
                started_at=opened.started_at,
                terminal_receipt=opened.terminal_receipt,
                resolved_terminal_block=opened.resolved_terminal_block,
            )
    created_at = _stamp(now)
    domain_contract = loom_domain.select_domains(
        request, explicit=list(prepared.domains),
        project_facts=loom_project_inspection.facts(
            loom_runtime._thaw(prepared.project_inspection)),
        project_inspection=loom_runtime._thaw(prepared.project_inspection)
    )["domain_contract"]
    if prepared.intent == "plan" and prepared.route_contract["tier"] == "S" \
            and not prepared.route_contract["blocked"]:
        preview_action = {
            "tier": "S",
            "domains": list(prepared.domains),
            "domain_contract": domain_contract,
            "request": request,
            "survey_hash": prepared.survey_hash,
            "initial_pack_hash": "0" * 64,
            "project_id": prepared.project_id,
            "created_at": created_at,
        }
        try:
            _tier_s_host_capsule(_make_plan_contract(preview_action, prepared))
        except OrchestratorError as exc:
            if exc.code != "TIER_PROMOTION_REQUIRED":
                raise
            prepared = loom_runtime.promote_prepared_tier(
                prepared, "M", evidence="tier-s-host-capsule-overflow")
            opened = loom_session.OpenSession(
                prepared=prepared,
                session_id=opened.session_id,
                operation_id=opened.operation_id,
                journal_path=opened.journal_path,
                started_at=opened.started_at,
                terminal_receipt=opened.terminal_receipt,
                resolved_terminal_block=opened.resolved_terminal_block,
            )
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
    if prepared.intent == "plan" and _explicit_zero_project_write_requested(request):
        controller.handlers["plan"] = lambda _context: {
            "status": "blocked",
            "code": "project-write-prohibited",
            "success": False,
            "metrics": {},
            "evidence_ids": [],
            "reversible_action_ids": [],
            "user_message": (
                "Loom stopped before changing the project. Creating a persistent Loom plan "
                "currently requires project-local planning files under plans/. Remove the "
                "no-file-write constraint if you want those files created."),
        }
        return controller.run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared).to_dict()
    if revision_archive is not None:
        archive_sha256 = _persist_revision_archive(
            memory, revision_archive)
        if archive_sha256 != plan_revision["archive_sha256"]:
            raise OrchestratorError(
                "PLAN_REVISION_ARCHIVE_FAILED",
                "the immutable revision archive identity changed before persistence")
    context_capsule = controller.prepare_context(opened, request)
    expires_at = _stamp(
        loom_runtime._parse_time(created_at) + dt.timedelta(seconds=timeout_seconds))
    action_id = invocation_id
    path = _action_path(home, instance_id, prepared.project_id, action_id)
    pack_present_at_start = _path_present(target / "plans")
    revision_uses_immutable_stage = (
        isinstance(plan_revision, dict)
        and plan_revision.get("schema_version") == 2)
    lifecycle_state = None
    if os.path.lexists(target / "plans" / loom_plan_store.INDEX_NAME):
        witness_store = _lifecycle_witness_store(
            memory, path.parent, prepared.project_id)
        try:
            _resolved, _semantics, _ledger, _witness, lifecycle_state = \
                loom_lifecycle_transition.observe(
                    target, witness_store=witness_store)
        except loom_lifecycle_transition.LifecycleTransitionError as exc:
            raise OrchestratorError(
                "INVALID_LIFECYCLE",
                f"indexed lifecycle authority cannot be observed safely: {exc}") from exc
    request_control = _sealed_request_control(
        request, expected_plan_decision=expected_plan_decision,
        revision_context=revision_context,
        lifecycle_state=(
            loom_lifecycle_kernel.project(lifecycle_state)
            if lifecycle_state is not None else None))
    generation_id = (
        (plan_revision or {}).get("generation_id")
        or (plan_decision or {}).get("generation_id")
        or (lifecycle_state.generation_id
            if lifecycle_state is not None
            and request_control["relation"] in {
                "continue-active", "repair-active", "cancel-generation"}
            else None)
        or (_derived_generation_id(prepared.project_id, action_id)
            if prepared.intent == "plan" else None))
    rollover_uses_immutable_stage = (
        prepared.intent == "plan"
        and lifecycle_state is not None
        and lifecycle_state.generation_phase.startswith("terminal-")
        and request_control["relation"] == "new")
    action = {
        "schema_version": ACTION_SCHEMA_VERSION, "action_id": action_id,
        "status": "initializing" if prepared.intent == "plan" else "pending",
        "instance_id": instance_id,
        "project_id": prepared.project_id, "request": request,
        "assurance": assurance,
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
        "repair_plan": None,
        "host_result": ({
            **({"plan_decision": plan_decision}
               if plan_decision is not None else {}),
            **({"plan_revision": plan_revision}
               if plan_revision is not None else {}),
        } or None),
        "plan_contract": None,
        "domain_contract": domain_contract,
        "context_manifest": loom_performance.production_context_manifest(install_root),
        "continuation_authority": loom_authority.decide(
            _domain_authority_facts(prepared.intent, domain_contract),
            owner_authorized=prepared.intent in {
                "plan", "execute", "close", "remember", "forget", "undo"}),
        "owner_message": loom_message.build(
            state="progress",
            consequence=_action_consequence({
                "tier": prepared.route_contract["tier"],
                "domain_contract": domain_contract,
            }, use_domain_contract=True),
            verification="pending", freshness="current",
            changes_made=prepared.intent == "plan",
            undo_status=("unavailable" if prepared.intent == "plan"
                         else "not-applicable"),
            summary=(
                _planning_seed_summary(prepared.route_contract["tier"])
                if prepared.intent == "plan"
                else "Loom prepared the next safe frontier."),
            next_action=(
                "Have the agent finish the plan, then review it before any project work starts."
                if prepared.intent == "plan"
                else "Complete and verify the sealed frontier."),
            receipt_id="action-" + action_id),
        "result": None,
        "pack_seed": ({
            "state": "recorded",
            "created_pack": (
                not pack_present_at_start or revision_uses_immutable_stage
                or rollover_uses_immutable_stage),
            "kind": "small" if prepared.route_contract["tier"] == "S" else "planned",
            "manifest": None,
            "activation_atomic_rename": None,
        } if prepared.intent == "plan" else {
            "state": "not-applicable", "created_pack": False,
            "kind": None, "manifest": None, "activation_atomic_rename": None,
        }),
        "recovery_receipt": None,
        "generation_id": generation_id,
        "request_control": request_control,
        "lifecycle_transition": None,
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
        immediate_controller = _controller(action)
        if prepared.intent in {"status", "why"} \
                and _generation_status_projection_requested(request):
            active = status_subject_action
            if active is None:
                active = _active_action_for_status(
                    path.parent, owner_home=home, install_root=install_root)
            if active is not None:
                explain = prepared.intent == "why" or bool(re.search(
                    r"\bstatus\s+and\s+why\b|"
                    r"\bstatus\b[^.!?]{0,80}\bwhy\b|"
                    r"\bwhy\b[^.!?]{0,80}\bstatus\b",
                    request, re.I))
                immediate_controller.handlers[prepared.intent] = (
                    lambda _context, subject=active, include_reason=explain:
                    _active_action_transparency(
                        subject, explain=include_reason)
                )
            elif lifecycle_state is not None:
                explain = prepared.intent == "why" or bool(re.search(
                    r"\bstatus\s+and\s+why\b|"
                    r"\bstatus\b[^.!?]{0,80}\bwhy\b|"
                    r"\bwhy\b[^.!?]{0,80}\bstatus\b",
                    request, re.I))
                immediate_controller.handlers[prepared.intent] = (
                    lambda _context, subject=lifecycle_state,
                    include_reason=explain:
                    _generation_transparency(
                        subject, explain=include_reason)
                )
        if prepared.intent == "undo":
            immediate_controller.handlers["undo"] = \
                lambda _context: _safe_plan_undo_handler(
                    action, immediate_controller.memory,
                    now=loom_runtime._parse_time(created_at))
        immediate = immediate_controller.run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared, selected_context=context_capsule)
        action["status"], action["result"] = "completed", immediate.to_dict()
        _write_action(path, action, action_security)
        return immediate.to_dict()
    if prepared.intent == "plan":
        pack = target / "plans"
        if not action["pack_seed"]["created_pack"]:
            if plan_revision is None:
                raise OrchestratorError(
                    "PLAN_PACK_EXISTS",
                    "a planning pack already exists; use resume or repair instead of mutating it")
            directory = path.parent
            action = _write_action(path, action, action_security)
            _write_active_pointer(
                directory, action_id=action_id, project_id=prepared.project_id)
            action["initial_pack_hash"] = _pack_hash(pack)
            action["pack_seed"] = {
                **action["pack_seed"],
                "state": "installed",
            }
            action["plan_contract"] = _make_plan_contract(action, prepared)
            action["status"] = "pending"
            action = _write_action(path, action, action_security)
            return _pending_action_result(action)
        directory = path.parent
        action = _write_action(path, action, action_security)
        _write_active_pointer(
            directory, action_id=action_id, project_id=prepared.project_id)
        stage, manifest, stage_identity = _seed_stage(path, action, prepared)
        action["pack_seed"] = {**action["pack_seed"], "state": "prepared",
                               "manifest": manifest}
        action["initial_pack_hash"] = _pack_hash(stage)
        action["remove_pristine_pack"] = True
        action["plan_contract"] = _make_plan_contract(action, prepared)
        action["status"] = "pending"
        action = _write_action(path, action, action_security)
    elif prepared.intent == "execute":
        pack = target / "plans"
        work_order_id, work_order_path = _prepare_execution_pack(
            pack, target, action["tier"], prepared.prepared_at,
            action=action, action_path=path, memory=memory,
            plan_decision=plan_decision)
        action["work_order"] = work_order_path
    elif prepared.intent == "repair":
        v3_repair = os.path.lexists(
            target / "plans" / loom_plan_store.INDEX_NAME)
        if v3_repair:
            _prepare_v3_repair_action(action, path, memory)
        elif action["tier"] == "S":
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
            changed_paths = sorted(
                path for path in set(before["baseline_files"])
                | set(after["baseline_files"])
                if before["baseline_files"].get(path)
                != after["baseline_files"].get(path))
            action["repair_plan"] = {
                "force_full": True,
                "changed_paths": changed_paths,
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
        if not v3_repair:
            _write_contract_rebase(
                target / "plans", prepared,
                action["repair_plan"]["changed_paths"], action["install_root"],
                current_consequence=domain_contract["consequence"]["class"])
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
    action_path = (_validate_action_path_authority(action_path, owner_home)
                   if owner_home is not None else _absolute(action_path, "action"))
    try:
        with loom_reliability.exclusive_file_lock(
                _orchestration_lock(action_path.parent)):
            return _complete_under_lock(
                action_path, usage_path, result_path=result_path, now=now,
                owner_home=owner_home, install_root=install_root)
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc


def author(action_path, draft, *, now=None, owner_home=None, install_root=None):
    """Machine-author one pending plan from a bounded semantic draft."""
    action_path = (_validate_action_path_authority(action_path, owner_home)
                   if owner_home is not None else _absolute(action_path, "action"))
    try:
        with loom_reliability.exclusive_file_lock(
                _orchestration_lock(action_path.parent)):
            path, action, action_security = _read_action(
                action_path, owner_home=owner_home, install_root=install_root)
            _reconcile_plan_authoring(action)
            try:
                checked = loom_install.check(action["install_root"])
            except loom_install.InstallError as exc:
                raise OrchestratorError("INSTALL_CHANGED", str(exc)) from exc
            if checked["status"] != "installed":
                raise OrchestratorError(
                    "INSTALL_CHANGED", "installation receipt is not current")
            if action["status"] != "pending" or action["intent"] != "plan" \
                    or not isinstance(action["plan_contract"], dict):
                raise OrchestratorError(
                    "ACTION_NOT_AUTHORABLE",
                    "only one pending sealed planning action can be machine-authored")
            instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
            if instant > loom_runtime._parse_time(action["expires_at"]):
                raise OrchestratorError(
                    "ACTION_TIMEOUT", "planning action expired before authoring",
                    status="expired")
            revision_record = (action.get("host_result") or {}).get(
                "plan_revision")
            if action["schema_version"] == ACTION_SCHEMA_VERSION \
                    and action["pack_seed"]["created_pack"] \
                    and action["pack_seed"]["state"] == "prepared":
                current_world = _staged_plan_world(action)
                if current_world["state_sha256"] != action["survey_hash"]:
                    raise OrchestratorError(
                        "TARGET_DRIFT",
                        "product bytes changed before plan authoring")
            else:
                current = loom_runtime.prepare_invocation(
                    action["request"], instance_id=action["instance_id"],
                    invocation_id=action["invocation_id"], cwd=action["cwd"],
                    explicit_target=action["explicit_target"],
                    owner_home=action["owner_home"], now=instant,
                    bound_intent=("plan" if revision_record is not None else None),
                    lifecycle_witness_reader=_action_lifecycle_witness_reader(
                        action, path.parent))
                if current.survey_hash != action["survey_hash"] \
                        or current.project_id != action["project_id"] \
                        or current.intent != "plan":
                    raise OrchestratorError(
                        "TARGET_DRIFT",
                        "target, project, or routed intent changed before plan authoring")
            root = Path(action["explicit_target"] or action["cwd"])
            version = (
                Path(action["install_root"]) / "VERSION").read_text(
                    encoding="utf-8").strip()
            if revision_record is not None:
                try:
                    presentation_draft = {
                        **draft,
                        "work_orders": [
                            {**item, "id": f"WO-{index:03d}"}
                            for index, item in enumerate(
                                draft["work_orders"], start=1)
                        ],
                    }
                    candidate_semantics = (
                        loom_plan_presentation.extract_semantics(
                            presentation_draft))
                except (
                        KeyError, TypeError,
                        loom_plan_presentation.PresentationError):
                    candidate_semantics = None
                if candidate_semantics is not None and _canonical_bytes(
                        candidate_semantics) == _canonical_bytes(
                            revision_record["prior_semantics"]):
                    raise OrchestratorError(
                        "PLAN_REVISION_EMPTY",
                        "the revised plan is semantically identical to the displayed plan",
                        status="action-required")
            try:
                authored_pack = _action_pack_root(action)
                receipt = loom_plan_author.author(
                    authored_pack, contract=action["plan_contract"], draft=draft,
                    request=action["request"], version=version, repo=root,
                    transaction_path=_plan_author_transaction_path(action),
                    now=instant,
                    fresh_lifecycle=revision_record is not None,
                    validate_stage=lambda stage: _validate_authored_plan(
                        action, pack_override=stage))
                _validate_authored_plan(action)
            except loom_plan_author.PlanAuthorError as exc:
                detail = exc.message
                if exc.diagnostics:
                    detail += ": " + "; ".join(
                        f"{item['code']} {item['path']}: {item['message']}"
                        for item in exc.diagnostics[:8])
                raise OrchestratorError(exc.code, detail, status="action-required") from exc
            semantics = receipt.pop("presentation_semantics")
            revision_number = (
                revision_record["revision"]
                if revision_record is not None else 1)
            action["host_result"] = {
                **(action.get("host_result") or {}),
                "plan_review": {
                    "schema_version": 1,
                    "state": "authored",
                    "revision": revision_number,
                    "semantics": semantics,
                },
            }
            _write_action(path, action, action_security)
            return {
                **receipt, "action_id": action["action_id"],
                "action_path": str(path), "ready_for_completion": True,
            }
    except loom_reliability.ReliabilityError as exc:
        raise OrchestratorError(
            "ACTION_LOCK_UNAVAILABLE", f"project orchestration lock failed: {exc}") from exc


def _complete_under_lock(action_path, usage_path=None, *, result_path=None, now=None,
                         owner_home=None, install_root=None):
    path, action, action_security = _read_action(
        action_path, owner_home=owner_home, install_root=install_root)
    _reconcile_plan_authoring(action)
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
        prior_transition = action.get("lifecycle_transition")
        recovered_completion = (
            isinstance(prior_transition, dict)
            and prior_transition.get("status") == "completed"
            and prior_transition.get("command_id") ==
            "repair-complete-" + action["action_id"]
            and action.get("host_result") is not None)
        if not recovered_completion:
            action["host_result"] = _read_repair_result(result_path, action)
    elif result_path is not None:
        action["host_result"] = {
            **(action.get("host_result") or {}),
            **_read_host_outcome(result_path, action),
        }
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
        revision_record = (action.get("host_result") or {}).get(
            "plan_revision")
        inspection = loom_runtime._thaw(sealed.project_inspection)
        if action["intent"] == "plan" and not inspection["g1_eligible"]:
            unresolved = [item["path"] for item in
                          inspection["unresolved_roots"]]
            raise OrchestratorError(
                "PROJECT_INSPECTION_INCOMPLETE",
                "G1 remains blocked until relevant project coverage is complete: "
                + ", ".join(unresolved[:8]), status="action-required")
        staged_v3_plan = action["intent"] == "plan" \
            and action["pack_seed"]["created_pack"] \
            and action["pack_seed"]["state"] == "prepared" \
            and action["generation_id"] is not None
        current = None
        if staged_v3_plan:
            current_world = _staged_plan_world(action)
            if current_world["state_sha256"] != action["survey_hash"]:
                raise OrchestratorError(
                    "TARGET_DRIFT",
                    "product bytes changed while the reviewed plan was being authored")
        else:
            current = loom_runtime.prepare_invocation(
                action["request"], instance_id=action["instance_id"],
                invocation_id=action["invocation_id"], cwd=action["cwd"],
                explicit_target=action["explicit_target"], owner_home=action["owner_home"],
                now=instant,
                bound_intent=("plan" if revision_record is not None else None),
                lifecycle_witness_reader=_action_lifecycle_witness_reader(
                    action, path.parent))
        if revision_record is not None \
                and revision_record.get("schema_version") == 1:
            root = Path(action["explicit_target"] or action["cwd"])
            try:
                state = loom_gate._stable_state(root, root / "plans")
            except loom_survey.SurveyError as exc:
                raise OrchestratorError(
                    "TARGET_DRIFT",
                    f"revision target could not be observed safely: {exc}") from exc
            project = loom_runtime.resolve_project(
                action["instance_id"], explicit_target=action["explicit_target"],
                cwd=action["cwd"])
            if project.project_id != action["project_id"] \
                    or project.canonical_target_identity \
                    != sealed.canonical_target_identity \
                    or state.state_hash != revision_record["project_state_hash"]:
                raise OrchestratorError(
                    "TARGET_DRIFT",
                    "project files changed while the displayed plan was being revised")
        elif not staged_v3_plan and (
                current.survey_hash != action["survey_hash"]
                or current.project_id != action["project_id"]
                or current.intent != action["intent"]):
            raise OrchestratorError(
                "TARGET_DRIFT",
                "target, project, or routed intent changed during delegated work")
    validated_domain_bundle = None
    if action["intent"] == "plan":
        validated_domain_bundle = _validate_authored_plan(action)
    seal_plan_author = None
    if action["intent"] == "plan" and action["pack_seed"]["created_pack"]:
        def seal_plan_author(memory_adapter):
            revision_record = (action.get("host_result") or {}).get(
                "plan_revision")
            activation = (
                _activate_reviewed_revision(
                    action, path, memory_adapter, instant)
                if isinstance(revision_record, dict)
                and revision_record.get("schema_version") == 2
                else _activate_reviewed_generation(
                    action, path, memory_adapter, instant))
            manifest = activation["manifest"]
            action["host_result"] = {
                **(action.get("host_result") or {}),
                "plan_author": {
                    "schema_version": 1,
                    "action_id": action["action_id"],
                    "state": "active",
                    "manifest": manifest,
                    "archive_path": None,
                    "completed_at": _stamp(instant),
                    "undone_at": None,
                },
                **({
                    "generation_rollover": {
                        "schema_version": 1,
                        "archive_sha256": activation[
                            "generation_archive_sha256"],
                    },
                } if activation.get("generation_archive_sha256") is not None
                    else {}),
            }
            action["pack_seed"] = {
                **action["pack_seed"], "state": "installed",
            }
            action["lifecycle_transition"] = activation["receipt"]
            _write_action(path, action, action_security)
            return action["action_id"]
    seal_execution_completion = None
    if action["intent"] == "execute" and action.get("generation_id") is not None:
        def seal_execution_completion(memory_adapter):
            return _seal_v3_execution_completion(
                action, path, memory_adapter)
    seal_repair_completion = None
    if action["intent"] == "repair" and action.get("generation_id") is not None:
        def seal_repair_completion(memory_adapter):
            return _seal_v3_repair_completion(
                action, path, memory_adapter)
    controller = _controller(
        action, usage=usage, seal_plan_author=seal_plan_author,
        seal_execution_completion=seal_execution_completion,
        seal_repair_completion=seal_repair_completion)
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
    if result.get("status") == "completed" \
            and action["intent"] == "plan" \
            and action["pack_seed"]["created_pack"]:
        try:
            pack = loom_plan_store.resolve(
                Path(action["explicit_target"] or action["cwd"])
            ).generation_root
            final_manifest = loom_reliability.exact_tree_manifest(pack)
            loom_reliability.validate_exact_tree_manifest(final_manifest)
        except (
                loom_plan_store.PlanStoreError,
                loom_reliability.ReliabilityError) as exc:
            raise OrchestratorError(
                "PLAN_UNDO_EVIDENCE_FAILED",
                f"completed plan could not be rebound to its final tree: {exc}") from exc
        action["host_result"]["plan_author"]["manifest"] = final_manifest
    if result.get("status") == "completed":
        stored_domain_records = _store_domain_bundle(
            controller.memory, validated_domain_bundle)
        if stored_domain_records:
            result["domain_learning"] = {
                "bundle_digest": validated_domain_bundle["bundle_digest"],
                "stored_records": len(stored_domain_records),
            }
    plan_host_projection = None
    if result.get("status") == "completed" and action["intent"] == "plan":
        root = Path(action["explicit_target"] or action["cwd"])
        presentation, plan_host_projection = _completed_plan_review(action, root)
        if presentation is not None:
            result["plan_presentation"] = presentation
            revision_result = _completed_plan_revision(action)
            if revision_result is not None:
                result["plan_revision"] = revision_result
    production_replay = _record_production_replay(action, controller.memory)
    if production_replay is not None:
        result["production_replay"] = production_replay
    action["status"], action["result"] = "completed", result
    _write_action(path, action, action_security)
    _clear_active_pointer(path.parent, action["action_id"])
    if plan_host_projection is not None:
        return {**result, "plan_host_projection": plan_host_projection}
    return result


def cancel(action_path, *, now=None, owner_home=None, install_root=None):
    action_path = (_validate_action_path_authority(action_path, owner_home)
                   if owner_home is not None else _absolute(action_path, "action"))
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
    _reconcile_plan_authoring(action)
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


def _project_world_observation(result):
    context = result.get("context_manifest")
    world_fingerprint = result.get("world_fingerprint")
    project_id = result.get("project_id")
    observed = (
        isinstance(context, dict)
        or (
            isinstance(project_id, str)
            and loom_runtime.PROJECT_RE.fullmatch(project_id) is not None
            and isinstance(world_fingerprint, str)
            and re.fullmatch(r"[0-9a-f]{64}", world_fingerprint) is not None
        )
    )
    return {
        "project_id": project_id,
        "action_id": result.get("action_id"),
        "context_manifest_sha256": (
            _hash(context) if isinstance(context, dict) else None),
        "world_fingerprint": world_fingerprint if observed else None,
        "world_observed": observed,
    }, ("observed" if observed else "unavailable")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    invoke_parser = commands.add_parser("invoke-stdio")
    invoke_parser.add_argument("--home", required=True)
    invoke_parser.add_argument("--install-root", required=True)
    invoke_parser.add_argument("--target")
    invoke_parser.add_argument("--timeout-seconds", type=int, default=900)
    invoke_parser.add_argument("--execution-chain")
    resolve_parser = commands.add_parser("resolve-stdio")
    resolve_parser.add_argument("--home", required=True)
    resolve_parser.add_argument("--install-root", required=True)
    author_parser = commands.add_parser("author-stdio")
    author_parser.add_argument("--home", required=True)
    author_parser.add_argument("--install-root", required=True)
    start_parser = commands.add_parser("start-stdio")
    start_parser.add_argument("--home", required=True)
    start_parser.add_argument("--install-root", required=True)
    revise_parser = commands.add_parser("revise-stdio")
    revise_parser.add_argument("--home", required=True)
    revise_parser.add_argument("--install-root", required=True)
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
    chain_id = getattr(args, "execution_chain", None)
    try:
        if args.command == "invoke-stdio":
            envelope = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type="request-envelope")
            if chain_id is not None:
                module_identity = loom_execution_chain.verify_loaded_modules(
                    args.install_root)
                isolation = loom_execution_chain.startup_isolation()
                if not all(isolation[key] for key in (
                        "isolated_flag", "no_user_site", "safe_path",
                        "pythonpath_ignored", "pythonstartup_ignored")):
                    raise OrchestratorError(
                        "RUNTIME_SHADOWING_UNSAFE",
                        "runtime process isolation could not be proven")
                loom_execution_chain.append(
                    args.home, chain_id, "loaded-modules",
                    {**module_identity, **isolation})
            result = invoke(
                request=envelope["request"], cwd=envelope["cwd"], home=args.home,
                install_root=args.install_root, explicit_target=args.target,
                timeout_seconds=args.timeout_seconds,
                transport_invocation_id=_transport_invocation_id(envelope),
                assurance=envelope["assurance"])
            if chain_id is not None:
                project_world, observability = _project_world_observation(result)
                loom_execution_chain.append(
                    args.home, chain_id, "project-world", project_world,
                    observability=observability)
                action_id = result.get("action_id")
                session_id = result.get("session_id")
                loom_execution_chain.append(
                    args.home, chain_id, "operation-journal", {
                        "action_id": action_id,
                        "session_id": session_id,
                        "operation_observed": bool(action_id or session_id),
                    }, observability=(
                        "observed" if action_id or session_id else "unavailable"))
                loom_execution_chain.append(
                    args.home, chain_id, "result", {
                        "status": result.get("status"),
                        "result_sha256": _hash(result),
                    })
                projection = loom_execution_chain.seal(args.home, chain_id)
                result = {**result, "execution_chain": projection}
        elif args.command == "resolve-stdio":
            message = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type="resolve")
            result = resolve(
                request=message["request"], cwd=message["cwd"],
                action_path=message["action"],
                action_sha256=message["action_sha256"],
                home=args.home, install_root=args.install_root)
        elif args.command == "author-stdio":
            message = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type="author")
            result = author(
                message["action"], message["draft"],
                owner_home=args.home, install_root=args.install_root)
        elif args.command == "start-stdio":
            message = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type="start")
            result = start(
                message.get("action"),
                presentation_sha256=message.get("presentation_sha256"),
                cwd=message.get("cwd"),
                owner_home=args.home, install_root=args.install_root)
        elif args.command == "revise-stdio":
            message = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type="revise")
            result = revise(
                message.get("action"),
                presentation_sha256=message.get("presentation_sha256"),
                cwd=message.get("cwd"),
                request=message["request"],
                owner_home=args.home, install_root=args.install_root)
        elif args.command == "complete":
            result = complete(
                args.action, args.usage, result_path=args.result,
                owner_home=args.home, install_root=args.install_root)
        else:
            result = cancel(
                args.action, owner_home=args.home, install_root=args.install_root)
    except OrchestratorError as exc:
        if chain_id is not None:
            try:
                loom_execution_chain.append(
                    args.home, chain_id, "result", {
                        "status": exc.status,
                        "error_code": exc.code,
                        "error_sha256": hashlib.sha256(
                            exc.message.encode("utf-8")).hexdigest(),
                    })
                loom_execution_chain.seal(args.home, chain_id, blocked=True)
            except loom_execution_chain.ExecutionChainError:
                pass
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": exc.status,
            "code": exc.code, "error": exc.message,
        }, sort_keys=True))
        return 2
    except loom_adapter_protocol.ProtocolError as exc:
        if chain_id is not None:
            try:
                loom_execution_chain.append(
                    args.home, chain_id, "result", {
                        "status": "blocked", "error_code": exc.code,
                        "error_sha256": hashlib.sha256(
                            str(exc).encode("utf-8")).hexdigest(),
                    })
                loom_execution_chain.seal(args.home, chain_id, blocked=True)
            except loom_execution_chain.ExecutionChainError:
                pass
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": "blocked",
            "code": exc.code, "error": str(exc),
        }, sort_keys=True))
        return 2
    except (loom_memory.MemoryError, loom_crypto.CryptoError, loom_owner.OwnerError,
            loom_vault_adapter.VaultAdapterError, loom_runtime.RuntimeError,
            loom_session.SessionError, loom_install.InstallError,
            loom_planning_intelligence.PlanningIntelligenceError,
            loom_execution_chain.ExecutionChainError,
            loom_survey.SurveyError) as exc:
        if chain_id is not None:
            try:
                loom_execution_chain.append(
                    args.home, chain_id, "result", {
                        "status": "blocked",
                        "error_code": "RUNTIME_BLOCKED",
                        "error_sha256": hashlib.sha256(
                            str(exc).encode("utf-8")).hexdigest(),
                    })
                loom_execution_chain.seal(args.home, chain_id, blocked=True)
            except loom_execution_chain.ExecutionChainError:
                pass
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": "blocked",
            "code": "RUNTIME_BLOCKED", "error": str(exc),
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
