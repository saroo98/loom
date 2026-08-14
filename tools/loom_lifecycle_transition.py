#!/usr/bin/env python3
"""Sole v3 lifecycle writer with exact preflight and monotonic commit semantics."""

import hashlib
import base64
import json
import os
import re
from pathlib import Path

import loom_lifecycle_kernel as kernel
import loom_plan_store
import loom_reliability


MAX_AUTHORITY_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 12 * 1024 * 1024
MAX_QUARANTINE_ENTRIES = 1024
MAX_QUARANTINE_FILE_BYTES = 4 * 1024 * 1024
MAX_QUARANTINE_TOTAL_BYTES = 16 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class LifecycleTransitionError(RuntimeError):
    """Raised when one transition cannot be proven safe or idempotent."""


class LifecycleTransitionInterrupted(LifecycleTransitionError):
    """Test/host-visible interruption at a named recovery boundary."""


class FileWitnessStore:
    """Test/legacy witness adapter; production uses the encrypted owner vault."""

    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        return _load_json(self.path, "lifecycle head witness")

    def read_optional(self):
        if not os.path.lexists(self.path):
            return None
        return self.read()

    def write(self, value):
        try:
            loom_reliability.atomic_write_json(self.path, value)
        except loom_reliability.ReliabilityError as exc:
            raise LifecycleTransitionError(
                f"lifecycle head witness write failed: {exc}") from exc
        return self.read()


class VaultWitnessStore:
    """Encrypted owner-vault adapter for one project's anti-rollback witness."""

    ENTITY_TYPE = "lifecycle-head-witness-v1"

    def __init__(self, vault, project_id):
        if not isinstance(project_id, str) or not project_id:
            raise LifecycleTransitionError("lifecycle witness project is invalid")
        self.vault = vault
        self.project_id = project_id

    def read(self):
        value = self.read_optional()
        if value is None:
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness is missing or ambiguous")
        return value

    def read_optional(self):
        try:
            matches = [
                item for item in self.vault.list_entities(
                    self.ENTITY_TYPE, limit=512)
                if item.get("id") == self.project_id
            ]
        except Exception as exc:
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness could not be read") from exc
        if not matches:
            return None
        if len(matches) != 1 or not isinstance(matches[0].get("value"), dict):
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness is missing or ambiguous")
        value = matches[0]["value"]
        try:
            witness = kernel.validate_head_witness(value)
        except kernel.LifecycleKernelError as exc:
            raise LifecycleTransitionError(
                f"encrypted lifecycle head witness is invalid: {exc}") from exc
        if witness.project_id != self.project_id:
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness belongs to another project")
        return value

    def write(self, value):
        try:
            witness = kernel.validate_head_witness(value)
        except kernel.LifecycleKernelError as exc:
            raise LifecycleTransitionError(
                f"encrypted lifecycle head witness is invalid: {exc}") from exc
        if witness.project_id != self.project_id:
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness belongs to another project")
        try:
            self.vault.put_entity(
                self.ENTITY_TYPE, self.project_id, value, source_sequence=0)
        except Exception as exc:
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness could not be advanced") from exc
        observed = self.read()
        if observed != value:
            raise LifecycleTransitionError(
                "encrypted lifecycle head witness changed during advancement")
        return observed


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path, label, maximum=MAX_AUTHORITY_BYTES):
    path = Path(path)
    try:
        info = path.lstat()
        redirected = path.is_symlink() or bool(
            getattr(info, "st_file_attributes", 0)
            & FILE_ATTRIBUTE_REPARSE_POINT)
        if redirected or not path.is_file() or int(info.st_nlink) != 1 \
                or not 1 <= info.st_size <= maximum:
            raise LifecycleTransitionError(
                f"{label} is missing, redirected, hardlinked, or oversized")
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, LifecycleTransitionError):
            raise
        raise LifecycleTransitionError(f"{label} is invalid: {exc}") from exc


def _witness_store(*, witness_path=None, witness_store=None):
    if (witness_path is None) == (witness_store is None):
        raise LifecycleTransitionError(
            "exactly one lifecycle witness store is required")
    return FileWitnessStore(witness_path) if witness_store is None else witness_store


def _observe(project_root, witness_store):
    try:
        resolved = loom_plan_store.resolve(project_root)
        if resolved.authority_version != "v3":
            raise LifecycleTransitionError("v3 lifecycle transition requires v3 authority")
        loom_plan_store.validate_resolution(resolved)
        semantics = _load_json(
            resolved.generation_root / "plan-semantics.json", "reviewed plan semantics")
        reviewed_world = _load_json(
            resolved.generation_root / "reviewed-world.json",
            "reviewed world observation")
        ledger = _load_json(
            resolved.generation_root / "lifecycle.json", "lifecycle ledger")
        witness = witness_store.read()
        validated_world = kernel.validate_reviewed_world_observation(
            reviewed_world)
        validated_semantics = kernel.validate_reviewed_plan_semantics(semantics)
        if validated_world["project_id"] != validated_semantics.project_id \
                or validated_world["generation_id"] != \
                validated_semantics.generation_id \
                or validated_world["state_sha256"] != \
                validated_semantics.reviewed_world_sha256 \
                or validated_world["observation_sha256"] != \
                validated_semantics.reviewed_world_observation_sha256:
            raise LifecycleTransitionError(
                "reviewed world observation does not match plan semantics")
        loom_plan_store.validate_resolution(resolved)
        state = kernel.fold(resolved.index, semantics, ledger, witness)
    except (loom_plan_store.PlanStoreError, kernel.LifecycleKernelError) as exc:
        raise LifecycleTransitionError(f"canonical lifecycle observation failed: {exc}") \
            from exc
    return resolved, semantics, ledger, witness, state


def observe(project_root, *, witness_store):
    """Return one fully validated canonical v3 observation without mutation."""
    if witness_store is None:
        raise LifecycleTransitionError(
            "canonical lifecycle observation requires its head witness")
    return _observe(project_root, witness_store)


def _event_value(event):
    return {
        "sequence": event.sequence,
        "event_type": event.event_type,
        "command_id": event.command_id,
        "transition_id": event.transition_id,
        "payload": event.payload_dict,
        "previous_event_sha256": event.previous_event_sha256,
        "event_sha256": event.event_sha256,
    }


def _initial_event(sequence, event_type, command_id, transition_id, payload,
                   previous_event_sha256):
    value = {
        "sequence": sequence,
        "event_type": event_type,
        "command_id": command_id,
        "transition_id": transition_id,
        "payload": payload,
        "previous_event_sha256": previous_event_sha256,
    }
    value["event_sha256"] = kernel.digest(value)
    return value


def _require_reviewed_plan_projection(stage, label):
    manifest = stage / "MANIFEST.md"
    compact = stage / "WO-001.md"
    manifest_valid = manifest.is_file() and not manifest.is_symlink()
    compact_valid = compact.is_file() and not compact.is_symlink()
    if manifest_valid == compact_valid:
        raise LifecycleTransitionError(
            f"{label} must contain exactly one reviewed plan projection")


def _write_or_verify_prepared_json(path, value, label, *, replace_sha256=None):
    """Idempotently finish a non-authoritative stage from exact target bytes."""
    path = Path(path)
    expected = kernel.canonical_bytes(value) + b"\n"
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_file():
            raise LifecycleTransitionError(f"{label} is redirected or invalid")
        try:
            observed = path.read_bytes()
        except OSError as exc:
            raise LifecycleTransitionError(f"{label} cannot be read") from exc
        if observed == expected:
            return
        if replace_sha256 is None \
                or hashlib.sha256(observed).hexdigest() != replace_sha256:
            raise LifecycleTransitionError(
                f"{label} conflicts with the exact prepared target")
    loom_reliability.atomic_write_json(path, value)
    try:
        observed = path.read_bytes()
    except OSError as exc:
        raise LifecycleTransitionError(f"{label} cannot be reread") from exc
    if observed != expected:
        raise LifecycleTransitionError(
            f"{label} changed during non-authoritative preparation")


def prepare_generation_authority(
        stage_root, *, index_value, semantics_value, reviewed_world_value,
        command_id, relation,
        predecessor_generation_id, predecessor_witness_sha256,
        replace_lifecycle_sha256=None, replace_lifecycle_name="lifecycle.json"):
    """Seal one complete non-authoritative reviewed generation in a stage."""
    stage = Path(stage_root)
    try:
        index = kernel.validate_generation_index(index_value)
        semantics = kernel.validate_reviewed_plan_semantics(semantics_value)
        reviewed_world = kernel.validate_reviewed_world_observation(
            reviewed_world_value)
    except kernel.LifecycleKernelError as exc:
        raise LifecycleTransitionError(
            f"prepared generation identity is invalid: {exc}") from exc
    if index.project_id != semantics.project_id \
            or index.generation_id != semantics.generation_id \
            or reviewed_world["project_id"] != semantics.project_id \
            or reviewed_world["generation_id"] != semantics.generation_id \
            or reviewed_world["state_sha256"] != semantics.reviewed_world_sha256 \
            or reviewed_world["observation_sha256"] != \
            semantics.reviewed_world_observation_sha256 \
            or relation not in {"new", "repair-of", "supersedes"} \
            or (predecessor_generation_id is None) != \
            (predecessor_witness_sha256 is None) \
            or relation != "new" and predecessor_generation_id is None \
            or (predecessor_witness_sha256 is not None and (
                not isinstance(predecessor_witness_sha256, str)
                or kernel.HEX64.fullmatch(predecessor_witness_sha256) is None)) \
            or not isinstance(command_id, str) \
            or kernel.SAFE_ID.fullmatch(command_id) is None \
            or replace_lifecycle_sha256 is not None and (
                not isinstance(replace_lifecycle_sha256, str)
                or kernel.HEX64.fullmatch(replace_lifecycle_sha256) is None):
        raise LifecycleTransitionError("prepared generation relation is invalid")
    try:
        if stage.is_symlink() or not stage.is_dir():
            raise LifecycleTransitionError(
                "prepared generation stage is missing or redirected")
        _require_reviewed_plan_projection(stage, "prepared generation")
        if replace_lifecycle_name not in {
                "lifecycle.json", ".loom-small-lifecycle.json"}:
            raise LifecycleTransitionError(
                "replaceable planning lifecycle name is invalid")
        lifecycle_path = stage / replace_lifecycle_name
        if replace_lifecycle_name != "lifecycle.json" \
                and os.path.lexists(lifecycle_path) \
                and (replace_lifecycle_sha256 is None
                     or not lifecycle_path.is_file()
                     or lifecycle_path.is_symlink()
                     or hashlib.sha256(lifecycle_path.read_bytes()).hexdigest()
                     != replace_lifecycle_sha256):
            raise LifecycleTransitionError(
                "replaceable planning lifecycle changed before generation sealing")
        transition_id = kernel.digest({
            "kind": "reviewed-generation-activation-v1",
            "command_id": command_id,
            "index_sha256": index.index_sha256,
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
            "predecessor_generation_id": predecessor_generation_id,
            "predecessor_witness_sha256": predecessor_witness_sha256,
            "relation": relation,
        })
        created = _initial_event(
            1, "generation-created", command_id, transition_id, {
                "predecessor_generation_id": predecessor_generation_id,
                "relation": relation,
            }, None)
        reviewed = _initial_event(
            2, "plan-reviewed", command_id, transition_id, {
                "plan_semantics_sha256": semantics.plan_semantics_sha256,
                "revision_number": semantics.revision_number,
                "reviewed_world_sha256": semantics.reviewed_world_sha256,
            }, created["event_sha256"])
        ledger = {
            "schema_version": 3,
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
            "execution_policy": semantics.execution_policy,
            "execution_sequence_sha256": kernel.digest(
                semantics.graph.execution_sequence),
            "events": [created, reviewed],
        }
        ledger["lifecycle_sha256"] = kernel.digest(ledger)
        kernel.validate_lifecycle_ledger(ledger)
        witness = {
            "schema_version": 1,
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "transition_id": transition_id,
            "authoritative_sha256": ledger["lifecycle_sha256"],
            "predecessor_witness_sha256": predecessor_witness_sha256,
        }
        witness["witness_sha256"] = kernel.digest(witness)
        kernel.validate_head_witness(witness)
        _write_or_verify_prepared_json(
            stage / "plan-semantics.json", semantics_value,
            "prepared plan semantics")
        _write_or_verify_prepared_json(
            stage / "reviewed-world.json", reviewed_world_value,
            "prepared reviewed world")
        _write_or_verify_prepared_json(
            stage / "lifecycle.json", ledger, "prepared lifecycle ledger",
            replace_sha256=(
                replace_lifecycle_sha256
                if replace_lifecycle_name == "lifecycle.json" else None))
        # Tier-S's compact lifecycle remains a verified human/compatibility
        # projection.  The new lifecycle.json is the only v3 authority; keeping
        # the exact reviewed compact bytes preserves their sealed freshness and
        # lets projection writers advance the historical surface safely.
        manifest = loom_reliability.exact_tree_manifest(
            stage, max_entries=1024, max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
        value = {
            "schema_version": 1,
            "activation_kind": "new-generation",
            "command_id": command_id,
            "index": index_value,
            "semantics": semantics_value,
            "reviewed_world": reviewed_world_value,
            "ledger": ledger,
            "witness": witness,
            "replaced_lifecycle_sha256": replace_lifecycle_sha256,
            "stage_manifest": manifest,
        }
        value["prepared_sha256"] = kernel.digest(value)
        _validate_prepared_generation(value)
        return value
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"prepared generation could not be sealed: {exc}") from exc


def prepare_revision_authority(
        stage_root, *, index_value, semantics_value, reviewed_world_value,
        source_index, source_semantics, source_ledger, source_witness,
        command_id, replace_lifecycle_sha256=None,
        replace_lifecycle_name="lifecycle.json"):
    """Seal one immutable pre-authorization revision for index activation."""
    stage = Path(stage_root)
    try:
        index = kernel.validate_generation_index(index_value)
        semantics = kernel.validate_reviewed_plan_semantics(semantics_value)
        reviewed_world = kernel.validate_reviewed_world_observation(
            reviewed_world_value)
        source_state = kernel.fold(
            source_index, source_semantics, source_ledger, source_witness)
    except kernel.LifecycleKernelError as exc:
        raise LifecycleTransitionError(
            f"prepared revision identity is invalid: {exc}") from exc
    if source_state.generation_phase != "reviewable" \
            or index.project_id != source_state.project_id \
            or index.generation_id != source_state.generation_id \
            or semantics.project_id != source_state.project_id \
            or semantics.generation_id != source_state.generation_id \
            or semantics.revision_number != \
            kernel.validate_reviewed_plan_semantics(
                source_semantics).revision_number + 1 \
            or semantics.plan_semantics_sha256 == \
            source_state.plan_semantics_sha256 \
            or reviewed_world["project_id"] != semantics.project_id \
            or reviewed_world["generation_id"] != semantics.generation_id \
            or reviewed_world["state_sha256"] != semantics.reviewed_world_sha256 \
            or reviewed_world["observation_sha256"] != \
            semantics.reviewed_world_observation_sha256 \
            or index.index_sha256 == source_index.get("index_sha256") \
            or not isinstance(command_id, str) \
            or kernel.SAFE_ID.fullmatch(command_id) is None \
            or replace_lifecycle_sha256 is not None and (
                not isinstance(replace_lifecycle_sha256, str)
                or kernel.HEX64.fullmatch(replace_lifecycle_sha256) is None):
        raise LifecycleTransitionError("prepared revision relation is invalid")
    try:
        if stage.is_symlink() or not stage.is_dir():
            raise LifecycleTransitionError(
                "prepared revision stage is missing or redirected")
        _require_reviewed_plan_projection(stage, "prepared revision")
        if replace_lifecycle_name not in {
                "lifecycle.json", ".loom-small-lifecycle.json"}:
            raise LifecycleTransitionError(
                "replaceable planning lifecycle name is invalid")
        lifecycle_path = stage / replace_lifecycle_name
        if replace_lifecycle_name != "lifecycle.json" \
                and os.path.lexists(lifecycle_path) \
                and (replace_lifecycle_sha256 is None
                     or not lifecycle_path.is_file()
                     or lifecycle_path.is_symlink()
                     or hashlib.sha256(lifecycle_path.read_bytes()).hexdigest()
                     != replace_lifecycle_sha256):
            raise LifecycleTransitionError(
                "replaceable planning lifecycle changed before revision sealing")
        transition_id = kernel.digest({
            "kind": "reviewed-plan-revision-activation-v1",
            "source_state_sha256": source_state.state_sha256,
            "command_id": command_id,
            "index_sha256": index.index_sha256,
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
        })
        revised = _initial_event(
            source_state.last_event_sequence + 1, "plan-revised",
            command_id, transition_id, {
                "plan_semantics_sha256": semantics.plan_semantics_sha256,
                "revision_number": semantics.revision_number,
                "reviewed_world_sha256": semantics.reviewed_world_sha256,
            }, source_state.last_event_sha256)
        ledger = {
            "schema_version": 3,
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
            "execution_policy": semantics.execution_policy,
            "execution_sequence_sha256": kernel.digest(
                semantics.graph.execution_sequence),
            "events": [*source_ledger["events"], revised],
        }
        ledger["lifecycle_sha256"] = kernel.digest(ledger)
        kernel.validate_lifecycle_ledger(ledger)
        witness = {
            "schema_version": 1,
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "transition_id": transition_id,
            "authoritative_sha256": ledger["lifecycle_sha256"],
            "predecessor_witness_sha256": source_witness["witness_sha256"],
        }
        witness["witness_sha256"] = kernel.digest(witness)
        kernel.validate_head_witness(witness)
        _write_or_verify_prepared_json(
            stage / "plan-semantics.json", semantics_value,
            "prepared revision semantics")
        _write_or_verify_prepared_json(
            stage / "reviewed-world.json", reviewed_world_value,
            "prepared revision world")
        _write_or_verify_prepared_json(
            stage / "lifecycle.json", ledger, "prepared revision ledger",
            replace_sha256=(
                replace_lifecycle_sha256
                if replace_lifecycle_name == "lifecycle.json" else None))
        # Preserve the exact compact projection beside the authoritative v3
        # ledger for the same reason as new-generation preparation above.
        manifest = loom_reliability.exact_tree_manifest(
            stage, max_entries=1024, max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
        value = {
            "schema_version": 1,
            "activation_kind": "revision",
            "command_id": command_id,
            "index": index_value,
            "semantics": semantics_value,
            "reviewed_world": reviewed_world_value,
            "ledger": ledger,
            "witness": witness,
            "replaced_lifecycle_sha256": replace_lifecycle_sha256,
            "stage_manifest": manifest,
        }
        value["prepared_sha256"] = kernel.digest(value)
        _validate_prepared_generation(value)
        return value
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"prepared revision could not be sealed: {exc}") from exc


def prepare_legacy_adoption(
        project_root, *, index_value, semantics_value, reviewed_world_value,
        command_id, source_lifecycle_name):
    """Prepare a read-only, exact-byte adoption of one validated legacy root."""
    root = Path(project_root).resolve(strict=True)
    try:
        resolved = loom_plan_store.resolve(root)
        index = kernel.validate_generation_index(index_value)
        semantics = kernel.validate_reviewed_plan_semantics(semantics_value)
        reviewed_world = kernel.validate_reviewed_world_observation(
            reviewed_world_value)
    except (loom_plan_store.PlanStoreError, kernel.LifecycleKernelError) as exc:
        raise LifecycleTransitionError(
            f"legacy adoption identity is invalid: {exc}") from exc
    if resolved.authority_version != "legacy-v2" \
            or resolved.generation_root != root / "plans" \
            or index.storage_kind != "legacy-root" \
            or index.generation_path != "plans" \
            or index.project_id != semantics.project_id \
            or index.generation_id != semantics.generation_id \
            or reviewed_world["project_id"] != semantics.project_id \
            or reviewed_world["generation_id"] != semantics.generation_id \
            or reviewed_world["state_sha256"] != semantics.reviewed_world_sha256 \
            or reviewed_world["observation_sha256"] != \
            semantics.reviewed_world_observation_sha256 \
            or source_lifecycle_name not in {
                "lifecycle.json", ".loom-small-lifecycle.json"} \
            or not isinstance(command_id, str) \
            or kernel.SAFE_ID.fullmatch(command_id) is None:
        raise LifecycleTransitionError("legacy adoption relation is invalid")
    plans = resolved.generation_root
    source_lifecycle = plans / source_lifecycle_name
    if source_lifecycle.is_symlink() or not source_lifecycle.is_file():
        raise LifecycleTransitionError(
            "legacy lifecycle is missing or redirected")
    try:
        source_bytes = source_lifecycle.read_bytes()
        if not 1 <= len(source_bytes) <= MAX_AUTHORITY_BYTES:
            raise LifecycleTransitionError("legacy lifecycle size is invalid")
        for name in ("plan-semantics.json", "reviewed-world.json"):
            if os.path.lexists(plans / name):
                raise LifecycleTransitionError(
                    "legacy root already contains unexplained v3 control state")
        if source_lifecycle_name != "lifecycle.json" \
                and os.path.lexists(plans / "lifecycle.json"):
            raise LifecycleTransitionError(
                "legacy root already contains an unexplained lifecycle target")
        source_manifest = loom_reliability.exact_tree_manifest(
            plans, max_entries=1024, max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
        loom_reliability.validate_exact_tree_manifest(
            source_manifest, max_entries=1024,
            max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
    except (OSError, loom_reliability.ReliabilityError) as exc:
        if isinstance(exc, LifecycleTransitionError):
            raise
        raise LifecycleTransitionError(
            f"legacy adoption source could not be sealed: {exc}") from exc
    transition_id = kernel.digest({
        "kind": "legacy-root-adoption-v1",
        "command_id": command_id,
        "index_sha256": index.index_sha256,
        "plan_semantics_sha256": semantics.plan_semantics_sha256,
        "source_tree_sha256": source_manifest["root_sha256"],
        "source_lifecycle_sha256": hashlib.sha256(source_bytes).hexdigest(),
    })
    created = _initial_event(
        1, "generation-created", command_id, transition_id,
        {"predecessor_generation_id": None, "relation": "new"}, None)
    reviewed = _initial_event(
        2, "plan-reviewed", command_id, transition_id, {
            "plan_semantics_sha256": semantics.plan_semantics_sha256,
            "revision_number": semantics.revision_number,
            "reviewed_world_sha256": semantics.reviewed_world_sha256,
        }, created["event_sha256"])
    ledger = {
        "schema_version": 3,
        "project_id": semantics.project_id,
        "generation_id": semantics.generation_id,
        "plan_semantics_sha256": semantics.plan_semantics_sha256,
        "execution_policy": semantics.execution_policy,
        "execution_sequence_sha256": kernel.digest(
            semantics.graph.execution_sequence),
        "events": [created, reviewed],
    }
    ledger["lifecycle_sha256"] = kernel.digest(ledger)
    witness = {
        "schema_version": 1,
        "project_id": semantics.project_id,
        "generation_id": semantics.generation_id,
        "transition_id": transition_id,
        "authoritative_sha256": ledger["lifecycle_sha256"],
        "predecessor_witness_sha256": None,
    }
    witness["witness_sha256"] = kernel.digest(witness)
    value = {
        "schema_version": 1,
        "activation_kind": "legacy-adoption",
        "command_id": command_id,
        "index": index_value,
        "semantics": semantics_value,
        "reviewed_world": reviewed_world_value,
        "ledger": ledger,
        "witness": witness,
        "source_lifecycle_name": source_lifecycle_name,
        "source_lifecycle_base64": base64.b64encode(source_bytes).decode("ascii"),
        "source_lifecycle_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "source_manifest": source_manifest,
    }
    value["prepared_sha256"] = kernel.digest(value)
    _validate_prepared_legacy_adoption(value)
    return value


def _validate_prepared_legacy_adoption(value):
    fields = {
        "schema_version", "activation_kind", "command_id", "index",
        "semantics", "reviewed_world", "ledger", "witness",
        "source_lifecycle_name", "source_lifecycle_base64",
        "source_lifecycle_sha256", "source_manifest", "prepared_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("activation_kind") != "legacy-adoption" \
            or value.get("prepared_sha256") != kernel.digest({
                key: item for key, item in value.items()
                if key != "prepared_sha256"}) \
            or value.get("source_lifecycle_name") not in {
                "lifecycle.json", ".loom-small-lifecycle.json"}:
        raise LifecycleTransitionError(
            "prepared legacy adoption contract is invalid")
    try:
        source_bytes = base64.b64decode(
            value["source_lifecycle_base64"], validate=True)
        if not 1 <= len(source_bytes) <= MAX_AUTHORITY_BYTES \
                or hashlib.sha256(source_bytes).hexdigest() != \
                value["source_lifecycle_sha256"]:
            raise LifecycleTransitionError(
                "prepared legacy lifecycle bytes are invalid")
        state = kernel.fold(
            value["index"], value["semantics"], value["ledger"],
            value["witness"])
        index = kernel.validate_generation_index(value["index"])
        reviewed_world = kernel.validate_reviewed_world_observation(
            value["reviewed_world"])
        loom_reliability.validate_exact_tree_manifest(
            value["source_manifest"], max_entries=1024,
            max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
    except (ValueError, kernel.LifecycleKernelError,
            loom_reliability.ReliabilityError) as exc:
        if isinstance(exc, LifecycleTransitionError):
            raise
        raise LifecycleTransitionError(
            f"prepared legacy adoption contract is invalid: {exc}") from exc
    if index.storage_kind != "legacy-root" \
            or index.generation_path != "plans" \
            or state.generation_phase != "reviewable" \
            or reviewed_world["project_id"] != state.project_id \
            or reviewed_world["generation_id"] != state.generation_id \
            or reviewed_world["state_sha256"] != state.reviewed_world_sha256 \
            or value["command_id"] != value["ledger"]["events"][-1]["command_id"]:
        raise LifecycleTransitionError(
            "prepared legacy adoption state is invalid")
    return state


def _validate_prepared_generation(value):
    fields = {
        "schema_version", "activation_kind", "command_id", "index", "semantics",
        "reviewed_world", "ledger", "witness", "stage_manifest",
        "replaced_lifecycle_sha256", "prepared_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("activation_kind") not in {"new-generation", "revision"} \
            or value.get("prepared_sha256") != kernel.digest({
                key: item for key, item in value.items()
                if key != "prepared_sha256"}):
        raise LifecycleTransitionError("prepared generation contract is invalid")
    replaced = value["replaced_lifecycle_sha256"]
    if replaced is not None and (
            not isinstance(replaced, str)
            or kernel.HEX64.fullmatch(replaced) is None):
        raise LifecycleTransitionError("prepared generation contract is invalid")
    try:
        state = kernel.fold(
            value["index"], value["semantics"], value["ledger"],
            value["witness"])
        reviewed_world = kernel.validate_reviewed_world_observation(
            value["reviewed_world"])
        loom_reliability.validate_exact_tree_manifest(
            value["stage_manifest"], max_entries=1024,
            max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
    except (kernel.LifecycleKernelError, loom_reliability.ReliabilityError) as exc:
        raise LifecycleTransitionError(
            f"prepared generation contract is invalid: {exc}") from exc
    if state.generation_phase != "reviewable" \
            or reviewed_world["project_id"] != state.project_id \
            or reviewed_world["generation_id"] != state.generation_id \
            or reviewed_world["state_sha256"] != state.reviewed_world_sha256 \
            or value["command_id"] != value["ledger"]["events"][-1]["command_id"]:
        raise LifecycleTransitionError("prepared generation state is invalid")
    return state


def _activation_envelope_path(root, command_id):
    leaf = hashlib.sha256(command_id.encode("utf-8")).hexdigest()
    return Path(root) / ("generation-" + leaf + ".json")


def _load_activation_envelope(path, command_id):
    if not os.path.lexists(path):
        return None
    value = _load_json(path, "generation activation envelope", MAX_ENVELOPE_BYTES)
    fields = {
        "schema_version", "kind", "command_id", "prepared",
        "source_index", "source_witness", "status", "receipt",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("kind") != "generation-activation-v1" \
            or value.get("command_id") != command_id \
            or value.get("status") not in {
                "prepared", "completed", "abandoned"} \
            or (value.get("status") == "prepared") != \
            (value.get("receipt") is None):
        raise LifecycleTransitionError("generation activation envelope is invalid")
    _validate_prepared_generation(value["prepared"])
    if value["receipt"] is not None:
        validate_receipt(value["receipt"])
    return value


def _index_observation(project_root):
    index_path = Path(project_root) / "plans" / loom_plan_store.INDEX_NAME
    if not os.path.lexists(index_path):
        return None
    return _load_json(index_path, "active-generation index", 64 * 1024)


def _generation_tree_matches(path, expected):
    try:
        actual = loom_reliability.exact_tree_manifest(
            path, max_entries=1024, max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
        return loom_reliability.exact_tree_manifests_equal(
            actual, expected, max_entries=1024,
            max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
    except (OSError, loom_reliability.ReliabilityError):
        return False


def _remove_exact_generation(path, expected):
    path = Path(path)
    if not _generation_tree_matches(path, expected):
        raise LifecycleTransitionError(
            "abandoned generation differs from its prepared evidence")
    try:
        entries = sorted(
            path.rglob("*"), key=lambda item: len(item.parts), reverse=True)
        for entry in entries:
            if entry.is_symlink():
                raise LifecycleTransitionError(
                    "abandoned generation contains a redirected entry")
            if entry.is_dir():
                entry.rmdir()
            else:
                entry.unlink()
        path.rmdir()
        loom_reliability._sync_parent(path)
    except OSError as exc:
        raise LifecycleTransitionError(
            f"abandoned generation cleanup failed: {exc}") from exc


def _activation_receipt(envelope, *, status, observation, projection_status):
    prepared = envelope["prepared"]
    source_index = envelope["source_index"]
    source_witness = envelope["source_witness"]
    value = {
        "schema_version": 1,
        "project_id": prepared["index"]["project_id"],
        "generation_id": prepared["index"]["generation_id"],
        "command_id": envelope["command_id"],
        "transition_id": prepared["witness"]["transition_id"],
        "status": status,
        "source_authority_sha256": (
            source_index["index_sha256"] if source_index is not None
            else kernel.digest({"active_generation": "absent"})),
        "target_authority_sha256": prepared["index"]["index_sha256"],
        "source_witness_sha256": (
            source_witness["witness_sha256"]
            if source_witness is not None else None),
        "target_witness_sha256": prepared["witness"]["witness_sha256"],
        "observation": observation,
        "durability_scope": (
            "power-loss-unconfirmed" if os.name == "nt"
            else "process-crash-confirmed"),
        "projection_status": projection_status,
        "findings": [],
    }
    value["receipt_sha256"] = kernel.digest(value)
    return value


def activate_generation(
        project_root, stage_root, prepared, *, witness_path=None,
        witness_store=None, envelope_root, lock_path, fault_at=None,
        project_projection=None, _lock_held=False):
    """Activate one complete generation with the index as linearization point."""
    _validate_prepared_generation(prepared)
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    command_id = prepared["command_id"]
    path = _activation_envelope_path(envelope_root, command_id)
    existing = _load_activation_envelope(path, command_id)
    if existing is not None:
        if existing["prepared"]["prepared_sha256"] != prepared["prepared_sha256"]:
            raise LifecycleTransitionError(
                "generation activation command identity conflicts")
        return recover_generation_activation(
            project_root, command_id, witness_store=witness_store,
            envelope_root=envelope_root, lock_path=lock_path,
            project_projection=project_projection, _lock_held=_lock_held)
    root = Path(project_root).resolve(strict=True)
    stage = Path(stage_root).resolve(strict=True)
    if not _generation_tree_matches(stage, prepared["stage_manifest"]):
        raise LifecycleTransitionError(
            "prepared generation stage changed before activation")
    def activate_locked():
        source_index = _index_observation(root)
        source_witness = witness_store.read_optional()
        predecessor = prepared["witness"]["predecessor_witness_sha256"]
        if (source_witness is None) != (source_index is None) \
                or predecessor != (
                    source_witness["witness_sha256"]
                    if source_witness is not None else None):
            raise LifecycleTransitionError(
                "generation activation predecessor is inconsistent")
        activation_kind = prepared["activation_kind"]
        created_payload = prepared["ledger"]["events"][0]["payload"]
        if source_index is None:
            if activation_kind != "new-generation" \
                    or created_payload["predecessor_generation_id"] is not None:
                raise LifecycleTransitionError(
                    "first generation unexpectedly names a predecessor")
        else:
            resolved, source_semantics, source_ledger, _witness, source_state = _observe(
                root, witness_store)
            exact_source_index = {
                    "schema_version": 1,
                    "project_id": resolved.index.project_id,
                    "generation_id": resolved.index.generation_id,
                    "storage_kind": resolved.index.storage_kind,
                    "generation_path": resolved.index.generation_path,
                    "index_sha256": resolved.index.index_sha256,
            }
            if source_index != exact_source_index:
                raise LifecycleTransitionError(
                    "generation activation source index changed")
            if activation_kind == "revision":
                target_semantics = kernel.validate_reviewed_plan_semantics(
                    prepared["semantics"])
                source_semantics_record = kernel.validate_reviewed_plan_semantics(
                    source_semantics)
                if source_state.generation_phase != "reviewable" \
                        or prepared["index"]["project_id"] != source_state.project_id \
                        or prepared["index"]["generation_id"] != source_state.generation_id \
                        or prepared["index"]["index_sha256"] == \
                        source_index["index_sha256"] \
                        or target_semantics.revision_number != \
                        source_semantics_record.revision_number + 1 \
                        or prepared["ledger"]["events"][:-1] != \
                        source_ledger["events"] \
                        or prepared["ledger"]["events"][-1]["event_type"] != \
                        "plan-revised":
                    raise LifecycleTransitionError(
                        "plan revision requires one exact reviewable predecessor")
            elif not source_state.generation_phase.startswith("terminal-") \
                    or created_payload["predecessor_generation_id"] != \
                    source_state.generation_id \
                    or prepared["index"]["project_id"] != source_state.project_id \
                    or prepared["index"]["generation_id"] == source_state.generation_id:
                raise LifecycleTransitionError(
                    "generation rollover requires one exact terminal predecessor")
        envelope = {
            "schema_version": 1,
            "kind": "generation-activation-v1",
            "command_id": command_id,
            "prepared": prepared,
            "source_index": source_index,
            "source_witness": source_witness,
            "status": "prepared",
            "receipt": None,
        }
        _write_envelope(path, envelope)
        _fault("after-prepare", fault_at)
        target = root.joinpath(
            *Path(prepared["index"]["generation_path"]).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            source_identity = loom_reliability.observe_root_identity(stage)
            loom_reliability.atomic_rename_noreplace(
                stage, target, expected_source_identity=source_identity,
                source_role="prepared_generation",
                destination_role="inactive_generation")
        except loom_reliability.ReliabilityError as exc:
            raise LifecycleTransitionError(
                f"prepared generation installation failed: {exc}") from exc
        if not _generation_tree_matches(target, prepared["stage_manifest"]):
            raise LifecycleTransitionError(
                "installed generation differs from prepared evidence")
        _fault("after-generation-install", fault_at)
        index_path = root / "plans" / loom_plan_store.INDEX_NAME
        loom_reliability.atomic_write_json(index_path, prepared["index"])
        _fault("after-index-commit", fault_at)
        witness_store.write(prepared["witness"])
        _fault("after-witness", fault_at)
        if project_projection is not None:
            project_projection(prepared)
        receipt = _activation_receipt(
            envelope, status="completed", observation="target",
            projection_status="verified")
        envelope["status"] = "completed"
        envelope["receipt"] = receipt
        _write_envelope(path, envelope)
        return {"status": "completed", "receipt": receipt}

    if _lock_held:
        return activate_locked()
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return activate_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"generation activation lock failed: {exc}") from exc


def recover_generation_activation(
        project_root, command_id, *, witness_path=None, witness_store=None,
        envelope_root, lock_path, project_projection=None, _lock_held=False):
    """Classify and reconcile an exact prepared generation activation."""
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    path = _activation_envelope_path(envelope_root, command_id)
    envelope = _load_activation_envelope(path, command_id)
    if envelope is None:
        raise LifecycleTransitionError(
            "no exact generation activation exists to recover")
    prepared = envelope["prepared"]
    root = Path(project_root).resolve(strict=True)
    def reconcile_locked():
        current_index = _index_observation(root)
        current_witness = witness_store.read_optional()
        source_index = envelope["source_index"]
        source_witness = envelope["source_witness"]
        target_index = prepared["index"]
        target_witness = prepared["witness"]
        target = root.joinpath(*Path(target_index["generation_path"]).parts)
        if current_index == source_index:
            if envelope["status"] == "completed":
                if not _generation_tree_matches(
                        target, prepared["stage_manifest"]):
                    raise LifecycleTransitionError(
                        "completed activation recovery material is unavailable")
                advance_witness = current_witness == source_witness
                if not advance_witness and current_witness != target_witness:
                    raise LifecycleTransitionError(
                        "rolled-back activation index and witness disagree")
                loom_reliability.atomic_write_json(
                    root / "plans" / loom_plan_store.INDEX_NAME, target_index)
                if advance_witness:
                    witness_store.write(target_witness)
                if project_projection is not None:
                    project_projection(prepared)
                receipt = _activation_receipt(
                    envelope, status="completed", observation="target",
                    projection_status="verified")
                envelope["status"] = "completed"
            else:
                if current_witness != source_witness:
                    raise LifecycleTransitionError(
                        "source activation index and witness disagree")
                if target.is_dir():
                    _remove_exact_generation(target, prepared["stage_manifest"])
                receipt = _activation_receipt(
                    envelope, status="abandoned", observation="source",
                    projection_status="not-applicable")
                envelope["status"] = "abandoned"
        elif current_index == target_index:
            if not _generation_tree_matches(
                    target, prepared["stage_manifest"]):
                raise LifecycleTransitionError(
                    "active generation differs from prepared evidence")
            if current_witness == source_witness:
                witness_store.write(target_witness)
            elif current_witness != target_witness:
                raise LifecycleTransitionError(
                    "target activation index and witness disagree")
            if project_projection is not None:
                project_projection(prepared)
            receipt = _activation_receipt(
                envelope, status="completed", observation="target",
                projection_status="verified")
            envelope["status"] = "completed"
        else:
            raise LifecycleTransitionError(
                "active-generation observation matches neither source nor target")
        envelope["receipt"] = receipt
        _write_envelope(path, envelope)
        return {"status": envelope["status"], "receipt": receipt}

    if _lock_held:
        return reconcile_locked()
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return reconcile_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"generation activation recovery lock failed: {exc}") from exc


def _legacy_adoption_envelope_path(root, command_id):
    leaf = hashlib.sha256(command_id.encode("utf-8")).hexdigest()
    return Path(root) / ("legacy-adoption-" + leaf + ".json")


def _load_legacy_adoption_envelope(path, command_id):
    if not os.path.lexists(path):
        return None
    value = _load_json(path, "legacy adoption envelope", MAX_ENVELOPE_BYTES)
    fields = {
        "schema_version", "kind", "command_id", "prepared", "status",
        "receipt",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("kind") != "legacy-root-adoption-v1" \
            or value.get("command_id") != command_id \
            or value.get("status") not in {
                "prepared", "completed", "abandoned"} \
            or (value.get("status") == "prepared") != \
            (value.get("receipt") is None):
        raise LifecycleTransitionError("legacy adoption envelope is invalid")
    _validate_prepared_legacy_adoption(value["prepared"])
    if value["receipt"] is not None:
        validate_receipt(value["receipt"])
    return value


def _legacy_source_matches(plans, prepared):
    try:
        actual = loom_reliability.exact_tree_manifest(
            plans, max_entries=1024, max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
        return loom_reliability.exact_tree_manifests_equal(
            actual, prepared["source_manifest"], max_entries=1024,
            max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
    except (OSError, loom_reliability.ReliabilityError):
        return False


def _exact_json_bytes(value):
    return kernel.canonical_bytes(value) + b"\n"


def _exact_file_bytes(path, expected):
    path = Path(path)
    try:
        return path.is_file() and not path.is_symlink() \
            and path.read_bytes() == expected
    except OSError:
        return False


def _legacy_target_controls_match(plans, prepared):
    return all((
        _exact_file_bytes(
            plans / "plan-semantics.json",
            _exact_json_bytes(prepared["semantics"])),
        _exact_file_bytes(
            plans / "reviewed-world.json",
            _exact_json_bytes(prepared["reviewed_world"])),
        _exact_file_bytes(
            plans / "lifecycle.json",
            _exact_json_bytes(prepared["ledger"])),
    ))


def _restore_legacy_source(plans, prepared):
    """Remove only exact staged controls and restore the exact legacy lifecycle."""
    plans = Path(plans)
    for name, expected in (
            ("plan-semantics.json", _exact_json_bytes(prepared["semantics"])),
            ("reviewed-world.json", _exact_json_bytes(prepared["reviewed_world"]))):
        path = plans / name
        if not os.path.lexists(path):
            continue
        if not _exact_file_bytes(path, expected):
            raise LifecycleTransitionError(
                "staged legacy adoption control changed before recovery")
        try:
            path.unlink()
            loom_reliability._sync_parent(path)
        except OSError as exc:
            raise LifecycleTransitionError(
                "staged legacy adoption control could not be removed") from exc
    source_bytes = base64.b64decode(
        prepared["source_lifecycle_base64"], validate=True)
    source_name = prepared["source_lifecycle_name"]
    lifecycle_target = plans / "lifecycle.json"
    if source_name == "lifecycle.json":
        if os.path.lexists(lifecycle_target) \
                and not (_exact_file_bytes(lifecycle_target, source_bytes)
                         or _exact_file_bytes(
                             lifecycle_target,
                             _exact_json_bytes(prepared["ledger"]))):
            raise LifecycleTransitionError(
                "staged legacy lifecycle changed before recovery")
        if not _exact_file_bytes(lifecycle_target, source_bytes):
            try:
                loom_reliability.atomic_write_bytes(
                    lifecycle_target, source_bytes)
            except loom_reliability.ReliabilityError as exc:
                raise LifecycleTransitionError(
                    "legacy lifecycle could not be restored") from exc
    else:
        source_path = plans / source_name
        if not _exact_file_bytes(source_path, source_bytes):
            raise LifecycleTransitionError(
                "legacy compact lifecycle changed before recovery")
        if os.path.lexists(lifecycle_target):
            if not _exact_file_bytes(
                    lifecycle_target, _exact_json_bytes(prepared["ledger"])):
                raise LifecycleTransitionError(
                    "staged lifecycle target changed before recovery")
            try:
                lifecycle_target.unlink()
                loom_reliability._sync_parent(lifecycle_target)
            except OSError as exc:
                raise LifecycleTransitionError(
                    "staged lifecycle target could not be removed") from exc
    if not _legacy_source_matches(plans, prepared):
        raise LifecycleTransitionError(
            "legacy source does not match its exact pre-adoption evidence")


def _legacy_adoption_receipt(envelope, *, status, observation,
                             projection_status):
    prepared = envelope["prepared"]
    value = {
        "schema_version": 1,
        "project_id": prepared["index"]["project_id"],
        "generation_id": prepared["index"]["generation_id"],
        "command_id": envelope["command_id"],
        "transition_id": prepared["witness"]["transition_id"],
        "status": status,
        "source_authority_sha256": kernel.digest({
            "legacy_tree_sha256": prepared["source_manifest"]["root_sha256"]}),
        "target_authority_sha256": prepared["index"]["index_sha256"],
        "source_witness_sha256": None,
        "target_witness_sha256": prepared["witness"]["witness_sha256"],
        "observation": observation,
        "durability_scope": (
            "power-loss-unconfirmed" if os.name == "nt"
            else "process-crash-confirmed"),
        "projection_status": projection_status,
        "findings": [],
    }
    value["receipt_sha256"] = kernel.digest(value)
    validate_receipt(value)
    return value


def adopt_legacy_root(
        project_root, prepared, *, witness_path=None, witness_store=None,
        envelope_root, lock_path, fault_at=None, project_projection=None,
        _lock_held=False):
    """Journal and activate one exact historical pack as v3 legacy-root authority."""
    _validate_prepared_legacy_adoption(prepared)
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    command_id = prepared["command_id"]
    path = _legacy_adoption_envelope_path(envelope_root, command_id)
    existing = _load_legacy_adoption_envelope(path, command_id)
    if existing is not None:
        if existing["prepared"]["prepared_sha256"] != prepared["prepared_sha256"]:
            raise LifecycleTransitionError(
                "legacy adoption command identity conflicts")
        return recover_legacy_adoption(
            project_root, command_id, witness_store=witness_store,
            envelope_root=envelope_root, lock_path=lock_path,
            project_projection=project_projection, _lock_held=_lock_held)
    root = Path(project_root).resolve(strict=True)
    plans = root / "plans"

    def adopt_locked():
        if _index_observation(root) is not None \
                or witness_store.read_optional() is not None:
            raise LifecycleTransitionError(
                "legacy adoption unexpectedly has v3 authority")
        try:
            resolved = loom_plan_store.resolve(root)
        except loom_plan_store.PlanStoreError as exc:
            raise LifecycleTransitionError(
                f"legacy adoption source cannot be resolved: {exc}") from exc
        if resolved.authority_version != "legacy-v2" \
                or not _legacy_source_matches(plans, prepared):
            raise LifecycleTransitionError(
                "legacy adoption source changed before locked revalidation")
        envelope = {
            "schema_version": 1,
            "kind": "legacy-root-adoption-v1",
            "command_id": command_id,
            "prepared": prepared,
            "status": "prepared",
            "receipt": None,
        }
        _write_envelope(path, envelope)
        _fault("after-prepare", fault_at)
        _write_or_verify_prepared_json(
            plans / "plan-semantics.json", prepared["semantics"],
            "adopted plan semantics")
        _fault("after-semantics", fault_at)
        _write_or_verify_prepared_json(
            plans / "reviewed-world.json", prepared["reviewed_world"],
            "adopted reviewed world")
        _fault("after-reviewed-world", fault_at)
        _write_or_verify_prepared_json(
            plans / "lifecycle.json", prepared["ledger"],
            "adopted lifecycle ledger",
            replace_sha256=prepared["source_lifecycle_sha256"] \
                if prepared["source_lifecycle_name"] == "lifecycle.json" else None)
        _fault("after-lifecycle", fault_at)
        loom_reliability.atomic_write_json(
            plans / loom_plan_store.INDEX_NAME, prepared["index"])
        _fault("after-index-commit", fault_at)
        witness_store.write(prepared["witness"])
        _fault("after-witness", fault_at)
        if project_projection is not None:
            project_projection(prepared)
        receipt = _legacy_adoption_receipt(
            envelope, status="completed", observation="target",
            projection_status="verified")
        envelope["status"] = "completed"
        envelope["receipt"] = receipt
        _write_envelope(path, envelope)
        return {"status": "completed", "receipt": receipt}

    if _lock_held:
        return adopt_locked()
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return adopt_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"legacy adoption lock failed: {exc}") from exc


def recover_legacy_adoption(
        project_root, command_id, *, witness_path=None, witness_store=None,
        envelope_root, lock_path, project_projection=None, _lock_held=False):
    """Reconcile one exact historical adoption from its index commit point."""
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    path = _legacy_adoption_envelope_path(envelope_root, command_id)
    envelope = _load_legacy_adoption_envelope(path, command_id)
    if envelope is None:
        raise LifecycleTransitionError(
            "no exact legacy adoption exists to recover")
    prepared = envelope["prepared"]
    root = Path(project_root).resolve(strict=True)
    plans = root / "plans"

    def reconcile_locked():
        current_index = _index_observation(root)
        current_witness = witness_store.read_optional()
        target_index = prepared["index"]
        target_witness = prepared["witness"]
        controls_match = _legacy_target_controls_match(plans, prepared)
        if current_index is None:
            if envelope["status"] == "completed":
                if not controls_match:
                    raise LifecycleTransitionError(
                        "completed legacy adoption recovery material is unavailable")
                if current_witness is not None \
                        and current_witness != target_witness:
                    raise LifecycleTransitionError(
                        "rolled-back legacy adoption index and witness disagree")
                loom_reliability.atomic_write_json(
                    plans / loom_plan_store.INDEX_NAME, target_index)
                if current_witness is None:
                    witness_store.write(target_witness)
                if project_projection is not None:
                    project_projection(prepared)
                receipt = _legacy_adoption_receipt(
                    envelope, status="completed", observation="target",
                    projection_status="verified")
                envelope["status"] = "completed"
            else:
                if current_witness is not None:
                    raise LifecycleTransitionError(
                        "precommit legacy adoption unexpectedly has a witness")
                _restore_legacy_source(plans, prepared)
                receipt = _legacy_adoption_receipt(
                    envelope, status="abandoned", observation="source",
                    projection_status="not-applicable")
                envelope["status"] = "abandoned"
        elif current_index == target_index:
            if not controls_match:
                raise LifecycleTransitionError(
                    "adopted legacy authority differs from prepared evidence")
            if current_witness is None:
                witness_store.write(target_witness)
            elif current_witness != target_witness:
                raise LifecycleTransitionError(
                    "target legacy adoption index and witness disagree")
            if project_projection is not None:
                project_projection(prepared)
            receipt = _legacy_adoption_receipt(
                envelope, status="completed", observation="target",
                projection_status="verified")
            envelope["status"] = "completed"
        else:
            raise LifecycleTransitionError(
                "legacy adoption index matches neither source nor target")
        envelope["receipt"] = receipt
        _write_envelope(path, envelope)
        return {"status": envelope["status"], "receipt": receipt}

    if _lock_held:
        return reconcile_locked()
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return reconcile_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"legacy adoption recovery lock failed: {exc}") from exc


def _target_ledger(source, decision):
    value = {
        key: item for key, item in source.items()
        if key != "lifecycle_sha256"
    }
    value["events"] = [*source["events"], *(
        _event_value(event) for event in decision.event_batch.events)]
    value["lifecycle_sha256"] = kernel.digest(value)
    kernel.validate_lifecycle_ledger(value)
    return value


def _target_witness(source, decision, target_ledger):
    value = {
        "schema_version": 1,
        "project_id": source["project_id"],
        "generation_id": source["generation_id"],
        "transition_id": decision.transition_id,
        "authoritative_sha256": target_ledger["lifecycle_sha256"],
        "predecessor_witness_sha256": source["witness_sha256"],
    }
    value["witness_sha256"] = kernel.digest(value)
    kernel.validate_head_witness(value)
    return value


def _receipt(decision, source_ledger, target_ledger, source_witness,
             target_witness, *, status="completed", observation="target",
             projection_status="verified", findings=()):
    value = {
        "schema_version": 1,
        "project_id": source_ledger["project_id"],
        "generation_id": source_ledger["generation_id"],
        "command_id": decision.command_id,
        "transition_id": decision.transition_id,
        "status": status,
        "source_authority_sha256": source_ledger["lifecycle_sha256"],
        "target_authority_sha256": target_ledger["lifecycle_sha256"],
        "source_witness_sha256": source_witness.get("witness_sha256"),
        "target_witness_sha256": target_witness["witness_sha256"],
        "observation": observation,
        "durability_scope": (
            "power-loss-unconfirmed" if os.name == "nt"
            else "process-crash-confirmed"),
        "projection_status": projection_status,
        "findings": list(findings),
    }
    value["receipt_sha256"] = kernel.digest(value)
    return validate_receipt(value)


def validate_receipt(value):
    """Validate one closed public-safe lifecycle transition receipt."""
    fields = {
        "schema_version", "project_id", "generation_id", "command_id",
        "transition_id", "status", "source_authority_sha256",
        "target_authority_sha256", "source_witness_sha256",
        "target_witness_sha256", "observation", "durability_scope",
        "projection_status", "findings", "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("status") not in {
                "prepared", "committed-projection-pending", "completed",
                "abandoned", "ambiguous", "failed"} \
            or value.get("observation") not in {
                "source", "target", "neither", "unavailable"} \
            or value.get("durability_scope") not in {
                "process-crash-confirmed", "power-loss-confirmed",
                "power-loss-unconfirmed"} \
            or value.get("projection_status") not in {
                "pending", "verified", "failed", "not-applicable"}:
        raise LifecycleTransitionError("lifecycle transition receipt is invalid")
    for name in ("project_id", "generation_id", "command_id"):
        if not isinstance(value.get(name), str) \
                or kernel.SAFE_ID.fullmatch(value[name]) is None:
            raise LifecycleTransitionError(
                "lifecycle transition receipt identity is invalid")
    for name in (
            "transition_id", "source_authority_sha256",
            "target_authority_sha256", "target_witness_sha256"):
        if not isinstance(value.get(name), str) \
                or kernel.HEX64.fullmatch(value[name]) is None:
            raise LifecycleTransitionError(
                "lifecycle transition receipt digest is invalid")
    source_witness = value.get("source_witness_sha256")
    if source_witness is not None and (
            not isinstance(source_witness, str)
            or kernel.HEX64.fullmatch(source_witness) is None):
        raise LifecycleTransitionError(
            "lifecycle transition receipt witness is invalid")
    findings = value.get("findings")
    if not isinstance(findings, list) or len(findings) > 32 \
            or findings != list(dict.fromkeys(findings)) \
            or any(not isinstance(item, str)
                   or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", item) is None
                   for item in findings):
        raise LifecycleTransitionError(
            "lifecycle transition receipt findings are invalid")
    claimed = value.get("receipt_sha256")
    unsigned = {key: item for key, item in value.items()
                if key != "receipt_sha256"}
    if not isinstance(claimed, str) or kernel.HEX64.fullmatch(claimed) is None \
            or claimed != kernel.digest(unsigned):
        raise LifecycleTransitionError(
            "lifecycle transition receipt digest does not match")
    return value


def _response(decision, *, receipt=None):
    return {
        "accepted": decision.accepted,
        "primary_code": decision.primary_code,
        "status": receipt["status"] if receipt is not None else "rejected",
        "transition_id": decision.transition_id,
        "receipt": receipt,
    }


def _envelope_path(root, command_id):
    leaf = hashlib.sha256(command_id.encode("utf-8")).hexdigest() + ".json"
    return Path(root) / leaf


def _load_existing_envelope(path, command, *, private_projection=None):
    if not os.path.lexists(path):
        return None
    value = _load_json(path, "lifecycle transition envelope", MAX_ENVELOPE_BYTES)
    fields = {
        "schema_version", "command", "command_id", "command_sha256", "transition_id",
        "decision_sha256", "primary_code", "source_ledger", "target_ledger",
        "source_witness", "target_witness", "private_projection",
        "private_projection_sha256", "status", "receipt",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("command_id") != command.command_id \
            or value.get("status") not in {
                "prepared", "completed", "abandoned"} \
            or (value.get("status") == "prepared") != \
            (value.get("receipt") is None):
        raise LifecycleTransitionError("lifecycle transition envelope is invalid")
    if value["command_sha256"] != command.command_sha256:
        raise LifecycleTransitionError(
            "command identity was reused for different lifecycle content")
    stored_private = value["private_projection"]
    stored_private_digest = value["private_projection_sha256"]
    if stored_private is None:
        if stored_private_digest is not None:
            raise LifecycleTransitionError(
                "lifecycle transition private projection is invalid")
    elif not isinstance(stored_private, dict) \
            or len(kernel.canonical_bytes(stored_private)) > MAX_AUTHORITY_BYTES \
            or stored_private_digest != kernel.digest(stored_private):
        raise LifecycleTransitionError(
            "lifecycle transition private projection is invalid")
    if private_projection is not None \
            and (not isinstance(private_projection, dict)
                 or kernel.digest(private_projection) != stored_private_digest):
        raise LifecycleTransitionError(
            "lifecycle transition private projection identity conflicts")
    try:
        stored_command = kernel.lifecycle_command(value["command"])
    except kernel.LifecycleKernelError as exc:
        raise LifecycleTransitionError(
            f"lifecycle transition envelope command is invalid: {exc}") from exc
    if stored_command.command_sha256 != command.command_sha256:
        raise LifecycleTransitionError(
            "lifecycle transition envelope command does not match")
    try:
        source_ledger = kernel.validate_lifecycle_ledger(
            value["source_ledger"])
        target_ledger = kernel.validate_lifecycle_ledger(
            value["target_ledger"])
        source_witness = kernel.validate_head_witness(
            value["source_witness"])
        target_witness = kernel.validate_head_witness(
            value["target_witness"])
    except kernel.LifecycleKernelError as exc:
        raise LifecycleTransitionError(
            f"lifecycle transition envelope authority is invalid: {exc}") from exc
    if source_ledger.project_id != target_ledger.project_id \
            or source_ledger.generation_id != target_ledger.generation_id \
            or source_witness.authoritative_sha256 != source_ledger.lifecycle_sha256 \
            or target_witness.authoritative_sha256 != target_ledger.lifecycle_sha256 \
            or value["transition_id"] != target_ledger.events[-1].transition_id:
        raise LifecycleTransitionError(
            "lifecycle transition envelope authority does not match")
    if value["receipt"] is not None:
        validate_receipt(value["receipt"])
    return value


def _write_envelope(path, value):
    path = Path(path)
    if path.parent.exists() and path.parent.is_symlink():
        raise LifecycleTransitionError("transition envelope root is redirected")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        loom_reliability.atomic_write_json(path, value)
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(f"transition envelope write failed: {exc}") \
            from exc


def _fault(name, requested):
    if requested == name:
        raise LifecycleTransitionInterrupted(name)


def validate_quarantine_receipt(value):
    """Validate one closed privacy-safe receipt for invalid store preservation."""
    fields = {
        "schema_version", "project_id", "command_id", "quarantine_id",
        "reason_code", "status", "source_tree_sha256", "source_file_count",
        "source_directory_count", "source_total_bytes", "durability_scope",
        "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("status") != "completed" \
            or value.get("durability_scope") not in {
                "process-crash-confirmed", "power-loss-unconfirmed"}:
        raise LifecycleTransitionError("plan-store quarantine receipt is invalid")
    for field in ("project_id", "command_id", "quarantine_id", "reason_code"):
        item = value.get(field)
        if not isinstance(item, str) or kernel.SAFE_ID.fullmatch(item) is None:
            raise LifecycleTransitionError(
                "plan-store quarantine receipt identity is invalid")
    if not isinstance(value.get("source_tree_sha256"), str) \
            or kernel.HEX64.fullmatch(value["source_tree_sha256"]) is None:
        raise LifecycleTransitionError(
            "plan-store quarantine receipt digest is invalid")
    for field, maximum in (
            ("source_file_count", MAX_QUARANTINE_ENTRIES),
            ("source_directory_count", MAX_QUARANTINE_ENTRIES),
            ("source_total_bytes", MAX_QUARANTINE_TOTAL_BYTES)):
        item = value.get(field)
        if type(item) is not int or not 0 <= item <= maximum:
            raise LifecycleTransitionError(
                "plan-store quarantine receipt bound is invalid")
    unsigned = {
        key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(value.get("receipt_sha256"), str) \
            or value["receipt_sha256"] != kernel.digest(unsigned):
        raise LifecycleTransitionError(
            "plan-store quarantine receipt digest does not match")
    return value


def _quarantine_receipt(*, project_id, command_id, quarantine_id,
                        reason_code, manifest):
    value = {
        "schema_version": 1,
        "project_id": project_id,
        "command_id": command_id,
        "quarantine_id": quarantine_id,
        "reason_code": reason_code,
        "status": "completed",
        "source_tree_sha256": manifest["root_sha256"],
        "source_file_count": manifest["file_count"],
        "source_directory_count": manifest["directory_count"],
        "source_total_bytes": manifest["total_bytes"],
        "durability_scope": (
            "power-loss-unconfirmed" if os.name == "nt"
            else "process-crash-confirmed"),
    }
    value["receipt_sha256"] = kernel.digest(value)
    return validate_quarantine_receipt(value)


def quarantine_invalid_store(
        project_root, *, project_id, command_id, reason_code, quarantine_root,
        lock_path, _lock_held=False):
    """Explicitly preserve a bounded invalid plan store without interpreting it.

    The exact tree is moved as one no-replace namespace operation. It is never
    treated as a normal lifecycle event because invalid authority cannot safely
    authorize an append. The returned receipt contains no path or source text.
    """
    for label, value in (
            ("project identity", project_id),
            ("quarantine command identity", command_id),
            ("quarantine reason", reason_code)):
        if not isinstance(value, str) or kernel.SAFE_ID.fullmatch(value) is None:
            raise LifecycleTransitionError(f"{label} is invalid")
    root = Path(project_root).resolve(strict=True)
    private = Path(quarantine_root).resolve(strict=True)
    try:
        private.relative_to(root)
    except ValueError:
        pass
    else:
        raise LifecycleTransitionError(
            "plan-store quarantine must be outside the project")
    plans = root / "plans"
    quarantine_id = "quarantine-" + hashlib.sha256(kernel.canonical_bytes({
        "project_id": project_id,
        "command_id": command_id,
        "reason_code": reason_code,
    })).hexdigest()[:32]
    directory = private / quarantine_id
    destination = directory / "plans"
    receipt_path = directory / "receipt.json"

    def read_completed():
        receipt = validate_quarantine_receipt(_load_json(
            receipt_path, "plan-store quarantine receipt", 64 * 1024))
        if receipt["project_id"] != project_id \
                or receipt["command_id"] != command_id \
                or receipt["quarantine_id"] != quarantine_id \
                or receipt["reason_code"] != reason_code:
            raise LifecycleTransitionError(
                "plan-store quarantine command identity conflicts")
        manifest = loom_reliability.exact_tree_manifest(
            destination, max_entries=MAX_QUARANTINE_ENTRIES,
            max_file_bytes=MAX_QUARANTINE_FILE_BYTES,
            max_total_bytes=MAX_QUARANTINE_TOTAL_BYTES)
        if manifest["root_sha256"] != receipt["source_tree_sha256"] \
                or manifest["file_count"] != receipt["source_file_count"] \
                or manifest["directory_count"] != \
                receipt["source_directory_count"] \
                or manifest["total_bytes"] != receipt["source_total_bytes"]:
            raise LifecycleTransitionError(
                "preserved plan-store quarantine differs from its receipt")
        return receipt

    def quarantine_locked():
        source_present = os.path.lexists(plans)
        destination_present = os.path.lexists(destination)
        receipt_present = os.path.lexists(receipt_path)
        if receipt_present:
            if source_present or not destination_present:
                raise LifecycleTransitionError(
                    "plan-store quarantine namespace is ambiguous")
            return read_completed()
        if source_present and destination_present:
            raise LifecycleTransitionError(
                "plan-store source and quarantine both exist")
        if not source_present and not destination_present:
            raise LifecycleTransitionError(
                "plan-store quarantine source and target are both absent")
        if source_present:
            try:
                loom_plan_store.resolve(root)
            except loom_plan_store.PlanStoreError:
                pass
            else:
                raise LifecycleTransitionError(
                    "valid plan authority must use a lifecycle transition, not quarantine")
            try:
                manifest = loom_reliability.exact_tree_manifest(
                    plans, max_entries=MAX_QUARANTINE_ENTRIES,
                    max_file_bytes=MAX_QUARANTINE_FILE_BYTES,
                    max_total_bytes=MAX_QUARANTINE_TOTAL_BYTES)
                source_identity = loom_reliability.observe_root_identity(plans)
                if not directory.exists():
                    loom_reliability.reserve_directory_leaf(
                        private, quarantine_id, mode=0o700)
                elif directory.is_symlink() or not directory.is_dir():
                    raise LifecycleTransitionError(
                        "plan-store quarantine destination is unsafe")
                loom_reliability.atomic_rename_noreplace(
                    plans, destination,
                    expected_source_identity=source_identity,
                    source_role="invalid_plan_store",
                    destination_role="quarantine_destination")
            except loom_reliability.ReliabilityError as exc:
                raise LifecycleTransitionError(
                    f"plan-store quarantine failed safely: {exc}") from exc
        else:
            try:
                manifest = loom_reliability.exact_tree_manifest(
                    destination, max_entries=MAX_QUARANTINE_ENTRIES,
                    max_file_bytes=MAX_QUARANTINE_FILE_BYTES,
                    max_total_bytes=MAX_QUARANTINE_TOTAL_BYTES)
            except loom_reliability.ReliabilityError as exc:
                raise LifecycleTransitionError(
                    f"preserved plan-store quarantine is invalid: {exc}") from exc
        receipt = _quarantine_receipt(
            project_id=project_id, command_id=command_id,
            quarantine_id=quarantine_id, reason_code=reason_code,
            manifest=manifest)
        try:
            loom_reliability.atomic_write_json(receipt_path, receipt)
        except loom_reliability.ReliabilityError as exc:
            raise LifecycleTransitionError(
                f"plan-store quarantine receipt could not be sealed: {exc}") from exc
        return read_completed()

    if _lock_held:
        return quarantine_locked()
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return quarantine_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"plan-store quarantine lock failed: {exc}") from exc


def transition(
        project_root, command_value, *, witness_path=None, witness_store=None,
        envelope_root,
        fault_at=None, project_projection=None, lock_path=None,
        private_projection=None, _lock_held=False):
    """Decide and commit one exact in-generation v3 transition."""
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    command = kernel.lifecycle_command(command_value)
    envelope_path = _envelope_path(envelope_root, command.command_id)
    if private_projection is not None and (
            not isinstance(private_projection, dict)
            or len(kernel.canonical_bytes(private_projection)) > MAX_AUTHORITY_BYTES):
        raise LifecycleTransitionError(
            "lifecycle private projection is invalid or oversized")
    existing = _load_existing_envelope(
        envelope_path, command, private_projection=private_projection)
    if existing is not None:
        return recover(
            project_root, command_value, witness_store=witness_store,
            envelope_root=envelope_root, project_projection=project_projection,
            lock_path=lock_path, _lock_held=_lock_held)

    resolved, _semantics, source_ledger, source_witness, state = _observe(
        project_root, witness_store)
    decision = kernel.decide(state, command)
    if not decision.accepted:
        return _response(decision)
    if not decision.event_batch.events:
        return _response(decision)

    def commit_locked():
        existing_locked = _load_existing_envelope(
            envelope_path, command, private_projection=private_projection)
        if existing_locked is not None:
            return recover(
                project_root, command_value, witness_store=witness_store,
                envelope_root=envelope_root,
                project_projection=project_projection,
                lock_path=lock_path, _lock_held=True)
        current, _semantics, locked_ledger, locked_witness, locked_state = _observe(
            project_root, witness_store)
        if locked_state.state_sha256 != decision.source_state_sha256:
            raise LifecycleTransitionError(
                "lifecycle source changed between preflight and locked revalidation")
        target_ledger = _target_ledger(locked_ledger, decision)
        target_witness = _target_witness(
            locked_witness, decision, target_ledger)
        envelope = {
            "schema_version": 1,
            "command": command_value,
            "command_id": command.command_id,
            "command_sha256": command.command_sha256,
            "transition_id": decision.transition_id,
            "decision_sha256": decision.decision_sha256,
            "primary_code": decision.primary_code,
            "source_ledger": locked_ledger,
            "target_ledger": target_ledger,
            "source_witness": locked_witness,
            "target_witness": target_witness,
            "private_projection": private_projection,
            "private_projection_sha256": (
                kernel.digest(private_projection)
                if private_projection is not None else None),
            "status": "prepared",
            "receipt": None,
        }
        _write_envelope(envelope_path, envelope)
        _fault("after-prepare", fault_at)
        loom_reliability.atomic_write_json(
            current.generation_root / "lifecycle.json", target_ledger)
        _fault("after-project-commit", fault_at)
        witness_store.write(target_witness)
        _fault("after-witness", fault_at)
        if project_projection is not None:
            project_projection(locked_state, decision, target_ledger)
        receipt = _receipt(
            decision, locked_ledger, target_ledger, locked_witness,
            target_witness)
        envelope["status"] = "completed"
        envelope["receipt"] = receipt
        _write_envelope(envelope_path, envelope)
        return _response(decision, receipt=receipt)

    if _lock_held:
        return commit_locked()
    stable_lock = (
        Path(lock_path) if lock_path is not None
        else Path(envelope_root).parent / ".orchestration.lock")
    try:
        with loom_reliability.exclusive_file_lock(stable_lock):
            return commit_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(f"lifecycle transition reliability failed: {exc}") \
            from exc


def recover(
        project_root, command_value, *, witness_path=None, witness_store=None,
        envelope_root,
        project_projection=None, recovery_projection=None,
        lock_path=None, _lock_held=False):
    """Reconcile one exact prepared transition from source/target observations."""
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    command = kernel.lifecycle_command(command_value)
    path = _envelope_path(envelope_root, command.command_id)
    envelope = _load_existing_envelope(path, command)
    if envelope is None:
        raise LifecycleTransitionError("no exact lifecycle transition exists to recover")

    def reconcile():
        resolved = loom_plan_store.resolve(project_root)
        semantics = _load_json(
            resolved.generation_root / "plan-semantics.json",
            "reviewed plan semantics")
        current_ledger = _load_json(
            resolved.generation_root / "lifecycle.json", "lifecycle ledger")
        current_witness = witness_store.read()
        source = envelope["source_ledger"]
        target = envelope["target_ledger"]
        source_witness = envelope["source_witness"]
        target_witness = envelope["target_witness"]
        ledger_digest = current_ledger.get("lifecycle_sha256")
        witness_digest = current_witness.get("witness_sha256")
        if ledger_digest == source["lifecycle_sha256"]:
            if witness_digest != source_witness["witness_sha256"]:
                raise LifecycleTransitionError(
                    "source project and lifecycle witness observations disagree")
            envelope["status"] = "abandoned"
            receipt = {
                **_recovery_receipt_from_envelope(
                    envelope, status="abandoned", observation="source",
                    projection_status="not-applicable"),
            }
        elif ledger_digest == target["lifecycle_sha256"]:
            if witness_digest == source_witness["witness_sha256"]:
                witness_store.write(target_witness)
            elif witness_digest != target_witness["witness_sha256"]:
                raise LifecycleTransitionError(
                    "target project and lifecycle witness observations disagree")
            try:
                source_state = kernel.fold(
                    resolved.index, semantics, source, source_witness)
                decision = kernel.decide(source_state, command)
            except kernel.LifecycleKernelError as exc:
                raise LifecycleTransitionError(
                    f"prepared lifecycle decision cannot be reconstructed: {exc}") \
                    from exc
            if not decision.accepted \
                    or decision.transition_id != envelope["transition_id"] \
                    or decision.decision_sha256 != envelope["decision_sha256"] \
                    or decision.primary_code != envelope["primary_code"]:
                raise LifecycleTransitionError(
                    "prepared lifecycle decision identity does not match recovery")
            receipt = _recovery_receipt_from_envelope(
                envelope, status="completed", observation="target",
                projection_status="verified")
            if project_projection is not None:
                project_projection(source_state, decision, target)
            if recovery_projection is not None:
                recovery_projection(
                    envelope, source_state, decision, target, receipt)
            envelope["status"] = "completed"
        else:
            raise LifecycleTransitionError(
                "authoritative lifecycle observation matches neither source nor target")
        envelope["receipt"] = receipt
        _write_envelope(path, envelope)
        decision_stub = type("DecisionStub", (), {
            "accepted": envelope["status"] == "completed",
            "primary_code": (
                envelope["primary_code"]
                if envelope["status"] == "completed" else "ABANDONED"),
            "transition_id": envelope["transition_id"],
        })()
        return _response(decision_stub, receipt=receipt)

    if _lock_held:
        return reconcile()
    stable_lock = (
        Path(lock_path) if lock_path is not None
        else Path(envelope_root).parent / ".orchestration.lock")
    try:
        with loom_reliability.exclusive_file_lock(stable_lock):
            return reconcile()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(f"lifecycle recovery lock failed: {exc}") from exc


def recover_pending(
        project_root, *, witness_path=None, witness_store=None, envelope_root,
        lock_path, project_projection=None, activation_projection=None,
        legacy_projection=None, recovery_projection=None,
        recovered_projection=None, _lock_held=False):
    """Recover every bounded prepared envelope before accepting a new mutation."""
    witness_store = _witness_store(
        witness_path=witness_path, witness_store=witness_store)
    envelope_root = Path(envelope_root)

    def scan_locked():
        if not os.path.lexists(envelope_root):
            return []
        if envelope_root.is_symlink() or not envelope_root.is_dir():
            raise LifecycleTransitionError(
                "lifecycle transition namespace is redirected or invalid")
        entries = []
        try:
            with os.scandir(envelope_root) as scan:
                for entry in scan:
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False) \
                            or not entry.name.endswith(".json"):
                        raise LifecycleTransitionError(
                            "lifecycle transition namespace contains an unsafe entry")
                    entries.append(Path(entry.path))
                    if len(entries) > 512:
                        raise LifecycleTransitionError(
                            "lifecycle transition namespace exceeds its bound")
        except OSError as exc:
            raise LifecycleTransitionError(
                "lifecycle transition namespace cannot be observed") from exc
        recovered = []
        for path in sorted(entries, key=lambda item: os.fsencode(item.name)):
            raw = _load_json(path, "lifecycle transition envelope",
                             MAX_ENVELOPE_BYTES)
            kind = raw.get("kind") if isinstance(raw, dict) else None
            if kind == "generation-activation-v1":
                command_id = raw.get("command_id")
                if path != _activation_envelope_path(
                        envelope_root, command_id):
                    raise LifecycleTransitionError(
                        "generation activation envelope name is not identity-bound")
                envelope = _load_activation_envelope(path, command_id)
                if envelope["status"] != "prepared":
                    continue
                result = recover_generation_activation(
                    project_root, command_id, witness_store=witness_store,
                    envelope_root=envelope_root, lock_path=lock_path,
                    project_projection=activation_projection,
                    _lock_held=True)
                if recovered_projection is not None:
                    recovered_projection(
                        "generation-activation", envelope, result)
                recovered.append({
                    "kind": "generation-activation",
                    "command_id": command_id,
                    "status": result["status"],
                    "receipt": result["receipt"],
                })
            elif kind == "legacy-root-adoption-v1":
                command_id = raw.get("command_id")
                if path != _legacy_adoption_envelope_path(
                        envelope_root, command_id):
                    raise LifecycleTransitionError(
                        "legacy adoption envelope name is not identity-bound")
                envelope = _load_legacy_adoption_envelope(path, command_id)
                if envelope["status"] != "prepared":
                    continue
                result = recover_legacy_adoption(
                    project_root, command_id, witness_store=witness_store,
                    envelope_root=envelope_root, lock_path=lock_path,
                    project_projection=legacy_projection, _lock_held=True)
                if recovered_projection is not None:
                    recovered_projection("legacy-adoption", envelope, result)
                recovered.append({
                    "kind": "legacy-adoption",
                    "command_id": command_id,
                    "status": result["status"],
                    "receipt": result["receipt"],
                })
            elif isinstance(raw, dict) and "command" in raw:
                try:
                    command = kernel.lifecycle_command(raw["command"])
                except kernel.LifecycleKernelError as exc:
                    raise LifecycleTransitionError(
                        f"pending lifecycle command is invalid: {exc}") from exc
                if path != _envelope_path(envelope_root, command.command_id):
                    raise LifecycleTransitionError(
                        "lifecycle transition envelope name is not identity-bound")
                envelope = _load_existing_envelope(path, command)
                if envelope["status"] != "prepared":
                    continue
                result = recover(
                    project_root, raw["command"], witness_store=witness_store,
                    envelope_root=envelope_root,
                    project_projection=project_projection,
                    recovery_projection=recovery_projection,
                    lock_path=lock_path, _lock_held=True)
                if recovered_projection is not None:
                    recovered_projection("in-generation", envelope, result)
                recovered.append({
                    "kind": "in-generation",
                    "command_id": command.command_id,
                    "status": result["status"],
                    "receipt": result["receipt"],
                })
            else:
                raise LifecycleTransitionError(
                    "lifecycle transition envelope kind is unsupported")
        return recovered

    if _lock_held:
        return scan_locked()
    try:
        with loom_reliability.exclusive_file_lock(lock_path):
            return scan_locked()
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleTransitionError(
            f"lifecycle pending-recovery lock failed: {exc}") from exc


def _recovery_receipt_from_envelope(
        envelope, *, status, observation, projection_status):
    value = {
        "schema_version": 1,
        "project_id": envelope["source_ledger"]["project_id"],
        "generation_id": envelope["source_ledger"]["generation_id"],
        "command_id": envelope["command_id"],
        "transition_id": envelope["transition_id"],
        "status": status,
        "source_authority_sha256": envelope["source_ledger"]["lifecycle_sha256"],
        "target_authority_sha256": envelope["target_ledger"]["lifecycle_sha256"],
        "source_witness_sha256": envelope["source_witness"]["witness_sha256"],
        "target_witness_sha256": envelope["target_witness"]["witness_sha256"],
        "observation": observation,
        "durability_scope": (
            "power-loss-unconfirmed" if os.name == "nt"
            else "process-crash-confirmed"),
        "projection_status": projection_status,
        "findings": [],
    }
    value["receipt_sha256"] = kernel.digest(value)
    return value
