#!/usr/bin/env python3
"""Single fail-closed resolver for Loom legacy and v3 plan-generation stores."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path

import loom_lifecycle_kernel
import loom_reliability


MAX_INDEX_BYTES = 64 * 1024
MAX_AUTHORITY_BYTES = 4 * 1024 * 1024
MAX_NAMESPACE_ENTRIES = 128
INDEX_NAME = "active-generation.json"
GENERATIONS_NAME = "generations"
LEGACY_AUTHORITY_NAMES = {
    "MANIFEST.md", ".loom-lifecycle.json", ".loom-small-lifecycle.json",
    "WO-001.md", "work-orders",
}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class PlanStoreError(RuntimeError):
    """Raised when active plan authority cannot be resolved uniquely and safely."""


@dataclass(frozen=True)
class PlanStoreResolution:
    project_root: Path
    plans_root: Path
    generation_root: Path
    authority_version: str
    generation_id: str | None
    storage_kind: str
    index: loom_lifecycle_kernel.GenerationIndex | None
    index_sha256: str | None
    project_root_identity: dict
    plans_root_identity: dict
    generation_root_identity: dict


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _redirected(path):
    try:
        stat = path.lstat()
    except OSError as exc:
        raise PlanStoreError(f"plan-store path cannot be observed: {exc}") from exc
    return path.is_symlink() or bool(
        getattr(stat, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _require_plain_directory(path, label):
    if not path.is_dir() or _redirected(path):
        raise PlanStoreError(f"{label} is missing or redirected")


def _require_plain_file(path, label):
    try:
        info = path.lstat()
    except OSError as exc:
        raise PlanStoreError(f"{label} cannot be observed: {exc}") from exc
    if not path.is_file() or _redirected(path):
        raise PlanStoreError(f"{label} is missing or redirected")
    if int(info.st_nlink) != 1:
        raise PlanStoreError(f"{label} has an unsupported hardlink")


def _require_safe_tree(path, label):
    """Validate every descendant through the existing bounded no-follow walker."""
    try:
        loom_reliability.exact_tree_manifest(
            path,
            max_entries=loom_reliability.MAX_EXACT_TREE_POLICY_ENTRIES,
            max_file_bytes=loom_reliability.MAX_EXACT_TREE_POLICY_FILE_BYTES,
            max_total_bytes=loom_reliability.MAX_EXACT_TREE_POLICY_TOTAL_BYTES)
    except loom_reliability.ReliabilityError as exc:
        raise PlanStoreError(f"{label} exact-tree safety failed: {exc}") from exc


def _root_identity(path, label):
    try:
        return loom_reliability.observe_root_identity(path)
    except loom_reliability.ReliabilityError as exc:
        raise PlanStoreError(f"{label} identity cannot be observed: {exc}") from exc


def validate_resolution(resolution):
    """Revalidate the exact directory objects selected by a prior resolution."""
    if not isinstance(resolution, PlanStoreResolution):
        raise PlanStoreError("plan-store resolution type is invalid")
    try:
        loom_reliability.validate_root_identity(
            resolution.project_root, resolution.project_root_identity)
        loom_reliability.validate_root_identity(
            resolution.plans_root, resolution.plans_root_identity)
        loom_reliability.validate_root_identity(
            resolution.generation_root, resolution.generation_root_identity)
    except loom_reliability.ReliabilityError as exc:
        raise PlanStoreError(
            f"plan-store root identity changed after resolution: {exc}") from exc
    _assert_contained(resolution.project_root, resolution.generation_root)
    return resolution


def _bounded_json(path):
    _require_plain_file(path, "active-generation index")
    try:
        size = path.stat().st_size
        if not 1 <= size <= MAX_INDEX_BYTES:
            raise PlanStoreError("active-generation index size is invalid")
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, PlanStoreError):
            raise
        raise PlanStoreError(f"active-generation index is invalid: {exc}") from exc


def _namespace_entries(path):
    if not path.exists():
        return []
    _require_plain_directory(path, "plan-generation namespace")
    entries = []
    try:
        with os.scandir(path) as scan:
            for entry in scan:
                entries.append(entry.name)
                if len(entries) > MAX_NAMESPACE_ENTRIES:
                    raise PlanStoreError("plan-generation namespace exceeds its bound")
    except OSError as exc:
        raise PlanStoreError(f"plan-generation namespace cannot be observed: {exc}") \
            from exc
    return sorted(entries)


def _authority_json(path, label):
    _require_plain_file(path, label)
    try:
        size = path.stat().st_size
        if not 1 <= size <= MAX_AUTHORITY_BYTES:
            raise PlanStoreError(f"{label} size is invalid")
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, PlanStoreError):
            raise
        raise PlanStoreError(f"{label} is invalid: {exc}") from exc


def _generation_roots(generations):
    """Enumerate only the closed direct/revision generation namespace."""
    if not generations.exists():
        return []
    _require_plain_directory(generations, "plan-generation namespace")
    roots = []
    count = 0

    def add(path):
        nonlocal count
        count += 1
        if count > MAX_NAMESPACE_ENTRIES:
            raise PlanStoreError("plan-generation namespace exceeds its bound")
        _require_plain_directory(path, "stored plan generation")
        roots.append(path.resolve())

    try:
        for entry in sorted(generations.iterdir(), key=lambda item: os.fsencode(item.name)):
            if entry.name != "revisions":
                add(entry)
                continue
            _require_plain_directory(entry, "plan revision namespace")
            generation_dirs = sorted(
                entry.iterdir(), key=lambda item: os.fsencode(item.name))
            for generation_dir in generation_dirs:
                _require_plain_directory(
                    generation_dir, "plan revision generation namespace")
                revisions = sorted(
                    generation_dir.iterdir(), key=lambda item: os.fsencode(item.name))
                if not revisions:
                    raise PlanStoreError(
                        "empty plan revision namespace is unexplained mixed state")
                for revision in revisions:
                    add(revision)
    except OSError as exc:
        raise PlanStoreError(
            f"plan-generation namespace cannot be observed: {exc}") from exc
    return roots


def _generation_record(project, root):
    _require_safe_tree(root, "stored plan generation")
    try:
        semantics_value = _authority_json(
            root / "plan-semantics.json", "stored plan semantics")
        ledger_value = _authority_json(
            root / "lifecycle.json", "stored plan lifecycle")
        semantics = loom_lifecycle_kernel.validate_reviewed_plan_semantics(
            semantics_value)
        ledger = loom_lifecycle_kernel.validate_lifecycle_ledger(ledger_value)
        relative = root.relative_to(project).as_posix()
        index_value = {
            "schema_version": 1,
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "storage_kind": "generation-dir",
            "generation_path": relative,
        }
        index_value["index_sha256"] = loom_lifecycle_kernel.digest(index_value)
        last = ledger_value["events"][-1]
        witness = {
            "schema_version": 1,
            "project_id": semantics.project_id,
            "generation_id": semantics.generation_id,
            "transition_id": last["transition_id"],
            "authoritative_sha256": ledger.lifecycle_sha256,
            "predecessor_witness_sha256": None,
        }
        witness["witness_sha256"] = loom_lifecycle_kernel.digest(witness)
        state = loom_lifecycle_kernel.fold(
            index_value, semantics_value, ledger_value, witness)
    except loom_lifecycle_kernel.LifecycleKernelError as exc:
        raise PlanStoreError(
            f"stored plan generation is not self-consistent: {exc}") from exc
    parts = Path(relative).parts
    if len(parts) == 3 and parts[:2] == ("plans", "generations"):
        if parts[2] != semantics.generation_id or semantics.revision_number != 1:
            raise PlanStoreError(
                "direct plan generation identity or revision is inconsistent")
    elif len(parts) == 5 and parts[:3] == (
            "plans", "generations", "revisions"):
        expected_leaf = (
            f"r{semantics.revision_number:06d}-"
            f"{semantics.plan_semantics_sha256}")
        if parts[3] != semantics.generation_id or parts[4] != expected_leaf \
                or semantics.revision_number <= 1:
            raise PlanStoreError(
                "stored plan revision path does not match reviewed semantics")
    else:
        raise PlanStoreError("stored plan generation path is outside the closed layout")
    return {
        "root": root,
        "generation_id": semantics.generation_id,
        "revision_number": semantics.revision_number,
        "events": ledger_value["events"],
        "predecessor_generation_id": ledger_value["events"][0][
            "payload"]["predecessor_generation_id"],
        "phase": state.generation_phase,
    }


def _validate_indexed_namespace(project, generations, active_root, active_index):
    """Reject unexplained generations while preserving exact predecessor history."""
    roots = _generation_roots(generations)
    if active_index.storage_kind != "generation-dir":
        if roots:
            raise PlanStoreError(
                "legacy-root authority has unexplained mixed generation state")
        return
    if active_root.resolve() not in roots:
        raise PlanStoreError("active generation is absent from the closed namespace")
    if len(roots) == 1:
        return
    try:
        records = [_generation_record(project, root) for root in roots]
    except PlanStoreError as exc:
        raise PlanStoreError(
            f"unexplained plan generation is invalid: {exc}") from exc
    groups = {}
    for record in records:
        groups.setdefault(record["generation_id"], []).append(record)
    finals = {}
    for generation_id, values in groups.items():
        ordered = sorted(values, key=lambda item: item["revision_number"])
        revisions = [item["revision_number"] for item in ordered]
        if revisions != sorted(set(revisions)):
            raise PlanStoreError("plan generation has duplicate revision authority")
        for earlier, later in zip(ordered, ordered[1:]):
            if later["events"][:len(earlier["events"])] != earlier["events"]:
                raise PlanStoreError(
                    "plan revision history is not an exact lifecycle prefix")
        finals[generation_id] = ordered[-1]
    active = finals.get(active_index.generation_id)
    if active is None or active["root"] != active_root.resolve():
        raise PlanStoreError(
            "active index does not select the final reviewed revision")
    visited = set()
    current = active_index.generation_id
    while current is not None:
        if current in visited or current not in finals:
            raise PlanStoreError("plan generation predecessor chain is invalid")
        visited.add(current)
        record = finals[current]
        if current != active_index.generation_id \
                and not record["phase"].startswith("terminal-"):
            raise PlanStoreError(
                "inactive predecessor generation is not terminal")
        current = record["predecessor_generation_id"]
    if visited != set(finals):
        raise PlanStoreError(
            "unexplained plan generation is outside the predecessor chain")


def _has_legacy_authority(plans):
    return any((plans / name).exists() for name in LEGACY_AUTHORITY_NAMES)


def _require_reviewed_plan_projection(generation):
    manifest = generation / "MANIFEST.md"
    compact = generation / "WO-001.md"
    manifest_valid = manifest.is_file() and not _redirected(manifest) \
        if manifest.exists() else False
    compact_valid = compact.is_file() and not _redirected(compact) \
        if compact.exists() else False
    if manifest_valid == compact_valid:
        raise PlanStoreError(
            "indexed generation must contain exactly one reviewed plan projection")


def _assert_contained(project, candidate):
    try:
        candidate.resolve(strict=True).relative_to(project)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PlanStoreError("indexed generation escapes the project") from exc
    current = project
    relative = candidate.relative_to(project)
    for part in relative.parts:
        current = current / part
        if _redirected(current):
            raise PlanStoreError("indexed generation path is redirected")


def resolve(project_root):
    """Resolve exactly one legacy or v3 authority without heuristic fallback."""
    project = Path(project_root).resolve(strict=True)
    _require_plain_directory(project, "project root")
    plans = project / "plans"
    _require_plain_directory(plans, "plans root")
    index_path = plans / INDEX_NAME
    generations = plans / GENERATIONS_NAME
    if os.path.lexists(index_path):
        value = _bounded_json(index_path)
        try:
            index = loom_lifecycle_kernel.validate_generation_index(value)
        except loom_lifecycle_kernel.LifecycleKernelError as exc:
            raise PlanStoreError(f"active-generation index is invalid: {exc}") from exc
        generation = project.joinpath(*Path(index.generation_path).parts)
        _assert_contained(project, generation)
        _require_plain_directory(generation, "indexed generation")
        _require_reviewed_plan_projection(generation)
        _require_safe_tree(generation, "indexed generation")
        if index.storage_kind == "generation-dir":
            _require_plain_file(
                generation / "lifecycle.json", "indexed generation lifecycle")
            if _has_legacy_authority(plans):
                raise PlanStoreError(
                    "mixed legacy and v3 plan authority requires reconciliation")
        _validate_indexed_namespace(
            project, generations, generation, index)
        resolution = PlanStoreResolution(
            project, plans, generation.resolve(), "v3", index.generation_id,
            index.storage_kind, index, index.index_sha256,
            _root_identity(project, "project root"),
            _root_identity(plans, "plans root"),
            _root_identity(generation, "indexed generation"))
        return validate_resolution(resolution)
    orphan_entries = _namespace_entries(generations)
    if orphan_entries:
        raise PlanStoreError(
            "mixed or unindexed plan-generation state requires reconciliation")
    if not _has_legacy_authority(plans):
        raise PlanStoreError("no active plan authority exists")
    _require_safe_tree(plans, "legacy plan authority")
    resolution = PlanStoreResolution(
        project, plans, plans.resolve(), "legacy-v2", None, "legacy-root",
        None, None,
        _root_identity(project, "project root"),
        _root_identity(plans, "plans root"),
        _root_identity(plans, "legacy plan authority"))
    return validate_resolution(resolution)


def index_bytes(value):
    """Return canonical bounded index bytes after full kernel validation."""
    loom_lifecycle_kernel.validate_generation_index(value)
    raw = loom_lifecycle_kernel.canonical_bytes(value) + b"\n"
    if len(raw) > MAX_INDEX_BYTES:
        raise PlanStoreError("active-generation index exceeds its byte bound")
    return raw


def file_sha256(path):
    _require_plain_file(Path(path), "plan-store file")
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
