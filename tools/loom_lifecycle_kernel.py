#!/usr/bin/env python3
"""Pure lifecycle state, scheduling, and transition semantics for Loom v3."""

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import PurePosixPath


MAX_WORK_ORDERS = 64
MAX_DEPENDENCIES = 16
MAX_TOUCH_PATTERNS = 5
MAX_REVIEWED_WORLD_FILES = 100_000
MAX_REVIEWED_WORLD_BYTES = 4 * 1024 * 1024
WORK_ORDER_ID = re.compile(r"^WO-[0-9]{3,}$")
DECISION_ID = re.compile(r"^D-[0-9]{3,}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

GENERATION_PHASES = {
    "reviewable", "active", "terminal-completed", "terminal-cancelled",
    "terminal-superseded", "terminal-quarantined",
}
COMMAND_RELATIONS = {
    "new", "revise-exact", "start-exact", "continue-active",
    "complete-active", "repair-active", "repair-complete", "read-only",
    "cancel-generation",
    "supersede-generation", "quarantine-generation",
}
EVENT_PAYLOAD_FIELDS = {
    "generation-created": {"predecessor_generation_id", "relation"},
    "plan-reviewed": {
        "plan_semantics_sha256", "revision_number", "reviewed_world_sha256"},
    "plan-revised": {
        "plan_semantics_sha256", "revision_number", "reviewed_world_sha256"},
    "implementation-authorized": {"work_order_id"},
    "work-order-started": {"work_order_id", "action_id"},
    "work-order-resumed": {"work_order_id", "action_id"},
    "work-order-completed": {
        "work_order_id", "completion_sha256", "completed_world_sha256"},
    "repair-authorized": {
        "work_order_id", "affected_scope_sha256", "action_id",
        "observed_world_sha256"},
    "repair-completed": {
        "work_order_id", "action_id", "repair_evidence_sha256",
        "repaired_world_sha256"},
    "generation-completed": {"completion_set_sha256"},
    "generation-cancelled": {"reason_code"},
    "generation-superseded": {"successor_generation_id", "reason_code"},
    "generation-quarantined": {"reason_code"},
}


class LifecycleKernelError(ValueError):
    """Raised when canonical lifecycle inputs cannot be interpreted safely."""


@dataclass(frozen=True)
class ExecutionPolicy:
    execution_policy: str
    max_work_orders: int
    max_dependencies_per_work_order: int
    max_touch_patterns_per_work_order: int
    max_ledger_events: int
    max_ledger_bytes: int
    active_index_storage_kinds: tuple[str, ...]
    commit_protocol: str
    idempotency: str
    recovery: str
    policy_sha256: str


@dataclass(frozen=True)
class WorkOrder:
    work_order_id: str
    work_order_dependencies: tuple[str, ...]
    decision_dependencies: tuple[str, ...]


@dataclass(frozen=True)
class WorkOrderGraph:
    work_orders: tuple[WorkOrder, ...]
    execution_sequence: tuple[str, ...]

    @property
    def by_id(self):
        return {item.work_order_id: item for item in self.work_orders}


@dataclass(frozen=True)
class WorkOrderSelection:
    work_order_id: str | None
    blocked_work_order_id: str | None
    blockers: tuple[str, ...]
    complete: bool


@dataclass(frozen=True)
class GenerationIndex:
    project_id: str
    generation_id: str
    storage_kind: str
    generation_path: str
    index_sha256: str


@dataclass(frozen=True)
class ReviewedPlanSemantics:
    project_id: str
    generation_id: str
    revision_number: int
    title: str
    summary: str
    assumptions: tuple[str, ...]
    decisions: tuple[str, ...]
    execution_policy: str
    graph: WorkOrderGraph
    work_orders: tuple[tuple[tuple[str, object], ...], ...]
    plan_contract_sha256: str
    domain_bindings_sha256: str | None
    reviewed_world_sha256: str
    reviewed_world_observation_sha256: str
    plan_semantics_sha256: str


@dataclass(frozen=True)
class LifecycleEvent:
    sequence: int
    event_type: str
    command_id: str
    transition_id: str
    payload: tuple[tuple[str, object], ...]
    previous_event_sha256: str | None
    event_sha256: str

    @property
    def payload_dict(self):
        return dict(self.payload)


@dataclass(frozen=True)
class LifecycleLedger:
    project_id: str
    generation_id: str
    plan_semantics_sha256: str
    execution_policy: str
    execution_sequence_sha256: str
    events: tuple[LifecycleEvent, ...]
    lifecycle_sha256: str


@dataclass(frozen=True)
class LifecycleHeadWitness:
    project_id: str
    generation_id: str
    transition_id: str
    authoritative_sha256: str
    predecessor_witness_sha256: str | None
    witness_sha256: str


@dataclass(frozen=True)
class LifecycleState:
    project_id: str | None
    generation_id: str | None
    generation_phase: str
    transition_observation: str
    authority_validity: str
    world_relation: str
    semantic_relation: str
    action_relation: str
    frontier: str
    selected_work_order_id: str | None
    blocked_work_order_id: str | None
    blockers: tuple[str, ...]
    completed_work_orders: tuple[str, ...]
    in_progress_work_order_id: str | None
    repair_action_id: str | None
    repair_work_order_id: str | None
    resolved_decisions: tuple[str, ...]
    plan_semantics_sha256: str | None
    reviewed_world_sha256: str | None
    expected_world_sha256: str | None
    lifecycle_sha256: str | None
    witness_sha256: str | None
    last_event_sequence: int
    last_event_sha256: str | None
    graph: WorkOrderGraph | None
    state_sha256: str


@dataclass(frozen=True)
class LifecycleCommand:
    command_id: str
    relation: str
    project_id: str
    generation_id: str | None
    plan_semantics_sha256: str | None
    observed_world_sha256: str | None
    action_id: str | None
    work_order_id: str | None
    evidence_sha256: str | None
    affected_scope_sha256: str | None
    successor_generation_id: str | None
    reason_code: str | None
    command_sha256: str


@dataclass(frozen=True)
class LifecycleEventBatch:
    transition_id: str
    events: tuple[LifecycleEvent, ...]
    batch_sha256: str


@dataclass(frozen=True)
class TransitionDecision:
    accepted: bool
    primary_code: str
    findings: tuple[str, ...]
    source_state_sha256: str
    command_id: str
    transition_id: str
    selected_work_order_id: str | None
    event_batch: LifecycleEventBatch
    required_projections: tuple[str, ...]
    decision_sha256: str


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise LifecycleKernelError(f"{label} fields are unknown or missing")
    return value


def _safe_id(value, label, *, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise LifecycleKernelError(f"{label} is invalid")
    return value


def _sha(value, label, *, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise LifecycleKernelError(f"{label} is invalid")
    return value


def _self_bound(value, field, label):
    _sha(value.get(field), f"{label} digest")
    unsigned = {key: item for key, item in value.items() if key != field}
    if digest(unsigned) != value[field]:
        raise LifecycleKernelError(f"{label} digest does not match")


def validate_execution_policy(value):
    fields = {
        "schema_version", "execution_policy", "max_work_orders",
        "max_dependencies_per_work_order", "max_touch_patterns_per_work_order",
        "max_ledger_events", "max_ledger_bytes", "active_index_storage_kinds",
        "commit_protocol", "idempotency", "recovery", "policy_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise LifecycleKernelError("execution policy fields are unknown or missing")
    body = {key: item for key, item in value.items() if key != "policy_sha256"}
    if value.get("schema_version") != 1 \
            or value.get("execution_policy") != "strict-serial-sequence-v1" \
            or value.get("max_work_orders") != MAX_WORK_ORDERS \
            or value.get("max_dependencies_per_work_order") != MAX_DEPENDENCIES \
            or value.get("max_touch_patterns_per_work_order") != \
            MAX_TOUCH_PATTERNS \
            or type(value.get("max_ledger_events")) is not int \
            or not 128 <= value["max_ledger_events"] <= 1024 \
            or type(value.get("max_ledger_bytes")) is not int \
            or not 1024 * 1024 <= value["max_ledger_bytes"] <= 16 * 1024 * 1024 \
            or value.get("active_index_storage_kinds") != [
                "generation-dir", "legacy-root"] \
            or value.get("commit_protocol") != "single-authoritative-object-v1" \
            or value.get("idempotency") != "exact-command-and-transition-v1" \
            or value.get("recovery") != \
            "source-discard-target-roll-forward-otherwise-block-v1" \
            or value.get("policy_sha256") != digest(body):
        raise LifecycleKernelError("execution policy contract or digest is invalid")
    return ExecutionPolicy(
        value["execution_policy"], value["max_work_orders"],
        value["max_dependencies_per_work_order"],
        value["max_touch_patterns_per_work_order"], value["max_ledger_events"],
        value["max_ledger_bytes"], tuple(value["active_index_storage_kinds"]),
        value["commit_protocol"], value["idempotency"], value["recovery"],
        value["policy_sha256"],
    )


def _closed_work_order(value):
    if not isinstance(value, dict) or set(value) != {"id", "depends_on"}:
        raise LifecycleKernelError("work-order graph fields are unknown or missing")
    identifier = value["id"]
    dependencies = value["depends_on"]
    if not isinstance(identifier, str) or not WORK_ORDER_ID.fullmatch(identifier):
        raise LifecycleKernelError("work-order identity is invalid")
    if not isinstance(dependencies, (list, tuple)) \
            or len(dependencies) > MAX_DEPENDENCIES \
            or len(dependencies) != len(set(dependencies)):
        raise LifecycleKernelError("work-order dependencies are invalid")
    work_order_dependencies = []
    decision_dependencies = []
    for dependency in dependencies:
        if not isinstance(dependency, str):
            raise LifecycleKernelError("work-order dependency identity is invalid")
        if WORK_ORDER_ID.fullmatch(dependency):
            work_order_dependencies.append(dependency)
        elif DECISION_ID.fullmatch(dependency):
            decision_dependencies.append(dependency)
        else:
            raise LifecycleKernelError("work-order dependency identity is invalid")
    return WorkOrder(
        identifier, tuple(work_order_dependencies), tuple(decision_dependencies))


def validate_work_order_graph(work_orders, execution_sequence):
    """Validate one closed DAG and its owner-reviewed strict serial sequence."""
    if not isinstance(work_orders, (list, tuple)) \
            or not 1 <= len(work_orders) <= MAX_WORK_ORDERS:
        raise LifecycleKernelError("work-order graph size is invalid")
    records = tuple(_closed_work_order(item) for item in work_orders)
    identifiers = tuple(item.work_order_id for item in records)
    if len(identifiers) != len(set(identifiers)):
        raise LifecycleKernelError("work-order identities must be unique")
    known = set(identifiers)
    for item in records:
        if item.work_order_id in item.work_order_dependencies \
                or any(dependency not in known
                       for dependency in item.work_order_dependencies):
            raise LifecycleKernelError("work-order dependency graph is invalid")
    if not isinstance(execution_sequence, (list, tuple)) \
            or tuple(execution_sequence) != tuple(dict.fromkeys(execution_sequence)) \
            or set(execution_sequence) != known \
            or len(execution_sequence) != len(records):
        raise LifecycleKernelError(
            "execution sequence must contain every work order exactly once")
    positions = {identifier: index for index, identifier in enumerate(execution_sequence)}
    if any(positions[dependency] >= positions[item.work_order_id]
           for item in records for dependency in item.work_order_dependencies):
        raise LifecycleKernelError(
            "execution sequence must be a topological linear extension")
    return WorkOrderGraph(records, tuple(execution_sequence))


def select_work_order(
        graph, *, completed=(), in_progress=None, resolved_decisions=()):
    """Select only the first unfinished entry in the sealed execution sequence."""
    if not isinstance(graph, WorkOrderGraph):
        raise LifecycleKernelError("work-order graph is invalid")
    completed = frozenset(completed)
    resolved_decisions = frozenset(resolved_decisions)
    known = set(graph.execution_sequence)
    if not completed <= known or in_progress is not None and in_progress not in known \
            or in_progress in completed:
        raise LifecycleKernelError("work-order progress projection is invalid")
    first = next(
        (identifier for identifier in graph.execution_sequence
         if identifier not in completed), None)
    if first is None:
        if in_progress is not None:
            raise LifecycleKernelError("completed graph cannot have in-progress work")
        return WorkOrderSelection(None, None, (), True)
    if in_progress is not None and in_progress != first:
        raise LifecycleKernelError(
            "in-progress work must be the first unfinished sequence entry")
    item = graph.by_id[first]
    blockers = tuple(
        dependency for dependency in (
            *item.work_order_dependencies, *item.decision_dependencies)
        if dependency not in completed and dependency not in resolved_decisions)
    if blockers:
        return WorkOrderSelection(None, first, blockers, False)
    return WorkOrderSelection(first, None, (), False)


def project_work_order_statuses(
        graph, *, completed=(), in_progress=None, resolved_decisions=()):
    """Derive human-readable work-order statuses from canonical progress."""
    completed = frozenset(completed)
    selection = select_work_order(
        graph, completed=completed, in_progress=in_progress,
        resolved_decisions=resolved_decisions)
    result = {}
    for identifier in graph.execution_sequence:
        if identifier in completed:
            result[identifier] = "done"
        elif identifier == in_progress:
            result[identifier] = "in-progress"
        elif identifier == selection.work_order_id:
            result[identifier] = "ready"
        else:
            result[identifier] = "blocked"
    return result


def validate_generation_index(value):
    _closed(value, {
        "schema_version", "project_id", "generation_id", "storage_kind",
        "generation_path", "index_sha256",
    }, "active-generation index")
    if value["schema_version"] != 1:
        raise LifecycleKernelError("active-generation index version is invalid")
    project_id = _safe_id(value["project_id"], "project identity")
    generation_id = _safe_id(value["generation_id"], "generation identity")
    storage_kind = value["storage_kind"]
    path_text = value["generation_path"]
    if storage_kind not in {"generation-dir", "legacy-root"} \
            or not isinstance(path_text, str):
        raise LifecycleKernelError("active-generation storage is invalid")
    path = PurePosixPath(path_text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
        raise LifecycleKernelError("active-generation path is invalid")
    if storage_kind == "generation-dir":
        base = PurePosixPath("plans", "generations", generation_id)
        revision_base = PurePosixPath(
            "plans", "generations", "revisions", generation_id)
        revision_path = (
            len(path.parts) == len(revision_base.parts) + 1
            and path.parts[:len(revision_base.parts)] == revision_base.parts
            and re.fullmatch(r"r[0-9]{6}-[0-9a-f]{64}", path.parts[-1])
        )
        if path != base and not revision_path:
            raise LifecycleKernelError("active-generation path is invalid")
    elif path != PurePosixPath("plans"):
        raise LifecycleKernelError("legacy active-generation path is invalid")
    _self_bound(value, "index_sha256", "active-generation index")
    return GenerationIndex(
        project_id, generation_id, storage_kind, path_text,
        value["index_sha256"])


def _semantic_text(value, label, maximum):
    if not isinstance(value, str) or not value or len(value) > maximum \
            or "\x00" in value:
        raise LifecycleKernelError(f"{label} is invalid")
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def _semantic_texts(value, label, maximum_items, maximum_characters):
    if not isinstance(value, list) or len(value) > maximum_items:
        raise LifecycleKernelError(f"{label} are invalid")
    return tuple(
        _semantic_text(item, f"{label} item", maximum_characters)
        for item in value)


def _semantic_work_order(value):
    fields = {
        "id", "title", "outcome", "tasks", "acceptance",
        "negative_acceptance", "out_of_scope", "escalation", "touches",
        "depends_on",
    }
    _closed(value, fields, "reviewed work order")
    identifier = value["id"]
    if not isinstance(identifier, str) or WORK_ORDER_ID.fullmatch(identifier) is None:
        raise LifecycleKernelError("reviewed work-order identity is invalid")
    normalized = {
        "id": identifier,
        "title": _semantic_text(value["title"], "work-order title", 100),
        "outcome": _semantic_text(value["outcome"], "work-order outcome", 500),
        "tasks": _semantic_texts(value["tasks"], "work-order tasks", 16, 500),
        "acceptance": _semantic_texts(
            value["acceptance"], "work-order acceptance", 16, 500),
        "negative_acceptance": _semantic_texts(
            value["negative_acceptance"], "work-order negative acceptance", 8, 500),
        "out_of_scope": _semantic_texts(
            value["out_of_scope"], "work-order out of scope", 16, 500),
        "escalation": _semantic_texts(
            value["escalation"], "work-order escalation", 16, 500),
        "depends_on": _semantic_texts(
            value["depends_on"], "work-order dependencies", 16, 16),
    }
    touches = _semantic_texts(
        value["touches"], "work-order touches", MAX_TOUCH_PATTERNS, 300)
    for item in touches:
        path = PurePosixPath(item)
        if path.is_absolute() or item != path.as_posix() \
                or any(part in {"", ".", ".."} for part in path.parts):
            raise LifecycleKernelError("work-order touch path is invalid")
    normalized["touches"] = touches
    return tuple(sorted(normalized.items()))


def validate_reviewed_world_observation(value):
    """Validate the immutable repository baseline used for completion causality."""
    _closed(value, {
        "schema_version", "project_id", "generation_id", "state_mode",
        "state_sha256", "repo_head", "files", "observation_sha256",
    }, "reviewed world observation")
    if value["schema_version"] != 1 \
            or value["state_mode"] not in {"git", "filesystem"} \
            or len(canonical_bytes(value)) > MAX_REVIEWED_WORLD_BYTES:
        raise LifecycleKernelError("reviewed world observation is invalid")
    _safe_id(value["project_id"], "reviewed world project")
    _safe_id(value["generation_id"], "reviewed world generation")
    _sha(value["state_sha256"], "reviewed world state digest")
    head = value["repo_head"]
    if head is not None and (
            not isinstance(head, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) is None):
        raise LifecycleKernelError("reviewed world repository head is invalid")
    files = value["files"]
    if not isinstance(files, dict) or len(files) > MAX_REVIEWED_WORLD_FILES:
        raise LifecycleKernelError("reviewed world file inventory is invalid")
    for path_text, file_sha256 in files.items():
        if not isinstance(path_text, str) or not path_text or len(path_text) > 1024:
            raise LifecycleKernelError("reviewed world file inventory is invalid")
        path = PurePosixPath(path_text)
        if path.is_absolute() or path_text != path.as_posix() \
                or any(part in {"", ".", ".."} for part in path.parts):
            raise LifecycleKernelError("reviewed world file path is invalid")
        _sha(file_sha256, "reviewed world file digest")
    _self_bound(value, "observation_sha256", "reviewed world observation")
    return value


def validate_reviewed_plan_semantics(value):
    _closed(value, {
        "schema_version", "project_id", "generation_id", "revision_number",
        "title", "summary", "assumptions", "decisions", "execution_policy",
        "execution_sequence", "work_orders",
        "plan_contract_sha256", "domain_bindings_sha256",
        "reviewed_world_sha256", "reviewed_world_observation_sha256",
        "plan_semantics_sha256",
    }, "reviewed plan semantics")
    if value["schema_version"] != 1 \
            or type(value["revision_number"]) is not int \
            or not 1 <= value["revision_number"] <= 1_000_000 \
            or value["execution_policy"] != "strict-serial-sequence-v1":
        raise LifecycleKernelError("reviewed plan semantics are invalid")
    title = _semantic_text(value["title"], "plan title", 100)
    summary = _semantic_text(value["summary"], "plan summary", 1000)
    assumptions = _semantic_texts(
        value["assumptions"], "plan assumptions", 16, 500)
    decisions = _semantic_texts(
        value["decisions"], "plan decisions", 16, 500)
    if not isinstance(value["work_orders"], list) \
            or not 1 <= len(value["work_orders"]) <= MAX_WORK_ORDERS:
        raise LifecycleKernelError("reviewed work orders are invalid")
    sealed_work_orders = tuple(
        _semantic_work_order(item) for item in value["work_orders"])
    graph = validate_work_order_graph(
        [{"id": item["id"], "depends_on": item["depends_on"]}
         for item in value["work_orders"]],
        value["execution_sequence"])
    _self_bound(value, "plan_semantics_sha256", "reviewed plan semantics")
    return ReviewedPlanSemantics(
        _safe_id(value["project_id"], "project identity"),
        _safe_id(value["generation_id"], "generation identity"),
        value["revision_number"], title, summary, assumptions, decisions,
        value["execution_policy"], graph, sealed_work_orders,
        _sha(value["plan_contract_sha256"], "plan-contract digest"),
        _sha(value["domain_bindings_sha256"], "domain-bindings digest", optional=True),
        _sha(value["reviewed_world_sha256"], "reviewed-world digest"),
        _sha(value["reviewed_world_observation_sha256"],
             "reviewed-world observation digest"),
        value["plan_semantics_sha256"],
    )


def _validate_event_payload(event_type, value):
    fields = EVENT_PAYLOAD_FIELDS.get(event_type)
    if fields is None:
        raise LifecycleKernelError("lifecycle event type is invalid")
    _closed(value, fields, "lifecycle event payload")
    if event_type == "generation-created":
        _safe_id(value["predecessor_generation_id"], "predecessor generation", optional=True)
        if value["relation"] not in {"new", "repair-of", "supersedes"}:
            raise LifecycleKernelError("generation relation is invalid")
    elif event_type in {"plan-reviewed", "plan-revised"}:
        _sha(value["plan_semantics_sha256"], "plan semantics digest")
        _sha(value["reviewed_world_sha256"], "reviewed-world digest")
        if type(value["revision_number"]) is not int \
                or not 1 <= value["revision_number"] <= 1_000_000:
            raise LifecycleKernelError("plan revision is invalid")
    elif event_type in {"implementation-authorized", "work-order-started",
                        "work-order-resumed", "work-order-completed",
                        "repair-authorized", "repair-completed"}:
        identifier = value["work_order_id"]
        if not isinstance(identifier, str) or WORK_ORDER_ID.fullmatch(identifier) is None:
            raise LifecycleKernelError("event work-order identity is invalid")
        if event_type in {"work-order-started", "work-order-resumed"}:
            _safe_id(value["action_id"], "action identity")
        elif event_type == "work-order-completed":
            _sha(value["completion_sha256"], "completion digest")
            _sha(value["completed_world_sha256"], "completed-world digest")
        elif event_type == "repair-authorized":
            _sha(value["affected_scope_sha256"], "affected-scope digest")
            _sha(value["observed_world_sha256"], "observed-world digest")
        elif event_type == "repair-completed":
            _sha(value["repair_evidence_sha256"], "repair evidence digest")
            _sha(value["repaired_world_sha256"], "repaired-world digest")
    elif event_type == "generation-completed":
        _sha(value["completion_set_sha256"], "completion-set digest")
    elif event_type in {"generation-cancelled", "generation-quarantined"}:
        _safe_id(value["reason_code"], "reason code")
    elif event_type == "generation-superseded":
        _safe_id(value["successor_generation_id"], "successor generation")
        _safe_id(value["reason_code"], "reason code")
    return tuple(sorted(value.items()))


def validate_lifecycle_ledger(value, *, max_events=512, max_bytes=4_194_304):
    _closed(value, {
        "schema_version", "project_id", "generation_id",
        "plan_semantics_sha256", "execution_policy",
        "execution_sequence_sha256", "events", "lifecycle_sha256",
    }, "lifecycle ledger")
    if value["schema_version"] != 3 \
            or value["execution_policy"] != "strict-serial-sequence-v1" \
            or not isinstance(value["events"], list) \
            or not 1 <= len(value["events"]) <= max_events \
            or len(canonical_bytes(value)) > max_bytes:
        raise LifecycleKernelError("lifecycle ledger bounds or version are invalid")
    _self_bound(value, "lifecycle_sha256", "lifecycle ledger")
    records = []
    previous = None
    for expected, item in enumerate(value["events"], start=1):
        _closed(item, {
            "sequence", "event_type", "command_id", "transition_id", "payload",
            "previous_event_sha256", "event_sha256",
        }, "lifecycle event")
        if item["sequence"] != expected:
            raise LifecycleKernelError("lifecycle event sequence is invalid")
        if item["previous_event_sha256"] != previous:
            raise LifecycleKernelError("lifecycle event predecessor does not match")
        _safe_id(item["command_id"], "command identity")
        _sha(item["transition_id"], "transition identity")
        if item["previous_event_sha256"] is not None:
            _sha(item["previous_event_sha256"], "event predecessor digest")
        payload = _validate_event_payload(item["event_type"], item["payload"])
        _self_bound(item, "event_sha256", "lifecycle event")
        previous = item["event_sha256"]
        records.append(LifecycleEvent(
            expected, item["event_type"], item["command_id"],
            item["transition_id"], payload, item["previous_event_sha256"],
            item["event_sha256"],
        ))
    return LifecycleLedger(
        _safe_id(value["project_id"], "project identity"),
        _safe_id(value["generation_id"], "generation identity"),
        _sha(value["plan_semantics_sha256"], "plan semantics digest"),
        value["execution_policy"],
        _sha(value["execution_sequence_sha256"], "execution sequence digest"),
        tuple(records), value["lifecycle_sha256"],
    )


def validate_head_witness(value):
    _closed(value, {
        "schema_version", "project_id", "generation_id", "transition_id",
        "authoritative_sha256", "predecessor_witness_sha256", "witness_sha256",
    }, "lifecycle head witness")
    if value["schema_version"] != 1:
        raise LifecycleKernelError("lifecycle head witness version is invalid")
    _self_bound(value, "witness_sha256", "lifecycle head witness")
    return LifecycleHeadWitness(
        _safe_id(value["project_id"], "project identity"),
        _safe_id(value["generation_id"], "generation identity"),
        _sha(value["transition_id"], "transition identity"),
        _sha(value["authoritative_sha256"], "authoritative digest"),
        _sha(value["predecessor_witness_sha256"], "witness predecessor", optional=True),
        value["witness_sha256"],
    )


def _state_digest_source(**values):
    return {
        key: value for key, value in values.items()
        if key not in {"graph", "state_sha256"}
    }


def fold(index, plan, ledger, head_witness):
    """Validate canonical v3 authority and derive one immutable lifecycle state."""
    if index is None and plan is None and ledger is None and head_witness is None:
        source = _state_digest_source(
            project_id=None, generation_id=None, generation_phase="absent",
            transition_observation="stable", authority_validity="owned-valid",
            world_relation="unavailable", semantic_relation="missing",
            action_relation="none", frontier="complete",
            selected_work_order_id=None, blocked_work_order_id=None, blockers=(),
            completed_work_orders=(), in_progress_work_order_id=None,
            repair_action_id=None, repair_work_order_id=None,
            resolved_decisions=(), plan_semantics_sha256=None,
            reviewed_world_sha256=None, expected_world_sha256=None,
            lifecycle_sha256=None,
            witness_sha256=None, last_event_sequence=0,
            last_event_sha256=None)
        return LifecycleState(**source, graph=None, state_sha256=digest(source))
    if any(item is None for item in (index, plan, ledger, head_witness)):
        raise LifecycleKernelError("canonical lifecycle authority is incomplete")
    index = index if isinstance(index, GenerationIndex) else validate_generation_index(index)
    plan = plan if isinstance(plan, ReviewedPlanSemantics) \
        else validate_reviewed_plan_semantics(plan)
    ledger = ledger if isinstance(ledger, LifecycleLedger) \
        else validate_lifecycle_ledger(ledger)
    witness = head_witness if isinstance(head_witness, LifecycleHeadWitness) \
        else validate_head_witness(head_witness)
    identities = {(index.project_id, index.generation_id),
                  (plan.project_id, plan.generation_id),
                  (ledger.project_id, ledger.generation_id),
                  (witness.project_id, witness.generation_id)}
    if len(identities) != 1:
        raise LifecycleKernelError("canonical lifecycle identities do not match")
    if ledger.plan_semantics_sha256 != plan.plan_semantics_sha256 \
            or ledger.execution_policy != plan.execution_policy \
            or ledger.execution_sequence_sha256 != digest(plan.graph.execution_sequence):
        raise LifecycleKernelError("lifecycle ledger plan binding does not match")
    if witness.authoritative_sha256 != ledger.lifecycle_sha256 \
            or witness.transition_id != ledger.events[-1].transition_id:
        raise LifecycleKernelError("lifecycle head witness is inconsistent")

    phase = "reviewable"
    reviewed = False
    latest_review = None
    authorized = False
    completed = []
    in_progress = None
    expected_world_sha256 = plan.reviewed_world_sha256
    resolved_decisions = set()
    repair_action_id = None
    repair_work_order_id = None
    for position, event in enumerate(ledger.events):
        payload = event.payload_dict
        if position == 0 and event.event_type != "generation-created":
            raise LifecycleKernelError("generation-created must be the first event")
        if event.event_type == "generation-created":
            if position != 0:
                raise LifecycleKernelError("generation-created event is duplicated")
        elif event.event_type in {"plan-reviewed", "plan-revised"}:
            expected_type = "plan-reviewed" if latest_review is None else "plan-revised"
            if authorized or phase != "reviewable" \
                    or event.event_type != expected_type \
                    or latest_review is not None \
                    and payload["revision_number"] != latest_review["revision_number"] + 1:
                raise LifecycleKernelError("reviewed plan event does not match semantics")
            reviewed = True
            latest_review = payload
        elif event.event_type == "implementation-authorized":
            if not reviewed or authorized or phase != "reviewable":
                raise LifecycleKernelError("implementation authorization order is invalid")
            selection = select_work_order(plan.graph, completed=completed)
            if selection.work_order_id != payload["work_order_id"]:
                raise LifecycleKernelError("implementation authorization selection is invalid")
            authorized = True
            phase = "active"
        elif event.event_type == "work-order-started":
            selection = select_work_order(
                plan.graph, completed=completed, in_progress=in_progress,
                resolved_decisions=resolved_decisions)
            if not authorized or in_progress is not None \
                    or selection.work_order_id != payload["work_order_id"]:
                raise LifecycleKernelError("work-order start order is invalid")
            in_progress = payload["work_order_id"]
        elif event.event_type == "work-order-resumed":
            if phase != "active" or in_progress != payload["work_order_id"] \
                    or repair_action_id is not None:
                raise LifecycleKernelError("work-order resume order is invalid")
        elif event.event_type == "work-order-completed":
            if phase != "active" or in_progress != payload["work_order_id"] \
                    or repair_action_id is not None:
                raise LifecycleKernelError("work-order completion order is invalid")
            completed.append(in_progress)
            in_progress = None
            expected_world_sha256 = payload["completed_world_sha256"]
        elif event.event_type == "repair-authorized":
            selection = select_work_order(
                plan.graph, completed=completed, in_progress=in_progress,
                resolved_decisions=resolved_decisions)
            selected = in_progress or selection.work_order_id
            if phase != "active" or repair_action_id is not None \
                    or payload["work_order_id"] != selected:
                raise LifecycleKernelError("repair authorization is invalid")
            repair_action_id = payload["action_id"]
            repair_work_order_id = payload["work_order_id"]
        elif event.event_type == "repair-completed":
            if phase != "active" \
                    or payload["action_id"] != repair_action_id \
                    or payload["work_order_id"] != repair_work_order_id:
                raise LifecycleKernelError("repair completion is invalid")
            expected_world_sha256 = payload["repaired_world_sha256"]
            repair_action_id = None
            repair_work_order_id = None
        elif event.event_type == "generation-completed":
            if phase != "active" or in_progress is not None \
                    or repair_action_id is not None \
                    or tuple(completed) != plan.graph.execution_sequence:
                raise LifecycleKernelError("generation completion is invalid")
            if payload["completion_set_sha256"] != digest(completed):
                raise LifecycleKernelError("generation completion set does not match")
            phase = "terminal-completed"
        elif event.event_type == "generation-cancelled":
            if phase not in {"reviewable", "active"}:
                raise LifecycleKernelError("generation cancellation is invalid")
            phase = "terminal-cancelled"
            in_progress = None
            repair_action_id = None
            repair_work_order_id = None
        elif event.event_type == "generation-superseded":
            if phase not in {"reviewable", "active"}:
                raise LifecycleKernelError("generation supersession is invalid")
            phase = "terminal-superseded"
            in_progress = None
            repair_action_id = None
            repair_work_order_id = None
        elif event.event_type == "generation-quarantined":
            if phase.startswith("terminal-"):
                raise LifecycleKernelError("generation quarantine is invalid")
            phase = "terminal-quarantined"
            in_progress = None
            repair_action_id = None
            repair_work_order_id = None
        elif phase.startswith("terminal-"):
            raise LifecycleKernelError("terminal generation has trailing events")
    if not reviewed or latest_review is None \
            or latest_review["plan_semantics_sha256"] != plan.plan_semantics_sha256 \
            or latest_review["revision_number"] != plan.revision_number \
            or latest_review["reviewed_world_sha256"] != plan.reviewed_world_sha256:
        raise LifecycleKernelError("generation has no reviewed plan event")
    if phase.startswith("terminal-"):
        selection = WorkOrderSelection(None, None, (), phase == "terminal-completed")
    else:
        selection = select_work_order(
            plan.graph, completed=completed, in_progress=in_progress,
            resolved_decisions=resolved_decisions)
    frontier = (
        "complete" if selection.complete else
        "blocked" if selection.blocked_work_order_id else "selected")
    source = _state_digest_source(
        project_id=index.project_id, generation_id=index.generation_id,
        generation_phase=phase, transition_observation="stable",
        authority_validity="owned-valid", world_relation="exact",
        semantic_relation="exact-revision",
        action_relation=(
            "repairing" if repair_action_id is not None else
            "pending" if in_progress else "none"),
        frontier=frontier, selected_work_order_id=selection.work_order_id,
        blocked_work_order_id=selection.blocked_work_order_id,
        blockers=selection.blockers, completed_work_orders=tuple(completed),
        in_progress_work_order_id=in_progress,
        repair_action_id=repair_action_id,
        repair_work_order_id=repair_work_order_id,
        resolved_decisions=tuple(sorted(resolved_decisions)),
        plan_semantics_sha256=plan.plan_semantics_sha256,
        reviewed_world_sha256=plan.reviewed_world_sha256,
        expected_world_sha256=expected_world_sha256,
        lifecycle_sha256=ledger.lifecycle_sha256,
        witness_sha256=witness.witness_sha256,
        last_event_sequence=ledger.events[-1].sequence,
        last_event_sha256=ledger.events[-1].event_sha256)
    return LifecycleState(
        **source, graph=plan.graph, state_sha256=digest(source))


def lifecycle_command(value):
    fields = {
        "schema_version", "command_id", "relation", "project_id",
        "generation_id", "plan_semantics_sha256", "observed_world_sha256",
        "action_id", "work_order_id", "evidence_sha256",
        "affected_scope_sha256", "successor_generation_id", "reason_code",
    }
    _closed(value, fields, "lifecycle command")
    if value["schema_version"] != 1 or value["relation"] not in COMMAND_RELATIONS:
        raise LifecycleKernelError("lifecycle command is invalid")
    if value["work_order_id"] is not None \
            and (not isinstance(value["work_order_id"], str)
                 or WORK_ORDER_ID.fullmatch(value["work_order_id"]) is None):
        raise LifecycleKernelError("command work-order identity is invalid")
    command_sha256 = digest(value)
    return LifecycleCommand(
        _safe_id(value["command_id"], "command identity"), value["relation"],
        _safe_id(value["project_id"], "project identity"),
        _safe_id(value["generation_id"], "generation identity", optional=True),
        _sha(value["plan_semantics_sha256"], "plan semantics digest", optional=True),
        _sha(value["observed_world_sha256"], "observed-world digest", optional=True),
        _safe_id(value["action_id"], "action identity", optional=True),
        value["work_order_id"],
        _sha(value["evidence_sha256"], "evidence digest", optional=True),
        _sha(value["affected_scope_sha256"], "affected-scope digest", optional=True),
        _safe_id(value["successor_generation_id"], "successor generation", optional=True),
        _safe_id(value["reason_code"], "reason code", optional=True),
        command_sha256,
    )


def _event_batch(state, command, event_specs):
    transition_source = {
        "source_state_sha256": state.state_sha256,
        "command_sha256": command.command_sha256,
        "events": [{"event_type": kind, "payload": payload}
                   for kind, payload in event_specs],
    }
    transition_id = digest(transition_source)
    events = []
    previous = state.last_event_sha256
    for offset, (event_type, payload) in enumerate(event_specs, start=1):
        item = {
            "sequence": state.last_event_sequence + offset,
            "event_type": event_type,
            "command_id": command.command_id,
            "transition_id": transition_id,
            "payload": payload,
            "previous_event_sha256": previous,
        }
        event_sha256 = digest(item)
        events.append(LifecycleEvent(
            item["sequence"], event_type, command.command_id, transition_id,
            tuple(sorted(payload.items())), previous, event_sha256))
        previous = event_sha256
    source = {
        "transition_id": transition_id,
        "event_sha256s": [event.event_sha256 for event in events],
    }
    return LifecycleEventBatch(transition_id, tuple(events), digest(source))


def _decision(state, command, *, accepted, code, findings=(), event_specs=(),
              selected=None, projections=()):
    batch = _event_batch(state, command, event_specs)
    source = {
        "accepted": accepted, "primary_code": code,
        "findings": list(findings), "source_state_sha256": state.state_sha256,
        "command_id": command.command_id, "transition_id": batch.transition_id,
        "selected_work_order_id": selected,
        "event_batch_sha256": batch.batch_sha256,
        "required_projections": list(projections),
    }
    return TransitionDecision(
        accepted, code, tuple(findings), state.state_sha256, command.command_id,
        batch.transition_id, selected, batch, tuple(projections), digest(source))


def decide(state, command):
    """Return a deterministic accepted event batch or a nonmutating rejection."""
    if not isinstance(state, LifecycleState) or not isinstance(command, LifecycleCommand):
        raise LifecycleKernelError("lifecycle decision inputs are invalid")
    if state.authority_validity != "owned-valid":
        if command.relation == "quarantine-generation" and command.reason_code:
            return _decision(
                state, command, accepted=True, code="QUARANTINE_ACCEPTED",
                event_specs=(("generation-quarantined", {
                    "reason_code": command.reason_code}),),
                projections=("ledger", "status", "receipt"))
        return _decision(
            state, command, accepted=False, code="AUTHORITY_INVALID",
            findings=(state.authority_validity,))
    if state.transition_observation != "stable" and command.relation != "read-only":
        return _decision(
            state, command, accepted=False, code="TRANSITION_RECONCILIATION_REQUIRED",
            findings=(state.transition_observation,))
    if command.project_id != state.project_id and state.project_id is not None:
        return _decision(state, command, accepted=False, code="WRONG_PROJECT")
    if command.relation == "read-only":
        return _decision(state, command, accepted=True, code="READ_ONLY_ACCEPTED")
    if state.generation_phase == "absent":
        if command.relation == "new" and command.generation_id:
            return _decision(state, command, accepted=True, code="NEW_GENERATION_ACCEPTED",
                             projections=("active-index", "ledger", "status"))
        return _decision(state, command, accepted=False, code="NO_ACTIVE_GENERATION")
    if command.generation_id != state.generation_id:
        return _decision(state, command, accepted=False, code="WRONG_GENERATION")
    if command.plan_semantics_sha256 is not None \
            and command.plan_semantics_sha256 != state.plan_semantics_sha256:
        return _decision(state, command, accepted=False, code="PLAN_DECISION_STALE")
    terminal = state.generation_phase.startswith("terminal-")
    if terminal:
        if command.relation == "new" and command.successor_generation_id:
            return _decision(
                state, command, accepted=True, code="ROLLOVER_ACCEPTED",
                projections=("generation-archive", "active-index", "status"))
        return _decision(state, command, accepted=False, code="GENERATION_TERMINAL")
    if state.repair_action_id is not None and command.relation not in {
            "repair-complete", "cancel-generation", "supersede-generation"}:
        return _decision(
            state, command, accepted=False, code="REPAIR_IN_PROGRESS")
    if command.relation in {"start-exact", "continue-active"} \
            and command.observed_world_sha256 != state.expected_world_sha256:
        return _decision(state, command, accepted=False, code="PROJECT_WORLD_CHANGED")
    if command.relation == "start-exact":
        if state.generation_phase != "reviewable":
            return _decision(state, command, accepted=False, code="GENERATION_NOT_REVIEWABLE")
        if state.selected_work_order_id is None:
            return _decision(
                state, command, accepted=False, code="WORK_ORDER_BLOCKED",
                findings=state.blockers)
        if command.action_id is None:
            return _decision(state, command, accepted=False, code="ACTION_ID_REQUIRED")
        selected = state.selected_work_order_id
        return _decision(
            state, command, accepted=True, code="START_ACCEPTED", selected=selected,
            event_specs=(
                ("implementation-authorized", {"work_order_id": selected}),
                ("work-order-started", {
                    "work_order_id": selected, "action_id": command.action_id}),
            ), projections=("ledger", "work-orders", "manifest", "action", "pointer"))
    if command.relation == "continue-active":
        if state.generation_phase != "active":
            return _decision(state, command, accepted=False, code="GENERATION_NOT_ACTIVE")
        if state.in_progress_work_order_id:
            if command.action_id is None:
                return _decision(
                    state, command, accepted=False, code="ACTION_ID_REQUIRED")
            return _decision(
                state, command, accepted=True, code="CONTINUE_EXISTING_ACCEPTED",
                selected=state.in_progress_work_order_id,
                event_specs=(("work-order-resumed", {
                    "work_order_id": state.in_progress_work_order_id,
                    "action_id": command.action_id}),),
                projections=("ledger", "action", "pointer"))
        if state.selected_work_order_id is None or command.action_id is None:
            return _decision(state, command, accepted=False, code="WORK_ORDER_BLOCKED",
                             findings=state.blockers)
        selected = state.selected_work_order_id
        return _decision(
            state, command, accepted=True, code="CONTINUE_ACCEPTED", selected=selected,
            event_specs=(("work-order-started", {
                "work_order_id": selected, "action_id": command.action_id}),),
            projections=("ledger", "work-orders", "manifest", "action", "pointer"))
    if command.relation == "complete-active":
        selected = state.in_progress_work_order_id
        if state.generation_phase != "active" or selected is None \
                or command.work_order_id != selected \
                or command.evidence_sha256 is None \
                or command.observed_world_sha256 is None:
            return _decision(state, command, accepted=False, code="COMPLETION_NOT_AUTHORIZED")
        completed = (*state.completed_work_orders, selected)
        events = [("work-order-completed", {
            "work_order_id": selected,
            "completion_sha256": command.evidence_sha256,
            "completed_world_sha256": command.observed_world_sha256,
        })]
        if state.graph and tuple(completed) == state.graph.execution_sequence:
            events.append(("generation-completed", {
                "completion_set_sha256": digest(completed)}))
        return _decision(
            state, command, accepted=True, code="COMPLETION_ACCEPTED",
            selected=selected, event_specs=tuple(events),
            projections=("ledger", "work-orders", "manifest", "action", "pointer"))
    if command.relation == "repair-active":
        if state.generation_phase != "active" \
                or command.affected_scope_sha256 is None \
                or command.observed_world_sha256 is None \
                or command.action_id is None:
            return _decision(state, command, accepted=False, code="REPAIR_SCOPE_INDETERMINATE")
        selected = state.in_progress_work_order_id or state.selected_work_order_id
        if selected is None:
            return _decision(state, command, accepted=False, code="WORK_ORDER_BLOCKED")
        return _decision(
            state, command, accepted=True, code="REPAIR_ACCEPTED", selected=selected,
            event_specs=(("repair-authorized", {
                "work_order_id": selected,
                "affected_scope_sha256": command.affected_scope_sha256,
                "action_id": command.action_id,
                "observed_world_sha256": command.observed_world_sha256}),),
            projections=("ledger", "action", "pointer"))
    if command.relation == "repair-complete":
        if state.generation_phase != "active" \
                or state.repair_action_id is None \
                or command.action_id != state.repair_action_id \
                or command.work_order_id != state.repair_work_order_id \
                or command.evidence_sha256 is None \
                or command.observed_world_sha256 is None \
                or command.affected_scope_sha256 is None:
            return _decision(
                state, command, accepted=False,
                code="REPAIR_COMPLETION_NOT_AUTHORIZED")
        return _decision(
            state, command, accepted=True, code="REPAIR_COMPLETION_ACCEPTED",
            selected=state.repair_work_order_id,
            event_specs=(("repair-completed", {
                "work_order_id": state.repair_work_order_id,
                "action_id": state.repair_action_id,
                "repair_evidence_sha256": command.evidence_sha256,
                "repaired_world_sha256": command.observed_world_sha256}),),
            projections=("ledger", "action", "pointer", "status"))
    if command.relation == "revise-exact":
        if state.generation_phase != "reviewable":
            return _decision(state, command, accepted=False, code="PLAN_REVISION_REQUIRES_SUPERSESSION")
        return _decision(state, command, accepted=True, code="REVISION_PREFLIGHT_ACCEPTED",
                         projections=("plan-revision", "ledger", "presentation"))
    if command.relation == "cancel-generation":
        if not command.reason_code:
            return _decision(state, command, accepted=False, code="CANCEL_REASON_REQUIRED")
        return _decision(
            state, command, accepted=True, code="CANCEL_ACCEPTED",
            event_specs=(("generation-cancelled", {
                "reason_code": command.reason_code}),),
            projections=("ledger", "work-orders", "manifest", "action", "pointer"))
    if command.relation in {"new", "supersede-generation"}:
        if not command.successor_generation_id or not command.reason_code:
            return _decision(state, command, accepted=False, code="SUPERSESSION_AUTHORITY_REQUIRED")
        return _decision(
            state, command, accepted=True, code="SUPERSESSION_ACCEPTED",
            event_specs=(("generation-superseded", {
                "successor_generation_id": command.successor_generation_id,
                "reason_code": command.reason_code}),),
            projections=("ledger", "generation-archive", "active-index", "status"))
    return _decision(state, command, accepted=False, code="COMMAND_NOT_LEGAL")


def project(state):
    if not isinstance(state, LifecycleState):
        raise LifecycleKernelError("lifecycle state is invalid")
    statuses = {}
    if state.graph is not None:
        statuses = project_work_order_statuses(
            state.graph, completed=state.completed_work_orders,
            in_progress=state.in_progress_work_order_id,
            resolved_decisions=state.resolved_decisions)
        if state.generation_phase in {
                "terminal-cancelled", "terminal-superseded", "terminal-quarantined"}:
            statuses = {
                identifier: status if status == "done" else "cancelled"
                for identifier, status in statuses.items()}
    value = {
        "schema_version": 1,
        "project_id": state.project_id,
        "generation_id": state.generation_id,
        "generation_phase": state.generation_phase,
        "transition_observation": state.transition_observation,
        "authority_validity": state.authority_validity,
        "world_relation": state.world_relation,
        "semantic_relation": state.semantic_relation,
        "action_relation": state.action_relation,
        "frontier": state.frontier,
        "selected_work_order_id": state.selected_work_order_id,
        "blocked_work_order_id": state.blocked_work_order_id,
        "blockers": list(state.blockers),
        "work_order_statuses": statuses,
        "expected_world_sha256": state.expected_world_sha256,
        "state_sha256": state.state_sha256,
    }
    value["projection_sha256"] = digest(value)
    return value


def verify_projection(state, projection):
    expected = project(state)
    if projection != expected:
        raise LifecycleKernelError("lifecycle projection does not match canonical state")
    return projection
