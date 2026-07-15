#!/usr/bin/env python3
"""Bounded context caching, adaptive budgets, and honest usage accounting."""

import hashlib
import json
import math
import os
import re
import tempfile
import time
import uuid
import datetime as dt
from pathlib import Path


MAX_CONTEXT_BYTES = 2 * 1024 * 1024
USAGE_FIELDS = (
    "input_tokens", "cache_read_tokens", "output_tokens",
    "tool_tokens", "retry_tokens",
)
MAX_USAGE_SAMPLES = 256
MAX_USAGE_STORE_BYTES = 2 * 1024 * 1024
USAGE_STORE_FIELDS = {"schema_version", "instance_id", "total_count", "samples"}
USAGE_SAMPLE_FIELDS = {
    "schema_version", "id", "session_id", "project_id", "intent", "tier",
    "domains", "recorded_at", "measurement_source", "provider_receipt",
    *USAGE_FIELDS, "total_tokens",
}
PROVIDER_RECEIPT_FIELDS = {
    "source", "provider", "model", "response_id", "captured_at",
    "raw_response_sha256", "usage",
}
TIER_BUDGETS = {"S": 2000, "M": 6000, "L": 16000, "XL": 40000}


class PerformanceError(RuntimeError):
    pass


def adaptive_memory_budget(*, tier, intent, domain_count):
    """Return a small deterministic budget from task risk, not a fixed maximum."""
    if tier not in {"S", "M", "L", "XL"}:
        raise PerformanceError("tier must be S, M, L, or XL")
    if not isinstance(intent, str) or not intent:
        raise PerformanceError("intent is required")
    if type(domain_count) is not int or not 1 <= domain_count <= 16:
        raise PerformanceError("domain_count must be in [1, 16]")
    if tier == "S":
        max_chars, max_records = 512, 3
    elif tier == "M":
        max_chars, max_records = 960, 2
    elif tier == "L":
        max_chars, max_records = 1664, 3
    else:
        max_chars, max_records = 2304, 4
    max_chars += min(domain_count - 1, 4) * (192 if tier != "S" else 48)
    include_project_history = intent not in {"execute", "wo"}
    if not include_project_history:
        max_chars = min(max_chars, 640)
        max_records = min(max_records, 2)
    return {
        "max_chars": min(max_chars, 4096),
        "max_records": max_records,
        "include_project_history": include_project_history,
    }


def _normalize_counts(value):
    if not isinstance(value, dict) or set(value) != set(USAGE_FIELDS):
        raise PerformanceError(
            "usage measurement must provide all five token categories")
    normalized = {}
    for field in USAGE_FIELDS:
        count = value[field]
        if type(count) is not int or count < 0:
            raise PerformanceError("usage token counts must be non-negative integers")
        normalized[field] = count
    if normalized["input_tokens"] == 0 or normalized["output_tokens"] == 0:
        raise PerformanceError(
            "measured agent work requires nonzero input and output token counts")
    return normalized


def _provider_receipt(value):
    if not isinstance(value, dict) or set(value) != PROVIDER_RECEIPT_FIELDS \
            or value.get("source") != "provider-response":
        raise PerformanceError("provider receipt fields are invalid")
    safe = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    if any(not isinstance(value.get(field), str) or safe.fullmatch(value[field]) is None
           for field in ("provider", "model", "response_id")) \
            or not isinstance(value.get("raw_response_sha256"), str) \
            or re.fullmatch(r"[0-9a-f]{64}", value["raw_response_sha256"]) is None:
        raise PerformanceError("provider receipt identity is invalid")
    try:
        captured = dt.datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise PerformanceError("provider receipt timestamp is invalid") from exc
    if captured.tzinfo is None:
        raise PerformanceError("provider receipt timestamp must be timezone-aware")
    return {
        "provider": value["provider"], "model": value["model"],
        "response_id": value["response_id"],
        "captured_at": captured.astimezone(dt.timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z"),
        "raw_response_sha256": value["raw_response_sha256"],
        "attestation_status": "requires-independent-attestation",
    }, _normalize_counts(value["usage"])


def normalize_usage(value):
    """Accept only a complete five-part token measurement or an honest unknown."""
    if value is None:
        return {
            "measurement_status": "unreported",
            "measurement_source": None,
            "receipt": None,
            **{field: None for field in USAGE_FIELDS},
            "total_tokens": None,
        }
    if isinstance(value, dict) and set(value) == PROVIDER_RECEIPT_FIELDS:
        receipt, normalized = _provider_receipt(value)
        source = "provider-receipt"
    else:
        receipt, normalized = None, _normalize_counts(value)
        source = "caller-reported"
    return {
        "measurement_status": "measured",
        "measurement_source": source,
        "receipt": receipt,
        **normalized,
        "total_tokens": sum(normalized.values()),
    }


def measured_usage_payload(normalized):
    """Recover the canonical persisted input from a normalized measurement."""
    if not isinstance(normalized, dict) \
            or normalized.get("measurement_status") != "measured":
        return None
    counts = {field: normalized[field] for field in USAGE_FIELDS}
    if normalized.get("measurement_source") == "provider-receipt":
        receipt = normalized.get("receipt")
        if not isinstance(receipt, dict):
            raise PerformanceError("normalized provider receipt is missing")
        return {
            "source": "provider-response", "provider": receipt["provider"],
            "model": receipt["model"], "response_id": receipt["response_id"],
            "captured_at": receipt["captured_at"],
            "raw_response_sha256": receipt["raw_response_sha256"],
            "usage": counts,
        }
    return counts


def _usage_path(owner_home, instance_id):
    try:
        uuid.UUID(str(instance_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise PerformanceError("usage ledger instance_id is invalid") from exc
    root = Path(owner_home)
    if not root.is_absolute():
        raise PerformanceError("usage ledger owner_home must be absolute")
    return root / "instances" / str(instance_id) / "performance.json"


def _empty_usage_store(instance_id):
    return {"schema_version": 2, "instance_id": str(instance_id),
            "total_count": 0, "samples": []}


def _read_usage_store(path, instance_id):
    path = Path(path)
    if not path.is_file():
        return _empty_usage_store(instance_id)
    try:
        if path.stat().st_size > MAX_USAGE_STORE_BYTES:
            raise PerformanceError("usage ledger exceeds its byte bound")
        store = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PerformanceError(f"usage ledger is unreadable: {exc}") from exc
    if not isinstance(store, dict) or set(store) != USAGE_STORE_FIELDS \
            or store.get("schema_version") not in {1, 2} \
            or store.get("instance_id") != str(instance_id) \
            or type(store.get("total_count")) is not int \
            or store["total_count"] < 0 \
            or not isinstance(store.get("samples"), list) \
            or len(store["samples"]) > MAX_USAGE_SAMPLES \
            or store["total_count"] < len(store["samples"]):
        raise PerformanceError("usage ledger shape or bounds are invalid")
    if store["schema_version"] == 1:
        legacy_fields = USAGE_SAMPLE_FIELDS - {"provider_receipt"}
        migrated = []
        for sample in store["samples"]:
            if not isinstance(sample, dict) or set(sample) != legacy_fields \
                    or sample.get("schema_version") != 1:
                raise PerformanceError("legacy usage ledger sample is invalid")
            migrated.append({**sample, "schema_version": 2, "provider_receipt": None})
        store = {**store, "schema_version": 2, "samples": migrated}
    for sample in store["samples"]:
        if not isinstance(sample, dict) or set(sample) != USAGE_SAMPLE_FIELDS \
                or sample.get("schema_version") != 2 \
                or sample.get("tier") not in TIER_BUDGETS \
                or sample.get("measurement_source") not in {
                    "caller-reported", "provider-receipt"} \
                or not isinstance(sample.get("domains"), list) \
                or not sample["domains"] \
                or any(type(sample.get(field)) is not int or sample[field] < 0
                       for field in (*USAGE_FIELDS, "total_tokens")) \
                or sample["total_tokens"] != sum(sample[field] for field in USAGE_FIELDS) \
                or ((sample["measurement_source"] == "provider-receipt")
                    != isinstance(sample.get("provider_receipt"), dict)):
            raise PerformanceError("usage ledger sample is invalid")
        if sample["provider_receipt"] is not None:
            receipt = sample["provider_receipt"]
            if set(receipt) != {
                    "provider", "model", "response_id", "captured_at",
                    "raw_response_sha256", "attestation_status"} \
                    or receipt.get("attestation_status") != \
                    "requires-independent-attestation":
                raise PerformanceError("usage ledger provider receipt is invalid")
    return store


def record_usage(owner_home, instance_id, *, session_id, project_id, intent, tier,
                 domains, usage, recorded_at=None):
    """Persist one bounded production measurement without calling it provider-attested."""
    normalized = normalize_usage(usage)
    if normalized["measurement_status"] != "measured":
        return None
    if tier not in TIER_BUDGETS or not isinstance(intent, str) or not intent \
            or not isinstance(project_id, str) \
            or not re.fullmatch(r"p-[0-9a-f]{32}", project_id) \
            or not isinstance(domains, (list, tuple)) or not domains:
        raise PerformanceError("usage sample route identity is invalid")
    try:
        canonical_session = str(uuid.UUID(str(session_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise PerformanceError("usage sample session_id is invalid") from exc
    if canonical_session != str(session_id):
        raise PerformanceError("usage sample session_id is not canonical")
    if recorded_at is None:
        stamp = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    elif isinstance(recorded_at, dt.datetime):
        stamp = recorded_at
    else:
        try:
            stamp = dt.datetime.fromisoformat(str(recorded_at).replace("Z", "+00:00"))
        except ValueError as exc:
            raise PerformanceError("usage sample recorded_at is invalid") from exc
    if stamp.tzinfo is None:
        raise PerformanceError("usage sample recorded_at must be timezone-aware")
    stamp_text = stamp.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat() \
        .replace("+00:00", "Z")
    sample = {
        "schema_version": 2,
        "id": str(uuid.uuid5(uuid.UUID(str(instance_id)), f"usage:{session_id}")),
        "session_id": str(session_id), "project_id": project_id,
        "intent": intent, "tier": tier, "domains": list(domains),
        "recorded_at": stamp_text,
        "measurement_source": normalized["measurement_source"],
        "provider_receipt": normalized["receipt"],
        **{field: normalized[field] for field in USAGE_FIELDS},
        "total_tokens": normalized["total_tokens"],
    }
    path = _usage_path(owner_home, instance_id)
    import loom_memory
    with loom_memory.FileLock(path.with_name(".performance.lock")):
        store = _read_usage_store(path, instance_id)
        existing = next((item for item in store["samples"]
                         if item["id"] == sample["id"]), None)
        if existing is not None:
            if existing != sample:
                raise PerformanceError(
                    "usage sample identity is already bound to different counts")
            return json.loads(json.dumps(existing))
        if normalized["receipt"] is not None and any(
                item.get("provider_receipt", {}).get("response_id")
                == normalized["receipt"]["response_id"]
                for item in store["samples"] if item.get("provider_receipt") is not None):
            raise PerformanceError("provider response identity is already recorded")
        store["samples"] = (store["samples"] + [sample])[-MAX_USAGE_SAMPLES:]
        store["total_count"] += 1
        encoded = (json.dumps(
            store, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        if len(encoded) > MAX_USAGE_STORE_BYTES:
            raise PerformanceError("usage ledger would exceed its byte bound")
        loom_memory._atomic_bytes(path, encoded)
    return json.loads(json.dumps(sample))


def _percentile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def usage_report(owner_home, instance_id):
    store = _read_usage_store(_usage_path(owner_home, instance_id), instance_id)
    totals = [sample["total_tokens"] for sample in store["samples"]]
    violations = [sample for sample in store["samples"]
                  if sample["total_tokens"] > TIER_BUDGETS[sample["tier"]]]
    provider = [sample for sample in store["samples"]
                if sample["measurement_source"] == "provider-receipt"]
    caller = [sample for sample in store["samples"]
              if sample["measurement_source"] == "caller-reported"]
    tiers = {}
    for tier, budget in TIER_BUDGETS.items():
        samples = [sample for sample in provider if sample["tier"] == tier]
        tier_totals = [sample["total_tokens"] for sample in samples]
        tiers[tier] = {
            "provider_receipt_count": len(samples),
            "p50_total_tokens": _percentile(tier_totals, 0.50),
            "p95_total_tokens": _percentile(tier_totals, 0.95),
            "worst_total_tokens": max(tier_totals) if tier_totals else None,
            "token_budget": budget,
            "budget_violation_count": sum(value > budget for value in tier_totals),
        }
    source = ("mixed" if provider and caller else "provider-receipt" if provider
              else "caller-reported" if caller else None)
    return {
        "schema_version": 1,
        "measurement_source": source,
        "source_limitation": (
            "caller counts are descriptive; provider receipts retain response identity but "
            "still require independent attestation"),
        "total_count": store["total_count"],
        "retained_sample_count": len(totals),
        "caller_reported_count": len(caller),
        "provider_receipt_count": len(provider),
        "retained_sample_bound": MAX_USAGE_SAMPLES,
        "p50_total_tokens": _percentile(totals, 0.50),
        "p95_total_tokens": _percentile(totals, 0.95),
        "worst_total_tokens": max(totals) if totals else None,
        "budget_violation_count": len(violations),
        "budgets": dict(TIER_BUDGETS),
        "tiers": tiers,
        "certification_status": (
            "failed" if any(item["budget_violation_count"] for item in tiers.values()) else
            "requires-independent-attestation" if all(
                item["provider_receipt_count"] >= 20 for item in tiers.values()) else
            "caller-reported-only" if caller and not provider else
            "insufficient-provider-evidence"),
    }


def evaluate_overhead(*, task_size, usage, implementation_tokens):
    usage = normalize_usage(usage)
    if usage["measurement_status"] != "measured":
        raise PerformanceError("overhead evaluation requires complete token measurement")
    if type(implementation_tokens) is not int or implementation_tokens <= 0:
        raise PerformanceError("implementation_tokens must be a positive integer")
    budgets = {"tiny": 2000, "small": 6000, "medium": 16000, "large": 40000}
    if task_size not in budgets:
        raise PerformanceError("task_size is invalid")
    total = usage["total_tokens"]
    return {
        "task_size": task_size,
        "budget_tokens": budgets[task_size],
        "planning_tokens": total,
        "implementation_tokens": implementation_tokens,
        "within_budget": total <= budgets[task_size],
        "planning_le_implementation": (
            total <= implementation_tokens if task_size == "tiny" else None),
        "passed": total <= budgets[task_size]
        and (task_size != "tiny" or total <= implementation_tokens),
    }


def evaluate_benchmarks():
    """Run deterministic performance contracts without presenting them as live totals."""
    scenarios = {
        "cold-start": adaptive_memory_budget(
            tier="M", intent="plan", domain_count=1),
        "warm-session": {"max_disk_rereads": 0, "cache_required": True},
        "project-switch": {"loaded_domains": 1, "dormant_domain_chars": 0},
        "resume": adaptive_memory_budget(
            tier="M", intent="resume", domain_count=1),
        "year-long-memory": {"active_record_cap": 256, "selected_char_cap": 960},
    }
    checks = {
        "cold-start": scenarios["cold-start"]["max_chars"] <= 1024,
        "warm-session": scenarios["warm-session"]["max_disk_rereads"] == 0,
        "project-switch": scenarios["project-switch"]["dormant_domain_chars"] == 0,
        "resume": scenarios["resume"]["max_chars"] <= 1024,
        "year-long-memory": scenarios["year-long-memory"]["selected_char_cap"] <= 1024,
    }
    tiny = evaluate_overhead(
        task_size="tiny",
        usage={
            "input_tokens": 400, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        },
        implementation_tokens=1000)
    return {"scenarios": scenarios, "checks": checks, "tiny_task": tiny,
            "passed": all(checks.values()) and tiny["passed"]}


def memory_capsule(records, *, max_chars, max_records):
    """Reduce selected structured memory to the fields a handler can actually consume."""
    if not isinstance(records, (list, tuple)) or type(max_chars) is not int \
            or type(max_records) is not int or max_chars < 128 or max_records < 1:
        raise PerformanceError("memory capsule inputs are invalid")
    fields = (
        "id", "category", "statement", "provenance", "confidence",
        "preference_key", "preference_value", "verify_by",
    )
    capsule = []
    ordered = sorted(enumerate(records), key=lambda pair: (
        0 if isinstance(pair[1], dict)
        and pair[1].get("category") == "preference"
        and pair[1].get("provenance") == "stated" else 1,
        pair[0],
    ))
    for _index, record in ordered:
        if not isinstance(record, dict):
            continue
        item = {field: record.get(field) for field in fields
                if field in record and record.get(field) is not None}
        candidate = capsule + [item]
        if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))) \
                > max_chars:
            continue
        capsule.append(item)
        if len(capsule) >= max_records:
            break
    return capsule


class ContextCache:
    """Read each unchanged local context file once per session."""

    def __init__(self):
        self._entries = {}
        self._disk_reads = 0
        self._cache_hits = 0
        self._disk_bytes = 0
        self._cache_bytes = 0

    def load_text(self, path, *, max_bytes=MAX_CONTEXT_BYTES):
        path = Path(path)
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_CONTEXT_BYTES:
            raise PerformanceError("context byte bound is invalid")
        if path.is_symlink() or not path.is_file():
            raise PerformanceError("context path must be a regular non-link file")
        try:
            info = path.stat()
        except OSError as exc:
            raise PerformanceError(f"cannot inspect context: {exc}") from exc
        if info.st_size > max_bytes:
            raise PerformanceError("context exceeds its byte bound")
        key = os.path.normcase(os.path.abspath(path))
        signature = (info.st_size, info.st_mtime_ns, getattr(info, "st_ino", 0))
        cached = self._entries.get(key)
        if cached and cached["signature"] == signature:
            self._cache_hits += 1
            self._cache_bytes += len(cached["bytes"])
            return cached["text"]
        try:
            raw = path.read_bytes()
            if len(raw) > max_bytes:
                raise PerformanceError("context changed above its byte bound")
            after = path.stat()
            after_signature = (
                after.st_size, after.st_mtime_ns, getattr(after, "st_ino", 0))
            if after_signature != signature:
                raise PerformanceError("context changed while it was being read")
            text = raw.decode("utf-8")
        except PerformanceError:
            raise
        except (OSError, UnicodeError) as exc:
            raise PerformanceError(f"cannot read UTF-8 context: {exc}") from exc
        self._entries[key] = {
            "signature": signature,
            "bytes": raw,
            "text": text,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        self._disk_reads += 1
        self._disk_bytes += len(raw)
        return text

    def metrics(self):
        return {
            "disk_reads": self._disk_reads,
            "cache_hits": self._cache_hits,
            "disk_bytes": self._disk_bytes,
            "cache_bytes": self._cache_bytes,
            "entries": len(self._entries),
        }

    def content_hash(self, path):
        self.load_text(path)
        key = os.path.normcase(os.path.abspath(Path(path)))
        return self._entries[key]["sha256"]


def production_context_manifest(install_root):
    """Hash the complete static host guidance used by the one-surface bridge."""
    root = Path(install_root)
    paths = ("skill/loom/SKILL.md", "START-HERE.md")
    cache = ContextCache()
    entries = []
    for relative in paths:
        path = root / relative
        text = cache.load_text(path, max_bytes=256 * 1024)
        entries.append({
            "path": relative,
            "sha256": cache.content_hash(path),
            "bytes": len(text.encode("utf-8")),
        })
    body = {"schema_version": 1, "entries": entries,
            "total_bytes": sum(item["bytes"] for item in entries)}
    body["context_hash"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()
    body["load_metrics"] = cache.metrics()
    return body


def _metric_delta(before, after):
    return {key: after[key] - before[key] for key in (
        "disk_reads", "cache_hits", "disk_bytes", "cache_bytes")}


def run_observed_benchmarks():
    """Exercise real cache/capsule operations; label the only synthetic cost fixture."""
    scenarios = {}
    cache = ContextCache()
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        core = root / "core.md"
        first = root / "project-a.md"
        second = root / "project-b.md"
        core.write_bytes(b"core\n" * 32)
        first.write_bytes(b"project-a\n" * 24)
        second.write_bytes(b"project-b\n" * 20)

        def observe(name, operation):
            before = cache.metrics()
            started = time.perf_counter_ns()
            operation()
            elapsed = time.perf_counter_ns() - started
            scenarios[name] = {
                **_metric_delta(before, cache.metrics()), "elapsed_ns": elapsed}

        observe("cold_start", lambda: (cache.load_text(core), cache.load_text(first)))
        observe("warm_session", lambda: (cache.load_text(core), cache.load_text(first)))
        observe("project_switch", lambda: (cache.load_text(core), cache.load_text(second)))
        first.write_bytes(b"project-a-resumed-and-changed\n" * 24)
        observe("resume", lambda: cache.load_text(first))

        records = [{
            "id": f"00000000-0000-4000-8000-{index:012d}",
            "category": "domain", "statement": f"bounded rule {index}",
            "provenance": "inferred", "confidence": 0.8,
        } for index in range(256)]
        started = time.perf_counter_ns()
        capsule = memory_capsule(records, max_chars=512, max_records=3)
        scenarios["year_long"] = {
            "disk_reads": 0, "cache_hits": 0, "disk_bytes": 0, "cache_bytes": 0,
            "elapsed_ns": time.perf_counter_ns() - started,
            "active_records_considered": len(records),
            "capsule_records": len(capsule),
            "capsule_chars": len(json.dumps(
                capsule, ensure_ascii=False, separators=(",", ":"))),
        }
    tiny = evaluate_overhead(
        task_size="tiny",
        usage={"input_tokens": 400, "cache_read_tokens": 100,
               "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0},
        implementation_tokens=1000)
    tiny["measurement_kind"] = "synthetic-policy-fixture"
    return {"measurement_kind": "observed-local-operations",
            "scenarios": scenarios, "tiny_task": tiny}
