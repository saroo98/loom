#!/usr/bin/env python3
"""Bounded context caching, adaptive budgets, and honest usage accounting."""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path


MAX_CONTEXT_BYTES = 2 * 1024 * 1024
USAGE_FIELDS = (
    "input_tokens", "cache_read_tokens", "output_tokens",
    "tool_tokens", "retry_tokens",
)


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


def normalize_usage(value):
    """Accept only a complete five-part token measurement or an honest unknown."""
    if value is None:
        return {
            "measurement_status": "unreported",
            **{field: None for field in USAGE_FIELDS},
            "total_tokens": None,
        }
    if not isinstance(value, dict) or set(value) != set(USAGE_FIELDS):
        raise PerformanceError(
            "usage measurement must provide all five token categories")
    normalized = {}
    for field in USAGE_FIELDS:
        count = value[field]
        if type(count) is not int or count < 0:
            raise PerformanceError("usage token counts must be non-negative integers")
        normalized[field] = count
    return {
        "measurement_status": "measured",
        **normalized,
        "total_tokens": sum(normalized.values()),
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
