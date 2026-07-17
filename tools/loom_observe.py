#!/usr/bin/env python3
"""Bounded, content-free local performance spans."""

from __future__ import annotations

import time


MAX_SPANS = 64
MAX_COUNTERS = 16


class ObserveError(RuntimeError):
    pass


class SpanRecorder:
    def __init__(self, operation_id):
        self.operation_id = operation_id
        self._spans = []

    def measure(self, stage, function, *, counters=None):
        start = time.perf_counter_ns()
        status, code = "ok", "completed"
        try:
            return function()
        except Exception as exc:
            status, code = "error", type(exc).__name__.lower()
            raise
        finally:
            self.record(stage, time.perf_counter_ns() - start, status=status,
                        code=code, counters=counters or {})

    def record(self, stage, duration_ns, *, status="ok", code="completed", counters=None):
        if len(self._spans) >= MAX_SPANS:
            raise ObserveError("performance span bound exceeded")
        if not isinstance(stage, str) or not stage or len(stage) > 64 \
                or type(duration_ns) is not int or duration_ns < 0:
            raise ObserveError("performance span identity or duration is invalid")
        counters = counters or {}
        if not isinstance(counters, dict) or len(counters) > MAX_COUNTERS \
                or any(not isinstance(key, str) or not key or len(key) > 64
                       or type(value) is not int or value < 0
                       for key, value in counters.items()):
            raise ObserveError("performance span counters are invalid")
        self._spans.append({"stage": stage, "duration_ns": duration_ns,
            "status": status, "code": code, "counters": dict(counters),
            "parent_operation_id": self.operation_id})

    def receipt(self):
        return {"schema_version": 1, "span_count": len(self._spans),
                "spans": [dict(item) for item in self._spans]}
