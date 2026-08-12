"""Deterministic helpers for the isolated mechanism qualification workload."""

import hashlib
import json
import time


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


def parallel_hold(milliseconds):
    """Hold a fixture lane long enough to measure bounded parallelism."""
    if type(milliseconds) is not int or not 1 <= milliseconds <= 10_000:
        raise ValueError("parallel hold is outside its fixed bound")
    deadline = time.monotonic_ns() + milliseconds * 1_000_000
    while True:
        remaining = deadline - time.monotonic_ns()
        if remaining <= 0:
            return
        time.sleep(remaining / 1_000_000_000)
