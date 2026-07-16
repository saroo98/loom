#!/usr/bin/env python3
"""Independent bounded reference model for Loom event retention and forgetting."""

import argparse
import hashlib
import itertools
import json
import random


class ModelError(RuntimeError):
    pass


def rank(event):
    return (int(event["device_counter"]), str(event["device_id"]), str(event["event_id"]))


def materialize(events, *, bound):
    if type(bound) is not int or bound < 1:
        raise ModelError("model bound must be a positive integer")
    accepted = {}
    tombstones = {}
    for event in events:
        required = {"event_id", "device_id", "device_counter", "record_id", "op", "value"}
        if not isinstance(event, dict) or set(event) != required \
                or event["op"] not in {"put", "forget"}:
            raise ModelError("event contract is invalid")
        prior = accepted.get(event["event_id"])
        if prior is not None:
            if prior != event:
                raise ModelError("one event ID names different content")
            continue
        accepted[event["event_id"]] = event
        if event["op"] == "forget":
            current = tombstones.get(event["record_id"])
            if current is None or rank(event) > rank(current):
                tombstones[event["record_id"]] = event
    rows = {}
    for event in accepted.values():
        if event["op"] != "put":
            continue
        forgotten = tombstones.get(event["record_id"])
        if forgotten is not None and rank(forgotten) >= rank(event):
            continue
        current = rows.get(event["record_id"])
        if current is None or rank(event) > rank(current):
            rows[event["record_id"]] = event
    retained = sorted(rows.values(), key=rank, reverse=True)[:bound]
    return {
        "records": tuple(sorted((item["record_id"], item["value"]) for item in retained)),
        "forgotten": tuple(sorted(tombstones)), "events": len(accepted),
    }


def _event(device, counter, record, op="put", value=None):
    seed = f"{device}:{counter}:{record}:{op}:{value}".encode("utf-8")
    return {"event_id": hashlib.sha256(seed).hexdigest()[:32], "device_id": device,
            "device_counter": counter, "record_id": record, "op": op, "value": value}


def exhaustive_two_device():
    trace = [
        _event("a", 1, "one", value="old"), _event("a", 2, "one", value="new"),
        _event("b", 1, "two", value="kept"), _event("b", 2, "two", op="forget"),
    ]
    expected = materialize(trace, bound=2)
    checked = 0
    for order in itertools.permutations(trace):
        # Network delivery may reorder devices; the model must still converge.
        if materialize(order, bound=2) != expected:
            raise ModelError("two-device delivery order changed materialized state")
        checked += 1
    return checked


def seeded_three_device(seed, traces):
    randomizer = random.Random(seed)
    checked = 0
    for trace_index in range(traces):
        events = []
        for device in ("a", "b", "c"):
            for counter in range(1, 7):
                record = f"r-{randomizer.randrange(8)}"
                op = "forget" if randomizer.randrange(7) == 0 else "put"
                events.append(_event(device, counter, record, op,
                                     None if op == "forget" else f"v-{trace_index}-{counter}"))
        expected = materialize(events, bound=5)
        for _ in range(3):
            shuffled = list(events)
            randomizer.shuffle(shuffled)
            if materialize(shuffled + shuffled[:2], bound=5) != expected:
                raise ModelError("seeded three-device trace did not converge")
            checked += 1
    return checked


def run(*, seed=12026, traces=10000):
    return {"status": "passed", "seed": seed, "two_device_orders": exhaustive_two_device(),
            "three_device_traces": traces, "deliveries_checked": seeded_three_device(seed, traces)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=12026)
    parser.add_argument("--traces", type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        result = run(seed=args.seed, traces=args.traces)
    except ModelError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
