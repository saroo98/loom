#!/usr/bin/env python3
"""Validate current external facts and fail claims closed after expiry."""

import argparse
import datetime as dt
import json
import re
from pathlib import Path


class CurrentFactError(RuntimeError):
    pass


def _time(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise CurrentFactError("current fact timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CurrentFactError("current fact timestamp lacks timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate(value, *, as_of=None):
    if not isinstance(value, dict) or set(value) != {"schema_version", "policy_id", "facts"} \
            or value.get("schema_version") != 1 \
            or value.get("policy_id") != "loom-evidence-policy-v1" \
            or not isinstance(value.get("facts"), list) or len(value["facts"]) > 256:
        raise CurrentFactError("current fact manifest is invalid")
    evaluated = as_of or dt.datetime.now(dt.timezone.utc)
    seen, active, unverified, expired = set(), [], [], []
    fields = {"id", "claim", "source", "retrieved_at", "expires_at",
              "verification_owner", "status"}
    for fact in value["facts"]:
        if not isinstance(fact, dict) or set(fact) != fields \
                or not isinstance(fact["id"], str) \
                or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,95}", fact["id"]) \
                or fact["id"] in seen or not isinstance(fact["claim"], str) \
                or not fact["claim"] or not isinstance(fact["verification_owner"], str) \
                or fact["status"] not in {"verified", "observed", "unverified", "expired"}:
            raise CurrentFactError("current fact entry is invalid")
        seen.add(fact["id"])
        if fact["status"] in {"verified", "observed"}:
            if not isinstance(fact["source"], str) or not fact["source"] \
                    or fact["retrieved_at"] is None or fact["expires_at"] is None:
                raise CurrentFactError("verified current fact lacks provenance or expiry")
            if _time(fact["retrieved_at"]) > evaluated + dt.timedelta(minutes=5):
                raise CurrentFactError("current fact was retrieved in the future")
            if _time(fact["expires_at"]) <= evaluated:
                expired.append(fact["id"])
            else:
                active.append(fact["id"])
        elif fact["status"] == "unverified":
            unverified.append(fact["id"])
        else:
            expired.append(fact["id"])
    return {"schema_version": 1, "status": "current" if not expired else "stale",
            "active": sorted(active), "unverified": sorted(unverified),
            "expired": sorted(expired)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--as-of")
    args = parser.parse_args(argv)
    try:
        value = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        result = validate(value, as_of=_time(args.as_of) if args.as_of else None)
    except (OSError, UnicodeError, json.JSONDecodeError, CurrentFactError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "current" else 1


if __name__ == "__main__":
    raise SystemExit(main())
