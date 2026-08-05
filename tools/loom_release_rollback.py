#!/usr/bin/env python3
"""Run the bounded release rollback battery and emit only a public result digest."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import loom_reliability


TESTS = (
    "test_loom_update_v11.py",
    "test_loom_crash_recovery.py",
    "test_release_asset.py",
)
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA = re.compile(r"^[0-9a-f]{64}$")


class RollbackEvidenceError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def verify_receipt(value, *, expected_commit, expected_public_root_sha256):
    """Validate one successful rollback receipt for an exact release subject."""
    fields = {
        "schema_version", "status", "commit", "public_root_sha256", "tests",
        "transcript_sha256", "result_sha256",
    }
    body = ({key: item for key, item in value.items()
             if key != "result_sha256"} if isinstance(value, dict) else None)
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("status") != "passed" \
            or value.get("commit") != expected_commit \
            or value.get("public_root_sha256") != expected_public_root_sha256 \
            or value.get("tests") != list(TESTS) \
            or SHA.fullmatch(str(value.get("transcript_sha256", ""))) is None \
            or value.get("result_sha256") != hashlib.sha256(
                _canonical(body)).hexdigest():
        raise RollbackEvidenceError("rollback evidence receipt is invalid")
    return value


def run(tools_root, *, commit, public_root_sha256, timeout=900):
    try:
        tools_root = loom_reliability._absolute(
            tools_root, "rollback test root", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise RollbackEvidenceError(str(exc)) from exc
    if not tools_root.is_dir() or not COMMIT.fullmatch(str(commit)) \
            or not SHA.fullmatch(str(public_root_sha256)) \
            or type(timeout) is not int or not 1 <= timeout <= 1800 \
            or any(not (tools_root / test).is_file() for test in TESTS):
        raise RollbackEvidenceError("rollback test identity is invalid")
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "-v", *TESTS],
            cwd=str(tools_root), capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RollbackEvidenceError(f"rollback battery failed to execute: {exc}") from exc
    transcript = result.stdout + b"\n" + result.stderr
    body = {
        "schema_version": 1,
        "status": "passed" if result.returncode == 0 else "failed",
        "commit": commit, "public_root_sha256": public_root_sha256,
        "tests": list(TESTS),
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
    }
    return {**body, "result_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools_root")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--public-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    try:
        value = run(args.tools_root, commit=args.commit,
                    public_root_sha256=args.public_root, timeout=args.timeout)
        output = loom_reliability._absolute(args.output, "rollback evidence output")
        if output.exists():
            raise RollbackEvidenceError("rollback evidence output already exists")
        loom_reliability.atomic_write_json(output, value)
    except (RollbackEvidenceError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": value["status"],
                      "result_sha256": value["result_sha256"]}, sort_keys=True))
    return 0 if value["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
