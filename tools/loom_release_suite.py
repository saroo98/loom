#!/usr/bin/env python3
"""Certify one release-host suite only through exact bound matrix evidence."""

import argparse
import json
import re
from pathlib import Path

import loom_capability
import loom_reliability
import loom_test


class ReleaseSuiteError(RuntimeError):
    pass


def _read_reports(paths):
    reports = []
    for path in paths:
        try:
            reports.append(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseSuiteError(f"matrix report is invalid: {exc}") from exc
    return reports


def certify(local_report, matrix_paths, *, expected_commit, expected_root):
    if not re.fullmatch(r"[0-9a-f]{40}", str(expected_commit)) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected_root)):
        raise ReleaseSuiteError("release suite identity is invalid")
    required = {"tests_run", "failures", "errors", "within_budget",
                "skip_receipts", "timings"}
    if not isinstance(local_report, dict) or not required <= set(local_report) \
            or local_report["failures"] != 0 or local_report["errors"] != 0 \
            or local_report["within_budget"] is not True:
        raise ReleaseSuiteError("local release suite did not pass")
    paths = [Path(path) for path in matrix_paths]
    try:
        matrix = loom_capability.aggregate(paths)
    except loom_capability.CapabilityError as exc:
        raise ReleaseSuiteError(str(exc)) from exc
    if matrix["status"] != "certified" \
            or matrix["subject"] != {
                "source_commit": expected_commit,
                "public_root_sha256": expected_root,
            }:
        raise ReleaseSuiteError("matrix evidence is not certified for this release subject")
    reports = _read_reports(paths)
    passed = {item.get("test") for report in reports
              for item in report.get("timings", [])
              if item.get("status") == "passed" and item.get("test")}
    local_skips = sorted({item.get("test") for item in local_report["skip_receipts"]
                          if item.get("test")})
    uncovered = sorted(set(local_skips) - passed)
    if uncovered:
        raise ReleaseSuiteError(
            "local capability skips lack an exact-matrix pass: " + ", ".join(uncovered))
    return {
        "schema_version": 1,
        "status": "certified",
        "subject": matrix["subject"],
        "local": local_report,
        "matrix": matrix,
        "covered_local_skips": local_skips,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-report", action="append", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--public-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    local = loom_test.run("full")
    try:
        result = certify(
            local, args.matrix_report,
            expected_commit=args.commit, expected_root=args.public_root)
        output = loom_reliability._absolute(args.output, "release suite output")
        if output.exists():
            raise ReleaseSuiteError("release suite output already exists")
        loom_reliability.atomic_write_json(output, result)
    except (ReleaseSuiteError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": result["status"],
        "tests_run": local["tests_run"],
        "local_skips": len(result["covered_local_skips"]),
        "matrix_reports": result["matrix"]["reports"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
