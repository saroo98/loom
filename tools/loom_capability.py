#!/usr/bin/env python3
"""Aggregate per-run test skips into capability-bound matrix certification."""

import argparse
import json
import re
from pathlib import Path


class CapabilityError(RuntimeError):
    pass


def _report_failed(report):
    """Accept raw runner receipts and the release verifier's normalized receipt."""
    if {"failures", "errors", "within_budget"} <= set(report):
        return bool(report["failures"] or report["errors"]
                    or report["within_budget"] is not True)
    normalized = {"passed", "returncode", "capability_complete", "capability_status"}
    if normalized <= set(report):
        complete = report["capability_complete"] is True
        expected_returncode = 0 if complete else 1
        expected_status = "complete" if complete else "requires-matrix"
        return not (report["passed"] is True
                    and report["returncode"] == expected_returncode
                    and report["capability_status"] == expected_status)
    raise CapabilityError("capability report result contract is invalid")


def aggregate(paths):
    reports = []
    for path in paths:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CapabilityError(f"capability report is invalid: {exc}") from exc
        if not isinstance(value, dict) or not isinstance(value.get("timings"), list) \
                or not isinstance(value.get("skip_receipts"), list) \
                or not isinstance(value.get("binding"), dict) \
                or set(value["binding"]) != {
                    "source_commit", "public_root_sha256", "platform", "architecture",
                    "python", "runner"} \
                or not re.fullmatch(r"[0-9a-f]{40}", str(value["binding"]["source_commit"])) \
                or not re.fullmatch(
                    r"[0-9a-f]{64}", str(value["binding"]["public_root_sha256"])):
            raise CapabilityError("capability report contract is invalid")
        reports.append(value)
    if not reports:
        raise CapabilityError("at least one test report is required")
    subjects = {(report["binding"]["source_commit"],
                 report["binding"]["public_root_sha256"]) for report in reports}
    if len(subjects) != 1:
        raise CapabilityError("capability reports are not bound to one exact release subject")
    cells = [(report["binding"]["platform"], report["binding"]["architecture"],
              report["binding"]["python"], report["binding"]["runner"])
             for report in reports]
    if len(cells) != len(set(cells)):
        raise CapabilityError("capability report matrix cell is duplicated")
    passed_by = {}
    for report in reports:
        cell = tuple(report["binding"][key] for key in (
            "platform", "architecture", "python", "runner"))
        for item in report["timings"]:
            if item.get("status") == "passed" and item.get("test"):
                passed_by.setdefault(item["test"], set()).add(cell)
    skipped_rows = [(item.get("test"), tuple(report["binding"][key] for key in (
        "platform", "architecture", "python", "runner")))
        for report in reports for item in report["skip_receipts"] if item.get("test")]
    skipped = sorted({test for test, _cell in skipped_rows})
    unresolved = sorted({test for test, cell in skipped_rows
                         if not any(passed_cell != cell
                                    for passed_cell in passed_by.get(test, set()))})
    failed_reports = sum(1 for report in reports if _report_failed(report))
    certified = not unresolved and failed_reports == 0
    return {
        "schema_version": 1, "status": "certified" if certified else "not-certified",
        "reports": len(reports), "skipped_tests": len(skipped),
        "covered_elsewhere": len(skipped) - len(unresolved),
        "unresolved": unresolved, "failed_reports": failed_reports,
        "subject": {"source_commit": next(iter(subjects))[0],
                    "public_root_sha256": next(iter(subjects))[1]},
        "matrix_cells": len(cells),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = aggregate(args.reports)
    except CapabilityError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["status"] == "certified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
