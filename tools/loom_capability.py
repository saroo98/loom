#!/usr/bin/env python3
"""Aggregate per-run test skips into capability-bound matrix certification."""

import argparse
import json
from pathlib import Path


class CapabilityError(RuntimeError):
    pass


def aggregate(paths):
    reports = []
    for path in paths:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CapabilityError(f"capability report is invalid: {exc}") from exc
        if not isinstance(value, dict) or not isinstance(value.get("timings"), list) \
                or not isinstance(value.get("skip_receipts"), list):
            raise CapabilityError("capability report contract is invalid")
        reports.append(value)
    if not reports:
        raise CapabilityError("at least one test report is required")
    passed = {item.get("test") for report in reports for item in report["timings"]
              if item.get("status") == "passed"}
    skipped = sorted({item.get("test") for report in reports
                      for item in report["skip_receipts"] if item.get("test")})
    unresolved = [test for test in skipped if test not in passed]
    failed_reports = sum(1 for report in reports
                         if report.get("failures", 0) or report.get("errors", 0)
                         or not report.get("within_budget", False))
    certified = not unresolved and failed_reports == 0
    return {
        "schema_version": 1, "status": "certified" if certified else "not-certified",
        "reports": len(reports), "skipped_tests": len(skipped),
        "covered_elsewhere": len(skipped) - len(unresolved),
        "unresolved": unresolved, "failed_reports": failed_reports,
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
