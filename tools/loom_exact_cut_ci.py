#!/usr/bin/env python3
"""Always emit a bounded exact-cut CI receipt, including on verifier failure."""

import argparse
import hashlib
import json
import os
import platform
import traceback
from pathlib import Path

import loom_release
import loom_reliability


def _safe_trace(exc, roots):
    rendered = traceback.format_exception(type(exc), exc, exc.__traceback__)[-8:]
    replacements = {str(Path(value).resolve()) for value in roots if value}
    replacements.update(str(value) for value in (
        os.environ.get("RUNNER_TEMP"), os.environ.get("GITHUB_WORKSPACE"),
        os.environ.get("HOME"), os.environ.get("USERPROFILE")) if value)
    for root in sorted(replacements, key=len, reverse=True):
        rendered = [line.replace(root, "<local-path>") for line in rendered]
    return rendered


def run(source, cut, output, *, suite_output=None, forbidden_tokens=()):
    source = Path(source).resolve()
    cut = Path(cut).resolve()
    output = Path(output).resolve()
    base = {
        "schema_version": 1,
        "status": "failed",
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python": platform.python_version(),
        "source_commit": os.environ.get("GITHUB_SHA"),
        "build_root_sha256": None,
        "verified_root_sha256": None,
        "suite": None,
        "error_type": None,
        "error_sha256": None,
        "traceback_tail": [],
    }
    try:
        build = loom_release.build_public(
            source, cut, forbidden_tokens=list(forbidden_tokens),
            source_classification="public-release")
        base["build_root_sha256"] = build["root_sha256"]
        verified = loom_release.verify_cut(cut, forbidden_tokens=list(forbidden_tokens))
        suite = dict(verified["suite"])
        suite["binding"] = {
            "source_commit": os.environ.get("GITHUB_SHA") or "0" * 40,
            "public_root_sha256": verified["root_sha256"],
            "platform": platform.system().lower(),
            "architecture": platform.machine().lower(),
            "python": platform.python_version(),
            "runner": os.environ.get("RUNNER_NAME") or "local-unattested",
        }
        base.update({
            "status": "verified",
            "verified_root_sha256": verified["root_sha256"],
            "suite": suite,
        })
        return base
    except BaseException as exc:
        message = f"{type(exc).__name__}:{exc}"
        details = getattr(exc, "details", None)
        base.update({
            "error_type": type(exc).__name__,
            "error_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            "traceback_tail": _safe_trace(exc, (source, cut, output.parent)),
        })
        if isinstance(details, dict) and isinstance(details.get("suite"), dict):
            base["suite"] = details["suite"]
        return base
    finally:
        loom_reliability.atomic_write_json(output, base)
        if base["suite"] is not None and suite_output is not None:
            loom_reliability.atomic_write_json(suite_output, base["suite"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("cut")
    parser.add_argument("--output", required=True)
    parser.add_argument("--suite-output")
    parser.add_argument("--forbidden-token", action="append", default=[])
    args = parser.parse_args(argv)
    result = run(args.source, args.cut, args.output, suite_output=args.suite_output,
                 forbidden_tokens=args.forbidden_token)
    print(json.dumps({key: result[key] for key in (
        "status", "build_root_sha256", "verified_root_sha256", "error_type")},
        sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
