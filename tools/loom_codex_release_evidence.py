#!/usr/bin/env python3
"""Create a privacy-safe observation of one exact Loom request in a fresh Codex App task."""

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import loom_reliability
import loom_subject_identity


SHA = re.compile(r"^[0-9a-f]{64}$")


class CodexReleaseEvidenceError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def create(*, release_subject_sha256, installed_runtime_subject,
           request_sha256, response_sha256, task_sha256, observed_at,
           route="plugin-mcp", result="sealed-plan"):
    try:
        installed = loom_subject_identity.validate_subject(installed_runtime_subject)
    except loom_subject_identity.SubjectIdentityError as exc:
        raise CodexReleaseEvidenceError(str(exc)) from exc
    if installed["kind"] != "installed-runtime" \
            or any(SHA.fullmatch(str(value)) is None for value in (
                release_subject_sha256, request_sha256, response_sha256, task_sha256)) \
            or route not in {"plugin-mcp", "verified-hook"} \
            or result not in {"sealed-plan", "terminal-receipt"} \
            or not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        raise CodexReleaseEvidenceError("Codex release observation identity is invalid")
    try:
        parsed = dt.datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CodexReleaseEvidenceError(
            "Codex release observation time is invalid") from exc
    if parsed.tzinfo is None:
        raise CodexReleaseEvidenceError(
            "Codex release observation time lacks a timezone")
    body = {
        "schema_version": 1, "host": "codex-app", "surface": "app",
        "status": "passed", "evidence_class": "host-observed",
        "release_subject_sha256": release_subject_sha256,
        "installed_runtime_subject": installed,
        "request_sha256": request_sha256, "response_sha256": response_sha256,
        "task_sha256": task_sha256, "observed_at": observed_at,
        "route": route, "result": result,
        "fresh_task": True, "disposable_project": True,
        "privacy": {
            "request_text_included": False, "response_text_included": False,
            "task_identity_included": False, "project_identity_included": False,
            "absolute_paths_included": False,
        },
    }
    return {**body, "observation_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-subject-sha256", required=True)
    parser.add_argument("--installed-runtime-subject", required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--response-sha256", required=True)
    parser.add_argument("--task-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--route", choices=("plugin-mcp", "verified-hook"),
                        default="plugin-mcp")
    parser.add_argument("--result", choices=("sealed-plan", "terminal-receipt"),
                        default="sealed-plan")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        subject = json.loads(Path(args.installed_runtime_subject).read_text(encoding="utf-8"))
        value = create(
            release_subject_sha256=args.release_subject_sha256,
            installed_runtime_subject=subject, request_sha256=args.request_sha256,
            response_sha256=args.response_sha256, task_sha256=args.task_sha256,
            observed_at=args.observed_at, route=args.route, result=args.result)
        output = loom_reliability._absolute(args.output, "Codex evidence output")
        if output.exists():
            raise CodexReleaseEvidenceError("Codex evidence output already exists")
        loom_reliability.atomic_write_json(output, value)
    except (OSError, UnicodeError, json.JSONDecodeError, CodexReleaseEvidenceError,
            loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "created",
                      "observation_sha256": value["observation_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
