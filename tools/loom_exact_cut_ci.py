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
import loom_release_subject
import loom_reliability
import loom_operation_envelope


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
        "operation_id": None,
    }
    envelope_path = None
    terminal_phase = "failed"
    try:
        try:
            source_subject = loom_release_subject._tree(source)["sha256"]
        except loom_release_subject.ReleaseSubjectError as exc:
            if "tree is empty" not in str(exc):
                raise
            source_subject = hashlib.sha256(
                b"loom-empty-release-subject-v1").hexdigest()
        sidecar_contract = hashlib.sha256(
            ("exact-cut-receipt:" + output.name).encode("utf-8")).hexdigest()
        envelope_path, envelope = loom_operation_envelope.begin(
            (output.parent / ".loom-operations").resolve(),
            operation_class="exact-cut",
            subject_digest=source_subject,
            sidecar_type="exact-cut-receipt",
            sidecar_id=output.name,
            sidecar_digest=sidecar_contract)
        base["operation_id"] = envelope["operation_id"]
        loom_operation_envelope.transition(
            envelope_path, phase="started",
            side_effect_boundary="before-public-cut-build",
            state_may_have_changed=False)
        loom_operation_envelope.transition(
            envelope_path, phase="effect",
            side_effect_boundary="public-cut-build-started",
            state_may_have_changed=True)
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
        terminal_phase = "passed"
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
    finally:
        try:
            loom_reliability.atomic_write_json(output, base)
            if base["suite"] is not None and suite_output is not None:
                loom_reliability.atomic_write_json(suite_output, base["suite"])
            if envelope_path is not None:
                loom_operation_envelope.transition(
                    envelope_path, phase=terminal_phase,
                    side_effect_boundary="exact-cut-receipt-committed",
                    state_may_have_changed=True,
                    primary_failure=(
                        None if terminal_phase == "passed"
                        else base["error_type"] or "exact-cut-failed"),
                    cleanup_disposition=(
                        "completed" if terminal_phase == "passed" else "preserved"))
        except BaseException as final_exc:
            if base["error_type"] is None:
                message = f"{type(final_exc).__name__}:{final_exc}"
                base.update({
                    "status": "failed",
                    "error_type": type(final_exc).__name__,
                    "error_sha256": hashlib.sha256(
                        message.encode("utf-8")).hexdigest(),
                    "traceback_tail": _safe_trace(
                        final_exc, (source, cut, output.parent)),
                })
                loom_reliability.atomic_write_json(output, base)
    return base


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
