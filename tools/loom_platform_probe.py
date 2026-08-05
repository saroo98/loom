#!/usr/bin/env python3
"""Emit a bounded native filesystem and runtime capability receipt."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import loom_subject_identity


_DIGEST = re.compile(r"[0-9a-f]{64}")


def _canonical_digest(body):
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")).hexdigest()


def release_environment(*, requested_label=None, image_os=None,
                        image_version=None, workflow_path=None,
                        workflow_digest=None, action_manifest_digest=None,
                        event_name=None, run_id=None, run_attempt=None):
    """Return the closed runner and workflow identity used by release evidence.

    Requested labels and resolved images are intentionally separate. A moving
    label is never treated as proof that two actual runner images are equal.
    """
    supplied = [requested_label, image_os, image_version, workflow_path,
                workflow_digest, action_manifest_digest, event_name, run_id,
                run_attempt]
    if not any(value is not None for value in supplied) \
            and os.environ.get("GITHUB_ACTIONS") == "true":
        requested_label = os.environ.get("LOOM_REQUESTED_RUNNER_LABEL")
        image_os = os.environ.get("ImageOS")
        image_version = os.environ.get("ImageVersion")
        workflow_path = os.environ.get("LOOM_WORKFLOW_PATH")
        workflow_digest = os.environ.get("LOOM_WORKFLOW_DIGEST")
        action_manifest_digest = os.environ.get("LOOM_ACTION_MANIFEST_DIGEST")
        event_name = os.environ.get("GITHUB_EVENT_NAME")
        run_id = os.environ.get("GITHUB_RUN_ID")
        run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
        supplied = [requested_label, image_os, image_version, workflow_path,
                    workflow_digest, action_manifest_digest, event_name, run_id,
                    run_attempt]
    if any(value is not None for value in supplied) and not all(
            isinstance(value, str) and value.strip() for value in supplied):
        raise ValueError("release CI identity is incomplete")
    if workflow_digest is not None and (not _DIGEST.fullmatch(workflow_digest)
                                        or not _DIGEST.fullmatch(
                                            action_manifest_digest or "")):
        raise ValueError("release CI digests are invalid")
    ci = workflow_digest is not None
    body = {
        "evidence_class": "ci-reproduced" if ci else "local-unattested",
        "requested_label": requested_label or "local-unattested",
        "image_os": image_os or os.environ.get("ImageOS") or platform.system().lower(),
        "image_version": image_version or os.environ.get("ImageVersion") or "local-unattested",
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "workflow_path": workflow_path or "local-unattested",
        "workflow_digest": workflow_digest or "0" * 64,
        "action_manifest_digest": action_manifest_digest or "0" * 64,
        "event_name": event_name or "local-unattested",
        "run_id": run_id or "local-unattested",
        "run_attempt": run_attempt or "local-unattested",
    }
    return {**body, "environment_sha256": _canonical_digest(body)}


def _probe(root):
    results = {}
    target = root / "target"
    target.write_bytes(b"loom")
    link = root / "link"
    try:
        os.symlink(target, link)
        results["symlink"] = "supported" if link.is_symlink() else "failed"
    except (OSError, NotImplementedError):
        results["symlink"] = "unavailable"
    fifo = root / "fifo"
    if hasattr(os, "mkfifo"):
        try:
            os.mkfifo(fifo)
            results["fifo"] = "supported" if stat.S_ISFIFO(fifo.stat().st_mode) else "failed"
        except OSError:
            results["fifo"] = "unavailable"
    else:
        results["fifo"] = "unavailable"
    if hasattr(os, "setxattr") and hasattr(os, "getxattr"):
        try:
            os.setxattr(target, b"user.loom_test", b"ok")
            results["extended_attributes"] = (
                "supported" if os.getxattr(target, b"user.loom_test") == b"ok" else "failed")
        except OSError:
            results["extended_attributes"] = "unavailable"
    else:
        results["extended_attributes"] = "unavailable"
    replacement = root / "replacement"
    replacement.write_bytes(b"new")
    os.replace(replacement, target)
    results["atomic_replace"] = "supported" if target.read_bytes() == b"new" else "failed"
    exclusive = root / "exclusive"
    descriptor = os.open(exclusive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        os.open(exclusive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        results["exclusive_create"] = "failed"
    except FileExistsError:
        results["exclusive_create"] = "supported"
    mixed = root / "CaseProbe"
    mixed.write_text("x", encoding="utf-8")
    results["case_sensitive"] = "yes" if not (root / "caseprobe").exists() else "no"
    try:
        target.chmod(target.stat().st_mode | stat.S_IXUSR)
        results["executable_bit"] = (
            "supported" if target.stat().st_mode & stat.S_IXUSR else "unavailable")
    except OSError:
        results["executable_bit"] = "unavailable"
    return results


def collect(*, runner=None, workflow_digest=None, subject_bindings=None):
    if (runner is None) != (workflow_digest is None):
        raise ValueError("CI evidence requires both runner identity and workflow digest")
    if runner is not None and (not isinstance(runner, str) or not runner.strip()
                               or not re.fullmatch(r"[0-9a-f]{64}", workflow_digest or "")):
        raise ValueError("CI evidence binding is invalid")
    with tempfile.TemporaryDirectory(prefix="loom-platform-") as temporary:
        capabilities = _probe(Path(temporary))
    bindings = []
    if subject_bindings is not None:
        if not isinstance(subject_bindings, list) or not subject_bindings:
            raise ValueError("platform subject bindings are incomplete")
        for binding in subject_bindings:
            if not isinstance(binding, dict) or set(binding) != {
                    "kind", "subject_id", "subject_digest"} \
                    or binding.get("kind") not in (
                        loom_subject_identity.SUBJECT_KINDS & {
                        "candidate-source", "native-helper",
                        "installed-runtime"}) \
                    or not isinstance(binding.get("subject_id"), str) \
                    or not binding["subject_id"] \
                    or not re.fullmatch(
                        r"[0-9a-f]{64}", str(binding.get("subject_digest", ""))):
                raise ValueError("platform subject binding is invalid")
            bindings.append(dict(binding))
    system = platform.system().lower()
    credential_command = ({"windows": "cmdkey", "darwin": "security"}.get(
        system, "secret-tool"))
    credential_store = "available" if shutil.which(credential_command) else "unavailable"
    body = {
        "schema_version": 2 if bindings else 1,
        "evidence_class": "ci-reproduced" if workflow_digest else "mechanical-local",
        "runner": runner, "os": platform.system(), "os_release": platform.release(),
        "os_version": platform.version(), "architecture": platform.machine(),
        "python": platform.python_version(), "python_implementation": platform.python_implementation(),
        "filesystem_capabilities": capabilities, "credential_store": credential_store,
        "workflow_digest": workflow_digest,
        "limitations": ["Unavailable means this environment did not prove the capability."],
    }
    if bindings:
        body["subject_bindings"] = sorted(
            bindings, key=lambda item: (
                item["kind"], item["subject_id"], item["subject_digest"]))
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner")
    parser.add_argument("--workflow-digest")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = collect(runner=args.runner, workflow_digest=args.workflow_digest)
    except ValueError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    print(json.dumps({"status": "recorded", "receipt_sha256": result["receipt_sha256"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
