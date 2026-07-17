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


def collect(*, runner=None, workflow_digest=None):
    if (runner is None) != (workflow_digest is None):
        raise ValueError("CI evidence requires both runner identity and workflow digest")
    if runner is not None and (not isinstance(runner, str) or not runner.strip()
                               or not re.fullmatch(r"[0-9a-f]{64}", workflow_digest or "")):
        raise ValueError("CI evidence binding is invalid")
    with tempfile.TemporaryDirectory(prefix="loom-platform-") as temporary:
        capabilities = _probe(Path(temporary))
    system = platform.system().lower()
    credential_command = ({"windows": "cmdkey", "darwin": "security"}.get(
        system, "secret-tool"))
    credential_store = "available" if shutil.which(credential_command) else "unavailable"
    body = {
        "schema_version": 1,
        "evidence_class": "ci-reproduced" if workflow_digest else "mechanical-local",
        "runner": runner, "os": platform.system(), "os_release": platform.release(),
        "os_version": platform.version(), "architecture": platform.machine(),
        "python": platform.python_version(), "python_implementation": platform.python_implementation(),
        "filesystem_capabilities": capabilities, "credential_store": credential_store,
        "workflow_digest": workflow_digest,
        "limitations": ["Unavailable means this environment did not prove the capability."],
    }
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
