#!/usr/bin/env python3
"""Discover hosts honestly; real-host support still requires a witnessed invocation."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import loom_host_registry


class RealHostError(RuntimeError):
    pass


def discover(host_id, *, which=None, run=None):
    try:
        contract = loom_host_registry.contract(host_id)
    except KeyError as exc:
        raise RealHostError("host is not in the bounded registry") from exc
    finder = which or shutil.which
    executable_name = loom_host_registry.HOSTS[host_id]["executables"][0] \
        if loom_host_registry.HOSTS[host_id]["executables"] else None
    executable = finder(executable_name) if executable_name else None
    if not executable:
        return {"schema_version": 1, "host": host_id, "status": "not-detected",
                "evidence_class": "host-observed", "version": None,
                "binary_sha256": None, "official_source": contract["official_source"],
                "limitations": ["No host executable was discovered."]}
    runner = run or subprocess.run
    try:
        result = runner([executable, "--version"], capture_output=True, text=True,
                        timeout=10, check=False)
        binary = Path(executable)
        binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest() \
            if binary.is_file() and not binary.is_symlink() else None
    except (OSError, subprocess.SubprocessError) as exc:
        raise RealHostError(f"host discovery failed: {exc}") from exc
    version = (result.stdout or result.stderr).strip()[:128]
    status = "detected" if result.returncode == 0 and version else "unverified"
    return {"schema_version": 1, "host": host_id, "status": status,
            "evidence_class": "host-observed", "version": version or None,
            "binary_sha256": binary_digest, "official_source": contract["official_source"],
            "limitations": [
                "Discovery is not a Loom invocation and cannot upgrade real-host support."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=sorted(loom_host_registry.HOSTS))
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = discover(args.host)
    except RealHostError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    print(json.dumps({"status": result["status"], "evidence_class": "host-observed"},
                     sort_keys=True))
    return 0 if result["status"] == "detected" else 1


if __name__ == "__main__":
    raise SystemExit(main())
