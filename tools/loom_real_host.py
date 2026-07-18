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
    executable_name = next((name for name in loom_host_registry.HOSTS[host_id]["executables"]
                            if finder(name)), None)
    executable = finder(executable_name) if executable_name else None
    common = {
        "schema_version": 2,
        "contract_id": loom_host_registry.CONTRACT_ID,
        "contract_reviewed_at": loom_host_registry.REVIEWED_AT,
        "host": host_id,
        "surfaces": contract["surfaces"],
        "contract_status": contract["contract_status"],
        "contract_evidence_status": contract["evidence_status"],
        "proof_ttl_days": contract["proof_ttl_days"],
        "sources": contract["sources"],
        "evidence_class": "host-observed",
    }
    if not executable:
        return {**common, "status": "not-detected", "version": None,
                "binary_sha256": None, "version_command": None,
                "limitations": ["No host executable was discovered."]}
    runner = run or subprocess.run
    command = [executable, *contract["version_command"][1:]] \
        if contract["version_command"] else None
    if command is None:
        return {**common, "status": "unverified", "version": None,
                "binary_sha256": None, "version_command": None,
                "limitations": ["The versioned contract has no executable version probe."]}
    try:
        result = runner(command, capture_output=True, text=True,
                        timeout=10, check=False)
        binary = Path(executable)
        binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest() \
            if binary.is_file() and not binary.is_symlink() else None
    except (OSError, subprocess.SubprocessError) as exc:
        raise RealHostError(f"host discovery failed: {exc}") from exc
    version = (result.stdout or result.stderr).strip()[:128]
    status = "detected" if result.returncode == 0 and version else "unverified"
    return {**common, "status": status, "version": version or None,
            "binary_sha256": binary_digest, "version_command": command,
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
