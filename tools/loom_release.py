#!/usr/bin/env python3
"""Reproducible public builder and evidence-gated Loom release certification."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import loom_privacy
import loom_reliability
import loom_adaptation_eval
import loom_docs
import loom_install


ROOT_FILES = {
    "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE", "PRIVACY.md",
    "README.md", "START-HERE.md", "VERSION",
}
ROOT_DIRECTORIES = {".github", "docs", "loom", "schemas", "skill", "templates", "tools"}
MANIFEST = "BUILD-MANIFEST.json"
LOCAL_CHECKS = (
    "suite", "adaptation", "privacy", "failure_injection",
    "reproducible_build", "installer_cycle", "performance_budgets", "docs",
    "twenty_project_bound",
)
EXTERNAL_CHECKS = (
    "cross-platform-ci", "unfamiliar-user-usability", "independent-hostile-review",
)


class ReleaseError(RuntimeError):
    pass


def _eligible(relative):
    if relative.as_posix() == MANIFEST:
        return False
    if len(relative.parts) == 1:
        return relative.name in ROOT_FILES
    return relative.parts[0] in ROOT_DIRECTORIES \
        and "__pycache__" not in relative.parts \
        and relative.suffix.lower() not in {".pyc", ".pyo"}


def build_public(source, destination, *, forbidden_tokens):
    try:
        source = loom_reliability._absolute(
            source, "release source", must_exist=True)
        destination = loom_reliability._absolute(destination, "release destination")
    except loom_reliability.ReliabilityError as exc:
        raise ReleaseError(str(exc)) from exc
    if not source.is_dir() or destination.exists():
        raise ReleaseError("release source must be a directory and destination must not exist")
    if destination == source or destination.is_relative_to(source) \
            or source.is_relative_to(destination):
        raise ReleaseError("release source and destination must be separate trees")
    if not forbidden_tokens:
        raise ReleaseError("release build requires real private/owner firewall tokens")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".loom-public-", dir=destination.parent))
    try:
        copied = []
        for path in loom_reliability._regular_files(source):
            relative = path.relative_to(source)
            if not _eligible(relative):
                continue
            output = staging / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
            copied.append(relative.as_posix())
        missing = sorted(item for item in ROOT_FILES if item not in copied)
        if missing:
            raise ReleaseError("release source lacks required public roots: " + ", ".join(missing))
        payload_manifest = loom_reliability.deterministic_manifest(staging)
        loom_reliability.atomic_write_json(staging / MANIFEST, payload_manifest)
        firewall = loom_privacy.scan_publication(
            staging, forbidden_tokens=forbidden_tokens, require_owner_tokens=True)
        if not firewall["clean"]:
            raise ReleaseError("release firewall rejected the public build")
        os.replace(staging, destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {"status": "built", "destination": str(destination),
            "root_sha256": payload_manifest["root_sha256"],
            "files": payload_manifest["files"], "firewall": firewall}


def _external_passed(check_id, evidence):
    if not isinstance(evidence, dict) or evidence.get("status") != "passed" \
            or not isinstance(evidence.get("evidence"), str) \
            or not evidence["evidence"].strip():
        return False
    if check_id == "unfamiliar-user-usability":
        return type(evidence.get("participant_count")) is int \
            and evidence["participant_count"] >= 1
    if check_id == "independent-hostile-review":
        return evidence.get("critical_findings") == 0 \
            and evidence.get("high_findings") == 0
    return True


def certification_report(*, local_checks, external_evidence):
    if not isinstance(local_checks, dict) or not isinstance(external_evidence, dict):
        raise ReleaseError("release evidence must be structured mappings")
    checks = []
    for check_id in LOCAL_CHECKS:
        passed = local_checks.get(check_id) is True
        checks.append({"id": check_id, "status": "passed" if passed else "failed"})
    unverified = []
    for check_id in EXTERNAL_CHECKS:
        evidence = external_evidence.get(check_id)
        passed = _external_passed(check_id, evidence)
        status = "passed" if passed else ("failed" if evidence else "unverified")
        checks.append({"id": check_id, "status": status})
        if not passed:
            unverified.append({"id": check_id, "status": status})
    passed_count = sum(item["status"] == "passed" for item in checks)
    certified = passed_count == len(checks)
    return {
        "schema_version": 1,
        "status": "certified" if certified else "blocked",
        "score": 100 if certified else int(100 * passed_count / len(checks)),
        "checks": checks,
        "unverified": unverified,
        "claim_100_allowed": certified,
        "limitations": ([] if certified else [
            "No 100 score or production certification until every external proof is supplied."]),
    }


def _suite(root):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-p", "test_*.py"],
        cwd=root / "tools", capture_output=True, text=True, timeout=900, check=False,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return {"passed": result.returncode == 0, "returncode": result.returncode,
            "output": (result.stdout + result.stderr)[-4000:]}


def sanitize_suite_evidence(suite, *, root, home):
    value = dict(suite)
    value["output"] = loom_privacy.minimize_evidence(
        value.get("output", ""), roots=(root, home), max_chars=4000)
    return value


def verify_local(root, *, forbidden_tokens):
    try:
        root = loom_reliability._absolute(root, "release root", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise ReleaseError(str(exc)) from exc
    if not forbidden_tokens:
        raise ReleaseError("local verification requires real private/owner tokens")
    suite = sanitize_suite_evidence(_suite(root), root=root, home=Path.home())
    docs = loom_docs.audit_docs(root)
    offline = loom_privacy.audit_offline_modules(root / "tools")
    with tempfile.TemporaryDirectory(prefix="loom-release-proof-") as temporary:
        workspace = Path(temporary)
        adaptation = loom_adaptation_eval.run_suite(workspace / "adaptation")
        first = build_public(root, workspace / "public-one",
                             forbidden_tokens=forbidden_tokens)
        second = build_public(root, workspace / "public-two",
                              forbidden_tokens=forbidden_tokens)
        reproducible = first["root_sha256"] == second["root_sha256"]
        installed = loom_install.install(workspace / "public-one", workspace / "installed")
        checked = loom_install.check(workspace / "installed")
        removed = loom_install.uninstall(
            workspace / "installed", confirmation=installed["install_id"])
        installer_cycle = checked["status"] == "installed" \
            and removed["status"] == "uninstalled" and removed["target_removed"]
        privacy = first["firewall"]
    scenario = next((item for item in adaptation["scenarios"]
                     if item["id"] == "twenty-project-year"), None)
    local = {
        "suite": suite["passed"],
        "adaptation": adaptation["status"] == "passed",
        "privacy": privacy["clean"] and offline["offline"],
        "failure_injection": suite["passed"],
        "reproducible_build": reproducible,
        "installer_cycle": installer_cycle,
        "performance_budgets": suite["passed"],
        "docs": docs["status"] == "passed",
        "twenty_project_bound": bool(scenario and scenario["passed"]),
    }
    return {
        "schema_version": 1,
        "status": "passed" if all(local.values()) else "failed",
        "local_checks": local,
        "evidence": {
            "suite": suite,
            "adaptation_scenarios": adaptation["scenario_count"],
            "privacy": privacy,
            "offline": offline,
            "docs": docs,
            "build_hashes": [first["root_sha256"], second["root_sha256"]],
            "installer": {"files_verified": checked["files_verified"],
                          "target_removed": removed["target_removed"]},
            "twenty_project_measurements": (
                scenario["measurements"] if scenario else None),
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("source")
    build.add_argument("destination")
    build.add_argument("--forbid", action="append", default=[])
    certify = sub.add_parser("certify")
    certify.add_argument("--local-checks", required=True)
    certify.add_argument("--external-evidence", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("root")
    verify.add_argument("--forbid", action="append", default=[])
    verify.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_public(
                args.source, args.destination, forbidden_tokens=args.forbid)
        elif args.command == "certify":
            local = json.loads(Path(args.local_checks).read_text(encoding="utf-8"))
            external = json.loads(Path(args.external_evidence).read_text(encoding="utf-8"))
            result = certification_report(
                local_checks=local, external_evidence=external)
        else:
            result = verify_local(args.root, forbidden_tokens=args.forbid)
            if args.output:
                loom_reliability.atomic_write_json(Path(args.output).resolve(), result)
    except (ReleaseError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in {"built", "certified", "passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
