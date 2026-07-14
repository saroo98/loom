#!/usr/bin/env python3
"""Receipt-proven, fail-closed Loom install/check/uninstall lifecycle."""

import argparse
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

import loom_reliability


RECEIPT = ".loom-install-receipt.json"


class InstallError(RuntimeError):
    pass


def _root(path, label, *, exists=False):
    try:
        value = loom_reliability._absolute(path, label, must_exist=exists)
    except loom_reliability.ReliabilityError as exc:
        raise InstallError(str(exc)) from exc
    return value


def _read_receipt(target):
    path = target / RECEIPT
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"installation receipt is unreadable: {exc}") from exc
    return value


def install(source, target):
    source = _root(source, "installation source", exists=True)
    target = _root(target, "installation target")
    if not source.is_dir() or target.exists():
        raise InstallError("installation source must be a directory and target must not exist")
    if target == source or target.is_relative_to(source) or source.is_relative_to(target):
        raise InstallError("installation source and target must be separate trees")
    target.parent.mkdir(parents=True, exist_ok=True)
    parent = _root(target.parent, "installation target parent", exists=True)
    staging = Path(tempfile.mkdtemp(prefix=".loom-install-", dir=parent))
    owned = []
    try:
        for path in loom_reliability._regular_files(source):
            relative = path.relative_to(source)
            if relative.as_posix() == RECEIPT or "__pycache__" in relative.parts \
                    or path.suffix.lower() in {".pyc", ".pyo"}:
                continue
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            owned.append(relative.as_posix())
        skill_source = source / "skill" / "loom" / "SKILL.md"
        if skill_source.is_file() and "SKILL.md" not in owned:
            shutil.copyfile(skill_source, staging / "SKILL.md")
            owned.append("SKILL.md")
        if not owned:
            raise InstallError("installation source has no regular payload files")
        install_id = str(uuid.uuid4())
        receipt = loom_reliability.installation_receipt(
            staging, owned, install_id=install_id)
        loom_reliability.atomic_write_json(staging / RECEIPT, receipt)
        os.replace(staging, target)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    checked = check(target)
    return {**checked, "files_installed": len(owned)}


def check(target):
    target = _root(target, "installation target", exists=True)
    if not target.is_dir():
        raise InstallError("installation target must be a directory")
    receipt = _read_receipt(target)
    try:
        body = {key: value for key, value in receipt.items() if key != "receipt_hash"}
        if not isinstance(receipt, dict) or set(receipt) != {
                "schema_version", "install_id", "files", "receipt_hash"} \
                or receipt["receipt_hash"] != loom_reliability._canonical_hash(body):
            raise InstallError("installation receipt is invalid")
        for item in receipt["files"]:
            path = loom_reliability._target(target, item["path"])
            if not path.is_file() or loom_reliability.file_sha256(path) != item["sha256"]:
                raise InstallError(f"installed file changed or is missing: {item['path']}")
    except (KeyError, TypeError, loom_reliability.ReliabilityError) as exc:
        raise InstallError(f"installation receipt is invalid: {exc}") from exc
    return {"status": "installed", "install_id": receipt["install_id"],
            "files_verified": len(receipt["files"]),
            "receipt_hash": receipt["receipt_hash"]}


def uninstall(target, *, confirmation):
    target = _root(target, "installation target", exists=True)
    receipt = _read_receipt(target)
    try:
        result = loom_reliability.uninstall_owned_files(
            target, receipt, confirmation=confirmation)
    except loom_reliability.ReliabilityError as exc:
        raise InstallError(str(exc)) from exc
    receipt_path = target / RECEIPT
    receipt_path.unlink()
    for directory, _, _ in os.walk(target, topdown=False):
        try:
            Path(directory).rmdir()
        except OSError:
            pass
    return {"status": "uninstalled", **result,
            "target_removed": not target.exists()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    install_parser = sub.add_parser("install")
    install_parser.add_argument("source")
    install_parser.add_argument("target")
    check_parser = sub.add_parser("check")
    check_parser.add_argument("target")
    uninstall_parser = sub.add_parser("uninstall")
    uninstall_parser.add_argument("target")
    uninstall_parser.add_argument("--confirmation", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            result = install(args.source, args.target)
        elif args.command == "check":
            result = check(args.target)
        else:
            result = uninstall(args.target, confirmation=args.confirmation)
    except InstallError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
