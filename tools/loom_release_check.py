#!/usr/bin/env python3
"""Check Loom version, migration, template, public-overlay, and installed-copy coherence."""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import loom_install  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
STAMP_RE = re.compile(r'(?m)^\s*loom_version\s*:\s*["\']?(\d+\.\d+\.\d+)["\']?')


def version(root=ROOT):
    path = Path(root) / "VERSION"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read VERSION: {exc}") from exc
    if not SEMVER_RE.fullmatch(value):
        raise ValueError("VERSION is not semantic x.y.z")
    return value


def _changelog_version(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return None, str(exc)
    match = re.search(r"(?m)^##\s+(\d+\.\d+\.\d+)\b", text)
    return (match.group(1), None) if match else (None, "no semantic version heading")


def source_findings(root=ROOT):
    root = Path(root).resolve()
    findings = []
    try:
        current = version(root)
    except ValueError as exc:
        return [str(exc)]
    for rel in ("CHANGELOG.md", "public/CHANGELOG.md"):
        path = root / rel
        if rel.startswith("public/") and not path.is_file():
            continue  # a built public cut has already overlaid this at root
        found, error = _changelog_version(path)
        if error:
            findings.append(f"{rel}: {error}")
        elif found != current:
            findings.append(f"{rel}: newest version {found}, VERSION is {current}")

    stamp_files = []
    for base in (root / "templates", root / "plans"):
        if base.is_dir():
            stamp_files.extend(base.rglob("*.md"))
            stamp_files.extend(base.rglob("*.json"))
    intake = root / "loom" / "intake" / "intake.md"
    if intake.is_file():
        stamp_files.append(intake)
    for path in sorted(set(stamp_files)):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(f"{path.relative_to(root)}: unreadable: {exc}")
            continue
        for found in STAMP_RE.findall(text):
            if found != current:
                findings.append(
                    f"{path.relative_to(root).as_posix()}: loom_version {found}, "
                    f"VERSION is {current}")

    schema_dir = root / "schemas"
    if not schema_dir.is_dir():
        findings.append("schemas: directory missing")
    else:
        for path in sorted(schema_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                findings.append(f"schemas/{path.name}: invalid JSON: {exc}")
                continue
            if not isinstance(data, dict) or not data.get("$schema"):
                findings.append(f"schemas/{path.name}: missing object/$schema declaration")

    try:
        migration_text = (root / "tools" / "loom_migrate.py").read_text(encoding="utf-8")
        block = re.search(r"(?ms)^MIGRATIONS\s*=\s*\[(.*?)^\]", migration_text)
        targets = re.findall(r'\("(\d+\.\d+\.\d+)"\s*,\s*mig_',
                             block.group(1) if block else "")
    except (OSError, UnicodeError) as exc:
        findings.append(f"cannot inspect migration targets: {exc}")
    else:
        if not targets or targets[-1] != current:
            findings.append(
                f"migration target is {targets[-1] if targets else 'missing'}, "
                f"VERSION is {current}")
    return sorted(set(findings))


def installed_findings(root=ROOT, user_home=None):
    root = Path(root).resolve()
    user_home = Path(user_home or Path.home()).expanduser().resolve()
    try:
        owner = loom_install._owner_id(user_home, root, may_create=False)
        if owner is None:
            return ["installation identity unavailable"]
        targets = loom_install._targets(root, user_home)
        for target in targets:
            loom_install._safe_destination(target.destination, user_home)
        expected = tuple(
            loom_install._render(target.source, root, owner) for target in targets)
        inspections = tuple(
            loom_install._inspect(target.destination, owner) for target in targets)
    except loom_install.InstallError as exc:
        return [str(exc)]
    findings = []
    for target, content, inspection in zip(targets, expected, inspections):
        if inspection.state != "owned" \
                or inspection.normalized.encode("utf-8") != content:
            findings.append(
                f"{target.destination}: stale, foreign, or locally modified "
                f"[{inspection.state}]")
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--installed", action="store_true")
    parser.add_argument("--user-home")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    findings = source_findings(args.root)
    if args.installed:
        findings.extend(installed_findings(args.root, args.user_home))
    try:
        current = version(args.root)
    except ValueError:
        current = None
    payload = {
        "schema_version": 1,
        "status": "pass" if not findings else "fail",
        "version": current,
        "installed_checked": args.installed,
        "findings": findings,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True, ensure_ascii=False))
    else:
        for finding in findings:
            print(f"loom_release_check: FINDING — {finding}")
        print(f"loom_release_check: {payload['status'].upper()} — "
              f"{len(findings)} finding(s)")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
