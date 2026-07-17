#!/usr/bin/env python3
"""Enforce Loom's single VERSION authority across executable and public surfaces."""

import argparse
import json
import re
from pathlib import Path

import loom_cargo


class VersionError(RuntimeError):
    pass


TEXT_SURFACES = (
    "README.md", "START-HERE.md", "skills/loom/SKILL.md", "skill/loom/SKILL.md",
    "templates/pack/MANIFEST.md", "docs/architecture.md", "docs/limitations.md",
    "docs/index.html", "CHANGELOG.md",
)


def verify(root):
    root = Path(root).resolve()
    try:
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise VersionError(f"VERSION cannot be read: {exc}") from exc
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise VersionError("VERSION is not stable semantic versioning")
    findings = []
    marker = re.compile(rf"(?<![0-9.]){re.escape(version)}(?![0-9.])")
    for relative in TEXT_SURFACES:
        path = root / relative
        if not path.is_file() or not marker.search(path.read_text(encoding="utf-8")):
            findings.append(relative)
    for relative, key in ((".codex-plugin/plugin.json", "version"),
                          ("docs/capabilities.json", "version"),
                          ("docs/generated-evidence.json", "loom_version")):
        try:
            value = json.loads((root / relative).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            findings.append(relative)
            continue
        if value.get(key) != version:
            findings.append(relative)
    try:
        cargo_version = loom_cargo.package_version(root / "vault-helper" / "Cargo.toml")
        own = [item for item in loom_cargo.lock_packages(
            root / "vault-helper" / "Cargo.lock") if item[0] == "loom-vault"]
    except loom_cargo.CargoMetadataError:
        cargo_version, own = None, []
    if cargo_version != version:
        findings.append("vault-helper/Cargo.toml")
    if len(own) != 1 or own[0][1] != version:
        findings.append("vault-helper/Cargo.lock")
    if findings:
        raise VersionError("version drift: " + ", ".join(sorted(set(findings))))
    return {"status": "coherent", "version": version,
            "surfaces": len(TEXT_SURFACES) + 5}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args(argv)
    try:
        result = verify(args.root)
    except VersionError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
