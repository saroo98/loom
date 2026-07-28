#!/usr/bin/env python3
"""Enforce Loom's single VERSION authority across executable and public surfaces."""

import argparse
import json
import re
from pathlib import Path

import loom_cargo
import loom_truth


class VersionError(RuntimeError):
    pass


HTML_VERSION_RE = re.compile(
    r"<[^>]+\bdata-loom-version=[\"']([^\"']+)[\"'][^>]*>([^<]+)</",
    re.I)


def _json_pointer(value, pointer):
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise VersionError("registered version JSON pointer is invalid")
    current = value
    for raw in pointer[1:].split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            raise VersionError("registered version JSON pointer is unavailable")
        current = current[key]
    return current


def _registered_version_projections(root):
    try:
        registry = loom_truth.validate_registry(json.loads(
            (root / "contracts" / "truth-authorities-v1.json").read_text(
                encoding="utf-8")))
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_truth.TruthError) as exc:
        raise VersionError(f"truth authority registry is unavailable: {exc}") from exc
    return [
        item for item in registry["structured_projections"]
        if item["authority_id"] == "root-version"]


def verify(root):
    root = Path(root).resolve()
    try:
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise VersionError(f"VERSION cannot be read: {exc}") from exc
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise VersionError("VERSION is not stable semantic versioning")
    findings = []
    projections = _registered_version_projections(root)
    for projection in projections:
        relative = projection["path"]
        path = root / relative
        try:
            if projection["selector_kind"] == "json-pointer":
                value = json.loads(path.read_text(encoding="utf-8"))
                observed = _json_pointer(value, projection["selector"])
            elif projection["selector_kind"] == "html-data-attribute":
                text = path.read_text(encoding="utf-8")
                matches = HTML_VERSION_RE.findall(text)
                if projection["selector"] != "data-loom-version" \
                        or len(matches) != 1:
                    raise VersionError(
                        "registered HTML version slot is missing or ambiguous")
                attribute, label = matches[0]
                observed = attribute if label.strip() == attribute else None
            elif projection["selector_kind"] == "markdown-marker":
                marker = (
                    f"<!-- loom:projection {projection['selector']} -->"
                    f"{version}"
                    f"<!-- /loom:projection {projection['selector']} -->")
                observed = version if marker in path.read_text(
                    encoding="utf-8") else None
            else:
                continue
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                VersionError):
            findings.append(relative)
            continue
        if observed != version:
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
            "surfaces": len(projections) + 2}


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
