#!/usr/bin/env python3
"""Generate and validate the exact SPDX dependency inventory for Loom's Rust helper."""

import hashlib
import json
import re
import tomllib
from pathlib import Path

import loom_reliability


class SbomError(RuntimeError):
    pass


def _lock_packages(source):
    lock = Path(source) / "vault-helper" / "Cargo.lock"
    try:
        value = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SbomError(f"Cargo.lock is invalid: {exc}") from exc
    packages = value.get("package")
    if not isinstance(packages, list) or not packages:
        raise SbomError("Cargo.lock contains no packages")
    result = []
    for item in packages:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) \
                or not isinstance(item.get("version"), str):
            raise SbomError("Cargo.lock package identity is invalid")
        result.append((item["name"], item["version"], item.get("checksum")))
    return result


def generate(source, helper, platform_id, output, *, namespace_seed):
    source = loom_reliability._absolute(source, "SBOM source", must_exist=True)
    helper = loom_reliability._absolute(helper, "SBOM helper", must_exist=True)
    output = loom_reliability._absolute(output, "SBOM output")
    if output.exists() or not re.fullmatch(r"[a-z]+-(?:x64|arm64)", platform_id) \
            or not re.fullmatch(r"[0-9a-f]{64}", namespace_seed):
        raise SbomError("SBOM output, platform, or namespace seed is invalid")
    packages = []
    relationships = []
    for index, (name, version, checksum) in enumerate(_lock_packages(source), 1):
        spdx_id = f"SPDXRef-Cargo-{index}"
        package = {
            "SPDXID": spdx_id, "name": name, "versionInfo": version,
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum):
            package["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        packages.append(package)
        relationships.append({"spdxElementId": "SPDXRef-LoomVault",
                              "relationshipType": "DEPENDS_ON",
                              "relatedSpdxElement": spdx_id})
    helper_digest = loom_reliability.file_sha256(helper)
    packages.insert(0, {
        "SPDXID": "SPDXRef-LoomVault", "name": f"loom-vault-{platform_id}",
        "versionInfo": (source / "VERSION").read_text(encoding="utf-8").strip(),
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": helper_digest}],
        "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0",
        "copyrightText": "NOASSERTION",
    })
    relationships.insert(0, {"spdxElementId": "SPDXRef-DOCUMENT",
                             "relationshipType": "DESCRIBES",
                             "relatedSpdxElement": "SPDXRef-LoomVault"})
    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": f"loom-vault-{platform_id}",
        "documentNamespace": f"https://github.com/saroo98/loom/spdx/{namespace_seed}/{platform_id}",
        "creationInfo": {"creators": ["Tool: loom-sbom-1"],
                         "created": "2020-01-01T00:00:00Z"},
        "documentDescribes": ["SPDXRef-LoomVault"],
        "packages": packages, "relationships": relationships,
    }
    loom_reliability.atomic_write_json(output, document)
    return {"sha256": loom_reliability.file_sha256(output),
            "packages": len(packages), "helper_sha256": helper_digest}


def validate(path, source, helper, platform_id):
    path = loom_reliability._absolute(path, "helper SBOM", must_exist=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SbomError(f"helper SBOM is invalid: {exc}") from exc
    required = {"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace",
                "creationInfo", "documentDescribes", "packages", "relationships"}
    if not isinstance(value, dict) or set(value) != required \
            or value["spdxVersion"] != "SPDX-2.3" \
            or value["dataLicense"] != "CC0-1.0" \
            or value["SPDXID"] != "SPDXRef-DOCUMENT" \
            or value["documentDescribes"] != ["SPDXRef-LoomVault"] \
            or not isinstance(value["packages"], list):
        raise SbomError("helper SBOM contract or subject is invalid")
    by_id = {item.get("SPDXID"): item for item in value["packages"]
             if isinstance(item, dict)}
    helper_item = by_id.get("SPDXRef-LoomVault")
    expected_helper = loom_reliability.file_sha256(helper)
    if not isinstance(helper_item, dict) \
            or helper_item.get("name") != f"loom-vault-{platform_id}" \
            or helper_item.get("checksums") != [
                {"algorithm": "SHA256", "checksumValue": expected_helper}]:
        raise SbomError("helper SBOM names the wrong binary subject")
    observed = sorted(
        (item.get("name"), item.get("versionInfo")) for key, item in by_id.items()
        if key != "SPDXRef-LoomVault")
    expected = sorted((name, version) for name, version, _checksum in _lock_packages(source))
    if observed != expected:
        raise SbomError("helper SBOM does not exactly reconcile with Cargo.lock")
    return {"packages": len(value["packages"]), "helper_sha256": expected_helper}
