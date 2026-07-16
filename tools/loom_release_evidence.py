#!/usr/bin/env python3
"""Emit deterministic checksums and evidence for exact Loom release assets."""

import hashlib
import json
import re
from pathlib import Path


class EvidenceError(RuntimeError):
    pass


def _artifact(path):
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink() or path.stat().st_size < 1:
        raise EvidenceError("release evidence names a missing or unsafe artifact")
    return {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size}


def create(output_directory, *, repository, commit, version, release_sequence,
           source_tree_sha256, public_cut_sha256, plugin, sbom, helpers,
           test_matrix, capability_coverage, firewall, signer_key_ids,
           attestations=(), limitations=()):
    output = Path(output_directory).resolve()
    if output.exists() or repository != "https://github.com/saroo98/loom" \
            or not re.fullmatch(r"[0-9a-f]{40}", commit) \
            or not re.fullmatch(r"\d+\.\d+\.\d+", version) \
            or type(release_sequence) is not int or release_sequence < 1 \
            or any(not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in (source_tree_sha256, public_cut_sha256)) \
            or not isinstance(helpers, dict) or not helpers \
            or len(set(signer_key_ids)) < 2:
        raise EvidenceError("release evidence identity or output is invalid")
    output.mkdir(parents=True)
    plugin_value = _artifact(plugin)
    sbom_value = _artifact(sbom)
    helper_values = {key: _artifact(value) for key, value in sorted(helpers.items())}
    evidence = {
        "schema_version": 2, "repository": repository, "commit": commit,
        "tag": f"v{version}", "version": version, "release_sequence": release_sequence,
        "source_tree_sha256": source_tree_sha256,
        "public_cut_sha256": public_cut_sha256, "plugin": plugin_value,
        "sbom": sbom_value, "helpers": helper_values,
        "test_matrix": test_matrix, "capability_coverage": capability_coverage,
        "firewall": firewall, "threshold_signer_key_ids": sorted(set(signer_key_ids)),
        "attestations": sorted(set(attestations)), "limitations": list(limitations),
    }
    evidence_path = output / f"loom-v{version}-release-evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assets = [Path(plugin).resolve(), Path(sbom).resolve(), evidence_path]
    checksums = output / "SHA256SUMS"
    checksums.write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()} *{path.name}\n"
        for path in sorted(assets, key=lambda item: item.name)), encoding="utf-8")
    return {"status": "created", "evidence": str(evidence_path),
            "checksums": str(checksums), "assets": len(assets)}
