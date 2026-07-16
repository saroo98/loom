"""Shared external build cache for the exact Loom vault-helper test source."""

import hashlib
import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path


def build_vault_helper(root):
    root = Path(root).resolve()
    crate = root / "vault-helper"
    source_files = [crate / "Cargo.toml", crate / "Cargo.lock", *sorted(
        (crate / "src").rglob("*.rs"))]
    if any(not path.is_file() for path in source_files):
        raise RuntimeError("vault-helper test source is incomplete")
    rustc = subprocess.run(
        ["rustc", "--version", "--verbose"], capture_output=True, text=True,
        timeout=15, check=True).stdout.encode("utf-8")
    digest = hashlib.sha256(rustc)
    for path in source_files:
        relative = path.relative_to(crate).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big") + relative)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    source_key = digest.hexdigest()
    target = Path(tempfile.gettempdir()) / "loom-cargo-test-cache" / source_key
    binary = target / "debug" / ("loom-vault.exe" if os.name == "nt" else "loom-vault")
    receipt = target / "loom-test-helper-receipt.json"
    valid = False
    if binary.is_file() and receipt.is_file():
        try:
            value = json.loads(receipt.read_text(encoding="utf-8"))
            valid = value == {
                "source_key": source_key,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
        except (OSError, UnicodeError, json.JSONDecodeError):
            valid = False
    if not valid:
        binary.unlink(missing_ok=True)
        subprocess.run(
            ["cargo", "build", "--quiet", "--locked", "--manifest-path",
             str(crate / "Cargo.toml")], cwd=root,
            env={**os.environ, "CARGO_TARGET_DIR": str(target)},
            check=True, timeout=180)
        if not binary.is_file():
            raise RuntimeError("vault-helper build produced no executable")
        target.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({
            "source_key": source_key,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return binary


def package_evidence(root, helper, directory, platforms):
    """Create standards-valid, isolated package evidence fixtures for every platform."""
    import loom_plugin_package
    import loom_reliability
    import loom_sbom

    root = Path(root).resolve()
    helper = Path(helper).resolve()
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    commit = package_source_commit(root)
    source_digest = loom_plugin_package._source_digest(root)
    lock_digest = loom_reliability.file_sha256(root / "vault-helper" / "Cargo.lock")
    binary_digest = loom_reliability.file_sha256(helper)
    evidence = {}
    receipts = {}
    for platform_id in platforms:
        rebuild = directory / f"{platform_id}-rebuild" / helper.name
        rebuild.parent.mkdir(parents=True)
        shutil.copyfile(helper, rebuild)
        sbom = directory / f"{platform_id}.spdx.json"
        loom_sbom.generate(
            root, helper, platform_id, sbom, namespace_seed=source_digest)
        provenance = directory / f"{platform_id}.provenance.json"
        provenance.write_text(json.dumps({
            "schema_version": 1,
            "repository": "https://github.com/saroo98/loom",
            "commit": commit,
            "platform": platform_id,
            "binary_sha256": binary_digest,
            "source_sha256": source_digest,
            "cargo_lock_sha256": lock_digest,
            "independent_build": True,
            "builder": {"id": "test-independent-build", "run_id": platform_id},
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        evidence[platform_id] = {
            "rebuild": rebuild, "sbom": sbom, "provenance": provenance}
        receipts[platform_id] = {
            "platform": platform_id,
            "binary_sha256": binary_digest,
            "rebuild_sha256": loom_reliability.file_sha256(rebuild),
            "source_sha256": source_digest,
            "cargo_lock_sha256": lock_digest,
            "sbom_sha256": loom_reliability.file_sha256(sbom),
            "provenance_sha256": loom_reliability.file_sha256(provenance),
        }
    return receipts, evidence


def package_source_commit(root):
    """Return the real commit or a deterministic test identity for a Git-free public cut."""
    root = Path(root).resolve()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=10, check=False)
        candidate = result.stdout.strip()
        if result.returncode == 0 and len(candidate) == 40 \
                and all(character in "0123456789abcdef" for character in candidate):
            return candidate
    except (OSError, subprocess.TimeoutExpired):
        pass
    digest = hashlib.sha256(b"loom-git-free-test-fixture-v1")
    for path in [root / "VERSION", root / "vault-helper" / "Cargo.lock"]:
        raw = path.read_bytes()
        digest.update(len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()[:40]
