#!/usr/bin/env python3
"""Build deterministic, platform-specific Loom runtime archives for marketplace signing."""

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path

import loom_reliability
import loom_release
import loom_privacy


PLATFORMS = {
    "windows-x64": "loom-vault.exe", "windows-arm64": "loom-vault.exe",
    "macos-x64": "loom-vault", "macos-arm64": "loom-vault",
    "linux-x64": "loom-vault", "linux-arm64": "loom-vault",
}
FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


class PackageError(RuntimeError):
    pass


def _copy_helper_executable(source, destination):
    shutil.copyfile(source, destination)
    if os.name != "nt":
        mode = stat.S_IMODE(source.stat().st_mode)
        os.chmod(destination, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _deterministic_zip(source, output):
    files = list(loom_reliability._regular_files(source))
    if not files:
        raise PackageError("runtime source is empty")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for path in files:
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            executable = relative.startswith("bin/")
            info.external_attr = ((stat.S_IFREG | (0o755 if executable else 0o644)) << 16)
            package.writestr(info, path.read_bytes())
    return {"sha256": loom_reliability.file_sha256(output), "bytes": output.stat().st_size,
            "files": len(files)}


def _source_digest(source):
    root = source / "vault-helper"
    selected = [root / "Cargo.toml", *sorted((root / "src").rglob("*.rs"))]
    if not selected or any(not path.is_file() or path.is_symlink() for path in selected):
        raise PackageError("vault-helper source inputs are incomplete")
    digest = hashlib.sha256()
    for path in selected:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big") + relative)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()


def _verified_artifact(path, label):
    value = loom_reliability._absolute(path, label, must_exist=True)
    if not value.is_file() or value.is_symlink() or value.stat().st_size <= 0:
        raise PackageError(f"{label} is unsafe or empty")
    return loom_reliability.file_sha256(value)


def _verify_helper_receipt(platform_id, helper, receipt, evidence, source):
    required = {"platform", "binary_sha256", "rebuild_sha256", "source_sha256",
                "cargo_lock_sha256", "sbom_sha256", "provenance_sha256"}
    if not isinstance(receipt, dict) or set(receipt) != required \
            or not isinstance(evidence, dict) \
            or set(evidence) != {"rebuild", "sbom", "provenance"} \
            or receipt["platform"] != platform_id:
        raise PackageError(f"{platform_id} helper provenance receipt is incomplete")
    for key in required - {"platform"}:
        if not isinstance(receipt[key], str) or len(receipt[key]) != 64 \
                or any(character not in "0123456789abcdef" for character in receipt[key]):
            raise PackageError(f"{platform_id} helper provenance hash is invalid")
    observed = loom_reliability.file_sha256(helper)
    rebuilt = _verified_artifact(evidence["rebuild"], f"{platform_id} independent rebuild")
    sbom = _verified_artifact(evidence["sbom"], f"{platform_id} SBOM")
    provenance = _verified_artifact(evidence["provenance"], f"{platform_id} provenance")
    lock = _verified_artifact(
        source / "vault-helper" / "Cargo.lock", "vault-helper Cargo.lock")
    if observed != receipt["binary_sha256"] or rebuilt != receipt["rebuild_sha256"] \
            or observed != rebuilt:
        raise PackageError(f"{platform_id} helper is not a matching reproducible build")
    if receipt["sbom_sha256"] != sbom or receipt["provenance_sha256"] != provenance \
            or receipt["cargo_lock_sha256"] != lock \
            or receipt["source_sha256"] != _source_digest(source):
        raise PackageError(f"{platform_id} helper evidence does not match its receipt")
    return observed


def build(source, output, helpers, helper_receipts, helper_evidence, *, version, release_sequence,
          owner_tokens=()):
    source = loom_reliability._absolute(source, "plugin source", must_exist=True)
    output = loom_reliability._absolute(output, "plugin output")
    if output.exists() or set(helpers) != set(PLATFORMS) \
            or set(helper_receipts) != set(PLATFORMS) \
            or set(helper_evidence) != set(PLATFORMS):
        raise PackageError(
            "output, six platform helpers, receipts, and evidence sets are required")
    with tempfile.TemporaryDirectory(prefix="loom-plugin-build-") as temporary:
        public = Path(temporary) / "public"
        loom_release.build_public(
            source, public, forbidden_tokens=tuple(owner_tokens),
            source_classification="public-release")
        shutil.copytree(public, output)
        targets = []
        verified_opaque = set()
        for platform_id, binary_name in PLATFORMS.items():
            helper = loom_reliability._absolute(
                helpers[platform_id], f"{platform_id} crypto helper", must_exist=True)
            if not helper.is_file() or helper.is_symlink() or helper.stat().st_size <= 0:
                raise PackageError(f"{platform_id} crypto helper is unsafe")
            verified_opaque.add(_verify_helper_receipt(
                platform_id, helper, helper_receipts[platform_id],
                helper_evidence[platform_id], source))
            runtime = Path(temporary) / platform_id
            shutil.copytree(public, runtime)
            binary = runtime / "bin" / binary_name
            binary.parent.mkdir(parents=True)
            _copy_helper_executable(helper, binary)
            runtime_files = [{"path": path.relative_to(runtime).as_posix(),
                              "bytes": path.stat().st_size,
                              "sha256": loom_reliability.file_sha256(path)}
                             for path in loom_reliability._regular_files(runtime)]
            loom_reliability.atomic_write_json(runtime / "RUNTIME-MANIFEST.json", {
                "schema_version": 1, "version": version, "platform": platform_id,
                "files": runtime_files})
            archive = output / "runtime-payload" / platform_id / "loom-runtime.zip"
            archive_info = _deterministic_zip(runtime, archive)
            verified_opaque.add(archive_info["sha256"])
            verifier = output / "crypto" / platform_id / binary_name
            verifier.parent.mkdir(parents=True)
            _copy_helper_executable(helper, verifier)
            targets.append({"platform": platform_id, "path": "loom-runtime.zip",
                            "sha256": archive_info["sha256"], "bytes": archive_info["bytes"]})
        manifest = {
            "package": "loom", "release_sequence": release_sequence, "version": version,
            "targets": targets, "schema_range": {"minimum": 1, "maximum": 1},
            "migration_chain": ["legacy-0.8", "legacy-1.0", "vault-1"],
            "adapter_range": {"minimum": 1, "maximum": 1},
        }
        release = output / "release"
        release.mkdir()
        loom_reliability.atomic_write_json(release / "unsigned-manifest.json", manifest)
        files = [{"path": path.relative_to(output).as_posix(),
                  "bytes": path.stat().st_size,
                  "sha256": loom_reliability.file_sha256(path)}
                 for path in loom_reliability._regular_files(output)]
        loom_reliability.atomic_write_json(output / "PLUGIN-BUILD-MANIFEST.json", {
            "schema_version": 1, "version": version,
            "release_sequence": release_sequence, "files": files,
            "helper_provenance": helper_receipts,
        })
        firewall = loom_privacy.scan_publication(
            output, forbidden_tokens=tuple(owner_tokens),
            verified_opaque_hashes=verified_opaque)
        if not firewall["clean"]:
            raise PackageError(f"plugin firewall failed: {firewall['findings'][:3]}")
        return {"output": str(output), "manifest": manifest,
                "firewall": firewall,
                "public_manifest": json.loads((output / "BUILD-MANIFEST.json").read_text())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-sequence", required=True, type=int)
    for platform_id in PLATFORMS:
        parser.add_argument(f"--helper-{platform_id}", required=True)
        parser.add_argument(f"--receipt-{platform_id}", required=True)
        parser.add_argument(f"--rebuild-{platform_id}", required=True)
        parser.add_argument(f"--sbom-{platform_id}", required=True)
        parser.add_argument(f"--provenance-{platform_id}", required=True)
    args = parser.parse_args(argv)
    helpers = {platform_id: getattr(args, "helper_" + platform_id.replace("-", "_"))
               for platform_id in PLATFORMS}
    receipts = {platform_id: json.loads(Path(getattr(
        args, "receipt_" + platform_id.replace("-", "_"))).read_text(encoding="utf-8"))
                for platform_id in PLATFORMS}
    evidence = {platform_id: {
        name: getattr(args, name + "_" + platform_id.replace("-", "_"))
        for name in ("rebuild", "sbom", "provenance")}
        for platform_id in PLATFORMS}
    try:
        result = build(args.source, args.output, helpers, receipts, evidence,
                       version=args.version, release_sequence=args.release_sequence)
    except (PackageError, loom_release.ReleaseError, OSError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "built", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
