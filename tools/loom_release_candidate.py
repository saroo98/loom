#!/usr/bin/env python3
"""Compare independent release candidates and stage immutable same-byte assets."""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import zipfile
from pathlib import Path

import loom_release_verify
import loom_plugin_package
import loom_reliability
import loom_exact_cut_ci


NATIVE_PLATFORMS = {
    "windows-x64": "loom-vault.exe", "windows-arm64": "loom-vault.exe",
    "macos-x64": "loom-vault", "macos-arm64": "loom-vault",
    "linux-x64": "loom-vault", "linux-arm64": "loom-vault",
}
MAX_JSON_BYTES = 4 * 1024 * 1024


class CandidateError(RuntimeError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_bytes(raw, label):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_JSON_BYTES:
        raise CandidateError(f"{label} is oversized or empty")
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (UnicodeError, ValueError) as exc:
        raise CandidateError(f"{label} is invalid") from exc


def _json_file(path, label):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise CandidateError(f"{label} is unsafe")
    try:
        return _json_bytes(path.read_bytes(), label)
    except OSError as exc:
        raise CandidateError(f"{label} is unreadable") from exc


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _seal(body):
    return {**body, "receipt_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


def _archive_subject(path):
    path = Path(path).resolve()
    try:
        verified = loom_release_verify.verify(path)
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            rows = []
            contents = {}
            for entry in entries:
                raw = archive.read(entry)
                contents[entry.filename] = raw
                rows.append({
                    "path": entry.filename,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "mode": (entry.external_attr >> 16) & 0o7777,
                    "compression": entry.compress_type,
                    "compressed_bytes": entry.compress_size,
                    "crc32": f"{entry.CRC:08x}",
                    "timestamp": list(entry.date_time),
                })
    except (OSError, zipfile.BadZipFile, loom_release_verify.VerifyError) as exc:
        raise CandidateError(f"candidate archive is invalid: {exc}") from exc
    try:
        manifest_raw = contents["BUILD-MANIFEST.json"]
        manifest = _json_bytes(manifest_raw, "embedded public-cut manifest")
    except (KeyError, CandidateError) as exc:
        raise CandidateError(f"embedded public-cut manifest is invalid: {exc}") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version", "files", "root_sha256"} \
            or manifest.get("schema_version") != 1 or not isinstance(manifest["files"], list):
        raise CandidateError("embedded public-cut manifest contract is invalid")
    manifest_body = {"schema_version": 1, "files": manifest["files"]}
    if hashlib.sha256(_canonical(manifest_body)).hexdigest() != manifest["root_sha256"]:
        raise CandidateError("embedded public-cut root is invalid")
    observed = {row["path"]: row for row in rows}
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise CandidateError("embedded public-cut inventory is invalid")
        row = observed.get(item["path"])
        if row is None or any(row[key] != item[key] for key in ("bytes", "sha256")):
            raise CandidateError("embedded public-cut bytes do not match its manifest")
    tree_body = [{key: row[key] for key in (
        "path", "bytes", "sha256", "mode", "compression", "compressed_bytes",
        "crc32", "timestamp")} for row in rows]
    installed_rows = [{key: row[key] for key in ("path", "bytes", "sha256")}
                      for row in rows]
    native_binaries = {}
    for platform_id, binary_name in NATIVE_PLATFORMS.items():
        direct_path = f"crypto/{platform_id}/{binary_name}"
        runtime_path = f"runtime-payload/{platform_id}/loom-runtime.zip"
        if direct_path not in contents or runtime_path not in contents:
            raise CandidateError("candidate native-helper inventory is incomplete")
        binary_sha256 = hashlib.sha256(contents[direct_path]).hexdigest()
        try:
            with zipfile.ZipFile(io.BytesIO(contents[runtime_path])) as runtime:
                expected = f"bin/{binary_name}"
                if runtime.namelist().count(expected) != 1:
                    raise CandidateError(
                        "candidate runtime native-helper inventory is incomplete")
                runtime_binary_sha256 = hashlib.sha256(runtime.read(expected)).hexdigest()
        except zipfile.BadZipFile as exc:
            raise CandidateError("candidate runtime archive is invalid") from exc
        if runtime_binary_sha256 != binary_sha256:
            raise CandidateError("candidate native-helper copies differ")
        native_binaries[platform_id] = binary_sha256
    return {
        "sha256": verified["sha256"], "bytes": verified["bytes"],
        "files": verified["files"],
        "extracted_tree_sha256": hashlib.sha256(_canonical(tree_body)).hexdigest(),
        "installed_tree_sha256": hashlib.sha256(_canonical(installed_rows)).hexdigest(),
        "archive_metadata_sha256": hashlib.sha256(_canonical(rows)).hexdigest(),
        "public_cut": {
            "root_sha256": manifest["root_sha256"],
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "file_count": len(manifest["files"]) + 1,
        },
        "native_binaries": native_binaries,
    }


def compare(candidate_a, candidate_b, *, expected_public_root_sha256,
            native_subjects=None):
    if not isinstance(expected_public_root_sha256, str) \
            or len(expected_public_root_sha256) != 64:
        raise CandidateError("expected public-cut root is invalid")
    first = _archive_subject(candidate_a)
    second = _archive_subject(candidate_b)
    if first["sha256"] != second["sha256"] or first["bytes"] != second["bytes"]:
        raise CandidateError("independent candidate bytes differ")
    for key in ("extracted_tree_sha256", "installed_tree_sha256",
                "archive_metadata_sha256", "public_cut", "native_binaries"):
        if first[key] != second[key]:
            raise CandidateError("independent candidate inventories differ")
    if first["public_cut"]["root_sha256"] != expected_public_root_sha256:
        raise CandidateError("candidate embeds the wrong certified public cut")
    if not isinstance(native_subjects, list) or len(native_subjects) != 6:
        raise CandidateError("exactly six native-helper subjects are required")
    natives = sorted(native_subjects, key=lambda item: item.get("platform", ""))
    if {item.get("platform") for item in natives} != set(NATIVE_PLATFORMS) \
            or any(set(item) != {"platform", "binary_sha256", "sbom_sha256",
                                 "provenance_sha256"} for item in natives):
        raise CandidateError("native-helper subjects are incomplete")
    if any(re.fullmatch(r"[0-9a-f]{64}", str(item.get(field, ""))) is None
           for item in natives
           for field in ("binary_sha256", "sbom_sha256", "provenance_sha256")):
        raise CandidateError("native-helper subject digest is invalid")
    if any(first["native_binaries"][item["platform"]] != item["binary_sha256"]
           for item in natives):
        raise CandidateError("candidate embeds the wrong native-helper subject")
    body = {
        "schema_version": 1, "status": "reproduced",
        "candidate_a": first, "candidate_b": second,
        "canonical_candidate": "A", "public_cut": first["public_cut"],
        "native_subjects": natives,
    }
    return _seal(body)


def reconstruct(source, authority_archive, native_root, output, *, source_commit):
    """Rebuild all unsigned bytes from source and reuse only offline authority bytes."""
    source = Path(source).resolve()
    authority_archive = Path(authority_archive).resolve()
    native_root = Path(native_root).resolve()
    output = Path(output).resolve()
    if not source.is_dir() or not native_root.is_dir() or output.exists():
        raise CandidateError("candidate reconstruction inputs are unsafe")
    authority_names = {
        "release/metadata.json", "release/trusted-root.json",
        "FINAL-PACKAGE-RECEIPT.json",
    }
    try:
        loom_release_verify.verify(authority_archive)
        with zipfile.ZipFile(authority_archive) as archive:
            names = [entry.filename for entry in archive.infolist()]
            if any(names.count(name) != 1 for name in authority_names):
                raise CandidateError("candidate authority material is incomplete")
            authority = {name: archive.read(name) for name in authority_names}
        receipt = _json_bytes(
            authority["FINAL-PACKAGE-RECEIPT.json"], "candidate authority receipt")
        metadata = _json_bytes(
            authority["release/metadata.json"], "candidate signing metadata")
        trusted_root = _json_bytes(
            authority["release/trusted-root.json"], "candidate trusted root")
    except (OSError, CandidateError, zipfile.BadZipFile,
            loom_release_verify.VerifyError) as exc:
        raise CandidateError("candidate authority material is invalid") from exc
    if not isinstance(receipt, dict) or set(receipt) != {
            "schema_version", "version", "release_sequence", "files"} \
            or receipt.get("schema_version") != 1 \
            or not isinstance(receipt.get("version"), str) \
            or type(receipt.get("release_sequence")) is not int:
        raise CandidateError("candidate authority receipt is invalid")
    try:
        signed_manifest = metadata["targets"]["signed"]["manifest"]
        signed_root = metadata["root"]["signed"]
    except (KeyError, TypeError) as exc:
        raise CandidateError("candidate signing metadata is incomplete") from exc
    if trusted_root != signed_root:
        raise CandidateError("candidate trusted-root relation is invalid")
    helpers = {}
    helper_receipts = {}
    helper_evidence = {}
    for platform_id, binary_name in NATIVE_PLATFORMS.items():
        matches = []
        for receipt_path in native_root.rglob("receipt.json"):
            try:
                value = _json_file(receipt_path, "native-helper receipt")
            except CandidateError:
                continue
            if isinstance(value, dict) and value.get("platform") == platform_id:
                matches.append((receipt_path, value))
        if len(matches) != 1:
            raise CandidateError("candidate native-helper evidence is ambiguous")
        receipt_path, value = matches[0]
        directory = receipt_path.parent
        environment = _json_file(
            directory / "environment.json", "native-helper environment")
        environment_body = ({key: item for key, item in environment.items()
                             if key != "environment_sha256"}
                            if isinstance(environment, dict) else {})
        if not isinstance(environment, dict) \
                or set(environment) != loom_exact_cut_ci.ENVIRONMENT_FIELDS \
                or environment.get("environment_sha256") != hashlib.sha256(
                    _canonical(environment_body)).hexdigest() \
                or value.get("schema_version") != 2 \
                or value.get("source_commit") != source_commit \
                or value.get("environment_sha256") != environment.get(
                    "environment_sha256") \
                or value.get("workflow_digest") != environment.get(
                    "workflow_digest") \
                or value.get("action_manifest_digest") != environment.get(
                    "action_manifest_digest") \
                or value.get("receipt_sha256") != hashlib.sha256(_canonical({
                    key: item for key, item in value.items()
                    if key != "receipt_sha256"})).hexdigest():
            raise CandidateError("native-helper exact environment is invalid")
        helpers[platform_id] = directory / binary_name
        helper_receipts[platform_id] = value
        helper_evidence[platform_id] = {
            "rebuild": directory / (binary_name + ".rebuild"),
            "sbom": directory / "loom-vault.spdx.json",
            "provenance": directory / "provenance.json",
        }
    package = output.with_name(output.name + ".package")
    if package.exists():
        raise CandidateError("candidate reconstruction output already exists")
    try:
        built = loom_plugin_package.build(
            source, package, helpers, helper_receipts, helper_evidence,
            version=receipt["version"],
            release_sequence=receipt["release_sequence"],
            source_commit=source_commit)
        unsigned = package / "release" / "unsigned-manifest.json"
        if built["manifest"] != signed_manifest:
            raise CandidateError("candidate signed manifest differs from source build")
        unsigned.unlink()
        loom_reliability.atomic_write_bytes(
            package / "release" / "metadata.json", authority["release/metadata.json"])
        loom_reliability.atomic_write_bytes(
            package / "release" / "trusted-root.json",
            authority["release/trusted-root.json"])
        observed_files = [{
            "path": path.relative_to(package).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        } for path in sorted(
            loom_reliability._regular_files(package),
            key=lambda item: item.relative_to(package).as_posix())]
        if receipt["files"] != observed_files:
            raise CandidateError("candidate source build differs from signed receipt")
        loom_reliability.atomic_write_bytes(
            package / "FINAL-PACKAGE-RECEIPT.json",
            authority["FINAL-PACKAGE-RECEIPT.json"])
        loom_plugin_package.archive_finalized(package, output)
        if output.read_bytes() != authority_archive.read_bytes():
            raise CandidateError("candidate source reconstruction differs from authority bytes")
        return _archive_subject(output)
    except CandidateError:
        raise
    except (OSError, loom_plugin_package.PackageError,
            loom_reliability.ReliabilityError) as exc:
        raise CandidateError("candidate source reconstruction failed") from exc


def stage_immutable(source, destination):
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    if not source.is_file() or source.is_symlink():
        raise CandidateError("candidate source is unsafe")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not destination.is_file() or destination.is_symlink() \
                or hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise CandidateError("draft asset already exists with different bytes")
        disposition = "already-identical"
    else:
        try:
            with source.open("rb") as incoming, destination.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
        except FileExistsError:
            return stage_immutable(source, destination)
        if not destination.is_file() or destination.is_symlink() \
                or hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            try:
                if destination.is_file() and not destination.is_symlink():
                    destination.unlink()
            except OSError:
                pass
            raise CandidateError("draft asset staging changed candidate bytes")
        disposition = "created"
    return {"status": "staged", "disposition": disposition,
            "sha256": digest, "bytes": destination.stat().st_size}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("candidate_a")
    compare_parser.add_argument("candidate_b")
    compare_parser.add_argument("--public-root", required=True)
    compare_parser.add_argument("--native-subjects", required=True)
    compare_parser.add_argument("--output", required=True)
    stage_parser = commands.add_parser("stage-immutable")
    stage_parser.add_argument("source")
    stage_parser.add_argument("destination")
    reconstruct_parser = commands.add_parser("reconstruct")
    reconstruct_parser.add_argument("source")
    reconstruct_parser.add_argument("authority_archive")
    reconstruct_parser.add_argument("native_root")
    reconstruct_parser.add_argument("output")
    reconstruct_parser.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            natives = _json_file(args.native_subjects, "native-helper subjects")
            result = compare(args.candidate_a, args.candidate_b,
                             expected_public_root_sha256=args.public_root,
                             native_subjects=natives)
            Path(args.output).write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "stage-immutable":
            result = stage_immutable(args.source, args.destination)
        else:
            result = reconstruct(
                args.source, args.authority_archive, args.native_root, args.output,
                source_commit=args.source_commit)
    except (CandidateError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
