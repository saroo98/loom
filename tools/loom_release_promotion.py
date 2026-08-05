#!/usr/bin/env python3
"""Verify draft or public release bytes without building, uploading, or rewriting."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_reliability


class PromotionError(RuntimeError):
    pass


_GATE_FIELDS = {
    "signed_tag_verified", "passport_verified", "matrix_certificate_verified",
    "native_evidence_verified", "rollback_verified", "attestation_verified",
    "expected_sha256", "release_asset_sha256",
}
MAX_GATE_BYTES = 64 * 1024
MAX_API_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_RELEASE_ASSETS = 256
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
FINAL_MANIFEST = "SHA256SUMS"
RELEASE_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
NATIVE_PLATFORMS = (
    "windows-x64", "windows-arm64", "macos-x64", "macos-arm64",
    "linux-x64", "linux-arm64",
)
PASSPORT_ASSETS = frozenset({
    "RELEASE-EVIDENCE-ATTESTATION.json",
    "RELEASE-EVIDENCE-GRAPH.json",
    "RELEASE-EVIDENCE-SUBJECT.json",
    "RELEASE-EVIDENCE.json",
    "RELEASE-READINESS.json",
    "clean-room.json",
    "compatibility-matrix-certificate.json",
    "cut-receipt.json",
    "exact-cut-ci.json",
    "full-suite.json",
    "installed-runtime-evidence.json",
    "quality-matrix-certificate.json",
    "reproducibility-receipt.json",
    "rollback.json",
})


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_gate(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or not 0 < path.stat().st_size <= MAX_GATE_BYTES:
        raise PromotionError("promotion gate is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PromotionError("promotion gate is unreadable") from exc


def _load_json(path, label, *, maximum=MAX_API_BYTES):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or not 0 < path.stat().st_size <= maximum:
        raise PromotionError(f"{label} is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PromotionError(f"{label} is unreadable") from exc


def _digest(value):
    if isinstance(value, str) and value.startswith("sha256:"):
        value = value[7:]
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PromotionError("release digest is invalid")
    return value


def _asset_name(value):
    if not isinstance(value, str) or ASSET_NAME.fullmatch(value) is None:
        raise PromotionError("release asset name is invalid")
    return value


def _release_tag(value):
    if not isinstance(value, str) or RELEASE_TAG.fullmatch(value) is None:
        raise PromotionError("release tag is invalid")
    return value


def expected_base_assets(tag):
    """Return the one tag-bound draft inventory admitted to promotion."""
    tag = _release_tag(tag)
    return frozenset({
        "CODEX-APP-EVIDENCE.json",
        "RELEASE-SUBJECT.json",
        f"loom-plugin-{tag}-repro.zip",
        f"loom-plugin-{tag}.zip",
        *(f"native-evidence-{platform}.zip" for platform in NATIVE_PLATFORMS),
    })


def expected_manifest_assets(tag):
    """Return the exact non-manifest inventory for the immutable release."""
    return expected_base_assets(tag) | PASSPORT_ASSETS


def _require_exact_names(observed, expected, label):
    if set(observed) != set(expected):
        raise PromotionError(f"{label} is not the exact expected asset set")


def _local_asset_digests(root):
    try:
        root = loom_reliability._absolute(
            root, "release asset directory", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise PromotionError(str(exc)) from exc
    if not root.is_dir():
        raise PromotionError("release asset directory is unsafe")
    result = {}
    try:
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise PromotionError("release asset directory is unreadable") from exc
    if not entries or len(entries) > MAX_RELEASE_ASSETS:
        raise PromotionError("release asset inventory is invalid")
    for path in entries:
        name = _asset_name(path.name)
        try:
            safe = loom_reliability._absolute(
                path, "release asset", must_exist=True)
        except loom_reliability.ReliabilityError as exc:
            raise PromotionError(str(exc)) from exc
        if not safe.is_file() or name in result:
            raise PromotionError("release asset inventory is invalid")
        raw = safe.read_bytes()
        if len(raw) != safe.stat().st_size:
            raise PromotionError("release asset changed while hashing")
        result[name] = hashlib.sha256(raw).hexdigest()
    return result


def _api_asset_digests(release):
    assets = release.get("assets") if isinstance(release, dict) else None
    if not isinstance(assets, list) or not assets \
            or len(assets) > MAX_RELEASE_ASSETS:
        raise PromotionError("release API asset inventory is invalid")
    result = {}
    for row in assets:
        if not isinstance(row, dict):
            raise PromotionError("release API asset inventory is invalid")
        name = _asset_name(row.get("name"))
        if name in result:
            raise PromotionError("release API asset inventory is duplicated")
        result[name] = _digest(row.get("digest"))
    return result


def verify_base_assets(asset_root, api_release, *, tag):
    """Verify the exact pre-passport draft bytes without a final manifest."""
    local = _local_asset_digests(asset_root)
    remote = _api_asset_digests(api_release)
    expected = expected_base_assets(tag)
    if FINAL_MANIFEST in local or FINAL_MANIFEST in remote:
        raise PromotionError("preexisting draft already contains the final manifest")
    _require_exact_names(local, expected, "downloaded base asset inventory")
    _require_exact_names(remote, expected, "release API base asset inventory")
    if local != remote:
        raise PromotionError("downloaded base assets and release API bytes disagree")
    return {"status": "verified-base-assets", "assets": sorted(local)}


def create_asset_manifest(asset_roots, manifest, *, tag):
    """Create the one final checksum manifest from disjoint flat asset roots."""
    if not isinstance(asset_roots, (list, tuple)) or not asset_roots:
        raise PromotionError("final asset roots are invalid")
    manifest = Path(manifest)
    if manifest.name != FINAL_MANIFEST:
        raise PromotionError("final asset manifest name is invalid")
    try:
        manifest = loom_reliability._absolute(
            manifest, "final asset manifest", must_exist=False)
    except loom_reliability.ReliabilityError as exc:
        raise PromotionError(str(exc)) from exc
    if manifest.exists():
        raise PromotionError("final asset manifest already exists")
    combined = {}
    for root in asset_roots:
        for name, digest in _local_asset_digests(root).items():
            if name == FINAL_MANIFEST or name in combined:
                raise PromotionError("final release asset names are duplicated")
            combined[name] = digest
    _require_exact_names(
        combined, expected_manifest_assets(tag), "final manifest input inventory")
    lines = "".join(
        f"{digest} *{name}\n" for name, digest in sorted(combined.items()))
    try:
        loom_reliability.atomic_write_text(manifest, lines)
    except loom_reliability.ReliabilityError as exc:
        raise PromotionError(str(exc)) from exc
    return {"status": "created-final-manifest", "assets": sorted(combined)}


def _manifest_digests(manifest):
    try:
        manifest = loom_reliability._absolute(
            manifest, "final asset manifest", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise PromotionError(str(exc)) from exc
    if manifest.name != FINAL_MANIFEST or not manifest.is_file() \
            or not 0 < manifest.stat().st_size <= MAX_MANIFEST_BYTES:
        raise PromotionError("final asset manifest is unsafe")
    try:
        raw = manifest.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise PromotionError("final asset manifest is unreadable") from exc
    if len(raw) != manifest.stat().st_size or not text.endswith("\n") \
            or "\r" in text:
        raise PromotionError("final asset manifest format is invalid")
    lines = text.splitlines()
    if not lines or len(lines) >= MAX_RELEASE_ASSETS:
        raise PromotionError("final asset manifest inventory is invalid")
    result = {}
    for line in lines:
        matched = re.fullmatch(
            r"([0-9a-f]{64}) \*([A-Za-z0-9][A-Za-z0-9._+-]{0,254})", line)
        if matched is None:
            raise PromotionError("final asset manifest row is invalid")
        digest, name = matched.groups()
        if name == FINAL_MANIFEST or name in result:
            raise PromotionError("final asset manifest names are duplicated")
        result[name] = digest
    if list(result) != sorted(result):
        raise PromotionError("final asset manifest order is invalid")
    return result, hashlib.sha256(raw).hexdigest()


def verify_asset_set(asset_root, manifest, api_release, *, manifest_published, tag):
    """Require exact local, manifest, and GitHub API name/digest equality."""
    if type(manifest_published) is not bool:
        raise PromotionError("final manifest publication state is invalid")
    declared, manifest_digest = _manifest_digests(manifest)
    expected_assets = expected_manifest_assets(tag)
    _require_exact_names(declared, expected_assets, "final manifest inventory")
    local = _local_asset_digests(asset_root)
    expected = dict(declared)
    if manifest_published:
        expected[FINAL_MANIFEST] = manifest_digest
    if local != expected:
        raise PromotionError("local assets and final manifest digests disagree")
    remote = _api_asset_digests(api_release)
    if remote != expected:
        raise PromotionError("release API assets and local asset set disagree")
    canonical = json.dumps(
        sorted(expected.items()), separators=(",", ":")).encode("utf-8")
    return {
        "status": "verified-asset-set", "asset_count": len(expected),
        "asset_set_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _verify(asset, gate, status):
    if not isinstance(gate, dict) or set(gate) != _GATE_FIELDS:
        raise PromotionError("promotion gate is incomplete or contains unknown fields")
    for name in sorted(_GATE_FIELDS - {"expected_sha256", "release_asset_sha256"}):
        if gate[name] is not True:
            raise PromotionError(name.replace("_verified", "").replace("_", " ") +
                                 " verification failed")
    expected = _digest(gate["expected_sha256"])
    api_digest = _digest(gate["release_asset_sha256"])
    path = Path(asset).resolve()
    if not path.is_file() or path.is_symlink():
        raise PromotionError("downloaded release asset is unsafe")
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected or api_digest != expected:
        raise PromotionError("downloaded, expected, and release API bytes disagree")
    normalized_gate = dict(gate)
    normalized_gate["expected_sha256"] = expected
    normalized_gate["release_asset_sha256"] = api_digest
    body = {"schema_version": 1, "status": status, "asset_sha256": observed,
            "asset_bytes": path.stat().st_size, "gate": normalized_gate}
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def verify_draft(asset, gate):
    return _verify(asset, gate, "verified-draft")


def verify_public(asset, gate, *, installed_subject_sha256=None,
                  represented_installed_subjects=()):
    result = _verify(asset, gate, "verified-public")
    installed = (_digest(installed_subject_sha256)
                 if installed_subject_sha256 is not None else result["asset_sha256"])
    represented = sorted({_digest(value) for value in represented_installed_subjects})
    body = {key: value for key, value in result.items() if key != "receipt_sha256"}
    body.update({"installed_subject_sha256": installed,
                 "represented_installed_subjects": represented,
                 "behavior_rerun_required": installed != result["asset_sha256"]
                 and installed not in represented})
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify_draft_parser = commands.add_parser("verify-draft")
    verify_public_parser = commands.add_parser("verify-public")
    for verify in (verify_draft_parser, verify_public_parser):
        verify.add_argument("asset")
        verify.add_argument("--gate", required=True)
        verify.add_argument("--installed-subject")
        verify.add_argument(
            "--represented-installed-subject", action="append", default=[])
        verify.add_argument("--output", required=True)
    base = commands.add_parser("verify-base-assets")
    base.add_argument("asset_root")
    base.add_argument("--api-release", required=True)
    base.add_argument("--tag", required=True)
    manifest = commands.add_parser("create-asset-manifest")
    manifest.add_argument("--asset-root", action="append", required=True)
    manifest.add_argument("--manifest", required=True)
    manifest.add_argument("--tag", required=True)
    asset_set = commands.add_parser("verify-asset-set")
    asset_set.add_argument("asset_root")
    asset_set.add_argument("--manifest", required=True)
    asset_set.add_argument("--api-release", required=True)
    asset_set.add_argument("--manifest-published", action="store_true")
    asset_set.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-base-assets":
            result = verify_base_assets(
                args.asset_root, _load_json(args.api_release, "release API response"),
                tag=args.tag)
        elif args.command == "create-asset-manifest":
            result = create_asset_manifest(
                args.asset_root, args.manifest, tag=args.tag)
        elif args.command == "verify-asset-set":
            result = verify_asset_set(
                args.asset_root, args.manifest,
                _load_json(args.api_release, "release API response"),
                manifest_published=args.manifest_published, tag=args.tag)
        else:
            gate = _load_gate(args.gate)
            result = (verify_draft(args.asset, gate)
                      if args.command == "verify-draft" else verify_public(
                          args.asset, gate,
                          installed_subject_sha256=args.installed_subject,
                          represented_installed_subjects=(
                              args.represented_installed_subject)))
            output = Path(args.output).resolve()
            if output.exists():
                raise PromotionError("promotion receipt output already exists")
            loom_reliability.atomic_write_json(output, result)
    except (PromotionError, loom_reliability.ReliabilityError, OSError,
            UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    summary = {"status": result["status"]}
    if "receipt_sha256" in result:
        summary["receipt_sha256"] = result["receipt_sha256"]
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
