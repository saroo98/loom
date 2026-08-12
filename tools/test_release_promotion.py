import hashlib
import tempfile
import unittest
from pathlib import Path

import json

import loom_lint
import loom_release_passport
import loom_release_promotion


TAG = "v1.9.0"
BASE_ASSET_NAMES = (
    "CODEX-APP-EVIDENCE.json",
    "RELEASE-SUBJECT.json",
    "loom-plugin-v1.9.0-repro.zip",
    "loom-plugin-v1.9.0.zip",
    "native-evidence-linux-arm64.zip",
    "native-evidence-linux-x64.zip",
    "native-evidence-macos-arm64.zip",
    "native-evidence-macos-x64.zip",
    "native-evidence-windows-arm64.zip",
    "native-evidence-windows-x64.zip",
)
PASSPORT_ASSET_NAMES = (
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
)
FINAL_ASSET_NAMES = tuple(sorted((*BASE_ASSET_NAMES, *PASSPORT_ASSET_NAMES)))


class ReleasePromotionTests(unittest.TestCase):
    def _gate(self, digest):
        return {
            "signed_tag_verified": True,
            "passport_verified": True,
            "matrix_certificate_verified": True,
            "native_evidence_verified": True,
            "rollback_verified": True,
            "attestation_verified": True,
            "expected_sha256": digest,
            "release_asset_sha256": digest,
        }

    def _asset_set_fixture(self, root):
        self._write_assets(root, FINAL_ASSET_NAMES)
        digests = self._asset_digests(root)
        manifest = root / "SHA256SUMS"
        manifest.write_bytes("".join(
            f"{digest} *{name}\n" for name, digest in sorted(digests.items())).encode(
                "utf-8"))
        api = {"assets": [
            {"name": name, "digest": "sha256:" + digest}
            for name, digest in sorted({
                **digests,
                manifest.name: hashlib.sha256(manifest.read_bytes()).hexdigest(),
            }.items())
        ]}
        return manifest, api

    @staticmethod
    def _write_assets(root, names):
        for name in names:
            (root / name).write_bytes(("fixture:" + name).encode("utf-8"))

    @staticmethod
    def _asset_digests(root):
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.iterdir() if path.name != "SHA256SUMS"
        }

    def _api_release(self, root):
        return {"assets": [
            {"name": name, "digest": "sha256:" + digest}
            for name, digest in sorted(self._asset_digests(root).items())
        ]}

    def _asset_set_verifier(self):
        verify = getattr(loom_release_promotion, "verify_asset_set", None)
        self.assertTrue(callable(verify), "exact asset-set verifier is required")
        return verify

    def test_draft_verifier_accepts_only_same_bytes_and_complete_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "loom.zip"
            asset.write_bytes(b"canonical")
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            result = loom_release_promotion.verify_draft(asset, self._gate(digest))
            self.assertEqual("verified-draft", result["status"])
            self.assertEqual(digest, result["asset_sha256"])
            self.assertEqual(
                result, loom_release_promotion.verify_receipt(
                    result, expected_sha256=digest,
                    expected_bytes=len(b"canonical"),
                    required_status="verified-draft"))
            prefixed = self._gate(digest)
            prefixed["release_asset_sha256"] = "sha256:" + digest
            normalized = loom_release_promotion.verify_draft(asset, prefixed)
            self.assertEqual(digest, normalized["gate"]["release_asset_sha256"])
            report = loom_lint.Report()
            loom_lint.validate_schema(
                report, __file__, result,
                "release-promotion-receipt-v1.schema.json")
            self.assertEqual([], report.errors)

            gate = self._gate(digest)
            gate["rollback_verified"] = False
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "rollback"):
                loom_release_promotion.verify_draft(asset, gate)

    def test_public_verifier_records_transformed_installation_requirement(self):
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "loom.zip"
            asset.write_bytes(b"canonical")
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            unchanged = loom_release_promotion.verify_public(
                asset, self._gate(digest), installed_subject_sha256=digest)
            changed = loom_release_promotion.verify_public(
                asset, self._gate(digest), installed_subject_sha256="f" * 64)
            represented = loom_release_promotion.verify_public(
                asset, self._gate(digest), installed_subject_sha256="f" * 64,
                represented_installed_subjects=["f" * 64])
            self.assertFalse(unchanged["behavior_rerun_required"])
            self.assertTrue(changed["behavior_rerun_required"])
            self.assertFalse(represented["behavior_rerun_required"])
            self.assertEqual(
                represented, loom_release_promotion.verify_receipt(
                    represented, expected_sha256=digest,
                    expected_bytes=len(b"canonical"),
                    required_status="verified-public"))

    def test_promotion_module_has_no_build_or_upload_surface(self):
        self.assertFalse(hasattr(loom_release_promotion, "build"))
        self.assertFalse(hasattr(loom_release_promotion, "upload"))

    def test_gate_loader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "gate.json"
            gate.write_text('{"signed_tag_verified":true,"signed_tag_verified":true}',
                            encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "unreadable"):
                loom_release_promotion._load_gate(gate)

    def test_preexisting_draft_base_assets_verify_without_a_final_manifest(self):
        verify = getattr(loom_release_promotion, "verify_base_assets", None)
        self.assertTrue(callable(verify), "base-asset verifier is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_assets(root, BASE_ASSET_NAMES)
            release = self._api_release(root)

            result = verify(root, release, tag=TAG)

        self.assertEqual("verified-base-assets", result["status"])
        self.assertEqual(list(BASE_ASSET_NAMES), result["assets"])

    def test_base_assets_reject_matching_injection_and_missing_expected_name(self):
        verify = loom_release_promotion.verify_base_assets
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_assets(root, BASE_ASSET_NAMES)
            (root / "injected.bin").write_bytes(b"injected")
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "unexpected|exact"):
                verify(root, self._api_release(root), tag=TAG)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = tuple(name for name in BASE_ASSET_NAMES
                          if name != "CODEX-APP-EVIDENCE.json")
            self._write_assets(root, names)
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "missing|exact"):
                verify(root, self._api_release(root), tag=TAG)

    def test_final_manifest_is_created_once_for_the_exact_combined_asset_set(self):
        create = getattr(loom_release_promotion, "create_asset_manifest", None)
        self.assertTrue(callable(create), "final asset-manifest creator is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            passport = root / "passport"
            base.mkdir()
            passport.mkdir()
            self._write_assets(base, BASE_ASSET_NAMES)
            self._write_assets(passport, PASSPORT_ASSET_NAMES)
            manifest = passport / "SHA256SUMS"

            result = create([base, passport], manifest, tag=TAG)
            lines = manifest.read_text(encoding="utf-8").splitlines()
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "already exists"):
                create([base, passport], manifest, tag=TAG)

        self.assertEqual("created-final-manifest", result["status"])
        self.assertEqual(list(FINAL_ASSET_NAMES), result["assets"])
        self.assertEqual(24, len(lines))
        self.assertTrue(all(__import__("re").fullmatch(
            r"[0-9a-f]{64} \*[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", line)
                            for line in lines))

    def test_real_passport_outputs_feed_the_one_final_combined_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            passport = root / "passport"
            base.mkdir()
            self._write_assets(base, BASE_ASSET_NAMES)
            loom_release_passport.write_outputs(
                passport,
                {
                    "evidence_bundle": {"schema_version": 2},
                    "evidence_graph": {"status": "passed"},
                    "readiness": {
                        "release_subject_sha256": "1" * 64,
                        "status": "ready",
                    },
                },
                defer_checksum_manifest=True)
            self._write_assets(
                passport,
                tuple(name for name in PASSPORT_ASSET_NAMES
                      if not (passport / name).exists()))
            expected_digests = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for asset_root in (base, passport)
                for path in asset_root.iterdir()
            }

            result = loom_release_promotion.create_asset_manifest(
                [base, passport], passport / "SHA256SUMS", tag=TAG)
            lines = (passport / "SHA256SUMS").read_text(
                encoding="utf-8").splitlines()
            manifest_digests = {
                name: digest for digest, name in (
                    line.split(" *", 1) for line in lines)
            }

        self.assertEqual("created-final-manifest", result["status"])
        self.assertEqual(24, len(lines))
        self.assertEqual(list(FINAL_ASSET_NAMES), result["assets"])
        self.assertEqual(expected_digests, manifest_digests)

    def test_final_manifest_refuses_missing_or_injected_manifest_input(self):
        for mutation in ("missing", "injected"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base, passport = root / "base", root / "passport"
                base.mkdir()
                passport.mkdir()
                self._write_assets(base, BASE_ASSET_NAMES)
                self._write_assets(passport, PASSPORT_ASSET_NAMES)
                if mutation == "missing":
                    (passport / "rollback.json").unlink()
                else:
                    (passport / "injected.bin").write_bytes(b"injected")
                with self.assertRaisesRegex(
                        loom_release_promotion.PromotionError,
                        "missing|unexpected|exact"):
                    loom_release_promotion.create_asset_manifest(
                        [base, passport], passport / "SHA256SUMS", tag=TAG)

    def test_exact_asset_set_accepts_local_manifest_and_api_digest_equality(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)

            result = verify(
                root, manifest, api, manifest_published=True, tag=TAG)

        self.assertEqual("verified-asset-set", result["status"])
        self.assertEqual(25, result["asset_count"])

    def test_exact_asset_set_rejects_every_unlisted_local_asset(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)
            (root / "injected.bin").write_bytes(b"injected")
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "manifest|local"):
                verify(root, manifest, api, manifest_published=True, tag=TAG)

    def test_exact_asset_set_rejects_stale_manifest_digest(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)
            (root / "RELEASE-READINESS.json").write_bytes(b"changed")
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "manifest|digest"):
                verify(root, manifest, api, manifest_published=True, tag=TAG)

    def test_exact_asset_set_rejects_every_injected_api_asset(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)
            api["assets"].append({"name": "injected.bin", "digest": "sha256:" +
                                  hashlib.sha256(b"injected").hexdigest()})
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "API|asset"):
                verify(root, manifest, api, manifest_published=True, tag=TAG)

    def test_exact_asset_set_rejects_unsafe_or_duplicated_manifest_rows(self):
        verify = self._asset_set_verifier()
        malformed = (
            f"{'a' * 64} *../escape\n",
            f"{'a' * 64} *asset.bin\n{'b' * 64} *asset.bin\n",
        )
        for content in malformed:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                asset = root / "asset.bin"
                asset.write_bytes(b"asset")
                manifest = root / "SHA256SUMS"
                manifest.write_text(content, encoding="utf-8")
                api = {"assets": [
                    {"name": asset.name, "digest": "sha256:" +
                     hashlib.sha256(asset.read_bytes()).hexdigest()},
                    {"name": manifest.name, "digest": "sha256:" +
                     hashlib.sha256(manifest.read_bytes()).hexdigest()},
                ]}
                with self.assertRaisesRegex(
                        loom_release_promotion.PromotionError, "manifest"):
                    verify(root, manifest, api, manifest_published=True, tag=TAG)


if __name__ == "__main__":
    unittest.main()
