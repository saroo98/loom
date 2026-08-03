import hashlib
import tempfile
import unittest
from pathlib import Path

import json

import loom_lint
import loom_release_promotion


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
        plugin = root / "loom-plugin-v1.9.0.zip"
        readiness = root / "RELEASE-READINESS.json"
        plugin.write_bytes(b"plugin")
        readiness.write_bytes(b"ready")
        digests = {
            plugin.name: hashlib.sha256(plugin.read_bytes()).hexdigest(),
            readiness.name: hashlib.sha256(readiness.read_bytes()).hexdigest(),
        }
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
            plugin = root / "loom-plugin-v1.9.0.zip"
            subject = root / "RELEASE-SUBJECT.json"
            plugin.write_bytes(b"plugin")
            subject.write_bytes(b"subject")
            release = {
                "assets": [
                    {"name": plugin.name,
                     "digest": "sha256:" + hashlib.sha256(
                         plugin.read_bytes()).hexdigest()},
                    {"name": subject.name,
                     "digest": "sha256:" + hashlib.sha256(
                         subject.read_bytes()).hexdigest()},
                ],
            }

            result = verify(root, release)

        self.assertEqual("verified-base-assets", result["status"])
        self.assertEqual([subject.name, plugin.name], result["assets"])

    def test_final_manifest_is_created_once_for_the_exact_combined_asset_set(self):
        create = getattr(loom_release_promotion, "create_asset_manifest", None)
        self.assertTrue(callable(create), "final asset-manifest creator is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            passport = root / "passport"
            base.mkdir()
            passport.mkdir()
            (base / "loom-plugin-v1.9.0.zip").write_bytes(b"plugin")
            (passport / "RELEASE-READINESS.json").write_bytes(b"ready")
            manifest = passport / "SHA256SUMS"

            result = create([base, passport], manifest)
            lines = manifest.read_text(encoding="utf-8").splitlines()
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "already exists"):
                create([base, passport], manifest)

        self.assertEqual("created-final-manifest", result["status"])
        self.assertEqual(
            ["RELEASE-READINESS.json", "loom-plugin-v1.9.0.zip"],
            result["assets"])
        self.assertEqual(2, len(lines))
        self.assertTrue(all(__import__("re").fullmatch(
            r"[0-9a-f]{64} \*[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", line)
                            for line in lines))

    def test_exact_asset_set_accepts_local_manifest_and_api_digest_equality(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)

            result = verify(root, manifest, api, manifest_published=True)

        self.assertEqual("verified-asset-set", result["status"])
        self.assertEqual(3, result["asset_count"])

    def test_exact_asset_set_rejects_every_unlisted_local_asset(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)
            (root / "injected.bin").write_bytes(b"injected")
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "manifest|local"):
                verify(root, manifest, api, manifest_published=True)

    def test_exact_asset_set_rejects_stale_manifest_digest(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)
            (root / "RELEASE-READINESS.json").write_bytes(b"changed")
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "manifest|digest"):
                verify(root, manifest, api, manifest_published=True)

    def test_exact_asset_set_rejects_every_injected_api_asset(self):
        verify = self._asset_set_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, api = self._asset_set_fixture(root)
            api["assets"].append({"name": "injected.bin", "digest": "sha256:" +
                                  hashlib.sha256(b"injected").hexdigest()})
            with self.assertRaisesRegex(
                    loom_release_promotion.PromotionError, "API|asset"):
                verify(root, manifest, api, manifest_published=True)

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
                    verify(root, manifest, api, manifest_published=True)


if __name__ == "__main__":
    unittest.main()
