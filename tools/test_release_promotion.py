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


if __name__ == "__main__":
    unittest.main()
