"""Real offline threshold-signing tests for Loom release metadata."""

import datetime as dt
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import loom_crypto
import loom_release_sign
import loom_update
from v11_test_support import build_vault_helper


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "vault-helper"


class ReleaseSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def test_two_distinct_encrypted_authorities_sign_verifiable_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "offline"
            ceremony = loom_release_sign.create_root_authority(
                self.helper, directory,
                ["first authority passphrase", "second authority phrase!",
                 "third independent phrase!"],
                expires=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
            paths = ceremony["private_key_paths"]
            manifest = {
                "package": "loom", "release_sequence": 11, "version": "1.1.0",
                "targets": [], "schema_range": {"minimum": 1, "maximum": 1},
                "migration_chain": ["vault-1"],
                "adapter_range": {"minimum": 1, "maximum": 1},
            }
            bundle = loom_release_sign.sign_release(
                self.helper, ceremony["root"], manifest,
                [(paths[0], "first authority passphrase"),
                 (paths[1], "second authority phrase!")],
                expires=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
            verified = loom_update.verify_metadata(
                bundle, trusted_root=ceremony["root"],
                verify_signature=lambda message, signature, public: loom_crypto.verify_signature(
                    self.helper, message, signature, public),
                now="2026-07-15T12:00:00Z")
            self.assertEqual(manifest, verified)
            for path in paths:
                self.assertNotIn("signing_key", Path(path).read_text(encoding="utf-8"))

            broken = dict(bundle)
            broken["timestamp"] = dict(bundle["timestamp"])
            broken["timestamp"]["signatures"] = bundle["timestamp"]["signatures"][:1]
            with self.assertRaisesRegex(loom_update.UpdateError, "threshold"):
                loom_update.verify_metadata(
                    broken, trusted_root=ceremony["root"],
                    verify_signature=lambda message, signature, public: loom_crypto.verify_signature(
                        self.helper, message, signature, public),
                    now="2026-07-15T12:00:00Z")

    def test_root_rotation_requires_old_and_new_thresholds_and_no_skips(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            old_phrases = ["old authority one!", "old authority two!", "old authority three!"]
            new_phrases = ["new authority one!", "new authority two!", "new authority three!"]
            expires = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
            old = loom_release_sign.create_root_authority(
                self.helper, base / "old", old_phrases, expires=expires)
            new = loom_release_sign.create_root_authority(
                self.helper, base / "new", new_phrases, expires=expires)
            new["root"]["version"] = 2
            manifest = {
                "package": "loom", "release_sequence": 12, "version": "1.2.0",
                "targets": [], "schema_range": {"minimum": 1, "maximum": 2},
                "migration_chain": ["vault-1", "vault-2"],
                "adapter_range": {"minimum": 1, "maximum": 1},
            }
            new_paths = new["private_key_paths"]
            bundle = loom_release_sign.sign_release(
                self.helper, new["root"], manifest,
                list(zip(new_paths[:2], new_phrases[:2])),
                expires=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
            old_paths = old["private_key_paths"]
            transition = loom_release_sign.sign_root_transition(
                self.helper, old["root"], new["root"],
                list(zip(old_paths[:2], old_phrases[:2])),
                list(zip(new_paths[:2], new_phrases[:2])))
            bundle["root"] = transition
            verify = lambda message, signature, public: loom_crypto.verify_signature(
                self.helper, message, signature, public)
            self.assertEqual(manifest, loom_update.verify_metadata(
                bundle, trusted_root=old["root"], verify_signature=verify,
                now="2026-07-15T12:00:00Z"))

            for signatures, error in (
                    (transition["signatures"][:2], "new-root transition"),
                    (transition["signatures"][2:], "old-root transition")):
                rejected = dict(bundle)
                rejected["root"] = {"signed": new["root"], "signatures": signatures}
                with self.assertRaisesRegex(loom_update.UpdateError, error):
                    loom_update.verify_metadata(
                        rejected, trusted_root=old["root"], verify_signature=verify,
                        now="2026-07-15T12:00:00Z")

            skipped = dict(bundle)
            skipped_root = dict(new["root"])
            skipped_root["version"] = 3
            skipped["root"] = {"signed": skipped_root, "signatures": []}
            with self.assertRaisesRegex(loom_update.UpdateError, "skipped"):
                loom_update.verify_metadata(
                    skipped, trusted_root=old["root"], verify_signature=verify,
                    now="2026-07-15T12:00:00Z")


if __name__ == "__main__":
    unittest.main()
