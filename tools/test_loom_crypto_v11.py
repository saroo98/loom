"""Real Rust loom-vault helper interoperability tests."""

import base64
import json
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_crypto
import loom_vault
from v11_test_support import build_vault_helper


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "vault-helper"


class RustCryptoHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def test_authenticated_encryption_signing_and_blind_indexes_are_real(self):
        keys = loom_crypto.generate_keys(self.helper)
        crypto = loom_crypto.HelperCrypto(
            self.helper,
            master_key=base64.b64decode(keys["master_key"]),
            signing_key=base64.b64decode(keys["signing_key"]))
        aad = b"loom-vault-test-aad"
        plaintext = b"owner-private-statement"
        ciphertext = crypto.seal(plaintext, aad)
        self.assertNotIn(plaintext, base64.b64decode(ciphertext))
        self.assertEqual(plaintext, crypto.open(ciphertext, aad))
        signature = crypto.sign(plaintext)
        self.assertTrue(crypto.verify(plaintext, signature, crypto.public_key()))
        self.assertFalse(crypto.verify(plaintext + b"x", signature, crypto.public_key()))
        self.assertEqual(crypto.blind_index("domain", "accounting"),
                         crypto.blind_index("domain", "accounting"))
        self.assertNotEqual(crypto.blind_index("domain", "accounting"),
                            crypto.blind_index("domain", "three-d"))

    def test_helper_secrets_travel_over_stdin_not_argv_or_environment(self):
        keys = loom_crypto.generate_keys(self.helper)
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.run(command, **kwargs)

        crypto = loom_crypto.HelperCrypto(
            self.helper,
            master_key=base64.b64decode(keys["master_key"]),
            signing_key=base64.b64decode(keys["signing_key"]), runner=runner)
        crypto.seal(b"private", b"aad")
        command, kwargs = calls[-1]
        flattened = " ".join(map(str, command))
        self.assertEqual([str(self.helper)], command)
        self.assertNotIn(keys["master_key"], flattened)
        self.assertNotIn(keys["master_key"], json.dumps(kwargs.get("env", {})))
        self.assertIn(keys["master_key"], kwargs["input"])

    def test_real_helper_backs_a_vault_without_plaintext_at_rest(self):
        keys = loom_crypto.generate_keys(self.helper)
        crypto = loom_crypto.HelperCrypto(
            self.helper, master_key=base64.b64decode(keys["master_key"]),
            signing_key=base64.b64decode(keys["signing_key"]))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "vault" / "owner.sqlite3"
            vault = loom_vault.OwnerVault.create(path, crypto=crypto)
            vault.put_memory({
                "id": "00000000-0000-4000-8000-000000001101",
                "scope": "domain", "domain": "accounting", "project_id": None,
                "category": "domain", "statement": "balanced postings are private",
                "provenance": "observed", "status": "active", "confidence": 1.0,
                "evidence_count": 3, "created_at": "2026-07-15T12:00:00Z",
                "preference_key": None, "preference_value": None,
            })
            self.assertNotIn(b"balanced postings", path.read_bytes())
            self.assertEqual(1, len(vault.select_memory(
                domain="accounting", project_id=None)))

    def test_os_key_store_round_trip_is_scoped_and_deleted(self):
        owner = str(uuid.uuid4())
        secret = b"k" * 64
        try:
            try:
                loom_crypto.key_store_set(self.helper, owner, secret)
            except loom_crypto.CryptoError as exc:
                if "unavailable" in str(exc) or "refused" in str(exc):
                    self.skipTest(f"secure OS key store unavailable in this session: {exc}")
                raise
            self.assertEqual(secret, loom_crypto.key_store_get(self.helper, owner))
        finally:
            try:
                loom_crypto.key_store_delete(self.helper, owner)
            except loom_crypto.CryptoError:
                pass
        with self.assertRaisesRegex(loom_crypto.CryptoError, "unavailable"):
            loom_crypto.key_store_get(self.helper, owner)

    def test_passphrase_wrapped_offline_secret_rejects_wrong_passphrase(self):
        secret = b"offline-root-signing-key"
        aad = b"loom-release-root-key-v1"
        wrapped = loom_crypto.passphrase_wrap(
            self.helper, passphrase="correct horse battery", plaintext=secret, aad=aad)
        self.assertEqual(secret, loom_crypto.passphrase_open(
            self.helper, passphrase="correct horse battery", aad=aad, **wrapped))
        with self.assertRaisesRegex(loom_crypto.CryptoError, "authentication"):
            loom_crypto.passphrase_open(
                self.helper, passphrase="wrong horse battery!", aad=aad, **wrapped)


if __name__ == "__main__":
    unittest.main()
