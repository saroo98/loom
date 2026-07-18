"""Owner-vault bootstrap and health contract tests."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import loom_owner
import loom_crypto
import loom_vault
from v11_test_support import build_vault_helper


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "vault-helper"


class MemoryKeyStore:
    def __init__(self, fail=False):
        self.values = {}
        self.fail = fail

    def set(self, owner, secret):
        if self.fail:
            raise RuntimeError("injected key store refusal")
        self.values[owner] = bytes(secret)

    def get(self, owner):
        return self.values[owner]

    def delete(self, owner):
        self.values.pop(owner, None)


class OwnerBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve() / ".loom"
        self.store = MemoryKeyStore()

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_bootstrap_reopens_same_owner_without_file_key_material(self):
        first = loom_owner.initialize_owner_vault(
            self.home, self.helper, key_store=self.store)
        owner = first["vault"].identity()["owner_vault_id"]
        self.assertEqual("initialized", first["status"])
        self.assertEqual(128, len(self.store.values[owner]))
        raw = (self.home / "vault" / "owner.sqlite3").read_bytes()
        self.assertNotIn(self.store.values[owner][:32], raw)
        second = loom_owner.initialize_owner_vault(
            self.home, self.helper, key_store=self.store)
        self.assertEqual("opened", second["status"])
        self.assertEqual(owner, second["vault"].identity()["owner_vault_id"])

    def test_key_store_refusal_leaves_no_active_vault(self):
        with self.assertRaisesRegex(loom_owner.OwnerError, "failed safely"):
            loom_owner.initialize_owner_vault(
                self.home, self.helper, key_store=MemoryKeyStore(fail=True))
        self.assertFalse((self.home / "vault" / "owner.sqlite3").exists())

    def test_health_summary_contains_operations_not_memory_bodies(self):
        result = loom_owner.initialize_owner_vault(
            self.home, self.helper, key_store=self.store)
        (self.home / "runtime").mkdir(exist_ok=True)
        (self.home / "runtime" / "current.json").write_text(json.dumps({
            "version": "1.1.0"}), encoding="utf-8")
        summary = loom_owner.health_summary(self.home, result["vault"])
        self.assertEqual("1.1.0", summary["runtime_version"])
        self.assertFalse(summary["telemetry"])
        self.assertEqual(0, summary["active_memory_records"])
        self.assertEqual(0, summary["recent_memory_effects"])
        self.assertEqual(0, summary["dormant_memory_records"])
        self.assertEqual({}, summary["recent_memory_effect_states"])
        self.assertTrue(summary["bounds_within_policy"])
        self.assertEqual(loom_vault.MAX_ACTIVE_RECORDS,
                         summary["bounds"]["active_memory"]["limit"])
        self.assertEqual(loom_vault.MAX_MEMORY_RECORDS,
                         summary["bounds"]["retained_memory"]["limit"])
        self.assertIn("preference_conflicts", summary)
        self.assertNotIn("statement", json.dumps(summary).casefold())
        self.assertNotIn("ciphertext", json.dumps(summary).casefold())

    def test_revocation_rotates_data_key_preserves_semantics_and_keeps_rollback(self):
        initialized = loom_owner.initialize_owner_vault(
            self.home, self.helper, key_store=self.store)
        vault = initialized["vault"]
        vault.put_memory({
            "id": "00000000-0000-4000-8000-000000009801",
            "scope": "domain", "domain": "accounting", "project_id": None,
            "category": "domain", "statement": "Preserve double-entry balance.",
            "provenance": "stated", "status": "active", "confidence": 1.0,
            "evidence_count": 1, "created_at": "2026-07-15T12:00:00Z",
            "preference_key": None, "preference_value": None,
        })
        forgotten_id = "00000000-0000-4000-8000-000000009804"
        vault.put_memory({
            "id": forgotten_id, "scope": "domain", "domain": "accounting",
            "project_id": None, "category": "domain",
            "statement": "Temporary private rule.", "provenance": "observed",
            "status": "active", "confidence": 0.8, "evidence_count": 3,
            "created_at": "2026-07-15T12:00:00Z", "preference_key": None,
            "preference_value": None,
        })
        vault.forget_memory(forgotten_id, reason="owner-request")
        remote_keys = loom_crypto.generate_keys(self.helper)
        remote_id = "00000000-0000-4000-8000-000000009802"
        vault.authorize_device(remote_id, remote_keys["signing_public"])
        owner = vault.identity()["owner_vault_id"]
        old_secret = self.store.values[owner]
        old_crypto = loom_crypto.HelperCrypto(
            self.helper, master_key=old_secret[:32], signing_key=old_secret[32:64],
            index_key=old_secret[96:128])
        with vault._connect() as connection:
            old_ciphertext = bytes(connection.execute(
                "SELECT ciphertext FROM memory_records WHERE record_id=?",
                ("00000000-0000-4000-8000-000000009801",)).fetchone()[0])

        result = loom_owner.revoke_device_and_rotate(
            self.home, self.helper, remote_id, key_store=self.store)
        self.assertEqual("rotated", result["status"])
        self.assertNotEqual(owner, result["key_slot_id"])
        self.assertEqual(128, len(self.store.values[result["key_slot_id"]]))
        self.assertTrue(Path(result["rollback_checkpoint"]).is_file())
        self.assertNotIn(old_ciphertext, (self.home / "vault" / "owner.sqlite3").read_bytes())
        self.assertEqual(
            "Preserve double-entry balance.",
            result["vault"].select_memory(
                domain="accounting", project_id=None)[0]["statement"])
        self.assertTrue(result["vault"].is_forgotten(forgotten_id))
        with result["vault"]._connect() as connection:
            status = connection.execute(
                "SELECT status FROM devices WHERE device_id=?", (remote_id,)).fetchone()[0]
        self.assertEqual("revoked", status)
        old_view = loom_vault.OwnerVault.open(
            self.home / "vault" / "owner.sqlite3", crypto=old_crypto)
        with self.assertRaises((loom_vault.VaultError, loom_crypto.CryptoError)):
            old_view.select_memory(domain="accounting", project_id=None)

    def test_revocation_key_store_refusal_leaves_old_vault_authoritative(self):
        initialized = loom_owner.initialize_owner_vault(
            self.home, self.helper, key_store=self.store)
        remote_keys = loom_crypto.generate_keys(self.helper)
        remote_id = "00000000-0000-4000-8000-000000009803"
        initialized["vault"].authorize_device(remote_id, remote_keys["signing_public"])
        before = (self.home / "vault" / "owner.sqlite3").read_bytes()
        self.store.fail = True
        with self.assertRaisesRegex(loom_owner.OwnerError, "failed safely"):
            loom_owner.revoke_device_and_rotate(
                self.home, self.helper, remote_id, key_store=self.store)
        self.store.fail = False
        self.assertEqual(before, (self.home / "vault" / "owner.sqlite3").read_bytes())
        reopened, _crypto = loom_owner.open_owner_vault(
            self.home, self.helper, key_store=self.store)
        with reopened._connect() as connection:
            status = connection.execute(
                "SELECT status FROM devices WHERE device_id=?", (remote_id,)).fetchone()[0]
        self.assertEqual("active", status)


if __name__ == "__main__":
    unittest.main()
