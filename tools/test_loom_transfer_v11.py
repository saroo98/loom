"""Encrypted device pairing and recovery-backup tests using the real helper."""

import base64
import datetime as dt
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import loom_crypto
import loom_transfer
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


class TransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        keys = loom_crypto.generate_keys(self.helper)
        self.crypto = loom_crypto.HelperCrypto(
            self.helper, master_key=base64.b64decode(keys["master_key"]),
            signing_key=base64.b64decode(keys["signing_key"]))
        self.vault = loom_vault.OwnerVault.create(
            self.root / "source" / "owner.sqlite3", crypto=self.crypto)
        self.vault.put_memory({
            "id": "00000000-0000-4000-8000-000000003301",
            "scope": "domain", "domain": "three-d", "project_id": None,
            "category": "domain", "statement": "private frame budget",
            "provenance": "observed", "status": "active", "confidence": 1.0,
            "evidence_count": 3, "created_at": "2026-07-15T12:00:00Z",
            "preference_key": None, "preference_value": None,
        })

    def tearDown(self):
        self.tmp.cleanup()

    def test_pairing_restores_complete_vault_without_plaintext_bundle(self):
        receiver = loom_transfer.new_device(self.helper)
        bundle = self.root / "pair.loom-pair"
        created = loom_transfer.create_pair_bundle(
            self.vault, self.crypto, receiver["pairing_payload"], bundle,
            owner_authorized=True)
        self.assertEqual("created", created["status"])
        self.assertNotIn(b"private frame budget", bundle.read_bytes())
        destination = self.root / "receiver" / "owner.sqlite3"
        accepted = loom_transfer.accept_pair_bundle(
            self.helper, bundle, receiver["private_material"], destination,
            expected_sender_fingerprint=created["sender_fingerprint"],
            expected_sas=created["sas"])
        self.assertEqual("validated-not-activated", accepted["status"])
        restored = loom_vault.OwnerVault.open(destination, crypto=accepted["crypto"])
        self.assertEqual(self.vault.identity()["owner_vault_id"],
                         restored.identity()["owner_vault_id"])
        self.assertEqual(1, len(restored.select_memory(domain="three-d", project_id=None)))
        receiver_keys = restored.list_entities("device-key")
        self.assertTrue(any(
            item["id"] == receiver["private_material"]["device_id"]
            for item in receiver_keys))

    def test_pairing_activates_secure_key_material_or_leaves_no_vault(self):
        receiver = loom_transfer.new_device(self.helper)
        bundle = self.root / "secure-pair.loom-pair"
        created = loom_transfer.create_pair_bundle(
            self.vault, self.crypto, receiver["pairing_payload"], bundle,
            owner_authorized=True)
        store = MemoryKeyStore()
        destination = self.root / "secure-receiver" / "owner.sqlite3"
        result = loom_transfer.accept_pair_bundle(
            self.helper, bundle, receiver["private_material"], destination,
            expected_sender_fingerprint=created["sender_fingerprint"],
            expected_sas=created["sas"], key_store=store)
        self.assertTrue(result["key_stored"])
        self.assertEqual(128, len(store.values[result["key_slot_id"]]))

        failed_destination = self.root / "failed-receiver" / "owner.sqlite3"
        with self.assertRaisesRegex(RuntimeError, "key store refusal"):
            loom_transfer.accept_pair_bundle(
                self.helper, bundle, receiver["private_material"], failed_destination,
                expected_sender_fingerprint=created["sender_fingerprint"],
                expected_sas=created["sas"],
                key_store=MemoryKeyStore(fail=True))
        self.assertFalse(failed_destination.exists())

    def test_pairing_requires_owner_authorized_sender_fingerprint(self):
        receiver = loom_transfer.new_device(self.helper)
        bundle = self.root / "sender-pinned.loom-pair"
        created = loom_transfer.create_pair_bundle(
            self.vault, self.crypto, receiver["pairing_payload"], bundle,
            owner_authorized=True)

        with self.assertRaisesRegex(loom_transfer.TransferError, "sender"):
            loom_transfer.accept_pair_bundle(
                self.helper, bundle, receiver["private_material"],
                self.root / "wrong-sender" / "owner.sqlite3",
                expected_sender_fingerprint="0" * 64,
                expected_sas=created["sas"])

        self.assertFalse((self.root / "wrong-sender" / "owner.sqlite3").exists())

    def test_pairing_v2_requires_receiver_authorization_sas_and_fresh_challenge(self):
        issued = dt.datetime(2026, 7, 16, 12, 0, tzinfo=dt.timezone.utc)
        receiver = loom_transfer.new_device(self.helper, now=issued)
        bundle = self.root / "pair-v2.loom-pair"
        with self.assertRaisesRegex(loom_transfer.TransferError, "authorization"):
            loom_transfer.create_pair_bundle(
                self.vault, self.crypto, receiver["pairing_payload"], bundle,
                owner_authorized=False, now=issued)
        created = loom_transfer.create_pair_bundle(
            self.vault, self.crypto, receiver["pairing_payload"], bundle,
            owner_authorized=True, now=issued)
        destination = self.root / "pair-v2-home" / "owner.sqlite3"
        with self.assertRaisesRegex(loom_transfer.TransferError, "SAS"):
            loom_transfer.accept_pair_bundle(
                self.helper, bundle, receiver["private_material"], destination,
                expected_sender_fingerprint=created["sender_fingerprint"],
                expected_sas="0000-0000-0000", now=issued)
        self.assertFalse(destination.exists())
        with self.assertRaisesRegex(loom_transfer.TransferError, "addressed|expiry"):
            loom_transfer.accept_pair_bundle(
                self.helper, bundle, receiver["private_material"], destination,
                expected_sender_fingerprint=created["sender_fingerprint"],
                expected_sas=created["sas"],
                now=issued + dt.timedelta(seconds=loom_transfer.PAIR_TTL_SECONDS + 1))

    def test_pairing_v2_replay_receipt_blocks_second_destination(self):
        receiver = loom_transfer.new_device(self.helper)
        bundle = self.root / "replay.loom-pair"
        created = loom_transfer.create_pair_bundle(
            self.vault, self.crypto, receiver["pairing_payload"], bundle,
            owner_authorized=True)
        receipt_store = self.root / "pair-receipts.json"
        loom_transfer.accept_pair_bundle(
            self.helper, bundle, receiver["private_material"],
            self.root / "first" / "owner.sqlite3",
            expected_sender_fingerprint=created["sender_fingerprint"],
            expected_sas=created["sas"], receipt_store=receipt_store)
        with self.assertRaisesRegex(loom_transfer.TransferError, "replay"):
            loom_transfer.accept_pair_bundle(
                self.helper, bundle, receiver["private_material"],
                self.root / "second" / "owner.sqlite3",
                expected_sender_fingerprint=created["sender_fingerprint"],
                expected_sas=created["sas"], receipt_store=receipt_store)

    def test_recovery_phrase_requires_backup_and_wrong_phrase_fails(self):
        recovery = loom_transfer.generate_recovery(self.helper)
        backup = self.root / "backups" / "owner.loom-backup"
        anchor = self.root / "recovery-anchor.json"
        loom_transfer.create_recovery_backup(
            self.vault, self.crypto, recovery["phrase"], backup, sequence=1,
            recovery_anchor=anchor)
        self.assertNotIn(b"private frame budget", backup.read_bytes())
        with self.assertRaisesRegex(loom_transfer.TransferError, "phrase|authentication"):
            loom_transfer.restore_recovery_backup(
                self.helper, backup, "abandon " * 23 + "about",
                self.root / "wrong" / "owner.sqlite3", recovery_anchor=anchor)
        with self.assertRaisesRegex(loom_transfer.TransferError, "backup.*required"):
            loom_transfer.restore_recovery_backup(
                self.helper, self.root / "missing.loom-backup", recovery["phrase"],
                self.root / "missing" / "owner.sqlite3", recovery_anchor=anchor)
        restored_path = self.root / "recovered" / "owner.sqlite3"
        result = loom_transfer.restore_recovery_backup(
            self.helper, backup, recovery["phrase"], restored_path,
            recovery_anchor=anchor)
        self.assertEqual("validated-not-activated", result["status"])
        restored = loom_vault.OwnerVault.open(restored_path, crypto=result["crypto"])
        self.assertEqual(1, len(restored.select_memory(domain="three-d", project_id=None)))
        self.assertTrue(any(
            item["id"] == result["device_id"]
            for item in restored.list_entities("device-key")))
        with self.assertRaisesRegex(loom_transfer.TransferError, "deletion epoch"):
            loom_transfer.restore_recovery_backup(
                self.helper, backup, recovery["phrase"],
                self.root / "stale" / "owner.sqlite3", minimum_sequence=2,
                recovery_anchor=anchor)

    def test_recovery_activates_secure_key_material_or_leaves_no_vault(self):
        recovery = loom_transfer.generate_recovery(self.helper)
        backup = self.root / "secure-recovery.loom-backup"
        anchor = self.root / "secure-recovery-anchor.json"
        loom_transfer.create_recovery_backup(
            self.vault, self.crypto, recovery["phrase"], backup, sequence=1,
            recovery_anchor=anchor)
        store = MemoryKeyStore()
        destination = self.root / "secure-recovery" / "owner.sqlite3"
        result = loom_transfer.restore_recovery_backup(
            self.helper, backup, recovery["phrase"], destination,
            recovery_anchor=anchor, key_store=store)
        self.assertTrue(result["key_stored"])
        self.assertEqual(128, len(store.values[result["key_slot_id"]]))

        failed_destination = self.root / "failed-recovery" / "owner.sqlite3"
        with self.assertRaisesRegex(RuntimeError, "key store refusal"):
            loom_transfer.restore_recovery_backup(
                self.helper, backup, recovery["phrase"], failed_destination,
                recovery_anchor=anchor,
                key_store=MemoryKeyStore(fail=True))
        self.assertFalse(failed_destination.exists())

    def test_backup_before_permanent_forget_cannot_activate_against_current_anchor(self):
        recovery = loom_transfer.generate_recovery(self.helper)
        backup = self.root / "pre-forget.loom-backup"
        anchor = self.root / "current-recovery-anchor.json"
        loom_transfer.create_recovery_backup(
            self.vault, self.crypto, recovery["phrase"], backup, sequence=1,
            recovery_anchor=anchor)
        self.vault.forget_memory(
            "00000000-0000-4000-8000-000000003301", reason="owner-request")
        loom_transfer.write_recovery_anchor(self.vault, self.crypto, anchor)

        destination = self.root / "must-not-resurrect" / "owner.sqlite3"
        with self.assertRaisesRegex(loom_transfer.TransferError, "deletion epoch"):
            loom_transfer.restore_recovery_backup(
                self.helper, backup, recovery["phrase"], destination,
                recovery_anchor=anchor)

        self.assertFalse(destination.exists())

    def test_managed_backup_retention_is_bounded_and_never_deletes_unowned_files(self):
        recovery = loom_transfer.generate_recovery(self.helper)
        directory = self.root / "managed-backups"
        unowned = directory / "family-photo.txt"
        directory.mkdir()
        unowned.write_text("never touch", encoding="utf-8")
        start = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
        for sequence in range(1, 18):
            result = loom_transfer.create_managed_recovery_backup(
                self.vault, self.crypto, recovery["phrase"], directory,
                sequence=sequence, now=start + dt.timedelta(days=31 * sequence))
        index = json.loads((directory / loom_transfer.BACKUP_INDEX).read_text(
            encoding="utf-8"))
        self.assertLessEqual(len(index["entries"]), 12)
        self.assertEqual("never touch", unowned.read_text(encoding="utf-8"))
        self.assertEqual(len(index["entries"]), result["retained"])

        changed = directory / index["entries"][0]["name"]
        changed.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(loom_transfer.TransferError, "refused"):
            loom_transfer.create_managed_recovery_backup(
                self.vault, self.crypto, recovery["phrase"], directory,
                sequence=18, now=start + dt.timedelta(days=31 * 18))
        self.assertEqual("tampered", changed.read_text(encoding="utf-8"))

    def test_chunked_transfer_exceeds_old_one_megabyte_helper_limit(self):
        self.vault.put_entity("fixture", "large-a", {"data": "a" * 700_000})
        self.vault.put_entity("fixture", "large-b", {"data": "b" * 700_000})
        checkpoint = self.root / "large.sqlite3"
        self.vault.online_backup(checkpoint)
        self.assertGreater(checkpoint.stat().st_size, 1024 * 1024)

        recovery = loom_transfer.generate_recovery(self.helper)
        backup = self.root / "large.loom-backup"
        anchor = self.root / "large-recovery-anchor.json"
        loom_transfer.create_recovery_backup(
            self.vault, self.crypto, recovery["phrase"], backup, sequence=1,
            recovery_anchor=anchor)
        restored = self.root / "large-restored.sqlite3"
        result = loom_transfer.restore_recovery_backup(
            self.helper, backup, recovery["phrase"], restored,
            recovery_anchor=anchor)
        opened = loom_vault.OwnerVault.open(restored, crypto=result["crypto"])
        self.assertEqual(2, len(opened.list_entities("fixture")))

    def test_forged_backup_index_cannot_escape_directory(self):
        directory = self.root / "forged-backups"
        directory.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("owner file", encoding="utf-8")
        (directory / loom_transfer.BACKUP_INDEX).write_text(json.dumps({
            "schema_version": 1,
            "entries": [{"name": "../outside.txt", "sha256": "0" * 64,
                         "created_at": "2026-01-01T00:00:00Z", "sequence": 1,
                         "deletion_epoch": 0,
                         "owner_vault_id": self.vault.identity()["owner_vault_id"]}]
        }), encoding="utf-8")
        recovery = loom_transfer.generate_recovery(self.helper)
        with self.assertRaisesRegex(loom_transfer.TransferError, "values"):
            loom_transfer.create_managed_recovery_backup(
                self.vault, self.crypto, recovery["phrase"], directory,
                sequence=2, now=dt.datetime(2026, 2, 1, tzinfo=dt.timezone.utc))
        self.assertEqual("owner file", outside.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
