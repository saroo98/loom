"""Deletion-floor and anti-resurrection regression matrix."""

import base64
import datetime as dt
import hashlib
import hmac
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_vault


class DeviceCrypto:
    production_safe = False

    def __init__(self, master, signing):
        self.master = hashlib.sha256(master).digest()
        self.signing = hashlib.sha256(signing).digest()

    def seal(self, plaintext, aad):
        mask = hashlib.sha256(self.master + aad).digest()
        body = bytes(
            value ^ mask[index % 32] for index, value in enumerate(plaintext))
        return base64.b64encode(
            hmac.new(self.master, aad + body, hashlib.sha256).digest() + body)

    def open(self, ciphertext, aad):
        raw = base64.b64decode(ciphertext, validate=True)
        tag, body = raw[:32], raw[32:]
        if not hmac.compare_digest(
                tag, hmac.new(self.master, aad + body, hashlib.sha256).digest()):
            raise ValueError("authentication failed")
        mask = hashlib.sha256(self.master + aad).digest()
        return bytes(
            value ^ mask[index % 32] for index, value in enumerate(body))

    def sign(self, message):
        return base64.b64encode(
            hmac.new(self.signing, message, hashlib.sha256).digest())

    def verify(self, message, signature, public_key=None):
        key = base64.b64decode(public_key) if public_key else self.signing
        return hmac.compare_digest(
            base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()),
            signature)

    def blind_index(self, label, value):
        return hmac.new(
            self.master, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()

    def public_key(self):
        return base64.b64encode(self.signing).decode()


def record(record_id, statement="Retire this rule.", *, provenance="observed"):
    return {
        "id": record_id,
        "scope": "domain",
        "domain": "three-d",
        "project_id": None,
        "category": "domain",
        "statement": statement,
        "provenance": provenance,
        "status": "active",
        "confidence": 0.9,
        "evidence_count": 2,
        "created_at": "2026-07-15T12:00:00Z",
        "preference_key": None,
        "preference_value": None,
    }


class AntiResurrectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.owner = str(uuid.uuid4())
        self.a_id = str(uuid.uuid4())
        self.b_id = str(uuid.uuid4())
        self.a_crypto = DeviceCrypto(b"owner", b"device-a")
        self.b_crypto = DeviceCrypto(b"owner", b"device-b")
        self.a = loom_vault.OwnerVault.create(
            self.root / "a.sqlite3", crypto=self.a_crypto,
            owner_vault_id=self.owner, device_id=self.a_id,
            allow_test_crypto=True)
        self.b = loom_vault.OwnerVault.create(
            self.root / "b.sqlite3", crypto=self.b_crypto,
            owner_vault_id=self.owner, device_id=self.b_id,
            allow_test_crypto=True)
        self.a.authorize_device(self.b_id, self.b_crypto.public_key())
        self.b.authorize_device(self.a_id, self.a_crypto.public_key())

    def tearDown(self):
        self.tmp.cleanup()

    def test_forgetting_materializes_before_older_upsert_in_same_signed_batch(self):
        memory_id = "00000000-0000-4000-8000-00000000a301"
        self.a.put_memory(record(memory_id))
        self.a.forget_memory(memory_id, reason="owner-request")

        receipt = self.b.merge_events(self.a.export_events())

        self.assertEqual(1, receipt["forgotten"])
        self.assertEqual(0, receipt["added"])
        self.assertTrue(self.b.is_forgotten(memory_id))
        self.assertEqual([], self.b.select_memory(
            domain="three-d", project_id=None))

    def test_forgetting_tombstones_derived_descendants_and_semantic_reimports(self):
        parent = "00000000-0000-4000-8000-00000000a311"
        child = "00000000-0000-4000-8000-00000000a312"
        self.a.put_memory(record(parent, "Parent private rule."))
        self.a.put_memory(record(child, "Derived private rule."))
        self.a.add_derivation(parent, child)
        self.a.forget_memory(parent, reason="owner-request")

        self.assertTrue(self.a.is_forgotten(parent))
        self.assertTrue(self.a.is_forgotten(child))
        replay = self.a.import_memory(
            record(child, "Derived private rule."), source_sequence=1)
        self.assertEqual("forgotten", replay["status"])
        self.assertEqual(2, self.a.count("tombstones"))

    def test_readd_requires_new_identity_owner_evidence_and_explicit_lineage(self):
        old_id = "00000000-0000-4000-8000-00000000a321"
        new_id = "00000000-0000-4000-8000-00000000a322"
        self.a.put_memory(record(old_id))
        self.a.forget_memory(old_id, reason="owner-request")
        with self.assertRaisesRegex(loom_vault.VaultError, "new ID"):
            self.a.readd_memory(
                record(old_id, provenance="stated"),
                forgotten_record_id=old_id, evidence_id="owner-confirmation")
        with self.assertRaisesRegex(loom_vault.VaultError, "explicit owner"):
            self.a.readd_memory(
                record(new_id, provenance="observed"),
                forgotten_record_id=old_id, evidence_id="owner-confirmation")

        result = self.a.readd_memory(
            record(new_id, provenance="stated"),
            forgotten_record_id=old_id, evidence_id="owner-confirmation")
        self.assertEqual(new_id, result["id"])
        self.assertEqual(1, self.a.count("memory_records"))
        self.assertEqual(1, len(self.a.list_entities("memory-readd")))

    def test_dormant_device_needs_latest_checkpoint_and_current_deletion_floor(self):
        memory_id = "00000000-0000-4000-8000-00000000a331"
        self.b.put_memory(record(memory_id))
        self.b.forget_memory(memory_id, reason="owner-request")
        lifecycle = self.b.maintain_devices(
            now=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
        self.assertIn(self.a_id, lifecycle["device_ids"])
        checkpoint = self.b.checkpoint_if_due(force=True)
        floor = self.b.deletion_epoch()
        with self.assertRaisesRegex(loom_vault.VaultError, "complete current"):
            self.b.reactivate_dormant_device(
                self.a_id, checkpoint_id=checkpoint["checkpoint_id"],
                root_hash=checkpoint["root_hash"], deletion_epoch=floor - 1)
        result = self.b.reactivate_dormant_device(
            self.a_id, checkpoint_id=checkpoint["checkpoint_id"],
            root_hash=checkpoint["root_hash"], deletion_epoch=floor)
        self.assertEqual("active", result["status"])
        self.assertEqual(floor, result["deletion_epoch"])

    def test_duplicate_forget_never_moves_deletion_floor_backward_or_twice(self):
        memory_id = "00000000-0000-4000-8000-00000000a341"
        self.a.put_memory(record(memory_id))
        first = self.a.forget_memory(memory_id, reason="owner-request")
        floor = self.a.deletion_epoch()
        second = self.a.forget_memory(memory_id, reason="owner-request")
        self.assertEqual(floor, self.a.deletion_epoch())
        self.assertEqual(first["status"], "pending-devices")
        self.assertEqual(second["status"], "forgotten")


if __name__ == "__main__":
    unittest.main()
