"""Deterministic signed multi-device Loom merge tests."""

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
        body = bytes(value ^ mask[index % 32] for index, value in enumerate(plaintext))
        tag = hmac.new(self.master, aad + body, hashlib.sha256).digest()
        return base64.b64encode(tag + body)

    def open(self, ciphertext, aad):
        raw = base64.b64decode(ciphertext, validate=True)
        tag, body = raw[:32], raw[32:]
        if not hmac.compare_digest(tag, hmac.new(self.master, aad + body, hashlib.sha256).digest()):
            raise ValueError("authentication failed")
        mask = hashlib.sha256(self.master + aad).digest()
        return bytes(value ^ mask[index % 32] for index, value in enumerate(body))

    def sign(self, message):
        return base64.b64encode(hmac.new(self.signing, message, hashlib.sha256).digest())

    def verify(self, message, signature, public_key=None):
        key = base64.b64decode(public_key) if public_key else self.signing
        return hmac.compare_digest(
            base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()), signature)

    def blind_index(self, label, value):
        return hmac.new(self.master, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()

    def public_key(self):
        return base64.b64encode(self.signing).decode()


def preference(record_id, value):
    return {
        "id": record_id, "scope": "global", "domain": None, "project_id": None,
        "category": "preference", "statement": f"Report style is {value}.",
        "provenance": "stated", "status": "active", "confidence": 1.0,
        "evidence_count": 1, "created_at": "2026-07-15T12:00:00Z",
        "preference_key": "report_style", "preference_value": value,
    }


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.owner = str(uuid.uuid4())
        self.a_id = str(uuid.uuid4())
        self.b_id = str(uuid.uuid4())
        self.a_crypto = DeviceCrypto(b"shared-owner-key", b"device-a")
        self.b_crypto = DeviceCrypto(b"shared-owner-key", b"device-b")
        self.a = loom_vault.OwnerVault.create(
            self.root / "a.sqlite3", crypto=self.a_crypto,
            owner_vault_id=self.owner, device_id=self.a_id, allow_test_crypto=True)
        self.b = loom_vault.OwnerVault.create(
            self.root / "b.sqlite3", crypto=self.b_crypto,
            owner_vault_id=self.owner, device_id=self.b_id, allow_test_crypto=True)
        self.a.authorize_device(self.b_id, self.b_crypto.public_key())
        self.b.authorize_device(self.a_id, self.a_crypto.public_key())

    def tearDown(self):
        self.tmp.cleanup()

    def test_signed_delta_merges_once_and_forgetting_dominates_replay(self):
        record = preference("00000000-0000-4000-8000-000000002201", "concise")
        self.a.put_memory(record)
        first = self.b.merge_events(self.a.export_events())
        second = self.b.merge_events(self.a.export_events())
        self.assertEqual((1, 0), (first["added"], first["quarantined"]))
        self.assertEqual(0, second["added"])
        self.assertEqual([record["id"]], [item["id"] for item in self.b.select_memory(
            domain="accounting", project_id=None)])
        self.a.forget_memory(record["id"], reason="owner-request")
        forgotten = self.b.merge_events(self.a.export_events())
        self.assertEqual(1, forgotten["forgotten"])
        self.assertEqual([], self.b.select_memory(domain="accounting", project_id=None))
        replay = self.b.merge_events(self.a.export_events()[:1])
        self.assertEqual(0, replay["added"])
        self.assertEqual([], self.b.select_memory(domain="accounting", project_id=None))

    def test_concurrent_stated_preference_conflict_quarantines_both(self):
        self.a.put_memory(preference(
            "00000000-0000-4000-8000-000000002211", "concise"))
        self.b.put_memory(preference(
            "00000000-0000-4000-8000-000000002212", "detailed"))
        a_receipt = self.a.merge_events(self.b.export_events())
        b_receipt = self.b.merge_events(self.a.export_events())
        self.assertEqual(1, a_receipt["quarantined"])
        self.assertEqual(1, b_receipt["quarantined"])
        self.assertEqual([], self.a.select_memory(domain="accounting", project_id=None))
        self.assertEqual([], self.b.select_memory(domain="accounting", project_id=None))
        self.assertEqual(1, self.a.count("quarantine"))
        self.assertEqual(1, self.b.count("quarantine"))
        self.assertEqual(
            [{"conflict_id": self.a.relevant_preference_conflicts(
                domain="accounting")[0]["conflict_id"],
              "preference_key": "report_style"}],
            self.a.relevant_preference_conflicts(domain="accounting"))
        resolved = preference(
            "00000000-0000-4000-8000-000000002213", "balanced")
        self.a.put_memory(resolved)
        self.assertEqual([], self.a.relevant_preference_conflicts(domain="accounting"))

    def test_revoked_device_and_broken_chain_fail_closed(self):
        self.a.put_memory(preference(
            "00000000-0000-4000-8000-000000002221", "concise"))
        events = self.a.export_events()
        self.b.revoke_device(self.a_id)
        with self.assertRaisesRegex(loom_vault.VaultError, "revoked"):
            self.b.merge_events(events)
        self.assertEqual(0, self.b.count("memory_records"))

    def test_ninety_day_dormant_device_must_receive_checkpoint_before_merge(self):
        self.a.put_memory(preference(
            "00000000-0000-4000-8000-000000002231", "concise"))
        lifecycle = self.b.maintain_devices(
            now=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
        self.assertIn(self.a_id, lifecycle["device_ids"])
        with self.assertRaisesRegex(loom_vault.VaultError, "checkpoint"):
            self.b.merge_events(self.a.export_events())

    def test_remote_state_entities_obey_same_deterministic_per_type_bound(self):
        for index in range(300):
            self.a.put_entity("bounded-evidence", f"evidence-{index:04d}", {"index": index})
        receipt = self.b.merge_events(self.a.export_events())
        self.assertEqual(300, receipt["added"])
        self.assertEqual(loom_vault.MAX_ENTITY_TYPE,
                         len(self.b.list_entities("bounded-evidence")))
        self.assertEqual(
            {item["id"] for item in self.a.list_entities("bounded-evidence")},
            {item["id"] for item in self.b.list_entities("bounded-evidence")})

    def test_sequential_same_id_update_materializes_latest_value_and_truthful_receipt(self):
        record_id = "00000000-0000-4000-8000-000000002241"
        self.a.put_memory(preference(record_id, "concise"))
        self.a.put_memory(preference(record_id, "detailed"))

        receipt = self.b.merge_events(self.a.export_events())

        selected = self.b.select_memory(domain="accounting", project_id=None)
        self.assertEqual(["detailed"], [item["preference_value"] for item in selected])
        self.assertEqual(1, receipt["added"])
        self.assertEqual(1, receipt["updated"])

    def test_reverse_id_bound_converges_between_local_and_remote_materializations(self):
        for index in reversed(range(300)):
            self.a.put_entity("reverse-bound", f"entity-{index:04d}", {"index": index})

        self.b.merge_events(self.a.export_events())

        self.assertEqual(
            {item["id"] for item in self.a.list_entities("reverse-bound")},
            {item["id"] for item in self.b.list_entities("reverse-bound")})


if __name__ == "__main__":
    unittest.main()
