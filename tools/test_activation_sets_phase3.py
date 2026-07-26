"""Immutable runtime/state activation-set and rollback invariants."""

import base64
import hashlib
import hmac
import json
import shutil
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import loom_activation
import loom_reliability
import loom_update
import loom_vault


class TestCrypto:
    production_safe = False

    def __init__(self):
        self.key = hashlib.sha256(b"activation-test").digest()

    def seal(self, plaintext, aad):
        body = bytes(
            value ^ self.key[index % len(self.key)]
            for index, value in enumerate(plaintext))
        return base64.b64encode(
            hmac.new(self.key, aad + body, hashlib.sha256).digest() + body)

    def open(self, ciphertext, aad):
        raw = base64.b64decode(ciphertext, validate=True)
        tag, body = raw[:32], raw[32:]
        if not hmac.compare_digest(
                tag, hmac.new(self.key, aad + body, hashlib.sha256).digest()):
            raise ValueError("authentication failed")
        return bytes(
            value ^ self.key[index % len(self.key)]
            for index, value in enumerate(body))

    def sign(self, message):
        return base64.b64encode(hmac.new(
            self.key, b"sign:" + message, hashlib.sha256).digest())

    def verify(self, message, signature, _public_key=None):
        return hmac.compare_digest(self.sign(message), signature)

    def blind_index(self, label, value):
        return hmac.new(
            self.key, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()

    def public_key(self):
        return base64.b64encode(self.key).decode()


class ActivationSetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve() / ".loom"
        self.runtime = self.home / "runtime" / "versions" / "1.8.15"
        self.runtime.mkdir(parents=True)
        (self.runtime / "loom-runtime.txt").write_text(
            "runtime", encoding="utf-8")
        self.pointer = {
            "version": "1.8.15",
            "path": "1.8.15",
            "payload_sha256": hashlib.sha256(b"runtime").hexdigest(),
            "release_sequence": 15,
            "previous": None,
        }
        self.crypto = TestCrypto()
        self.legacy = self.home / "vault" / "owner.sqlite3"
        self.vault = loom_vault.OwnerVault.create(
            self.legacy, crypto=self.crypto, allow_test_crypto=True)
        self.store = loom_activation.ActivationStore(self.home)

    def tearDown(self):
        self.tmp.cleanup()

    def test_adoption_clones_state_and_pointer_binds_exact_pair(self):
        adopted = self.store.adopt_legacy(self.pointer)
        state_path = self.store.state_path(adopted)
        self.assertNotEqual(self.legacy, state_path)
        self.assertEqual(
            loom_activation.state_inventory(self.legacy)["inventory_sha256"],
            loom_activation.state_inventory(state_path)["inventory_sha256"])
        self.assertEqual(adopted, self.store.validate_pointer(adopted))
        receipt = self.store.read_receipt(adopted["activation_set_id"])
        self.assertEqual("baseline-adoption", receipt["purpose"])
        self.assertEqual("1.8.15", receipt["runtime"]["version"])

    def test_mismatched_state_owner_schema_and_deletion_floor_fail_closed(self):
        adopted = self.store.adopt_legacy(self.pointer)
        state_path = self.store.state_path(adopted)
        connection = sqlite3.connect(state_path)
        try:
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='owner_vault_id'",
                (str(uuid.uuid4()),))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
                loom_activation.ActivationError, "moved behind|outside"):
            self.store.validate_pointer(adopted)

    def test_new_activation_cannot_move_behind_previous_deletion_floor(self):
        adopted = self.store.adopt_legacy(self.pointer)
        current_path = self.store.state_path(adopted)
        current = loom_vault.OwnerVault.open(
            current_path, crypto=self.crypto, allow_test_crypto=True)
        item = {
            "id": "00000000-0000-4000-8000-00000000a351",
            "scope": "domain", "domain": "three-d", "project_id": None,
            "category": "domain", "statement": "Forget this.",
            "provenance": "observed", "status": "active",
            "confidence": 0.9, "evidence_count": 2,
            "created_at": "2026-07-15T12:00:00Z",
            "preference_key": None, "preference_value": None,
        }
        current.put_memory(item)
        current.forget_memory(item["id"], reason="owner-request")
        advanced = self.store.create(
            adopted, state_source=current_path,
            schema_range={"minimum": 3, "maximum": 3},
            previous_activation_set_id=adopted["activation_set_id"],
            purpose="reactivation")
        # A receipt made before the deletion has a lower floor and cannot replace it.
        with self.assertRaisesRegex(
                loom_activation.ActivationError, "moves behind"):
            self.store.create(
                advanced, state_source=self.legacy,
                schema_range={"minimum": 3, "maximum": 3},
                previous_activation_set_id=advanced["activation_set_id"],
                purpose="reactivation")

    def test_pointer_switch_failure_leaves_old_activation_authoritative(self):
        adopted = self.store.adopt_legacy(self.pointer)
        current = self.home / "runtime" / "current.json"
        loom_reliability.atomic_write_json(current, adopted)
        replacement = self.store.create(
            adopted, state_source=self.store.state_path(adopted),
            schema_range={"minimum": 3, "maximum": 3},
            previous_activation_set_id=adopted["activation_set_id"],
            purpose="reactivation")
        before = current.read_bytes()
        with mock.patch.object(
                loom_reliability, "atomic_write_json",
                side_effect=OSError("injected pointer failure")):
            with self.assertRaisesRegex(OSError, "pointer failure"):
                loom_reliability.atomic_write_json(current, replacement)
        self.assertEqual(before, current.read_bytes())
        self.assertEqual(adopted, self.store.validate_pointer(
            json.loads(current.read_text(encoding="utf-8"))))

    def test_active_session_pins_activation_and_deletion_floor(self):
        shutil.rmtree(self.runtime)
        runtime = loom_update.SharedRuntime(self.home)
        runtime.install_baseline("1.8.15", b"runtime", release_sequence=15)
        # Replace the synthetic baseline state with the real vault before the first session.
        current = runtime.current()
        adopted = runtime.activations.create(
            current, state_source=self.legacy,
            schema_range={"minimum": 3, "maximum": 3},
            previous_activation_set_id=current.get("activation_set_id"),
            purpose="reactivation")
        loom_reliability.atomic_write_json(runtime.current_path, adopted)
        lease = runtime.begin_session()
        self.assertEqual(adopted["activation_set_id"], lease["activation_set_id"])
        self.assertEqual(adopted["state"]["generation"], lease["state_generation"])
        self.assertEqual(adopted["state"]["deletion_epoch"], lease["deletion_epoch"])
        runtime.end_session(lease["session_id"])

    def test_pruning_refuses_unowned_state_bytes(self):
        adopted = self.store.adopt_legacy(self.pointer)
        replacement = self.store.create(
            adopted, state_source=self.store.state_path(adopted),
            schema_range={"minimum": 3, "maximum": 3},
            previous_activation_set_id=adopted["activation_set_id"],
            purpose="reactivation")
        stale = self.store.state_path(adopted).parent
        (stale / "owner-added.txt").write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(
                loom_activation.ActivationError, "unowned"):
            self.store.prune_inactive({replacement["activation_set_id"]})
        self.assertTrue((stale / "owner-added.txt").is_file())


if __name__ == "__main__":
    unittest.main()
