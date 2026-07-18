"""Loom 1.1 owner-vault identity, encryption, and transaction tests."""

import base64
import datetime as dt
import hashlib
import hmac
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

import loom_vault


class TestCrypto:
    production_safe = False

    def __init__(self, key=b"loom-v11-test-key-material-32b!"):
        self.key = hashlib.sha256(key).digest()

    def _stream(self, aad, length):
        blocks = []
        counter = 0
        while sum(map(len, blocks)) < length:
            blocks.append(hmac.new(
                self.key, aad + counter.to_bytes(8, "big"), hashlib.sha256).digest())
            counter += 1
        return b"".join(blocks)[:length]

    def seal(self, plaintext, aad):
        stream = self._stream(aad, len(plaintext))
        body = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        return base64.b64encode(tag + body)

    def open(self, ciphertext, aad):
        raw = base64.b64decode(ciphertext, validate=True)
        tag, body = raw[:32], raw[32:]
        if not hmac.compare_digest(tag, hmac.new(self.key, aad + body, hashlib.sha256).digest()):
            raise ValueError("authentication failed")
        stream = self._stream(aad, len(body))
        return bytes(a ^ b for a, b in zip(body, stream))

    def sign(self, message):
        return base64.b64encode(hmac.new(self.key, b"sign:" + message, hashlib.sha256).digest())

    def verify(self, message, signature, _public_key=None):
        return hmac.compare_digest(self.sign(message), signature)

    def blind_index(self, label, value):
        return hmac.new(self.key, label.encode() + b":" + value.encode(), hashlib.sha256).hexdigest()

    def public_key(self):
        return base64.b64encode(hashlib.sha256(b"public:" + self.key).digest()).decode()


class OwnerVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.path = self.home / "vault" / "owner.sqlite3"
        self.crypto = TestCrypto()
        self.vault = loom_vault.OwnerVault.create(
            self.path, crypto=self.crypto, allow_test_crypto=True)

    def tearDown(self):
        self.tmp.cleanup()

    def record(self, *, statement="Private accounting invariant", scope="domain",
               domain="accounting", project_id=None, record_id=None):
        return {
            "id": record_id or str(uuid.uuid4()), "scope": scope,
            "domain": domain if scope != "global" else None,
            "project_id": project_id if scope == "project" else None,
            "category": "domain" if scope != "global" else "calibration",
            "statement": statement, "provenance": "observed", "status": "active",
            "confidence": 0.9, "evidence_count": 3, "created_at": "2026-07-15T12:00:00Z",
            "preference_key": None, "preference_value": None,
        }

    def test_owner_identity_is_stable_while_device_and_runtime_identities_are_distinct(self):
        identity = self.vault.identity()
        reopened = loom_vault.OwnerVault.open(
            self.path, crypto=self.crypto, allow_test_crypto=True)
        self.assertEqual(identity["owner_vault_id"], reopened.identity()["owner_vault_id"])
        self.assertNotEqual(identity["owner_vault_id"], identity["device_id"])
        first_runtime = loom_vault.runtime_install_id("1.1.0", "a" * 64)
        second_runtime = loom_vault.runtime_install_id("1.1.1", "b" * 64)
        self.assertNotEqual(first_runtime, second_runtime)

    def test_v1_schema_migrates_from_a_staged_copy_with_receipt_and_provenance(self):
        record = self.vault.put_memory(self.record())
        self.vault.put_entity("preference", "editor", {"value": "compact"})
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
            for table in ("memory_records", "tombstones", "state_entities"):
                connection.execute(f"ALTER TABLE {table} DROP COLUMN source_event_id")
                connection.execute(f"ALTER TABLE {table} DROP COLUMN source_device_id")
            connection.commit()
        finally:
            connection.close()

        migrated = loom_vault.OwnerVault.open(
            self.path, crypto=self.crypto, allow_test_crypto=True)
        self.assertEqual(3, migrated.identity()["schema_version"])
        self.assertEqual(1, migrated.schema_migration_receipt()["from"])
        self.assertEqual(3, migrated.schema_migration_receipt()["to"])
        self.assertEqual("migrated", migrated.schema_migration_receipt()["status"])
        rollback = Path(str(self.path) + ".schema-v1.rollback")
        self.assertTrue(rollback.is_file())
        connection = sqlite3.connect(rollback)
        try:
            self.assertEqual("1", connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0])
        finally:
            connection.close()
        connection = sqlite3.connect(self.path)
        try:
            provenance = connection.execute(
                "SELECT source_event_id,source_device_id FROM memory_records "
                "WHERE record_id=?", (record["id"],)).fetchone()
            self.assertEqual(("legacy-v1", "legacy-v1"), provenance)
        finally:
            connection.close()
        self.assertEqual(record["id"], migrated.select_memory(
            domain="accounting", project_id=None)[0]["id"])

    def test_v1_schema_pointer_switch_failure_restores_the_original(self):
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
            connection.commit()
        finally:
            connection.close()
        real_replace = loom_vault.os.replace
        calls = 0

        def fail_activation(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected activation failure")
            return real_replace(source, destination)

        with mock.patch.object(loom_vault.os, "replace", side_effect=fail_activation):
            with self.assertRaisesRegex(loom_vault.VaultError, "failed safely"):
                loom_vault.OwnerVault.open(
                    self.path, crypto=self.crypto, allow_test_crypto=True)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual("1", connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0])
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
        finally:
            connection.close()
        self.assertFalse(Path(str(self.path) + ".schema-v1.rollback").exists())

    def test_encrypted_record_never_appears_in_database_bytes_and_selection_is_scoped(self):
        accounting = self.vault.put_memory(self.record())
        three_d = self.vault.put_memory(self.record(
            statement="Private frame-time invariant", domain="three-d"))
        global_record = self.vault.put_memory(self.record(
            statement="Private calibration", scope="global", domain=None))
        raw = self.path.read_bytes()
        for plaintext in (b"Private accounting", b"Private frame-time", b"Private calibration"):
            self.assertNotIn(plaintext, raw)
        selected = self.vault.select_memory(domain="accounting", project_id=None)
        self.assertEqual({accounting["id"], global_record["id"]}, {item["id"] for item in selected})
        self.assertNotIn(three_d["id"], {item["id"] for item in selected})

    def test_legacy_stale_status_materializes_as_revalidation_required(self):
        legacy = self.record()
        legacy["status"] = "stale"
        stored = self.vault.put_memory(legacy)
        self.assertEqual("revalidation-required", stored["status"])
        with self.vault._connect() as connection:
            status = connection.execute(
                "SELECT status FROM memory_records WHERE record_id=?",
                (stored["id"],)).fetchone()[0]
        self.assertEqual("revalidation-required", status)

    def test_dormant_records_do_not_consume_the_active_selection_bound(self):
        for index in range(loom_vault.MAX_ACTIVE_RECORDS):
            value = self.record(
                statement=f"Dormant retained rule {index}",
                record_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"dormant-{index}")))
            value["status"] = "dormant"
            self.vault.put_memory(value)
        active = self.vault.put_memory(self.record(statement="Still selectable"))
        self.assertEqual("active", active["status"])
        self.assertEqual(loom_vault.MAX_ACTIVE_RECORDS + 1,
                         self.vault.count("memory_records"))

    def test_project_identity_uses_owner_vault_not_runtime_install(self):
        lineage = {"kind": "git-lineage-v1", "roots": ["a" * 40], "origin_hash": "b" * 64}
        owner = self.vault.identity()["owner_vault_id"]
        first = loom_vault.project_identity(owner, lineage)
        second = loom_vault.project_identity(owner, dict(lineage))
        other = loom_vault.project_identity(str(uuid.uuid4()), lineage)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_forgetting_dominates_replayed_earlier_record(self):
        record = self.vault.put_memory(self.record())
        forgotten = self.vault.forget_memory(record["id"], reason="owner-request")
        self.assertEqual("complete", forgotten["status"])
        replay = self.vault.import_memory(self.record(
            record_id=record["id"], statement="Private accounting invariant"),
            source_sequence=1)
        self.assertEqual("forgotten", replay["status"])
        self.assertEqual([], self.vault.select_memory(domain="accounting", project_id=None))

    def test_online_backup_is_consistent_and_transaction_failure_preserves_old_generation(self):
        self.vault.put_memory(self.record())
        before = self.vault.identity()["generation"]
        with self.assertRaisesRegex(loom_vault.VaultError, "injected"):
            self.vault.run_transaction(lambda connection: (_ for _ in ()).throw(RuntimeError("injected")))
        self.assertEqual(before, self.vault.identity()["generation"])
        backup = self.home / "checkpoints" / "snapshot.sqlite3"
        receipt = self.vault.online_backup(backup)
        self.assertEqual(1, receipt["records"])
        connection = sqlite3.connect(backup)
        try:
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
        finally:
            connection.close()

    def test_ten_concurrent_writers_commit_unique_signed_events(self):
        errors = []

        def writer(index):
            try:
                self.vault.put_memory(self.record(
                    statement=f"Private concurrent invariant {index}",
                    record_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"loom:{index}"))))
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual([], errors)
        self.assertEqual(10, self.vault.count("memory_records"))
        self.assertEqual(10, self.vault.count("events"))
        self.assertEqual(10, len({item["device_counter"] for item in self.vault.export_events()}))

    def test_unused_domain_learning_dormants_archives_and_expires_automatically(self):
        record = self.vault.put_memory(self.record())
        dormant = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2026, 8, 20, tzinfo=dt.timezone.utc))
        self.assertEqual(1, dormant["dormant"])
        self.assertEqual([], self.vault.select_memory(domain="accounting", project_id=None))
        archived = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc))
        self.assertEqual(1, archived["archived"])
        expired = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2027, 8, 20, tzinfo=dt.timezone.utc))
        self.assertEqual(1, expired["expired"])
        self.assertEqual(0, self.vault.count("memory_records"))
        self.assertEqual(1, self.vault.count("tombstones"))
        replay = self.vault.import_memory(self.record(record_id=record["id"]), source_sequence=0)
        self.assertEqual("forgotten", replay["status"])

    def test_helpful_learning_and_stated_preferences_are_retained(self):
        learned = self.vault.put_memory(self.record())
        preference = self.record(scope="global", domain=None)
        preference.update({"category": "preference", "provenance": "stated",
                           "preference_key": "report_style", "preference_value": "careful"})
        stated = self.vault.put_memory(preference)
        self.vault.record_memory_outcome([learned["id"]], helped_ids=[learned["id"]])
        result = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual(0, result["expired"])
        selected = self.vault.select_memory(domain="accounting", project_id=None)
        self.assertEqual({learned["id"], stated["id"]}, {item["id"] for item in selected})

    def test_changed_owner_preference_supersedes_old_value_without_ossifying(self):
        first = self.record(scope="global", domain=None)
        first.update({"category": "preference", "provenance": "stated",
                      "preference_key": "autonomy_default", "preference_value": "maximum"})
        old = self.vault.put_memory(first)
        second = self.record(scope="global", domain=None)
        second.update({"category": "preference", "provenance": "stated",
                       "preference_key": "autonomy_default", "preference_value": "careful"})
        new = self.vault.put_memory(second)
        selected = self.vault.select_memory(domain="accounting", project_id=None)
        self.assertEqual([new["id"]], [item["id"] for item in selected
                                       if item["category"] == "preference"])
        self.assertNotIn(old["id"], {item["id"] for item in selected})
        compacted = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual(1, compacted["expired"])
        self.assertEqual(1, self.vault.count("memory_records"))


    def test_state_entity_materialized_view_evicts_oldest_at_hard_bound(self):
        with mock.patch.object(loom_vault, "MAX_ENTITY_TYPE", 3), \
                mock.patch.object(loom_vault, "MAX_STATE_ENTITIES", 3):
            for index in range(4):
                self.vault.put_entity("outcome", f"item-{index}", {"index": index})
        self.assertEqual(3, self.vault.count("state_entities"))
        self.assertEqual({1, 2, 3}, {item["value"]["index"]
                                    for item in self.vault.list_entities("outcome")})


if __name__ == "__main__":
    unittest.main()
