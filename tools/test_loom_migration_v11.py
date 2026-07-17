"""Lossless, idempotent Loom 1.0 to 1.1 migration tests."""

import base64
import hashlib
import hmac
import json
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_memory
import loom_migrate
import loom_vault
import loom_vault_adapter
import types


class FixtureCrypto:
    production_safe = False

    def __init__(self):
        self.key = hashlib.sha256(b"migration-fixture-key").digest()

    def seal(self, plaintext, aad):
        mask = hashlib.sha256(self.key + aad).digest()
        body = bytes(value ^ mask[index % len(mask)] for index, value in enumerate(plaintext))
        tag = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        return base64.b64encode(tag + body)

    def open(self, ciphertext, aad):
        raw = base64.b64decode(ciphertext, validate=True)
        tag, body = raw[:32], raw[32:]
        if not hmac.compare_digest(tag, hmac.new(self.key, aad + body, hashlib.sha256).digest()):
            raise ValueError("authentication failed")
        mask = hashlib.sha256(self.key + aad).digest()
        return bytes(value ^ mask[index % len(mask)] for index, value in enumerate(body))

    def sign(self, message):
        return base64.b64encode(hmac.new(self.key, message, hashlib.sha256).digest())

    def verify(self, message, signature, _public_key=None):
        return hmac.compare_digest(self.sign(message), signature)

    def blind_index(self, label, value):
        return hmac.new(self.key, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()

    def public_key(self):
        return base64.b64encode(hashlib.sha256(self.key).digest()).decode()


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "home"
        self.install = self.root / "installed"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)
        self.preference = loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        self.domain = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect", future_decision="verification-strategy",
            evidence_count=3, confidence=1.0, domain="three-d")
        forgotten = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="guidance-wasted-work", future_decision="guidance-selection",
            evidence_count=3, confidence=1.0, domain="web")
        loom_memory.forget(self.home, self.instance, forgotten["id"])
        self.source = self.home / "instances" / self.instance
        self.before = loom_migrate.source_inventory(self.source)
        self.crypto = FixtureCrypto()
        self.vault = loom_vault.OwnerVault.create(
            self.home / "vault" / "owner.sqlite3", crypto=self.crypto,
            allow_test_crypto=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_migration_is_read_only_idempotent_and_semantically_reconciled(self):
        first = loom_migrate.migrate_v1(
            self.home, self.install, self.vault, expected_instance_id=self.instance)
        second = loom_migrate.migrate_v1(
            self.home, self.install, self.vault, expected_instance_id=self.instance)
        self.assertEqual("migrated", first["status"])
        self.assertEqual("already-migrated", second["status"])
        self.assertEqual(first["migration_id"], second["migration_id"])
        self.assertEqual(self.before, loom_migrate.source_inventory(self.source))
        selected = self.vault.select_memory(domain="three-d", project_id=None)
        self.assertEqual({self.preference["id"], self.domain["id"]},
                         {record["id"] for record in selected})
        self.assertEqual(first["before"], first["after"])
        self.assertTrue(first["activated"])

    def test_legacy_performance_samples_import_once_without_retro_certification(self):
        performance = self.source / "performance.json"
        performance.write_text(json.dumps({"schema_version": 2,
            "instance_id": self.instance, "total_count": 1, "samples": [{
                "id": "legacy-usage", "input_tokens": 100,
                "cache_read_tokens": 80, "output_tokens": 40,
                "tool_tokens": 10, "retry_tokens": 0, "total_tokens": 230
            }]}), encoding="utf-8")
        before = loom_migrate.source_inventory(self.source)
        first = loom_migrate.migrate_v1(
            self.home, self.install, self.vault, expected_instance_id=self.instance)
        second = loom_migrate.migrate_v1(
            self.home, self.install, self.vault, expected_instance_id=self.instance)
        self.assertEqual("migrated", first["status"])
        self.assertEqual("already-migrated", second["status"])
        self.assertEqual(before, loom_migrate.source_inventory(self.source))
        records = self.vault.list_entities("performance-observation", limit=8)
        self.assertEqual(1, len(records))
        self.assertEqual("legacy-ambiguous", records[0]["value"]["measurement_status"])
        self.assertIsNone(records[0]["value"]["processed_total_tokens"])

    def test_tombstones_import_before_active_rows_and_block_resurrection(self):
        receipt = loom_migrate.migrate_v1(
            self.home, self.install, self.vault, expected_instance_id=self.instance)
        self.assertGreaterEqual(receipt["after"]["tombstones"], 1)
        store = json.loads((self.source / "active.json").read_text(encoding="utf-8"))
        tombstone = json.loads((self.source / "tombstones.json").read_text(encoding="utf-8"))
        forgotten_id = tombstone["entries"][0]["record_id"]
        resurrected = dict(store["records"][0])
        resurrected["id"] = forgotten_id
        resurrected["statement"] = "wrongly resurrected private rule"
        result = loom_migrate.import_legacy_record(
            self.vault, resurrected, source_sequence=0)
        self.assertEqual("forgotten", result["status"])

    def test_wrong_instance_or_changed_source_fails_without_vault_mutation(self):
        generation = self.vault.identity()["generation"]
        with self.assertRaisesRegex(loom_migrate.MigrationError, "marker"):
            loom_migrate.migrate_v1(
                self.home, self.install, self.vault,
                expected_instance_id=str(uuid.uuid4()))
        self.assertEqual(generation, self.vault.identity()["generation"])

    def test_activation_failure_leaves_live_vault_byte_and_semantics_unchanged(self):
        before_bytes = self.vault.path.read_bytes()
        before_generation = self.vault.identity()["generation"]

        def refuse_activation(_source, _destination):
            raise OSError("injected pointer switch failure")

        with self.assertRaisesRegex(loom_migrate.MigrationError, "failed safely"):
            loom_migrate.migrate_v1(
                self.home, self.install, self.vault,
                expected_instance_id=self.instance, activate=refuse_activation)
        self.assertEqual(before_bytes, self.vault.path.read_bytes())
        self.assertEqual(before_generation, self.vault.identity()["generation"])
        self.assertEqual(0, self.vault.count("memory_records"))

    def test_legacy_project_memory_rekeys_only_for_same_observed_lineage(self):
        project = self.root / "project"
        project.mkdir()
        legacy_project_id = loom_memory.project_identity(
            self.instance, project, state_mode="filesystem")
        record = loom_memory.add_record(
            self.home, self.instance, scope="project", category="process",
            statement="Keep the project-specific audit ledger.", provenance="stated",
            evidence_count=1, domain="accounting", project_id=legacy_project_id,
            confidence=1.0)
        loom_migrate.migrate_v1(
            self.home, self.install, self.vault, expected_instance_id=self.instance)
        current_project_id = loom_memory.project_identity(
            self.vault.identity()["owner_vault_id"], project, state_mode="filesystem")
        adapter = loom_vault_adapter.VaultMemoryAdapter(
            owner_home=self.home, vault=self.vault, project_root=project)
        context = types.SimpleNamespace(
            project_id=current_project_id,
            prepared=types.SimpleNamespace(
                route_contract={"tier": "M"}, domains=("accounting",)),
            intent="plan")
        result = adapter.housekeeping(context)
        self.assertEqual(1, result["project_memory_rekeyed"])
        selected = self.vault.select_memory(
            domain="accounting", project_id=current_project_id)
        self.assertIn(record["id"], {item["id"] for item in selected})
        unrelated = self.root / "other"
        unrelated.mkdir()
        other_id = loom_memory.project_identity(
            self.vault.identity()["owner_vault_id"], unrelated, state_mode="filesystem")
        self.assertNotIn(record["id"], {item["id"] for item in self.vault.select_memory(
            domain="accounting", project_id=other_id)})


if __name__ == "__main__":
    unittest.main()
