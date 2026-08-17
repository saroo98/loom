"""Loom 1.1 owner-vault identity, encryption, and transaction tests."""

import base64
import datetime as dt
import hashlib
import hmac
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

import loom_vault
import loom_reliability


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

    def executor_guard_head(self, *, project_id="p-" + "7" * 32,
                            action_id="00000000-0000-4000-8000-00000000e701",
                            sequence=1, previous_head_sha256=None,
                            coverage_state="awaiting-host", operations=None,
                            freeze=None):
        owner_vault_id = self.vault.identity()["owner_vault_id"]
        value = {
            "schema_version": 3,
            "kind": "loom-executor-guard-head-v1",
            "owner_vault_id": owner_vault_id,
            "action_id": action_id,
            "project_id": project_id,
            "generation_id": "generation-1",
            "action_operation_id": "8" * 64,
            "sequence": sequence,
            "previous_head_sha256": previous_head_sha256,
            "coverage_state": coverage_state,
            "host_session_sha256": None,
            "coverage_failure": False,
            "operations": list(operations or []),
            "freeze": freeze,
            "storage_parent_identity": {
                "platform": "test", "path_sha256": "9" * 64,
                "kind": "directory", "device": 1, "inode": 2,
            },
        }
        value["guard_sha256"] = hashlib.sha256(json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")).hexdigest()
        value["guard_authentication"] = {
            "mode": "owner-vault-blind-index-v1",
            "owner_vault_id": owner_vault_id,
            "tag": self.crypto.blind_index(
                "executor-guard-head-v1",
                ":".join((
                    owner_vault_id, project_id, action_id, str(sequence),
                    previous_head_sha256 or "absent", value["guard_sha256"]))),
        }
        return value

    def test_executor_guard_head_cas_is_monotonic_and_lost_response_idempotent(self):
        """Break caught: no canonical monotonic guard authority exists in the vault."""
        first = self.executor_guard_head()

        stored = self.vault.advance_executor_guard_head(
            first["project_id"], expected_predecessor_sha256=None,
            candidate=first)
        repeated = self.vault.advance_executor_guard_head(
            first["project_id"], expected_predecessor_sha256=None,
            candidate=first)

        self.assertFalse(stored["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(first, self.vault.read_executor_guard_head(first["project_id"]))

        second = self.executor_guard_head(
            sequence=2, previous_head_sha256=first["guard_sha256"],
            coverage_state="active")
        second["host_session_sha256"] = "a" * 64
        unsigned = {key: item for key, item in second.items()
                    if key not in {"guard_sha256", "guard_authentication"}}
        second["guard_sha256"] = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")).hexdigest()
        second["guard_authentication"]["tag"] = self.crypto.blind_index(
            "executor-guard-head-v1",
            ":".join((
                second["owner_vault_id"], second["project_id"],
                second["action_id"], "2", first["guard_sha256"],
                second["guard_sha256"])))
        self.vault.advance_executor_guard_head(
            second["project_id"],
            expected_predecessor_sha256=first["guard_sha256"],
            candidate=second)
        self.assertEqual(second, self.vault.read_executor_guard_head(second["project_id"]))

        stale = self.executor_guard_head(
            sequence=2, previous_head_sha256=first["guard_sha256"])
        with self.assertRaisesRegex(loom_vault.VaultError, "predecessor"):
            self.vault.advance_executor_guard_head(
                stale["project_id"],
                expected_predecessor_sha256=first["guard_sha256"],
                candidate=stale)
        self.assertEqual(second, self.vault.read_executor_guard_head(second["project_id"]))

    def test_executor_guard_head_rejects_generic_put_and_survives_generic_eviction(self):
        """Break caught: generic entity paths can forge, replay, or evict guard authority."""
        head = self.executor_guard_head()
        self.vault.advance_executor_guard_head(
            head["project_id"], expected_predecessor_sha256=None,
            candidate=head)

        with self.assertRaisesRegex(loom_vault.VaultError, "reserved"):
            self.vault.put_entity(
                loom_vault.EXECUTOR_GUARD_HEAD_ENTITY_TYPE,
                head["project_id"], head, source_sequence=999)
        with mock.patch.object(loom_vault, "MAX_STATE_ENTITIES", 3):
            for index in range(5):
                self.vault.put_entity("ordinary", f"item-{index}", {"index": index})

        self.assertEqual(head, self.vault.read_executor_guard_head(head["project_id"]))

        reopened = loom_vault.OwnerVault.open(
            self.path, crypto=self.crypto, allow_test_crypto=True)
        self.assertEqual(3, reopened.identity()["schema_version"])
        self.assertEqual(head, reopened.read_executor_guard_head(head["project_id"]))

        second = self.executor_guard_head(
            project_id="p-" + "8" * 32,
            action_id="00000000-0000-4000-8000-00000000e702")
        with mock.patch.object(loom_vault, "MAX_STATE_ENTITIES", 1), \
                self.assertRaisesRegex(loom_vault.VaultError, "bound"):
            self.vault.advance_executor_guard_head(
                second["project_id"], expected_predecessor_sha256=None,
                candidate=second)
        self.assertEqual(head, self.vault.read_executor_guard_head(head["project_id"]))
        self.assertIsNone(self.vault.read_executor_guard_head(second["project_id"]))

    def test_authenticated_merged_event_cannot_regress_executor_guard_head(self):
        """Break caught: a signed higher-rank generic event can launder a stale head."""
        head = self.executor_guard_head()
        self.vault.advance_executor_guard_head(
            head["project_id"], expected_predecessor_sha256=None,
            candidate=head)
        source_path = self.home / "checkpoints" / "guard-event-source.sqlite3"
        self.vault.online_backup(source_path)
        source = loom_vault.OwnerVault.open(
            source_path, crypto=self.crypto, allow_test_crypto=True)

        def sign_reserved_event(connection):
            body = {
                "entity_type": loom_vault.EXECUTOR_GUARD_HEAD_ENTITY_TYPE,
                "entity_id": head["project_id"],
                "value": {**head, "sequence": 999},
            }
            source._next_event(
                connection, kind="state-entity-upsert", payload=body,
                scope="vault", domain_tag=None, project_tag=None)

        source.run_transaction(sign_reserved_event)
        events = source.export_events()
        before_generation = self.vault.identity()["generation"]

        with self.assertRaisesRegex(loom_vault.VaultError, "reserved"):
            self.vault.merge_events(events)

        self.assertEqual(before_generation, self.vault.identity()["generation"])
        self.assertEqual(head, self.vault.read_executor_guard_head(head["project_id"]))

    def test_executor_guard_head_two_vault_cas_has_one_winner(self):
        """Break caught: two writers can both advance from one predecessor."""
        other = loom_vault.OwnerVault.open(
            self.path, crypto=self.crypto, allow_test_crypto=True)
        first = self.executor_guard_head()
        self.vault.advance_executor_guard_head(
            first["project_id"], expected_predecessor_sha256=None,
            candidate=first)
        candidate_a = self.executor_guard_head(
            action_id=first["action_id"], sequence=2,
            previous_head_sha256=first["guard_sha256"])
        candidate_b = json.loads(json.dumps(candidate_a))
        candidate_b["coverage_failure"] = True
        unsigned = {key: item for key, item in candidate_b.items()
                    if key not in {"guard_sha256", "guard_authentication"}}
        candidate_b["guard_sha256"] = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")).hexdigest()
        candidate_b["guard_authentication"]["tag"] = self.crypto.blind_index(
            "executor-guard-head-v1",
            ":".join((candidate_b["owner_vault_id"], candidate_b["project_id"],
                       candidate_b["action_id"], "2", first["guard_sha256"],
                       candidate_b["guard_sha256"])))
        barrier = threading.Barrier(2)
        outcomes = []

        def advance(vault, candidate):
            barrier.wait()
            try:
                vault.advance_executor_guard_head(
                    candidate["project_id"],
                    expected_predecessor_sha256=first["guard_sha256"],
                    candidate=candidate)
                outcomes.append("stored")
            except loom_vault.VaultError:
                outcomes.append("blocked")

        threads = [
            threading.Thread(target=advance, args=(self.vault, candidate_a)),
            threading.Thread(target=advance, args=(other, candidate_b)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(["blocked", "stored"], sorted(outcomes))
        self.assertIn(
            self.vault.read_executor_guard_head(first["project_id"]),
            (candidate_a, candidate_b))

    def test_executor_guard_head_transaction_failure_preserves_head_and_generation(self):
        """Break caught: failed head persistence can advance either authority surface."""
        first = self.executor_guard_head()
        self.vault.advance_executor_guard_head(
            first["project_id"], expected_predecessor_sha256=None,
            candidate=first)
        second = self.executor_guard_head(
            sequence=2, previous_head_sha256=first["guard_sha256"])
        before_generation = self.vault.identity()["generation"]
        real_read = self.vault._read_executor_guard_head_connection
        reads = 0

        def fail_reread(connection, project_id):
            nonlocal reads
            reads += 1
            if reads == 2:
                raise sqlite3.OperationalError("injected guard reread failure")
            return real_read(connection, project_id)

        with mock.patch.object(
                self.vault, "_read_executor_guard_head_connection",
                side_effect=fail_reread), \
                self.assertRaises(loom_vault.VaultError):
            self.vault.advance_executor_guard_head(
                second["project_id"],
                expected_predecessor_sha256=first["guard_sha256"],
                candidate=second)
        self.assertEqual(before_generation, self.vault.identity()["generation"])
        self.assertEqual(first, self.vault.read_executor_guard_head(first["project_id"]))

    def generation_archive(self, *, project_id, generation_id="generation-1",
                           terminal_phase="terminal-completed"):
        root = self.home / f"archive-{generation_id}"
        root.mkdir()
        raw = b"# Reviewed generation\n"
        (root / "MANIFEST.md").write_bytes(raw)
        tree_manifest = loom_reliability.exact_tree_manifest(
            root, max_entries=1024, max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=16 * 1024 * 1024)
        payload = {
            "schema_version": 1,
            "project_id": project_id,
            "generation_id": generation_id,
            "terminal_phase": terminal_phase,
            "active_index_sha256": "1" * 64,
            "lifecycle_sha256": "2" * 64,
            "plan_semantics_sha256": "3" * 64,
            "tree_sha256": tree_manifest["root_sha256"],
            "tree_manifest": tree_manifest,
            "files": [{
                "path": "MANIFEST.md",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "content_base64": base64.b64encode(raw).decode("ascii"),
            }],
        }
        payload["archive_sha256"] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        return payload

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

    def test_semantically_identical_new_id_does_not_claim_active_after_forget(self):
        record = self.vault.put_memory(self.record())
        self.vault.forget_memory(record["id"], reason="owner-request")
        replacement = self.vault.put_memory(self.record(record_id=str(uuid.uuid4())))

        self.assertEqual("forgotten", replacement["status"])
        self.assertIsNone(self.vault.get_memory(replacement["id"]))

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

    def test_plan_revision_archive_is_atomic_backed_up_and_forgotten_without_resurrection(self):
        record_id = "00000000-0000-4000-8000-00000000b501"
        project_id = "p-" + "5" * 32
        prior_plan = b"# Prior plan\n" + (b"x" * 450000)
        archive = {
            "schema_version": 1,
            "kind": "loom-plan-revision-archive-v1",
            "project_id": project_id,
            "action_id": "00000000-0000-4000-8000-00000000b502",
            "revision": 1,
            "presentation_sha256": "1" * 64,
            "pack_sha256": "2" * 64,
            "files": [{
                "path": "MANIFEST.md",
                "sha256": hashlib.sha256(prior_plan).hexdigest(),
                "content_base64": base64.b64encode(prior_plan).decode("ascii"),
            }],
        }
        unsigned = json.dumps(
            archive, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
        archive["archive_sha256"] = hashlib.sha256(unsigned).hexdigest()

        stored = self.vault.put_plan_revision_archive(
            record_id=record_id, project_id=project_id, payload=archive,
            created_at="2026-07-30T12:00:00Z")
        repeated = self.vault.put_plan_revision_archive(
            record_id=record_id, project_id=project_id, payload=archive,
            created_at="2026-07-30T12:00:00Z")

        self.assertEqual(record_id, stored["record_id"])
        self.assertFalse(stored["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(archive, self.vault.get_plan_revision_archive(record_id))
        self.assertEqual(1, self.vault.count("memory_records"))

        backup = self.home / "checkpoints" / "plan-revision.sqlite3"
        self.vault.online_backup(backup)
        reopened = loom_vault.OwnerVault.open(
            backup, crypto=self.crypto, allow_test_crypto=True)
        self.assertEqual(archive, reopened.get_plan_revision_archive(record_id))

        forgotten = self.vault.forget_memory(record_id, reason="owner-request")
        self.assertEqual("complete", forgotten["status"])
        self.assertIsNone(self.vault.get_plan_revision_archive(record_id))
        self.vault.put_entity(
            "plan-revision-archive", record_id,
            {"schema_version": 1, "kind": "stale-replay"},
            source_sequence=1)
        self.assertIsNone(self.vault.get_plan_revision_archive(record_id))
        self.assertEqual(0, self.vault.count("state_entities"))

    def test_plan_revision_archive_transaction_failure_leaves_no_partial_state(self):
        record_id = "00000000-0000-4000-8000-00000000b511"
        project_id = "p-" + "6" * 32
        payload = {
            "kind": "loom-plan-revision-archive-v1",
            "project_id": project_id,
        }
        payload["archive_sha256"] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        real_apply = self.vault._apply_event
        calls = 0

        def fail_after_memory(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise loom_vault.VaultError("injected archive failure")
            return real_apply(*args, **kwargs)

        with mock.patch.object(
                self.vault, "_apply_event", side_effect=fail_after_memory):
            with self.assertRaisesRegex(
                    loom_vault.VaultError, "injected archive failure"):
                self.vault.put_plan_revision_archive(
                    record_id=record_id, project_id=project_id,
                    payload=payload, created_at="2026-07-30T12:00:00Z")

        self.assertEqual(0, self.vault.count("memory_records"))
        self.assertEqual(0, self.vault.count("state_entities"))
        self.assertEqual(0, self.vault.count("events"))

    def test_plan_revision_archive_rejects_an_internally_false_digest(self):
        with self.assertRaisesRegex(
                loom_vault.VaultError,
                "plan revision archive content digest is invalid"):
            self.vault.put_plan_revision_archive(
                record_id="00000000-0000-4000-8000-00000000b512",
                project_id="p-" + "6" * 32,
                payload={
                    "kind": "loom-plan-revision-archive-v1",
                    "project_id": "p-" + "6" * 32,
                    "archive_sha256": "6" * 64,
                },
                created_at="2026-07-30T12:00:00Z")

    def test_plan_generation_archive_is_exact_idempotent_and_forgotten(self):
        record_id = "00000000-0000-4000-8000-00000000b701"
        project_id = "p-" + "7" * 32
        archive = self.generation_archive(project_id=project_id)

        stored = self.vault.put_plan_generation_archive(
            record_id=record_id, project_id=project_id, payload=archive,
            created_at="2026-08-14T12:00:00Z")
        repeated = self.vault.put_plan_generation_archive(
            record_id=record_id, project_id=project_id, payload=archive,
            created_at="2026-08-14T12:00:00Z")

        self.assertFalse(stored["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(archive, self.vault.get_plan_generation_archive(record_id))
        forgotten = self.vault.forget_memory(record_id, reason="owner-request")
        self.assertEqual("complete", forgotten["status"])
        self.assertIsNone(self.vault.get_plan_generation_archive(record_id))

    def test_plan_generation_archive_rejects_a_self_bound_false_tree(self):
        project_id = "p-" + "8" * 32
        archive = self.generation_archive(project_id=project_id)
        archive["tree_sha256"] = "f" * 64
        archive["archive_sha256"] = hashlib.sha256(json.dumps(
            {key: value for key, value in archive.items()
             if key != "archive_sha256"},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()

        with self.assertRaisesRegex(
                loom_vault.VaultError,
                "plan generation archive tree identity is invalid"):
            self.vault.put_plan_generation_archive(
                record_id="00000000-0000-4000-8000-00000000b702",
                project_id=project_id, payload=archive,
                created_at="2026-08-14T12:00:00Z")

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

    def test_slow_concurrent_writers_serialize_before_sqlite_busy_bound(self):
        real_seal = self.crypto.seal

        def slow_seal(plaintext, aad):
            time.sleep(0.35)
            return real_seal(plaintext, aad)

        self.crypto.seal = slow_seal
        errors = []

        def writer(index):
            try:
                self.vault.put_memory(self.record(
                    statement=f"Private slow concurrent invariant {index}",
                    record_id=str(uuid.uuid5(
                        uuid.NAMESPACE_URL, f"loom:slow:{index}"))))
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
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
