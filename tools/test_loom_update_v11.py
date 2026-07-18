"""Signed staged-update, session pinning, and rollback tests."""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import loom_update
import loom_install


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class SigningFixture:
    def __init__(self):
        self.keys = {name: hashlib.sha256(name.encode()).digest()
                     for name in ("root-a", "root-b", "root-c")}

    def public(self, name):
        return base64.b64encode(self.keys[name]).decode()

    def sign(self, name, value):
        return base64.b64encode(hmac.new(
            self.keys[name], canonical(value), hashlib.sha256).digest()).decode()

    def verify(self, message, signature, public_key):
        key = base64.b64decode(public_key)
        expected = base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()).decode()
        return hmac.compare_digest(expected, signature)

    def bundle(self, payload_root, *, version="1.1.0", sequence=2, bad_hash=False):
        content = (payload_root / "loom-runtime.txt").read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        manifest = {
            "package": "loom", "release_sequence": sequence, "version": version,
            "targets": [{"platform": loom_update.platform_id(),
                         "path": "loom-runtime.txt",
                         "sha256": "0" * 64 if bad_hash else digest,
                         "bytes": len(content)}],
            "schema_range": {"minimum": 1, "maximum": 1},
            "migration_chain": ["vault-1"],
            "adapter_range": {"minimum": 1, "maximum": 1},
        }
        targets = {"version": sequence, "manifest": manifest}
        snapshot = {"version": sequence,
                    "targets_sha256": hashlib.sha256(canonical(targets)).hexdigest()}
        timestamp = {"version": sequence,
                     "snapshot_sha256": hashlib.sha256(canonical(snapshot)).hexdigest(),
                     "expires": "2027-07-15T00:00:00Z"}
        root = {"version": 1, "threshold": 2,
                "keys": {name: self.public(name) for name in self.keys},
                "expires": "2030-01-01T00:00:00Z"}
        signatures = lambda value: [
            {"key_id": name, "signature": self.sign(name, value)}
            for name in ("root-a", "root-b")]
        return {
            "root": {"signed": root, "signatures": signatures(root)},
            "targets": {"signed": targets, "signatures": signatures(targets)},
            "snapshot": {"signed": snapshot, "signatures": signatures(snapshot)},
            "timestamp": {"signed": timestamp, "signatures": signatures(timestamp)},
        }, root


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.plugin = self.root / "plugin-cache" / "loom" / "1.1.0" / "runtime-payload"
        self.plugin.mkdir(parents=True)
        (self.plugin / "loom-runtime.txt").write_text("runtime 1.1", encoding="utf-8")
        self.fixture = SigningFixture()
        self.bundle, self.trusted_root = self.fixture.bundle(self.plugin)
        self.runtime = loom_update.SharedRuntime(
            self.root / "home", plugin_roots=[self.root / "plugin-cache"])
        self.runtime.install_baseline("1.0.0", b"runtime 1.0", release_sequence=1)

    def tearDown(self):
        self.tmp.cleanup()

    def test_platform_id_supports_apple_silicon(self):
        with mock.patch.object(loom_update.platform, "system", return_value="Darwin"), \
                mock.patch.object(loom_update.platform, "machine", return_value="arm64"):
            self.assertEqual("macos-arm64", loom_update.platform_id())

    def stage(self, **kwargs):
        health = {"healthy": True, "migration_complete": True,
                  "disposable_request_passed": True,
                  "before_inventory_sha256": "a" * 64,
                  "after_inventory_sha256": "a" * 64}
        return self.runtime.stage_update(
            self.plugin, self.bundle, trusted_root=self.trusted_root,
            verify_signature=self.fixture.verify,
            vault_schema=1, health_check=lambda _path: health,
            now="2026-07-15T12:00:00Z", **kwargs)

    def test_update_waits_for_active_session_then_switches_atomically(self):
        session = self.runtime.begin_session()
        self.assertEqual(0, session["state_generation"])
        self.assertEqual(0, session["state_schema"])
        staged = self.stage()
        self.assertEqual("staged-active-session", staged["status"])
        self.assertEqual("1.0.0", self.runtime.current()["version"])
        self.runtime.end_session(session["session_id"])
        activated = self.runtime.activate_pending()
        self.assertEqual("activated", activated["status"])
        self.assertEqual("1.1.0", self.runtime.current()["version"])
        state = json.loads(self.runtime.update_state_path.read_text(encoding="utf-8"))
        self.assertEqual("observing", state["state"])
        self.assertEqual(
            ["downloaded", "verified", "staged", "pending", "activated", "observing"],
            [item["state"] for item in state["history"][-6:]])
        pinned = self.runtime.begin_session()
        self.assertEqual("1.1.0", pinned["version"])
        self.runtime.end_session(pinned["session_id"])

    def test_session_pins_verified_owner_vault_generation(self):
        database = self.runtime.home / "vault" / "owner.sqlite3"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            connection.executemany("INSERT INTO metadata(key,value) VALUES(?,?)", [
                ("generation", "7"), ("schema_version", "2")])
            connection.commit()
        finally:
            connection.close()
        lease = self.runtime.begin_session()
        self.assertEqual(7, lease["state_generation"])
        self.assertEqual(2, lease["state_schema"])
        self.runtime.end_session(lease["session_id"])

    def test_corrupt_owner_vault_blocks_session_start(self):
        database = self.runtime.home / "vault" / "owner.sqlite3"
        database.parent.mkdir(parents=True)
        database.write_bytes(b"not sqlite")
        with self.assertRaisesRegex(loom_update.UpdateError, "unverifiable|integrity"):
            self.runtime.begin_session()

    def test_hash_downgrade_and_health_failures_leave_working_runtime_active(self):
        bad_bundle, _ = self.fixture.bundle(self.plugin, bad_hash=True)
        with self.assertRaisesRegex(loom_update.UpdateError, "hash"):
            self.runtime.stage_update(
                self.plugin, bad_bundle, trusted_root=self.trusted_root,
                verify_signature=self.fixture.verify, vault_schema=1,
                health_check=lambda _path: {"healthy": True, "migration_complete": True,
                    "disposable_request_passed": True,
                    "before_inventory_sha256": "a" * 64,
                    "after_inventory_sha256": "a" * 64},
                now="2026-07-15T12:00:00Z")
        self.assertEqual("1.0.0", self.runtime.current()["version"])
        old_bundle, _ = self.fixture.bundle(self.plugin, version="0.9.0", sequence=1)
        with self.assertRaisesRegex(loom_update.UpdateError, "sequence"):
            self.runtime.stage_update(
                self.plugin, old_bundle, trusted_root=self.trusted_root,
                verify_signature=self.fixture.verify, vault_schema=1,
                health_check=lambda _path: {"healthy": True, "migration_complete": True,
                    "disposable_request_passed": True,
                    "before_inventory_sha256": "a" * 64,
                    "after_inventory_sha256": "a" * 64},
                now="2026-07-15T12:00:00Z")
        with self.assertRaisesRegex(loom_update.UpdateError, "health"):
            self.runtime.stage_update(
                self.plugin, self.bundle, trusted_root=self.trusted_root,
                verify_signature=self.fixture.verify, vault_schema=1,
                health_check=lambda _path: {"healthy": False,
                    "migration_complete": False, "disposable_request_passed": False,
                    "before_inventory_sha256": "a" * 64,
                    "after_inventory_sha256": "b" * 64},
                now="2026-07-15T12:00:00Z")
        self.assertEqual("1.0.0", self.runtime.current()["version"])
        state = json.loads(self.runtime.update_state_path.read_text(encoding="utf-8"))
        self.assertEqual("quarantined", state["state"])
        self.assertRegex(state["reason_sha256"], r"^[0-9a-f]{64}$")

    def test_semantic_inventory_mismatch_blocks_activation(self):
        with self.assertRaisesRegex(loom_update.UpdateError, "health"):
            self.runtime.stage_update(
                self.plugin, self.bundle, trusted_root=self.trusted_root,
                verify_signature=self.fixture.verify, vault_schema=1,
                health_check=lambda _path: {
                    "healthy": True, "migration_complete": True,
                    "disposable_request_passed": True,
                    "before_inventory_sha256": "a" * 64,
                    "after_inventory_sha256": "b" * 64},
                now="2026-07-15T12:00:00Z")
        self.assertEqual("1.0.0", self.runtime.current()["version"])

    def test_fresh_install_gets_no_pointer_until_signed_payload_passes(self):
        fresh = loom_update.SharedRuntime(
            self.root / "fresh-home", plugin_roots=[self.root / "plugin-cache"])
        health = {"healthy": True, "migration_complete": True,
                  "disposable_request_passed": True,
                  "before_inventory_sha256": "a" * 64,
                  "after_inventory_sha256": "a" * 64}
        bad, _ = self.fixture.bundle(self.plugin, bad_hash=True)
        with self.assertRaisesRegex(loom_update.UpdateError, "hash"):
            fresh.stage_update(
                self.plugin, bad, trusted_root=self.trusted_root,
                verify_signature=self.fixture.verify, vault_schema=1,
                health_check=lambda _path: health, now="2026-07-15T12:00:00Z")
        self.assertFalse(fresh.current_path.exists())
        installed = fresh.stage_update(
            self.plugin, self.bundle, trusted_root=self.trusted_root,
            verify_signature=self.fixture.verify, vault_schema=1,
            health_check=lambda _path: health, now="2026-07-15T12:00:00Z")
        self.assertEqual("activated", installed["status"])
        self.assertEqual("1.1.0", fresh.current()["version"])
        self.assertIsNone(fresh.current()["previous"])

    def test_pointer_failure_and_rollback_are_safe(self):
        with mock.patch("loom_update.loom_reliability.atomic_write_json",
                        side_effect=OSError("injected pointer failure")):
            with self.assertRaisesRegex(OSError, "injected pointer"):
                self.stage()
        self.assertEqual("1.0.0", self.runtime.current()["version"])

    def test_corrupt_pending_pointer_cannot_replace_working_pointer(self):
        before = self.runtime.current_path.read_bytes()
        self.runtime.pending_path.write_text(json.dumps({
            "version": "1.1.0", "path": "1.0.0",
            "payload_sha256": "a" * 64, "release_sequence": 2,
            "previous": None,
        }), encoding="utf-8")
        with self.assertRaisesRegex(loom_update.UpdateError, "pending.*unsafe"):
            self.runtime.activate_pending()
        self.assertEqual(before, self.runtime.current_path.read_bytes())
        self.assertEqual("1.0.0", self.runtime.current()["version"])

    def test_crashed_session_is_reaped_but_invalid_lease_blocks_uncertain_activation(self):
        runtime = loom_update.SharedRuntime(
            self.root / "crash-home", plugin_roots=[self.root / "plugin-cache"],
            pid_alive=lambda _pid: False)
        runtime.install_baseline("1.0.0", b"runtime 1.0", release_sequence=1)
        lease = runtime.begin_session()
        self.assertTrue((runtime.sessions / f"{lease['session_id']}.json").is_file())
        self.assertEqual([], runtime._active_sessions())
        self.assertFalse((runtime.sessions / f"{lease['session_id']}.json").exists())
        (runtime.sessions / "not-a-lease.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(loom_update.UpdateError, "unknown"):
            runtime._active_sessions()

    def test_current_process_liveness_probe_is_read_only(self):
        self.assertTrue(loom_update.SharedRuntime._pid_alive(os.getpid()))
        self.assertFalse(loom_update.SharedRuntime._pid_alive(-1))
        self.stage()
        self.assertEqual("1.1.0", self.runtime.current()["version"])
        rolled = self.runtime.rollback("bootstrap-failure")
        self.assertEqual("rolled-back", rolled["status"])
        self.assertEqual("1.0.0", self.runtime.current()["version"])

    def test_runtime_archive_extracts_and_path_traversal_fails_safe(self):
        archive_plugin = self.root / "plugin-cache" / "loom" / "1.2.0" / "payload"
        archive_plugin.mkdir(parents=True)
        archive = archive_plugin / "loom-runtime.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("tools/loom_orchestrator.py", "print('ready')")
            package.writestr("bin/loom-vault", "helper")
        (archive_plugin / "loom-runtime.txt").write_text("fixture", encoding="utf-8")
        bundle, root = self.fixture.bundle(archive_plugin, version="1.2.0", sequence=3)
        (archive_plugin / "loom-runtime.txt").unlink()
        target = bundle["targets"]["signed"]["manifest"]["targets"][0]
        target.update(path="loom-runtime.zip", sha256=hashlib.sha256(
            archive.read_bytes()).hexdigest(), bytes=archive.stat().st_size)
        targets = bundle["targets"]["signed"]
        snapshot = bundle["snapshot"]["signed"]
        timestamp = bundle["timestamp"]["signed"]
        bundle["targets"]["signatures"] = [
            {"key_id": name, "signature": self.fixture.sign(name, targets)}
            for name in ("root-a", "root-b")]
        snapshot["targets_sha256"] = hashlib.sha256(canonical(targets)).hexdigest()
        bundle["snapshot"]["signatures"] = [
            {"key_id": name, "signature": self.fixture.sign(name, snapshot)}
            for name in ("root-a", "root-b")]
        timestamp["snapshot_sha256"] = hashlib.sha256(canonical(snapshot)).hexdigest()
        bundle["timestamp"]["signatures"] = [
            {"key_id": name, "signature": self.fixture.sign(name, timestamp)}
            for name in ("root-a", "root-b")]
        health = {"healthy": True, "migration_complete": True,
                  "disposable_request_passed": True,
                  "before_inventory_sha256": "a" * 64,
                  "after_inventory_sha256": "a" * 64}
        result = self.runtime.stage_update(
            archive_plugin, bundle, trusted_root=root,
            verify_signature=self.fixture.verify, vault_schema=1,
            health_check=lambda _path: health, now="2026-07-15T12:00:00Z")
        self.assertEqual("activated", result["status"])
        self.assertTrue((self.runtime.versions / "1.2.0" / "bin" / "loom-vault").is_file())
        self.assertEqual("installed", loom_install.check(
            self.runtime.versions / "1.2.0")["status"])

        hostile = self.root / "hostile.zip"
        with zipfile.ZipFile(hostile, "w") as package:
            package.writestr("../outside.txt", "escape")
        destination = self.root / "extract"
        destination.mkdir()
        with self.assertRaisesRegex(loom_update.UpdateError, "traverses"):
            loom_update._extract_runtime_archive(hostile, destination)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_old_runtime_cleanup_waits_for_ten_sessions_and_thirty_days(self):
        self.stage()
        plugin = self.root / "plugin-cache" / "loom" / "1.2.0" / "runtime-payload"
        plugin.mkdir(parents=True)
        (plugin / "loom-runtime.txt").write_text("runtime 1.2", encoding="utf-8")
        bundle, trusted = self.fixture.bundle(plugin, version="1.2.0", sequence=3)
        health = {"healthy": True, "migration_complete": True,
                  "disposable_request_passed": True,
                  "before_inventory_sha256": "a" * 64,
                  "after_inventory_sha256": "a" * 64}
        self.runtime.stage_update(
            plugin, bundle, trusted_root=trusted, verify_signature=self.fixture.verify,
            vault_schema=1, health_check=lambda _path: health,
            now="2026-07-15T12:00:00Z")
        retained = self.runtime.prune_versions(now="2026-08-20T12:00:00Z")
        self.assertEqual("retained", retained["status"])
        usage_path = self.runtime._usage_path("1.2.0")
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        usage.update(activated_at="2026-07-15T00:00:00Z", successful_sessions=10)
        usage_path.write_text(json.dumps(usage), encoding="utf-8")
        pruned = self.runtime.prune_versions(now="2026-08-20T12:00:00Z")
        self.assertEqual(["1.0.0"], pruned["removed"])
        self.assertTrue((self.runtime.versions / "1.1.0").is_dir())
        self.assertTrue((self.runtime.versions / "1.2.0").is_dir())

    def test_old_runtime_cleanup_refuses_unowned_files(self):
        self.stage()
        plugin = self.root / "plugin-cache" / "loom" / "1.2.0" / "runtime-payload"
        plugin.mkdir(parents=True)
        (plugin / "loom-runtime.txt").write_text("runtime 1.2", encoding="utf-8")
        bundle, trusted = self.fixture.bundle(plugin, version="1.2.0", sequence=3)
        health = {"healthy": True, "migration_complete": True,
                  "disposable_request_passed": True,
                  "before_inventory_sha256": "a" * 64,
                  "after_inventory_sha256": "a" * 64}
        self.runtime.stage_update(
            plugin, bundle, trusted_root=trusted, verify_signature=self.fixture.verify,
            vault_schema=1, health_check=lambda _path: health,
            now="2026-07-15T12:00:00Z")
        usage_path = self.runtime._usage_path("1.2.0")
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        usage.update(activated_at="2026-07-15T00:00:00Z", successful_sessions=10)
        usage_path.write_text(json.dumps(usage), encoding="utf-8")
        victim = self.runtime.versions / "1.0.0" / "owner-added.txt"
        victim.write_text("do not delete", encoding="utf-8")
        with self.assertRaisesRegex(loom_update.UpdateError, "unowned"):
            self.runtime.prune_versions(now="2026-08-20T12:00:00Z")
        self.assertEqual("do not delete", victim.read_text(encoding="utf-8"))

    def test_three_repeated_trust_failures_roll_back_to_last_runtime(self):
        self.stage()
        for expected in (1, 2):
            result = self.runtime.record_trust_health(
                healthy=False, reason="runtime manifest changed")
            self.assertEqual(expected, result["failures"])
            self.assertEqual("1.1.0", self.runtime.current()["version"])
        rolled = self.runtime.record_trust_health(
            healthy=False, reason="runtime manifest changed")
        self.assertEqual("rolled-back", rolled["status"])
        self.assertEqual("1.0.0", self.runtime.current()["version"])

    def test_preexisting_version_directory_without_exact_receipts_never_activates(self):
        final = self.runtime.versions / "1.1.0"
        final.mkdir()
        (final / "unverified.txt").write_text("must not activate", encoding="utf-8")
        health_calls = []

        with self.assertRaisesRegex(loom_update.UpdateError, "existing|receipt|verified"):
            self.runtime.stage_update(
                self.plugin, self.bundle, trusted_root=self.trusted_root,
                verify_signature=self.fixture.verify, vault_schema=1,
                health_check=lambda path: health_calls.append(path),
                now="2026-07-15T12:00:00Z")

        self.assertEqual([], health_calls)
        self.assertEqual("1.0.0", self.runtime.current()["version"])
        self.assertEqual("must not activate", (final / "unverified.txt").read_text(
            encoding="utf-8"))

    def test_exact_existing_runtime_receipt_rejects_changed_owned_bytes(self):
        session = self.runtime.begin_session()
        self.stage()
        final = self.runtime.versions / "1.1.0"
        (final / "loom-runtime.txt").write_text("tampered runtime", encoding="utf-8")

        try:
            with self.assertRaisesRegex(loom_update.UpdateError, "owned bytes"):
                self.stage()
        finally:
            self.runtime.end_session(session["session_id"])

        self.assertEqual("1.0.0", self.runtime.current()["version"])


if __name__ == "__main__":
    unittest.main()
