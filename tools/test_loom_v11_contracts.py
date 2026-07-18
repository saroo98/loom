"""Frozen Loom 1.1 compatibility and security-contract tests."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LoomV11ContractTests(unittest.TestCase):
    CONTRACTS = {
        "runtime-api.schema.json": {"request", "runtime", "vault", "session"},
        "owner-vault.schema.json": {
            "owner_vault_id", "schema_version", "generation", "deletion_epoch",
            "devices", "bounds"
        },
        "event-envelope.schema.json": {
            "event_id", "owner_vault_id", "device_id", "device_counter",
            "causal_parents", "payload_schema_version", "scope", "domain",
            "project_id", "ciphertext", "prior_event_hash", "signature", "event_hash"
        },
        "adapter-protocol.schema.json": {
            "adapter_version", "agent", "launcher", "owner_receipt"
        },
        "release-manifest.schema.json": {
            "package", "release_sequence", "version", "targets", "schema_range",
            "migration_chain", "adapter_range"
        },
        "transfer-bundle.schema.json": {
            "kind", "bundle_id", "owner_vault_id", "sender_device_id",
            "receiver_device_id", "sequence", "deletion_epoch", "checkpoint_sha256", "request_sha256",
            "receiver_challenge", "expires_at", "owner_vault_commitment", "envelope", "chunks"
        },
        "recovery-contract.schema.json": {
            "kind", "backup_id", "owner_vault_id", "sequence", "deletion_epoch",
            "checkpoint_sha256", "envelope", "chunks"
        },
        "migration-receipt.schema.json": {
            "migration_id", "source_versions", "source_hashes", "before",
            "after", "reconciliation", "activated"
        },
    }

    def test_version_and_every_entry_point_are_current(self):
        self.assertEqual("1.8.0", (ROOT / "VERSION").read_text(encoding="utf-8").strip())
        for path in (ROOT / "README.md", ROOT / "START-HERE.md",
                     ROOT / "skill" / "loom" / "SKILL.md"):
            self.assertIn("1.8.0", path.read_text(encoding="utf-8"), path)

    def test_contracts_are_closed_bounded_and_have_required_fields(self):
        for name, required in self.CONTRACTS.items():
            path = ROOT / "schemas" / name
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", value["$schema"])
            self.assertIs(value.get("additionalProperties"), False, name)
            self.assertEqual(required, set(value["required"]), name)
            self.assertEqual(required, set(value["properties"]), name)
            pending = [value]
            while pending:
                node = pending.pop()
                if isinstance(node, dict):
                    if node.get("type") == "object":
                        self.assertIs(node.get("additionalProperties"), False, name)
                        self.assertIn("properties", node, name)
                    pending.extend(node.values())
                elif isinstance(node, list):
                    pending.extend(node)

    def test_threat_and_compatibility_contracts_name_load_bearing_boundaries(self):
        threat = (ROOT / "docs" / "loom-1.1-threat-model.md").read_text(encoding="utf-8")
        compatibility = (ROOT / "docs" / "loom-1.1-compatibility.md").read_text(encoding="utf-8")
        for phrase in (
                "fully compromised operating-system account",
                "Passive Observer", "rollback", "replay", "split-brain",
                "Accepted Goal Status"):
            self.assertIn(phrase, threat)
        for phrase in (
                "No semantic disappearance", "No scope widening",
                "No implicit activation", "No provenance loss",
                "Executable payloads never transfer"):
            self.assertIn(phrase, compatibility)

    def test_sanitized_historical_fixtures_cover_required_states(self):
        fixture_root = ROOT / "tools" / "fixtures" / "legacy"
        fixtures = list(fixture_root.rglob("fixture.json"))
        self.assertGreaterEqual(len(fixtures), 2)
        statuses = set()
        for path in fixtures:
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(value["sanitized"])
            self.assertNotIn("C:\\Users\\", json.dumps(value))
            statuses.update(item["status"] for item in value["records"])
        self.assertTrue({"active", "dormant", "archived", "forgotten"} <= statuses)


if __name__ == "__main__":
    unittest.main()
