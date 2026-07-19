"""Closed schema contracts for orchestration recovery state."""

import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
SCHEMAS = ROOT / "schemas"
sys.path.insert(0, str(TOOLS))

import loom_lint  # noqa: E402
import loom_crypto  # noqa: E402
import loom_orchestrator  # noqa: E402
from v11_test_support import build_vault_helper  # noqa: E402


DIGEST = "a" * 64
ACTION_ID = "11111111-1111-4111-8111-111111111111"
INSTANCE_ID = "22222222-2222-4222-8222-222222222222"
PROJECT_ID = "p-" + "3" * 32
OWNER_VAULT_ID = "44444444-4444-4444-8444-444444444444"


def _errors(value, schema_name, *, schema_root=SCHEMAS):
    report = loom_lint.Report()
    with mock.patch.object(loom_lint, "SCHEMA_DIR", Path(schema_root)):
        loom_lint.validate_schema(report, __file__, value, schema_name)
    return report.errors


def _validate_definition(value, reference):
    """Validate one internal definition through Loom's real schema resolver."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source_name = reference.partition("#")[0]
        (root / source_name).write_bytes((SCHEMAS / source_name).read_bytes())
        wrapper = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": reference,
        }
        (root / "wrapper.schema.json").write_text(
            json.dumps(wrapper), encoding="utf-8")
        return _errors(value, "wrapper.schema.json", schema_root=root)


def _receipt_v1():
    return {
        "schema_version": 1,
        "recovery_id": "recovery-" + "4" * 24,
        "action_id": ACTION_ID,
        "project_id": PROJECT_ID,
        "reason": "interrupted-initialization",
        "source_path": "plans",
        "quarantine_relative": (
            f"instances/{INSTANCE_ID}/runtime/projects/{PROJECT_ID}/"
            f"planning-recovery/{ACTION_ID}/plans"),
        "seed_manifest_sha256": DIGEST,
        "quarantined_manifest_sha256": DIGEST,
        "complete_seed": True,
        "changes_made": True,
        "reversible": True,
        "recovered_at": "2026-07-19T12:00:00Z",
        "receipt_hash": DIGEST,
    }


def _receipt_v2():
    return {
        "schema_version": 2,
        "recovery_id": "recovery-" + "5" * 24,
        "action_id": ACTION_ID,
        "project_id": PROJECT_ID,
        "reason": "cancelled",
        "source_path": "legacy-tombstone",
        "quarantine_relative": None,
        "preserved_relatives": [],
        "seed_manifest_sha256": DIGEST,
        "quarantined_manifest_sha256": None,
        "manifest_schema_version": 2,
        "complete_seed": False,
        "changes_made": False,
        "reversible": False,
        "source_disposition": "preserved-in-place",
        "cleanup_phase": "preserved-in-place",
        "recovered_at": "2026-07-19T12:00:00+00:00",
        "receipt_hash": DIGEST,
    }


def _atomic_rename_state(*, durability="unconfirmed"):
    if durability == "confirmed":
        parent_sync = [
            {"role": "source_parent", "status": "confirmed"},
            {"role": "destination_parent", "status": "confirmed"},
        ]
    else:
        parent_sync = [
            {
                "role": "source_parent",
                "status": "unconfirmed",
                "reason": "windows_directory_flush_unimplemented",
            },
            {
                "role": "destination_parent",
                "status": "unconfirmed",
                "reason": "windows_directory_flush_unimplemented",
            },
        ]
    return {
        "schema_version": 1,
        "operation_id": "b" * 64,
        "source_role": "project_stage",
        "destination_role": "project_quarantine",
        "namespace_state": "committed",
        "durability": durability,
        "changes_made": True,
        "source_observed": "absent",
        "destination_observed": "expected_object",
        "parent_sync": parent_sync,
    }


def _receipt_v3():
    return {
        "schema_version": 3,
        "recovery_id": "recovery-" + "6" * 24,
        "action_id": ACTION_ID,
        "project_id": PROJECT_ID,
        "reason": "interrupted-initialization",
        "source_path": "install-stage",
        "quarantine_scope": "project-local",
        "owner_quarantine_relative": None,
        "project_quarantine_relative": f".loom-recovery-{ACTION_ID}",
        "preserved_relatives": [],
        "preserved_project_relatives": [],
        "seed_manifest_sha256": DIGEST,
        "quarantined_manifest_sha256": DIGEST,
        "manifest_schema_version": 2,
        "complete_seed": True,
        "changes_made": True,
        "reversible": True,
        "source_disposition": "quarantined",
        "cleanup_phase": "reconciliation-required",
        "project_namespace_changed": True,
        "owner_control_changed": False,
        "activation_atomic_rename": None,
        "quarantine_atomic_rename": _atomic_rename_state(),
        "recovered_at": "2026-07-19T12:00:00Z",
        "receipt_hash": DIGEST,
    }


class RecoveryContractSchemaTests(unittest.TestCase):
    ACTION_FIELDS = {
        "schema_version", "action_id", "status", "instance_id", "project_id",
        "request", "invocation_id", "owner_home", "install_root", "cwd",
        "explicit_target", "intent", "tier", "domains", "survey_hash",
        "created_at", "expires_at", "attempts", "max_attempts", "session_id",
        "operation_id", "journal_path", "initial_pack_hash",
        "remove_pristine_pack", "work_order", "prepared", "context", "result",
        "repair_plan", "host_result", "plan_contract", "domain_contract",
        "context_manifest", "continuation_authority", "owner_message",
        "action_hash", "pack_seed", "recovery_receipt",
    }

    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def _persist_real_encrypted_envelope(self, temporary):
        keys = loom_crypto.generate_keys(self.helper)
        crypto = loom_crypto.HelperCrypto(
            self.helper,
            master_key=base64.b64decode(keys["master_key"]),
            signing_key=base64.b64decode(keys["signing_key"]),
        )
        path = Path(temporary) / "orchestrations" / f"{ACTION_ID}.json"
        plaintext = {
            "action_id": ACTION_ID,
            "request": "private owner request that must not persist in plaintext",
        }
        loom_orchestrator._write_action(
            path, plaintext, (crypto, OWNER_VAULT_ID))
        persisted = path.read_bytes()
        return plaintext, persisted, json.loads(persisted), crypto

    def test_real_encrypted_action_persistence_matches_the_outer_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            plaintext, persisted, envelope, crypto = \
                self._persist_real_encrypted_envelope(temporary)

        self.assertNotIn(plaintext["request"].encode("utf-8"), persisted)
        self.assertEqual(
            [], _errors(envelope, "orchestration-action-envelope.schema.json"))
        aad = f"action:{OWNER_VAULT_ID}:{ACTION_ID}".encode("utf-8")
        opened = json.loads(crypto.open(
            envelope["ciphertext"].encode("ascii"), aad))
        self.assertEqual(plaintext["request"], opened["request"])

    def test_encrypted_action_envelope_rejects_unknown_and_missing_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            _plaintext, _persisted, envelope, _crypto = \
                self._persist_real_encrypted_envelope(temporary)

        unknown = copy.deepcopy(envelope)
        unknown["request"] = "plaintext must never become an envelope field"
        self.assertTrue(_errors(
            unknown, "orchestration-action-envelope.schema.json"))

        for field in envelope:
            missing = copy.deepcopy(envelope)
            missing.pop(field)
            with self.subTest(field=field):
                self.assertTrue(_errors(
                    missing, "orchestration-action-envelope.schema.json"))

    def test_encrypted_action_envelope_rejects_malformed_and_authenticated_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            _plaintext, _persisted, envelope, crypto = \
                self._persist_real_encrypted_envelope(temporary)

        malformed = copy.deepcopy(envelope)
        malformed["ciphertext"] = "$" + malformed["ciphertext"][1:]
        self.assertTrue(_errors(
            malformed, "orchestration-action-envelope.schema.json"))

        ciphertext_tamper = copy.deepcopy(envelope)
        first = ciphertext_tamper["ciphertext"][0]
        ciphertext_tamper["ciphertext"] = (
            ("A" if first != "A" else "B")
            + ciphertext_tamper["ciphertext"][1:])
        identity_tampers = []
        for field, value in (
                ("action_id", "55555555-5555-4555-8555-555555555555"),
                ("owner_vault_id", "66666666-6666-4666-8666-666666666666")):
            changed = copy.deepcopy(envelope)
            changed[field] = value
            identity_tampers.append((field, changed))

        for label, tampered in [
                ("ciphertext", ciphertext_tamper), *identity_tampers]:
            with self.subTest(tamper=label):
                self.assertEqual(
                    [], _errors(
                        tampered, "orchestration-action-envelope.schema.json"))
                aad = (
                    f"action:{tampered['owner_vault_id']}:{tampered['action_id']}"
                ).encode("utf-8")
                with self.assertRaises(loom_crypto.CryptoError):
                    crypto.open(tampered["ciphertext"].encode("ascii"), aad)

    def test_decrypted_action_inner_contract_is_current_complete_and_closed(self):
        schema = json.loads((SCHEMAS / "orchestration-action.schema.json").read_text(
            encoding="utf-8"))
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        self.assertEqual("Decrypted Loom orchestration action v8", schema["title"])
        self.assertIn("authenticated plaintext", schema["description"])
        self.assertIn("does not describe the persisted encrypted file",
                      schema["description"])
        self.assertEqual("object", schema["type"])
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(self.ACTION_FIELDS, set(schema["required"]))
        self.assertEqual(self.ACTION_FIELDS, set(schema["properties"]))
        self.assertEqual(8, schema["properties"]["schema_version"]["const"])

    def test_seed_manifest_v1_and_v2_are_both_strict(self):
        legacy = {
            "schema_version": 1,
            "files": [{"path": "intake.md", "bytes": 12, "sha256": DIGEST}],
            "root_sha256": DIGEST,
        }
        current = {
            "schema_version": 2,
            "policy": "exact-tree-no-extended-data-v1",
            "platform": "posix",
            "entries": [
                {"path": ".", "kind": "directory", "mode": 493},
                {"path": "intake.md", "kind": "file", "mode": 420,
                 "bytes": 12, "sha256": DIGEST, "links": 1},
            ],
            "file_count": 1,
            "directory_count": 1,
            "total_bytes": 12,
            "root_sha256": DIGEST,
        }
        reference = "orchestration-action.schema.json#/$defs/seedManifest"
        self.assertEqual([], _validate_definition(legacy, reference))
        self.assertEqual([], _validate_definition(current, reference))

        unknown = copy.deepcopy(current)
        unknown["entries"][1]["owner_note"] = "must be rejected"
        self.assertTrue(_validate_definition(unknown, reference))

        mixed = copy.deepcopy(legacy)
        mixed["policy"] = current["policy"]
        self.assertTrue(_validate_definition(mixed, reference))

    def test_recovery_receipt_v1_v2_and_v3_are_all_strict(self):
        self.assertEqual([], _errors(_receipt_v1(), "recovery-receipt.schema.json"))
        self.assertEqual([], _errors(_receipt_v2(), "recovery-receipt.schema.json"))
        self.assertEqual([], _errors(_receipt_v3(), "recovery-receipt.schema.json"))

        unknown = _receipt_v2()
        unknown["journal_phase"] = "not part of the final receipt"
        self.assertTrue(_errors(unknown, "recovery-receipt.schema.json"))

        mixed = _receipt_v1()
        mixed["source_disposition"] = "quarantined"
        self.assertTrue(_errors(mixed, "recovery-receipt.schema.json"))

        legacy_source_widening = _receipt_v1()
        legacy_source_widening["source_path"] = "owner-stage"
        self.assertTrue(_errors(
            legacy_source_widening, "recovery-receipt.schema.json"))

        legacy_v2_widening = _receipt_v2()
        legacy_v2_widening["project_quarantine_relative"] = \
            f".loom-recovery-{ACTION_ID}"
        self.assertTrue(_errors(
            legacy_v2_widening, "recovery-receipt.schema.json"))

    def test_v2_receipt_rejects_impossible_disposition_combinations(self):
        changed_without_quarantine = _receipt_v2()
        changed_without_quarantine.update({
            "changes_made": True,
            "reversible": True,
            "source_disposition": "quarantined",
            "cleanup_phase": "gc-complete",
        })
        self.assertTrue(_errors(
            changed_without_quarantine, "recovery-receipt.schema.json"))

        quarantined = _receipt_v2()
        quarantined.update({
            "source_path": "plans",
            "quarantine_relative": (
                f"instances/{INSTANCE_ID}/runtime/projects/{PROJECT_ID}/"
                f"planning-recovery/{ACTION_ID}/plans"),
            "quarantined_manifest_sha256": DIGEST,
            "complete_seed": True,
            "changes_made": True,
            "reversible": True,
            "source_disposition": "quarantined",
            "cleanup_phase": "gc-complete",
        })
        self.assertEqual([], _errors(
            quarantined, "recovery-receipt.schema.json"))

        unsafe_relative = _receipt_v2()
        unsafe_relative["preserved_relatives"] = ["../outside-owner-home"]
        self.assertTrue(_errors(
            unsafe_relative, "recovery-receipt.schema.json"))

    def test_v3_quarantine_requires_exactly_one_scoped_relative_location(self):
        project = _receipt_v3()
        self.assertEqual([], _errors(
            project, "recovery-receipt.schema.json"))

        owner = _receipt_v3()
        owner.update({
            "source_path": "owner-stage",
            "quarantine_scope": "owner-home",
            "owner_quarantine_relative": (
                f"instances/{INSTANCE_ID}/runtime/projects/{PROJECT_ID}/"
                f"planning-recovery/{ACTION_ID}/plans"),
            "project_quarantine_relative": None,
            "project_namespace_changed": False,
            "owner_control_changed": True,
            "quarantine_atomic_rename": _atomic_rename_state(durability="confirmed"),
            "cleanup_phase": "gc-complete",
        })
        self.assertEqual([], _errors(
            owner, "recovery-receipt.schema.json"))

        project_to_owner = copy.deepcopy(owner)
        project_to_owner.update({
            "source_path": "plans",
            "project_namespace_changed": True,
        })
        self.assertEqual([], _errors(
            project_to_owner, "recovery-receipt.schema.json"))

        understated_project_move = copy.deepcopy(project_to_owner)
        understated_project_move["project_namespace_changed"] = False
        self.assertTrue(_errors(
            understated_project_move, "recovery-receipt.schema.json"))

        both = copy.deepcopy(owner)
        both["project_quarantine_relative"] = f".loom-recovery-{ACTION_ID}"
        self.assertTrue(_errors(both, "recovery-receipt.schema.json"))

        neither = _receipt_v3()
        neither["project_quarantine_relative"] = None
        self.assertTrue(_errors(neither, "recovery-receipt.schema.json"))

        wrong_scope = _receipt_v3()
        wrong_scope["quarantine_scope"] = "owner-home"
        self.assertTrue(_errors(wrong_scope, "recovery-receipt.schema.json"))

        owner_to_project = _receipt_v3()
        owner_to_project["source_path"] = "owner-stage"
        self.assertTrue(_errors(
            owner_to_project, "recovery-receipt.schema.json"))

    def test_v3_project_locations_are_closed_bounded_and_scope_relative(self):
        for value in (
                f"subdir/.loom-recovery-{ACTION_ID}",
                f"../.loom-recovery-{ACTION_ID}",
                f"C:/.loom-recovery-{ACTION_ID}",
                ".loom-recovery-not-a-uuid",
                f".loom-recovery-{ACTION_ID}/child"):
            receipt = _receipt_v3()
            receipt["project_quarantine_relative"] = value
            with self.subTest(value=value):
                self.assertTrue(_errors(
                    receipt, "recovery-receipt.schema.json"))

        allowed = [
            "plans",
            f".loom-plan-stage-{ACTION_ID}",
            f".loom-recovery-{ACTION_ID}",
            f".loom-plan-recovery-{ACTION_ID}-plans",
        ]
        for value in allowed:
            receipt = _receipt_v3()
            receipt.update({
                "quarantine_scope": None,
                "project_quarantine_relative": None,
                "quarantined_manifest_sha256": None,
                "complete_seed": False,
                "preserved_project_relatives": [value],
                "changes_made": False,
                "reversible": False,
                "source_disposition": "preserved-in-place",
                "cleanup_phase": "preserved-in-place",
                "project_namespace_changed": False,
                "quarantine_atomic_rename": None,
            })
            with self.subTest(allowed=value):
                self.assertEqual([], _errors(
                    receipt, "recovery-receipt.schema.json"))

        receipt = _receipt_v3()
        receipt.update({
            "quarantine_scope": None,
            "project_quarantine_relative": None,
            "quarantined_manifest_sha256": None,
            "complete_seed": False,
            "preserved_project_relatives": ["arbitrary.txt"],
            "changes_made": False,
            "reversible": False,
            "source_disposition": "preserved-in-place",
            "cleanup_phase": "preserved-in-place",
            "project_namespace_changed": False,
            "quarantine_atomic_rename": None,
        })
        self.assertTrue(_errors(receipt, "recovery-receipt.schema.json"))

    def test_v3_preserved_and_not_present_have_no_quarantine_location(self):
        preserved = _receipt_v3()
        preserved.update({
            "quarantine_scope": None,
            "project_quarantine_relative": None,
            "preserved_project_relatives": [f".loom-plan-stage-{ACTION_ID}"],
            "quarantined_manifest_sha256": None,
            "complete_seed": False,
            "changes_made": False,
            "reversible": False,
            "source_disposition": "preserved-in-place",
            "cleanup_phase": "preserved-in-place",
            "project_namespace_changed": False,
            "quarantine_atomic_rename": None,
        })
        self.assertEqual([], _errors(
            preserved, "recovery-receipt.schema.json"))

        preserved_with_location = copy.deepcopy(preserved)
        preserved_with_location["project_quarantine_relative"] = \
            f".loom-recovery-{ACTION_ID}"
        self.assertTrue(_errors(
            preserved_with_location, "recovery-receipt.schema.json"))

        not_present = _receipt_v3()
        not_present.update({
            "source_path": "none",
            "quarantine_scope": None,
            "project_quarantine_relative": None,
            "quarantined_manifest_sha256": None,
            "complete_seed": False,
            "changes_made": False,
            "reversible": False,
            "source_disposition": "not-present",
            "cleanup_phase": "gc-complete",
            "project_namespace_changed": False,
            "quarantine_atomic_rename": None,
        })
        self.assertEqual([], _errors(
            not_present, "recovery-receipt.schema.json"))

        not_present_after_activation = copy.deepcopy(not_present)
        not_present_after_activation["activation_atomic_rename"] = \
            _atomic_rename_state()
        not_present_after_activation["cleanup_phase"] = "reconciliation-required"
        self.assertEqual([], _errors(
            not_present_after_activation, "recovery-receipt.schema.json"))

        not_present_with_preserved = copy.deepcopy(not_present)
        not_present_with_preserved["preserved_project_relatives"] = ["plans"]
        self.assertTrue(_errors(
            not_present_with_preserved, "recovery-receipt.schema.json"))

        preserved_with_complete_seed = copy.deepcopy(preserved)
        preserved_with_complete_seed["complete_seed"] = True
        self.assertTrue(_errors(
            preserved_with_complete_seed, "recovery-receipt.schema.json"))

        not_present_with_complete_seed = copy.deepcopy(not_present)
        not_present_with_complete_seed["complete_seed"] = True
        self.assertTrue(_errors(
            not_present_with_complete_seed, "recovery-receipt.schema.json"))

    def test_v3_preserved_owner_stage_uses_its_exact_owner_relative_locator(self):
        receipt = _receipt_v3()
        receipt.update({
            "source_path": "owner-stage",
            "quarantine_scope": None,
            "project_quarantine_relative": None,
            "preserved_relatives": [
                f"instances/{INSTANCE_ID}/runtime/projects/{PROJECT_ID}/"
                f"orchestrations/.staging/{ACTION_ID}/plans"],
            "preserved_project_relatives": [],
            "quarantined_manifest_sha256": None,
            "complete_seed": False,
            "changes_made": False,
            "reversible": False,
            "source_disposition": "preserved-in-place",
            "cleanup_phase": "preserved-in-place",
            "project_namespace_changed": False,
            "owner_control_changed": False,
            "quarantine_atomic_rename": None,
        })
        self.assertEqual([], _errors(receipt, "recovery-receipt.schema.json"))

        wrong = copy.deepcopy(receipt)
        wrong["preserved_relatives"] = [
            f"instances/{INSTANCE_ID}/runtime/projects/{PROJECT_ID}/"
            f"orchestrations/.staging/{ACTION_ID}/other"]
        self.assertTrue(_errors(wrong, "recovery-receipt.schema.json"))

    def test_v3_scoped_change_booleans_cannot_misreport_control(self):
        owner_claim = _receipt_v3()
        owner_claim["owner_control_changed"] = True
        self.assertTrue(_errors(
            owner_claim, "recovery-receipt.schema.json"))

        project_claim = _receipt_v3()
        project_claim["project_namespace_changed"] = False
        self.assertTrue(_errors(
            project_claim, "recovery-receipt.schema.json"))

    def test_v3_atomic_rename_state_is_closed_bounded_and_semantic(self):
        receipt = _receipt_v3()
        encoded = json.dumps(
            receipt["quarantine_atomic_rename"],
            sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 4096)
        self.assertEqual([], _errors(
            receipt, "recovery-receipt.schema.json"))

        mutations = []
        unknown = copy.deepcopy(receipt)
        unknown["quarantine_atomic_rename"]["owner_path"] = "forbidden"
        mutations.append(("unknown", unknown))
        oversized_role = copy.deepcopy(receipt)
        oversized_role["quarantine_atomic_rename"]["source_role"] = "a" * 65
        mutations.append(("oversized-role", oversized_role))
        wrong_order = copy.deepcopy(receipt)
        wrong_order["quarantine_atomic_rename"]["parent_sync"].reverse()
        mutations.append(("parent-order", wrong_order))
        false_change = copy.deepcopy(receipt)
        false_change["quarantine_atomic_rename"]["changes_made"] = False
        mutations.append(("false-change", false_change))
        committed_wrong_destination = copy.deepcopy(receipt)
        committed_wrong_destination["quarantine_atomic_rename"][
            "destination_observed"] = "absent"
        mutations.append(("committed-destination", committed_wrong_destination))
        confirmed_with_unconfirmed_sync = copy.deepcopy(receipt)
        confirmed_with_unconfirmed_sync["quarantine_atomic_rename"][
            "durability"] = "confirmed"
        mutations.append(("confirmed-sync", confirmed_with_unconfirmed_sync))
        unconfirmed_with_confirmed_sync = copy.deepcopy(receipt)
        unconfirmed_with_confirmed_sync["quarantine_atomic_rename"] = \
            _atomic_rename_state(durability="confirmed")
        unconfirmed_with_confirmed_sync["quarantine_atomic_rename"][
            "durability"] = "unconfirmed"
        mutations.append(("unconfirmed-sync", unconfirmed_with_confirmed_sync))

        for label, mutation in mutations:
            with self.subTest(label=label):
                self.assertTrue(_errors(
                    mutation, "recovery-receipt.schema.json"))

    def test_v3_atomic_reconciliation_requires_explicit_cleanup_phase(self):
        receipt = _receipt_v3()
        receipt["cleanup_phase"] = "gc-complete"
        self.assertTrue(_errors(
            receipt, "recovery-receipt.schema.json"))

        confirmed_activation = _receipt_v3()
        confirmed_activation.update({
            "quarantine_scope": None,
            "project_quarantine_relative": None,
            "preserved_project_relatives": [f".loom-plan-stage-{ACTION_ID}"],
            "quarantined_manifest_sha256": None,
            "complete_seed": False,
            "changes_made": False,
            "reversible": False,
            "source_disposition": "preserved-in-place",
            "cleanup_phase": "preserved-in-place",
            "project_namespace_changed": False,
            "activation_atomic_rename": _atomic_rename_state(durability="confirmed"),
            "quarantine_atomic_rename": None,
        })
        self.assertEqual([], _errors(
            confirmed_activation, "recovery-receipt.schema.json"))

        activation = copy.deepcopy(confirmed_activation)
        activation["activation_atomic_rename"] = _atomic_rename_state()
        activation["cleanup_phase"] = "reconciliation-required"
        self.assertEqual([], _errors(
            activation, "recovery-receipt.schema.json"))

        missing_quarantine_evidence = _receipt_v3()
        missing_quarantine_evidence["quarantine_atomic_rename"] = None
        missing_quarantine_evidence["cleanup_phase"] = "reconciliation-required"
        self.assertEqual([], _errors(
            missing_quarantine_evidence, "recovery-receipt.schema.json"))

    def test_v3_preserved_bytes_can_retain_prior_activation_evidence(self):
        preserved = _receipt_v3()
        preserved.update({
            "quarantine_scope": None,
            "project_quarantine_relative": None,
            "preserved_project_relatives": [f".loom-plan-stage-{ACTION_ID}"],
            "quarantined_manifest_sha256": None,
            "complete_seed": False,
            "changes_made": False,
            "reversible": False,
            "source_disposition": "preserved-in-place",
            "cleanup_phase": "reconciliation-required",
            "project_namespace_changed": False,
            "activation_atomic_rename": _atomic_rename_state(),
            "quarantine_atomic_rename": None,
        })
        self.assertEqual([], _errors(
            preserved, "recovery-receipt.schema.json"))

        hidden_reconciliation = copy.deepcopy(preserved)
        hidden_reconciliation["cleanup_phase"] = "preserved-in-place"
        self.assertTrue(_errors(
            hidden_reconciliation, "recovery-receipt.schema.json"))

        invented_reconciliation = copy.deepcopy(preserved)
        invented_reconciliation["activation_atomic_rename"] = None
        self.assertTrue(_errors(
            invented_reconciliation, "recovery-receipt.schema.json"))

        quarantine_evidence = copy.deepcopy(preserved)
        quarantine_evidence["quarantine_atomic_rename"] = \
            _atomic_rename_state()
        self.assertTrue(_errors(
            quarantine_evidence, "recovery-receipt.schema.json"))

    def test_action_references_versioned_closed_recovery_contracts(self):
        schema = json.loads((SCHEMAS / "orchestration-action.schema.json").read_text(
            encoding="utf-8"))
        pack_seed = schema["$defs"]["packSeed"]
        self.assertIs(pack_seed["additionalProperties"], False)
        self.assertEqual(set(pack_seed["required"]), set(pack_seed["properties"]))
        self.assertEqual(
            "#/$defs/seedManifest", pack_seed["properties"]["manifest"]["anyOf"][0]["$ref"])
        self.assertEqual(
            "recovery-receipt.schema.json",
            schema["properties"]["recovery_receipt"]["anyOf"][0]["$ref"])


if __name__ == "__main__":
    unittest.main()
