import copy
import json
import tempfile
import unittest
from pathlib import Path

import loom_message
import loom_proofline
import loom_proofline_completion
import loom_proofline_ux
from test_proofline_phase4 import _contract, _draft


ROOT = Path(__file__).resolve().parent.parent


def _proofline():
    request = "Add next and previous gallery navigation."
    contract = _contract(request)
    draft = _draft()
    ledger = loom_proofline.build_material_ledger(
        request=request, plan_contract=contract, semantic_draft=draft)
    assignments = {
        "plan_contract_hash": contract["contract_hash"],
        "assignment_digest": "sha256:" + "a" * 64,
    }
    graph = loom_proofline.build_graph(
        ledger=ledger, plan_contract=contract, semantic_draft=draft,
        assignments=assignments)
    policy = loom_proofline_completion.load_policy(
        ROOT / "contracts" / "proofline-policy-v1.json")
    report = loom_proofline_completion.evaluate(
        ledger=ledger, graph=graph, policy=policy, changed_paths=[],
        authorized_touches=["src/gallery/**", "assets/art/**"],
        lifecycle_sha256="b" * 64)
    return report


def _receipt(operation="a" * 64):
    message = loom_message.from_session(
        status="completed", code="execute-complete", intent="execute",
        tier="M", owner_input_required=False, reversible_action_ids=[],
        detail="Execution complete.", receipt_id="session-" + operation[:16],
        result_path="plans/proofline/trust-card.json")
    return {
        "receipt_hash": "c" * 64,
        "operation_id": operation,
        "intent": "execute",
        "status": "completed",
        "code": "execute-complete",
        "completed_at": "2026-07-29T12:00:00Z",
        "owner_message": message,
        "selected_memory_ids": ["private-memory-id"],
        "selected_preference_ids": ["private-preference-id"],
    }


class ProoflineUXTests(unittest.TestCase):
    def test_two_line_owner_message_is_plain_and_reconstructable(self):
        value = loom_message.from_session(
            status="completed", code="plan-complete", intent="plan", tier="M",
            owner_input_required=False, reversible_action_ids=["undo-1"],
            detail="LOOM_RESULT plans/MANIFEST.md | ready",
            receipt_id="session-1234")
        self.assertEqual(1, value["human"].count("\n"))
        self.assertIn("You can undo this Loom action.", value["human"])
        self.assertNotIn("tier", value["human"].casefold())
        self.assertEqual(value, loom_message.from_session(
            status="completed", code="plan-complete", intent="plan", tier="M",
            owner_input_required=False, reversible_action_ids=["undo-1"],
            detail="LOOM_RESULT plans/MANIFEST.md | ready",
            receipt_id="session-1234", result_path="plans/MANIFEST.md"))

    def test_bundle_firewall_excludes_private_bodies_and_transcripts(self):
        with tempfile.TemporaryDirectory() as raw:
            pack = Path(raw) / "plans"
            proofline = pack / "proofline"
            proofline.mkdir(parents=True)
            report = _proofline()
            (proofline / "completion-report.json").write_text(
                json.dumps(report), encoding="utf-8")
            result = loom_proofline_ux.record_receipt(pack, _receipt())
            self.assertEqual("excluded", result["flight_recorder"]["privacy"][
                "memory_bodies"])
            bundle = proofline / "proof-bundle"
            self.assertEqual(
                loom_proofline_ux.BUNDLE_FILES,
                {path.relative_to(bundle).as_posix()
                 for path in bundle.rglob("*") if path.is_file()})
            persisted = "\n".join(
                path.read_text(encoding="utf-8")
                for path in bundle.rglob("*.json"))
            self.assertNotIn("private-memory-id", persisted)
            self.assertNotIn("private-preference-id", persisted)
            self.assertNotIn("stdout", persisted)

    def test_replay_is_read_only_and_detects_stale_proof(self):
        with tempfile.TemporaryDirectory() as raw:
            pack = Path(raw) / "plans"
            proofline = pack / "proofline"
            proofline.mkdir(parents=True)
            report = _proofline()
            (proofline / "completion-report.json").write_text(
                json.dumps(report), encoding="utf-8")
            loom_proofline_ux.record_receipt(pack, _receipt())
            current = loom_proofline_ux.replay(
                proofline / "proof-bundle", report)
            self.assertEqual("current", current["freshness"])
            self.assertEqual(0, current["commands_executed"])
            self.assertFalse(current["historical_authority_granted"])
            changed = copy.deepcopy(report)
            body = dict(changed)
            body.pop("report_sha256")
            body["lifecycle_sha256"] = "d" * 64
            changed = {**body, "report_sha256": loom_proofline.digest(body)}
            stale = loom_proofline_ux.replay(
                proofline / "proof-bundle", changed)
            self.assertEqual("stale", stale["freshness"])
            self.assertEqual("none", stale["authority_effect"])

    def test_bundle_rejects_every_non_allowlisted_file(self):
        with tempfile.TemporaryDirectory() as raw:
            pack = Path(raw) / "plans"
            proofline = pack / "proofline"
            proofline.mkdir(parents=True)
            report = _proofline()
            (proofline / "completion-report.json").write_text(
                json.dumps(report), encoding="utf-8")
            loom_proofline_ux.record_receipt(pack, _receipt())
            extra = proofline / "proof-bundle" / "private" / "memory-body.json"
            extra.write_text('{"secret":"must not ship"}', encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_proofline_ux.ProofUXError, "privacy firewall"):
                loom_proofline_ux.validate_bundle(
                    proofline / "proof-bundle")


if __name__ == "__main__":
    unittest.main()
