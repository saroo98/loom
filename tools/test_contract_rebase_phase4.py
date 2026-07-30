import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import loom_contract_rebase
import loom_orchestrator
import loom_proofline
from test_proofline_phase4 import _contract, _draft


ROOT = Path(__file__).resolve().parent.parent


def _subjects():
    request = (
        "Add next and previous gallery navigation. "
        "Preserve every original artwork image.")
    contract = _contract(request)
    draft = _draft()
    ledger = loom_proofline.build_material_ledger(
        request=request, plan_contract=contract, semantic_draft=draft)
    graph = loom_proofline.build_graph(
        ledger=ledger, plan_contract=contract, semantic_draft=draft,
        assignments={
            "plan_contract_hash": contract["contract_hash"],
            "assignment_digest": "sha256:" + "a" * 64,
        })
    work_orders = [
        {"id": item["id"], "touches": item["touches"]}
        for item in draft["work_orders"]]
    return ledger, graph, work_orders


class ContractRebaseTests(unittest.TestCase):
    def setUp(self):
        self.policy = loom_contract_rebase.load_policy(
            ROOT / "contracts" / "contract-rebase-policy-v1.json")
        self.ledger, self.graph, self.work_orders = _subjects()

    def evaluate(self, **changes):
        values = {
            "ledger": self.ledger, "graph": self.graph,
            "work_orders": self.work_orders,
            "changed_paths": ["src/gallery/view.py"],
            "prior_consequence": "material",
            "current_consequence": "material",
            "world_coverage_complete": True,
            "domain_state": "consistent", "policy": self.policy,
        }
        values.update(changes)
        return loom_contract_rebase.evaluate(**values)

    def test_only_disjoint_path_subjects_are_preserved(self):
        report = self.evaluate()
        preserved = {
            (item["subject_type"], item["subject_id"])
            for item in report["preserved"]}
        invalidated = {
            (item["subject_type"], item["subject_id"])
            for item in report["invalidated"]}
        self.assertIn(("work-order", "WO-002"), preserved)
        self.assertIn(("work-order", "WO-001"), invalidated)
        self.assertIn(("evidence", "evidence:WO-001"), invalidated)
        self.assertFalse(report["implementation_authorized"])
        self.assertTrue(report["fresh_action_required"])

    def test_consequence_change_requires_a_decision_and_preserves_nothing(self):
        report = self.evaluate(current_consequence="high")
        self.assertEqual([], report["preserved"])
        self.assertTrue(report["decision_required"])
        self.assertTrue(all(
            item["reason_code"] == "consequence-changed"
            or item["reason_code"] == "material-intent-unresolved"
            for item in report["decision_required"]))

    def test_partial_world_and_domain_conflict_never_authorize(self):
        partial = self.evaluate(world_coverage_complete=False)
        conflicted = self.evaluate(domain_state="conflicted")
        self.assertEqual([], partial["preserved"])
        self.assertEqual([], conflicted["preserved"])
        self.assertFalse(partial["implementation_authorized"])
        self.assertFalse(conflicted["implementation_authorized"])

    def test_report_tampering_and_unsafe_paths_fail_closed(self):
        report = self.evaluate()
        report["fresh_action_required"] = False
        with self.assertRaises(loom_contract_rebase.RebaseError):
            loom_contract_rebase.validate(report)
        with self.assertRaisesRegex(
                loom_contract_rebase.RebaseError, "unsafe"):
            self.evaluate(changed_paths=["../owner/private.txt"])
        with self.assertRaisesRegex(
                loom_contract_rebase.RebaseError, "unsafe"):
            self.evaluate(changed_paths=["src//gallery.py"])

    def test_malformed_rows_and_duplicate_work_orders_fail_closed(self):
        report = self.evaluate()
        report["preserved"][0]["reason_code"] = "invented-reason"
        report["report_sha256"] = loom_proofline.digest({
            key: value for key, value in report.items()
            if key != "report_sha256"
        })
        with self.assertRaisesRegex(
                loom_contract_rebase.RebaseError, "row"):
            loom_contract_rebase.validate(report)
        with self.assertRaisesRegex(
                loom_contract_rebase.RebaseError, "work order"):
            self.evaluate(work_orders=self.work_orders + [self.work_orders[0]])

    def test_orchestrator_uses_domain_consequence_not_repair_tier(self):
        with tempfile.TemporaryDirectory() as temporary:
            pack = Path(temporary) / "plans"
            proofline = pack / "proofline"
            work_orders = pack / "work-orders"
            proofline.mkdir(parents=True)
            work_orders.mkdir()
            (proofline / "material-intent-ledger.json").write_text(
                json.dumps(self.ledger), encoding="utf-8")
            (proofline / "proof-graph.json").write_text(
                json.dumps(self.graph), encoding="utf-8")
            for work_order in self.work_orders:
                (work_orders / f"{work_order['id']}-fixture.md").write_text(
                    "---\n"
                    f"id: {work_order['id']}\n"
                    f"touches: [{', '.join(work_order['touches'])}]\n"
                    "---\n",
                    encoding="utf-8")
            prepared = SimpleNamespace(
                route_contract={"tier": "M", "needs_owner": False},
                project_inspection={"relevant_coverage_complete": True})
            observed = {}
            real_evaluate = loom_contract_rebase.evaluate

            def capture(**values):
                observed.update(values)
                return real_evaluate(**values)

            with mock.patch.object(
                    loom_contract_rebase, "evaluate", side_effect=capture):
                report = loom_orchestrator._write_contract_rebase(
                    pack, prepared, ["README.md"], ROOT,
                    current_consequence="ordinary")
            self.assertEqual("material", observed["prior_consequence"])
            self.assertEqual("ordinary", observed["current_consequence"])
            self.assertEqual(
                "ordinary", report["current_consequence"])


if __name__ == "__main__":
    unittest.main()
