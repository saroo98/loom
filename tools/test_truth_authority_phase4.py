import copy
import hashlib
import json
import unittest
import uuid
from pathlib import Path

import loom_subject_identity
import loom_truth
import loom_lint


ROOT = Path(__file__).resolve().parents[1]
EPOCH = "2026-07-28T12:00:00Z"


class TruthAuthorityPhase4Tests(unittest.TestCase):
    def registry(self):
        return json.loads((ROOT / "contracts" / "truth-authorities-v1.json").read_text(
            encoding="utf-8"))

    def subject(self, kind="plugin-zip", subject_id="loom.zip", raw=b"loom"):
        if kind == "plugin-zip":
            return loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": kind,
                "subject_id": subject_id, "filename": subject_id,
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            })
        return loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "native-helper",
            "subject_id": "linux-x64", "platform": "linux-x64",
            "filename": "loom-vault", "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "sbom_sha256": "1" * 64, "provenance_sha256": "2" * 64,
        })

    def receipt(self, subjects):
        value = {
            "schema_version": 1,
            "expectation_id": str(uuid.uuid4()),
            "issuer_kind": "ci",
            "issuer_id": "github-actions",
            "repository": loom_subject_identity.REPOSITORY,
            "run_id": "123",
            "job_id": "truth-test",
            "workflow_digest": "1" * 64,
            "base_commit": "2" * 40,
            "candidate_commit": "3" * 40,
            "issued_at": "2026-07-28T00:00:00Z",
            "subjects": subjects,
            "evaluation_epoch": EPOCH,
            "expires_at": "2026-07-29T00:00:00Z",
            "authority": {
                "kind": "ci-attestation",
                "attestation_sha256": "4" * 64,
            },
        }
        value["expectation_sha256"] = loom_subject_identity.digest({
            key: item for key, item in value.items()
            if key not in {"authority", "expectation_sha256"}})
        return loom_subject_identity.validate_expected_subjects(
            value, ci_attestation_verifier=lambda _value: True)

    def test_registry_has_closed_fact_classes_and_acyclic_order(self):
        registry = loom_truth.validate_registry(self.registry())
        order = loom_truth.topological_order(registry)
        self.assertEqual(8, len(registry["fact_classes"]))
        self.assertLess(
            order.index("fact:verification-subject"),
            order.index("claim:capabilities"))
        self.assertLess(
            order.index("claim:readiness"),
            order.index("fact:generated-freshness"))

    def test_phase4_contracts_and_generated_reports_match_closed_schemas(self):
        pairs = (
            ("contracts/truth-authorities-v1.json",
             "truth-authority-registry.schema.json"),
            ("contracts/capability-declarations-v1.json",
             "capability-declarations.schema.json"),
            ("benchmarks/truth-authority/corpus.json",
             "truth-shadow-corpus.schema.json"),
            ("docs/truth-contradictions.json",
             "contradiction-report.schema.json"),
            ("docs/release-readiness.json",
             "release-readiness.schema.json"),
            ("docs/capabilities.json",
             "capability-registry.schema.json"),
        )
        for relative, schema in pairs:
            with self.subTest(path=relative):
                report = loom_lint.Report()
                loom_lint.validate_schema(
                    report, relative,
                    json.loads((ROOT / relative).read_text(
                        encoding="utf-8")),
                    schema)
                self.assertEqual([], report.errors)

    def test_cycle_and_unknown_evaluator_fail_closed(self):
        cyclic = self.registry()
        cyclic["derivations"][0]["inputs"] = ["projection:public-docs"]
        with self.assertRaisesRegex(loom_truth.TruthError, "cycle"):
            loom_truth.validate_registry(cyclic)
        unknown = self.registry()
        unknown["derivations"][0]["evaluator"] = "run-prose"
        with self.assertRaisesRegex(loom_truth.TruthError, "derivation"):
            loom_truth.validate_registry(unknown)
        relaxed = self.registry()
        relaxed["budgets"]["git_entries"] += 1
        with self.assertRaisesRegex(loom_truth.TruthError, "hard evaluator"):
            loom_truth.validate_registry(relaxed)
        arbitrary_slot = self.registry()
        arbitrary_slot["structured_projections"][0]["selector_kind"] = \
            "markdown-marker"
        arbitrary_slot["structured_projections"][0]["selector"] = \
            "run arbitrary command"
        with self.assertRaisesRegex(loom_truth.TruthError, "projection"):
            loom_truth.validate_registry(arbitrary_slot)

    def test_wrong_subject_propagates_to_release_and_readiness(self):
        expected = self.subject(raw=b"expected")
        observed = self.subject(raw=b"observed")
        report = loom_truth.evaluate(
            self.registry(), expected_receipt=self.receipt([expected]),
            observed_subjects=[observed])
        item = report["contradictions"][0]
        self.assertEqual("WRONG_SUBJECT", item["reason"])
        self.assertIn("claim:readiness", item["affected_claims"])
        self.assertEqual("failed", report["claim_states"]["claim:readiness"])
        self.assertNotEqual("supported", report["claim_states"]["claim:readiness"])

    def test_missing_expectations_downgrade_even_in_shadow(self):
        report = loom_truth.evaluate(
            self.registry(), advisory_epoch=EPOCH, mode="shadow")
        self.assertEqual(
            "EXPECTED_SUBJECT_UNAVAILABLE",
            report["contradictions"][0]["reason"])
        self.assertEqual(
            "unverified", report["claim_states"]["claim:capabilities"])
        self.assertEqual("unverified", report["claim_states"]["claim:readiness"])

    def test_report_is_deterministic_and_live_expiry_is_not_persisted(self):
        expected = self.subject()
        receipt = self.receipt([expected])
        first = loom_truth.evaluate(
            self.registry(), expected_receipt=receipt,
            observed_subjects=[expected])
        second = loom_truth.evaluate(
            self.registry(), expected_receipt=receipt,
            observed_subjects=[expected])
        self.assertEqual(first, second)
        before = loom_truth.check_currentness(
            first, "2026-07-28T23:59:59Z")
        at_boundary = loom_truth.check_currentness(
            first, "2026-07-29T00:00:00Z")
        self.assertTrue(before["current"])
        self.assertFalse(at_boundary["current"])
        self.assertEqual(first, second)

    def test_regeneration_is_not_a_resolution_category(self):
        report = loom_truth.evaluate(
            self.registry(), advisory_epoch=EPOCH,
            projection_findings=[{
                "path": "docs/generated-semantic-parity.json",
                "detail": "stale",
            }])
        repairs = {
            item["smallest_repair"] for item in report["contradictions"]}
        self.assertIn("repair-projection-materializer", repairs)
        self.assertNotIn("regenerate-to-resolve", repairs)

    def test_unregistered_historical_prose_is_advisory_only(self):
        report = loom_truth.evaluate(
            self.registry(), advisory_epoch=EPOCH,
            advisories=[{
                "code": "UNREGISTERED_VERSION_PROSE",
                "path": "docs/history.md",
                "detail": "historical version",
            }])
        self.assertEqual(1, len(report["advisories"]))
        self.assertFalse(any(
            item["fact_key"] == "docs/history.md"
            for item in report["contradictions"]))

    def test_incomplete_ambiguous_and_conflicting_authority_downgrade(self):
        for reason, expected in (
                ("EVIDENCE_INCOMPLETE", "unverified"),
                ("AUTHORITY_AMBIGUOUS", "unverified"),
                ("CONFLICTING_RECEIPTS", "failed")):
            with self.subTest(reason=reason):
                report = loom_truth.evaluate(
                    self.registry(), advisory_epoch=EPOCH,
                    authority_findings=[{
                        "fact_class": "release",
                        "fact_key": "release-fixture",
                        "reason": reason,
                        "observed_values": [{"fixture": reason}],
                        "source_locators": ["fixture"],
                    }])
                contradiction = next(
                    item for item in report["contradictions"]
                    if item["reason"] == reason)
                self.assertIn(
                    contradiction["smallest_repair"],
                    loom_truth.REPAIR.values())
                self.assertEqual(
                    expected, report["claim_states"]["claim:readiness"])

    def test_shadow_rollback_never_restores_cached_support(self):
        for state in (
                "failed", "stale", "expired", "revoked", "unverified"):
            self.assertEqual(
                state, loom_truth.shadow_effective_status(
                    state, "supported"))

    def test_shadow_enforces_safety_but_not_new_non_safety_policy_findings(self):
        unsafe = loom_truth.evaluate(
            self.registry(), advisory_epoch=EPOCH,
            authority_findings=[{
                "fact_class": "release", "fact_key": "wrong",
                "reason": "EXPIRED", "observed_values": [],
                "source_locators": ["fixture"],
            }], mode="shadow")
        advisory = loom_truth.evaluate(
            self.registry(), advisory_epoch=EPOCH,
            projection_findings=[{
                "path": "docs/projection.json", "detail": "stale",
            }], mode="shadow")
        enforced = {**advisory, "mode": "enforced"}
        self.assertEqual("failed", loom_truth.enforcement_outcome(unsafe))
        self.assertEqual("passed", loom_truth.enforcement_outcome(advisory))
        self.assertEqual("failed", loom_truth.enforcement_outcome(enforced))


if __name__ == "__main__":
    unittest.main()
