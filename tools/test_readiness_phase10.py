import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import loom_readiness


class ReadinessPhase10Tests(unittest.TestCase):
    EPOCH = "2026-07-17T12:00:00Z"

    def graph(self, *, claim_id="release.exact-cut", reason=None,
              kinds=("main-source", "candidate-source", "release-tag",
                     "plugin-zip", "native-helper")):
        bindings = [{
            "kind": kind,
            "subject_id": {
                "main-source": "main",
                "candidate-source": "candidate",
                "release-tag": "v1.6.0",
                "plugin-zip": "loom.zip",
                "native-helper": "linux-x64",
                "installed-runtime": "1.6.0",
            }[kind],
            "subject_digest": str(index + 1) * 64,
        } for index, kind in enumerate(kinds)]
        evidence_id = "ev-readiness"
        body = {
            "schema_version": 2,
            "policy_id": "loom-evidence-policy-v1",
            "expected_subjects_sha256": "a" * 64,
            "subject_bindings": bindings,
            "active_bindings_by_evidence": (
                {evidence_id: bindings} if reason is None else {}),
            "evaluated_at": self.EPOCH,
            "next_invalidation_at": "2026-08-17T00:00:00Z",
            "active": [evidence_id] if reason is None else [],
            "inactive": [] if reason is None else [{
                "evidence_id": evidence_id,
                "reason": reason,
                "predicate_type": claim_id,
                "subject_bindings": bindings,
            }],
            "predicates": {claim_id: [evidence_id]} if reason is None else {},
        }
        body["graph_sha256"] = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        return body

    def test_codex_host_documentation_preserves_dual_assurance_contract(self):
        rendered = loom_readiness.render_host("codex")
        self.assertIn("**Standard:**", rendered)
        self.assertIn("**Verified:**", rendered)
        self.assertIn("guardrail, not a sandbox", rendered)

    def test_generated_readiness_keeps_public_output_machine_readable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            loom_readiness.write_outputs(
                root, loom_readiness.generate(version="1.6.0"))
            self.assertTrue(
                (root / "docs" / "release-readiness.json").is_file())
            self.assertFalse(
                (root / "docs" / "release-readiness.md").exists())
            self.assertFalse((root / "docs" / "hosts").exists())

    def test_missing_receipts_never_become_supported(self):
        value = loom_readiness.generate(version="1.6.0")
        self.assertEqual("not-ready", value["overall"])
        by_id = {item["id"]: item for item in value["claims"]}
        self.assertEqual("unverified", by_id["release.exact-cut"]["status"])
        self.assertEqual("unverified", by_id["host.codex.cli"]["status"])
        self.assertNotEqual("supported", by_id["host.codex.app"]["status"])

    def test_wrong_subject_and_conflicting_receipts_fail_closed(self):
        receipt = {"receipt_id": "r1", "claim_id": "release.exact-cut",
                   "status": "supported", "release_subject": "a" * 64,
                   "valid_until": None, "evidence_class": "ci-reproduced",
                   "artifact_sha256": "b" * 64, "runner": "runner",
                   "consumption_limit": 1}
        with self.assertRaises(loom_readiness.ReadinessError):
            loom_readiness.generate(
                version="1.6.0", release_subject="c" * 64,
                evidence={"schema_version": 1, "receipts": [receipt]})
        conflicting = {"schema_version": 1, "receipts": [
            receipt, {**receipt, "receipt_id": "r2", "status": "failed"}]}
        result = loom_readiness.generate(
            version="1.6.0", release_subject="a" * 64, evidence=conflicting)
        exact = next(item for item in result["claims"] if item["id"] == "release.exact-cut")
        self.assertEqual("failed", exact["status"])

    def test_legacy_supported_receipt_is_readable_but_cannot_promote(self):
        receipt = {
            "receipt_id": "r1", "claim_id": "release.exact-cut",
            "status": "supported", "release_subject": "a" * 64,
            "valid_until": "2026-08-17T00:00:00Z",
            "evidence_class": "ci-reproduced",
            "artifact_sha256": "b" * 64, "runner": "runner",
            "consumption_limit": 1,
        }
        result = loom_readiness.generate(
            version="1.6.0", release_subject="a" * 64,
            evidence={"schema_version": 1, "receipts": [receipt]},
            evaluation_epoch=self.EPOCH)
        exact = next(
            item for item in result["claims"]
            if item["id"] == "release.exact-cut")
        self.assertEqual("unverified", exact["status"])
        self.assertEqual(["LEGACY_SUBJECT_UNTYPED"], exact["reason_codes"])

    def test_legacy_expiry_boundary_is_enforced_deterministically(self):
        receipt = {
            "receipt_id": "r1", "claim_id": "release.exact-cut",
            "status": "supported", "release_subject": "a" * 64,
            "valid_until": self.EPOCH, "evidence_class": "ci-reproduced",
            "artifact_sha256": "b" * 64, "runner": "runner",
            "consumption_limit": 1,
        }
        result = loom_readiness.generate(
            version="1.6.0", release_subject="a" * 64,
            evidence={"schema_version": 1, "receipts": [receipt]},
            evaluation_epoch=self.EPOCH)
        exact = next(
            item for item in result["claims"]
            if item["id"] == "release.exact-cut")
        self.assertEqual("expired", exact["status"])

    def test_typed_support_requires_trusted_digest_and_every_subject_kind(self):
        graph = self.graph()
        supported = loom_readiness.generate(
            version="1.6.0", evidence=graph,
            evaluation_epoch=self.EPOCH,
            trusted_expected_subjects_sha256="a" * 64)
        exact = next(
            item for item in supported["claims"]
            if item["id"] == "release.exact-cut")
        self.assertEqual("supported", exact["status"])
        incomplete_graph = self.graph(kinds=(
            "main-source", "candidate-source", "release-tag", "plugin-zip"))
        incomplete = loom_readiness.generate(
            version="1.6.0", evidence=incomplete_graph,
            evaluation_epoch=self.EPOCH,
            trusted_expected_subjects_sha256="a" * 64)
        exact = next(
            item for item in incomplete["claims"]
            if item["id"] == "release.exact-cut")
        self.assertEqual("unverified", exact["status"])
        with self.assertRaisesRegex(
                loom_readiness.ReadinessError, "trusted expectation"):
            loom_readiness.generate(
                version="1.6.0", evidence=graph,
                evaluation_epoch=self.EPOCH,
                trusted_expected_subjects_sha256="b" * 64)

    def test_unsafe_typed_states_never_promote_in_shadow_projection(self):
        for reason, expected in (
                ("wrong-subject", "failed"),
                ("expired", "expired"),
                ("revoked", "revoked"),
                ("stale", "stale"),
                ("expected-subject-unavailable", "unverified"),
                ("verification-failed", "unverified"),
                ("dependency-inactive", "unverified")):
            with self.subTest(reason=reason):
                graph = self.graph(reason=reason)
                result = loom_readiness.generate(
                    version="1.6.0", evidence=graph,
                    evaluation_epoch=self.EPOCH,
                    trusted_expected_subjects_sha256="a" * 64)
                exact = next(
                    item for item in result["claims"]
                    if item["id"] == "release.exact-cut")
                self.assertEqual(expected, exact["status"])


if __name__ == "__main__":
    unittest.main()
