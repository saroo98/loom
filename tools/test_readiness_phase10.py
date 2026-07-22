import unittest

import loom_readiness


class ReadinessPhase10Tests(unittest.TestCase):
    def test_codex_host_documentation_preserves_dual_assurance_contract(self):
        rendered = loom_readiness.render_host("codex")
        self.assertIn("**Standard:**", rendered)
        self.assertIn("**Verified:**", rendered)
        self.assertIn("guardrail, not a sandbox", rendered)

    def test_missing_receipts_never_become_supported(self):
        value = loom_readiness.generate(version="1.6.0")
        self.assertEqual("not-ready", value["overall"])
        by_id = {item["id"]: item for item in value["claims"]}
        self.assertEqual("unverified", by_id["release.exact-cut"]["status"])
        self.assertEqual("experimental", by_id["host.codex.cli"]["status"])
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


if __name__ == "__main__":
    unittest.main()
