"""Evidence-bound scorecard and competitive comparison regression tests."""

import copy
import contextlib
import datetime as dt
import base64
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_scorecard
import loom_release
from test_release_standard import TEST_RSA_D, TEST_RSA_N


ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 7, 17, 12, 0, tzinfo=dt.timezone.utc)


class ScorecardPhase6Tests(unittest.TestCase):
    def setUp(self):
        self.rubric = loom_scorecard.load_rubric(ROOT / "contracts/score-rubric-v1.json")
        self.subject = {
            "kind": "source-tree", "repository": "https://github.com/saroo98/loom",
            "commit_sha": "1" * 40, "tree_sha256": "2" * 64,
        }
        self.artifacts = {"suite": {"status": "passed", "tests": 579}}

    def record(self, requirement="closed-cli-contracts", *, status="passed",
               evidence_class="mechanical-local", expires=True):
        return loom_scorecard._make_record(
            self.subject, requirement, status, "suite", self.artifacts,
            tool="loom-test", locator=requirement,
            observed_at="2026-07-17T11:00:00Z",
            expires_at="2026-08-17T11:00:00Z" if expires else None,
            evidence_class=evidence_class)

    def bundle(self, records):
        return {"schema_version": 1, "subject": self.subject,
                "generated_at": "2026-07-17T11:00:00Z",
                "artifacts": copy.deepcopy(self.artifacts), "records": records}

    def test_rubric_is_closed_unique_and_exactly_one_hundred_points(self):
        self.assertEqual(100, sum(item["weight"] for item in self.rubric["categories"]))
        self.assertEqual(17, len(self.rubric["categories"]))
        requirements = []
        for category in self.rubric["categories"]:
            self.assertEqual(100, sum(item["points"] for item in category["requirements"]))
            requirements.extend(item["id"] for item in category["requirements"])
        self.assertEqual(len(requirements), len(set(requirements)))
        for name in ("score-rubric", "score-evidence", "scorecard",
                     "competitor-snapshot", "score-comparison", "score-regression",
                     "score-trust-policy"):
            schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(
                encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"], name)

    def test_score_is_order_invariant_deterministic_and_explains_withheld_points(self):
        records = [self.record(), self.record("fail-closed-tool-behavior")]
        first = loom_scorecard.score(self.rubric, self.bundle(records), as_of=NOW)
        second = loom_scorecard.score(
            self.rubric, self.bundle(list(reversed(records))), as_of=NOW)
        self.assertEqual(first, second)
        self.assertEqual("local-evidence", first["status"])
        tools = next(item for item in first["categories"]
                     if item["id"] == "tool-correctness")
        self.assertEqual(75, tools["raw_score"])
        self.assertEqual(["cross-platform-tool-correctness"],
                         tools["withheld_requirements"])

    def test_tamper_duplicate_wrong_subject_and_stale_evidence_fail_closed(self):
        original = self.record()
        cases = []
        tampered = copy.deepcopy(original)
        tampered["status"] = "failed"
        cases.append(self.bundle([tampered]))
        duplicate = copy.deepcopy(original)
        duplicate["coverage_id"] += ":copy"
        duplicate["digest"] = loom_scorecard._digest(
            loom_scorecard._record_body(duplicate))
        duplicate["evidence_id"] = "ev-" + duplicate["digest"][:32]
        cases.append(self.bundle([original, duplicate]))
        wrong = copy.deepcopy(original)
        wrong["subject"] = {**self.subject, "tree_sha256": "3" * 64}
        wrong["digest"] = loom_scorecard._digest(loom_scorecard._record_body(wrong))
        wrong["evidence_id"] = "ev-" + wrong["digest"][:32]
        cases.append(self.bundle([wrong]))
        stale = self.record()
        stale["expires_at"] = "2026-07-17T11:30:00Z"
        stale["digest"] = loom_scorecard._digest(loom_scorecard._record_body(stale))
        stale["evidence_id"] = "ev-" + stale["digest"][:32]
        cases.append(self.bundle([stale]))
        artifact_tamper = self.bundle([original])
        artifact_tamper["artifacts"]["suite"]["tests"] = 1
        cases.append(artifact_tamper)
        for value in cases:
            with self.subTest(case=cases.index(value)), self.assertRaises(
                    loom_scorecard.ScoreError):
                loom_scorecard.score(self.rubric, value, as_of=NOW)

    def test_claimed_only_never_earns_points(self):
        result = loom_scorecard.score(
            self.rubric,
            self.bundle([self.record(evidence_class="claimed-only")]),
            as_of=NOW)
        tools = next(item for item in result["categories"]
                     if item["id"] == "tool-correctness")
        self.assertEqual(0, tools["raw_score"])
        self.assertIn("closed-cli-contracts", tools["withheld_requirements"])

    def test_self_asserted_external_evidence_cannot_inflate_a_score(self):
        record = self.record(evidence_class="mechanical-local")
        record["evidence_class"] = "matrix-reproduced"
        record["digest"] = loom_scorecard._digest(loom_scorecard._record_body(record))
        record["evidence_id"] = "ev-" + record["digest"][:32]
        with self.assertRaisesRegex(loom_scorecard.ScoreError, "trusted independent"):
            loom_scorecard.score(self.rubric, self.bundle([record]), as_of=NOW)

        record["attestation"] = {
            "algorithm": "rsa-pkcs1v15-sha256", "key_id": "score-test-key",
            "signature": "",
        }
        signed = {key: value for key, value in record.items() if key != "attestation"}
        signed["attestation"] = {
            "algorithm": record["attestation"]["algorithm"],
            "key_id": record["attestation"]["key_id"],
        }
        digest_info = loom_release.SHA256_DIGEST_INFO + hashlib.sha256(
            loom_release._canonical_bytes(signed)).digest()
        size = (TEST_RSA_N.bit_length() + 7) // 8
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) \
            + b"\x00" + digest_info
        signature = pow(int.from_bytes(encoded, "big"), TEST_RSA_D, TEST_RSA_N)
        record["attestation"]["signature"] = base64.b64encode(
            signature.to_bytes(size, "big")).decode("ascii")
        policy = {
            "schema_version": 1, "rubric_id": self.rubric["rubric_id"],
            "subject": self.subject,
            "issuers": [{
                "id": "independent-test", "key_id": "score-test-key",
                "algorithm": "rsa-pkcs1v15-sha256",
                "modulus_hex": f"{TEST_RSA_N:x}", "exponent": 65537,
                "independent": True, "evidence_classes": ["matrix-reproduced"],
                "requirements": ["closed-cli-contracts"],
            }],
        }
        verified = loom_scorecard.score(
            self.rubric, self.bundle([record]), as_of=NOW, trust_policy=policy)
        tools = next(item for item in verified["categories"]
                     if item["id"] == "tool-correctness")
        self.assertEqual(35, tools["raw_score"])

    def test_trust_regression_blocks_while_adoption_decrease_is_informational(self):
        baseline = loom_scorecard.score(
            self.rubric,
            self.bundle([self.record(), self.record("fail-closed-tool-behavior")]),
            as_of=NOW)
        current = loom_scorecard.score(
            self.rubric, self.bundle([self.record()]), as_of=NOW)
        blocked = loom_scorecard.regression(self.rubric, baseline, current)
        self.assertEqual("blocked", blocked["status"])
        self.assertEqual("tool-correctness", blocked["blocking_decreases"][0]["category_id"])

        adoption = self.record("public-installable-artifact")
        prior_adoption = loom_scorecard.score(
            self.rubric, self.bundle([adoption]), as_of=NOW)
        no_adoption = loom_scorecard.score(self.rubric, self.bundle([]), as_of=NOW)
        informational = loom_scorecard.regression(
            self.rubric, prior_adoption, no_adoption)
        self.assertEqual("passed", informational["status"])
        self.assertFalse(informational["decreases"][0]["trust_critical"])

        tampered = copy.deepcopy(current)
        tampered["overall_score"] = 99
        with self.assertRaises(loom_scorecard.ScoreError):
            loom_scorecard.regression(self.rubric, baseline, tampered)

    def snapshot(self, project_id, *, expires="2026-08-17T12:00:00Z"):
        categories = []
        for index, category in enumerate(self.rubric["categories"]):
            categories.append({
                "category_id": category["id"], "applicability": "applicable",
                "score": 80 if index == 0 else None,
                "status": "verified" if index == 0 else "unverified",
                "sources": ["https://github.com/example/project"] if index == 0 else [],
                "rationale": "Primary-source observation." if index == 0
                else "No current primary-source evidence.",
            })
        return {
            "schema_version": 1, "project_id": project_id,
            "project_name": project_id.title(),
            "canonical_repository": "https://github.com/example/project",
            "revision": "a" * 40, "accessed_at": "2026-07-17T10:00:00Z",
            "expires_at": expires, "rubric_id": self.rubric["rubric_id"],
            "categories": categories,
        }

    def test_comparison_preserves_unknowns_and_rejects_stale_or_unsourced_scores(self):
        result = loom_scorecard.compare(
            self.rubric, [self.snapshot("loom"), self.snapshot("peer")], as_of=NOW)
        self.assertEqual(2, len(result["projects"]))
        self.assertLess(result["projects"][0]["lower_bound"],
                        result["projects"][0]["upper_bound"])
        self.assertEqual(80, result["projects"][0]["known_score"])
        with self.assertRaises(loom_scorecard.ScoreError):
            loom_scorecard.compare(
                self.rubric, [self.snapshot("loom", expires="2026-07-17T11:00:00Z"),
                              self.snapshot("peer")], as_of=NOW)
        unsourced = self.snapshot("loom")
        unsourced["categories"][0]["sources"] = []
        with self.assertRaises(loom_scorecard.ScoreError):
            loom_scorecard.compare(
                self.rubric, [unsourced, self.snapshot("peer")], as_of=NOW)

    def test_cli_writes_only_the_explicit_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            output = root / "score.json"
            evidence.write_text(json.dumps(self.bundle([self.record()])), encoding="utf-8")
            before = sorted(path.name for path in root.iterdir())
            with contextlib.redirect_stdout(io.StringIO()):
                result = loom_scorecard.main([
                    "score", "--evidence", str(evidence),
                    "--as-of", "2026-07-17T12:00:00Z", "--output", str(output)])
            self.assertEqual(0, result)
            self.assertEqual(before + ["score.json"], sorted(path.name for path in root.iterdir()))

    def test_release_collector_reuses_the_exact_cut_suite_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "BUILD-MANIFEST.json").write_text("{}\n", encoding="utf-8")
            verification = {
                "root_sha256": "4" * 64,
                "firewall": {"clean": True, "files_scanned": 10},
                "suite": {"passed": True, "capability_complete": False,
                          "skip_receipts": [{"test": "fixture.posix", "reason": "matrix"}],
                          "tests_run": 20, "elapsed_seconds": 2.0, "timings": []},
            }
            captured = {}

            def fake_collect(_root, **kwargs):
                captured.update(kwargs)
                return {"schema_version": 1}

            with mock.patch.object(loom_release, "verify_cut", return_value=verification), \
                    mock.patch.object(loom_scorecard, "collect_local", side_effect=fake_collect):
                result = loom_scorecard.collect_release(root)
            self.assertEqual({"schema_version": 1}, result)
            self.assertEqual("full", captured["suite_report"]["mode"])
            self.assertFalse(captured["suite_report"]["successful"])
            self.assertTrue(captured["publication_report"]["exact_cut_suite_passed"])

    def test_platform_skips_do_not_double_deduct_suite_correctness(self):
        report = {
            "mode": "full", "failures": 0, "errors": 0,
            "within_budget": True, "capability_complete": False,
            "successful": False, "skipped": 3,
        }
        self.assertTrue(loom_scorecard._complete_suite_correctness(report))
        report["failures"] = 1
        self.assertFalse(loom_scorecard._complete_suite_correctness(report))


if __name__ == "__main__":
    unittest.main()
