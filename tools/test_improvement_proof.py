import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_improvement
import loom_improvement_audit
import loom_memory


class ImprovementProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)
        self.tracker = loom_improvement.ImprovementTracker(
            self.home, self.instance)

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_improving_longitudinal(self, metric="rework-rate", domain="three-d"):
        for index in range(16):
            self.tracker.record_observation(
                metric=metric, value=(0.8 if index < 8 else 0.2),
                domain=domain, project_id=f"p-{index + 401:032x}",
                evidence_id=f"longitudinal-{metric}-{domain}-{index}",
                recorded_at=f"2026-08-{index + 1:02d}T12:00:00Z")

    def test_longitudinal_claim_requires_minimum_samples_and_exact_domain(self):
        for index in range(15):
            self.tracker.record_observation(
                metric="rework-rate", value=(0.8 if index < 8 else 0.2),
                domain="three-d", project_id=f"p-{index + 1:032x}",
                evidence_id=f"three-d-{index}",
                recorded_at=f"2026-07-{index + 1:02d}T12:00:00Z")
            self.tracker.record_observation(
                metric="rework-rate", value=(0.1 if index < 8 else 0.9),
                domain="accounting", project_id=f"p-{index + 101:032x}",
                evidence_id=f"accounting-{index}",
                recorded_at=f"2026-07-{index + 1:02d}T13:00:00Z")
        insufficient = self.tracker.report(
            metric="rework-rate", domain="three-d")
        self.assertEqual("insufficient-evidence", insufficient["longitudinal"]["status"])
        self.assertFalse(insufficient["improvement_claim_allowed"])

        self.tracker.record_observation(
            metric="rework-rate", value=0.2, domain="three-d",
            project_id=f"p-{16:032x}", evidence_id="three-d-15",
            recorded_at="2026-07-16T12:00:00Z")
        proven = self.tracker.report(metric="rework-rate", domain="three-d")
        self.assertEqual("three-d", proven["domain"])
        self.assertEqual("improved", proven["longitudinal"]["status"])
        self.assertEqual(8, proven["longitudinal"]["early_sample_count"])
        self.assertEqual(8, proven["longitudinal"]["recent_sample_count"])
        self.assertLess(
            proven["longitudinal"]["recent_mean"],
            proven["longitudinal"]["early_mean"])
        self.assertNotIn("accounting", str(proven))
        with self.assertRaisesRegex(loom_improvement.ImprovementError, "exact domain"):
            self.tracker.report(metric="rework-rate", domain=None)

    def test_claim_requires_minimum_paired_memory_enabled_disabled_replays(self):
        self._seed_improving_longitudinal()
        for index in range(7):
            self.tracker.record_replay_pair(
                metric="rework-rate", domain="three-d", replay_id=f"replay-{index}",
                enabled_value=0.2, disabled_value=0.6,
                project_id=f"p-{index + 501:032x}",
                evidence_ids=[f"enabled-{index}", f"disabled-{index}"],
                recorded_at=f"2026-09-{index + 1:02d}T12:00:00Z")
        insufficient = self.tracker.report(metric="rework-rate", domain="three-d")
        self.assertEqual("insufficient-evidence", insufficient["replay"]["status"])
        self.assertFalse(insufficient["improvement_claim_allowed"])

        self.tracker.record_replay_pair(
            metric="rework-rate", domain="three-d", replay_id="replay-7",
            enabled_value=0.2, disabled_value=0.6,
            project_id=f"p-{508:032x}",
            evidence_ids=["enabled-7", "disabled-7"],
            recorded_at="2026-09-08T12:00:00Z")
        proven = self.tracker.report(metric="rework-rate", domain="three-d")
        self.assertEqual("improved", proven["replay"]["status"])
        self.assertEqual(8, proven["replay"]["pair_count"])
        self.assertLess(proven["replay"]["enabled_mean"],
                        proven["replay"]["disabled_mean"])
        self.assertTrue(proven["local_improvement_observed"])
        self.assertFalse(proven["improvement_claim_allowed"])
        self.assertEqual("requires-independent-attestation", proven["claim_status"])
        self.assertEqual("local-unattested", proven["attestation_status"])

    def test_direction_aware_regression_alarm_fires_when_recent_work_worsens(self):
        for index in range(16):
            self.tracker.record_observation(
                metric="verification-escape-rate",
                value=(0.1 if index < 8 else 0.6), domain="mobile",
                project_id=f"p-{index + 601:032x}", evidence_id=f"escape-{index}",
                recorded_at=f"2026-10-{index + 1:02d}T12:00:00Z")
            self.tracker.record_observation(
                metric="drift-caught-before-execution-rate",
                value=(0.2 if index < 8 else 0.8), domain="mobile",
                project_id=f"p-{index + 701:032x}", evidence_id=f"drift-{index}",
                recorded_at=f"2026-10-{index + 1:02d}T13:00:00Z")
        regressed = self.tracker.report(
            metric="verification-escape-rate", domain="mobile")
        improved = self.tracker.report(
            metric="drift-caught-before-execution-rate", domain="mobile")
        self.assertEqual("regressed", regressed["longitudinal"]["status"])
        self.assertTrue(regressed["regression_alarm"])
        self.assertEqual("improved", improved["longitudinal"]["status"])
        self.assertFalse(improved["regression_alarm"])

    def test_independent_auditor_reproduces_claim_and_rejects_tampering(self):
        self._seed_improving_longitudinal()
        for index in range(8):
            self.tracker.record_replay_pair(
                metric="rework-rate", domain="three-d", replay_id=f"audit-replay-{index}",
                enabled_value=0.2, disabled_value=0.6,
                project_id=f"p-{index + 801:032x}",
                evidence_ids=[f"audit-enabled-{index}", f"audit-disabled-{index}"],
                recorded_at=f"2026-11-{index + 1:02d}T12:00:00Z")
        bundle = self.tracker.audit_bundle(metric="rework-rate", domain="three-d")
        reproduced = loom_improvement_audit.audit_bundle(bundle)
        self.assertEqual("passed", reproduced["status"])
        self.assertTrue(reproduced["reproduced"])
        self.assertTrue(reproduced["report"]["local_improvement_observed"])
        self.assertFalse(reproduced["report"]["improvement_claim_allowed"])
        self.assertEqual(
            "requires-independent-attestation",
            reproduced["report"]["claim_status"])
        self.assertNotIn(str(self.home), str(bundle))

        bundle["claim"]["longitudinal"]["recent_mean"] = 0.0
        rejected = loom_improvement_audit.audit_bundle(bundle)
        self.assertEqual("failed", rejected["status"])
        self.assertFalse(rejected["reproduced"])
        self.assertTrue(any(item["code"] == "CLAIM_MISMATCH"
                            for item in rejected["findings"]))

    def test_evidence_store_stays_bounded_without_losing_comparison_windows(self):
        observations = []
        for index in range(600):
            observations.append({
                "metric": "planning-overhead-ratio",
                "value": 0.9 if index < 8 else 0.1,
                "domain": "cli",
                "project_id": f"p-{index + 901:032x}",
                "evidence_id": f"overhead-{index}",
                "recorded_at": f"2027-{index // 50 + 1:02d}-{index % 28 + 1:02d}T12:00:00Z",
            })
        self.tracker.record_observations_batch(observations)
        status = self.tracker.status()
        report = self.tracker.report(
            metric="planning-overhead-ratio", domain="cli")
        self.assertEqual(600, status["total_count"])
        self.assertLessEqual(status["active_record_count"],
                             loom_improvement.MAX_ACTIVE_RECORDS)
        self.assertEqual(600, report["longitudinal"]["sample_count"])
        self.assertEqual(0.9, report["longitudinal"]["early_mean"])
        self.assertEqual(0.1, report["longitudinal"]["recent_mean"])
        self.assertGreater(status["compacted_record_count"], 0)

    def test_many_domains_evict_partitions_but_old_evidence_identity_never_reopens(self):
        observations = [{
            "metric": "rework-rate", "value": 0.5,
            "domain": f"domain-{index}",
            "project_id": f"p-{index + 2901:032x}",
            "evidence_id": f"bounded-domain-{index}",
            "recorded_at": f"2029-{index // 50 + 1:02d}-{index % 28 + 1:02d}T12:00:00Z",
        } for index in range(600)]
        self.tracker.record_observations_batch(observations)
        status = self.tracker.status()
        self.assertLessEqual(status["partition_count"],
                             loom_improvement.MAX_PARTITIONS)
        self.assertEqual(600, status["evidence_identity_count"])
        self.assertLessEqual(self.tracker.path.stat().st_size,
                             loom_improvement.MAX_STORE_BYTES)

        exact = dict(observations[0])
        exact["recorded_at"] = "2030-01-01T00:00:00Z"
        repeated = self.tracker.record_observations_batch([exact])
        self.assertEqual(0, repeated["added"])
        self.assertEqual(600, repeated["total_count"])

        changed = dict(exact, value=0.9)
        with self.assertRaisesRegex(
                loom_improvement.ImprovementError,
                "identity is bound to another measurement"):
            self.tracker.record_observations_batch([changed])
        self.assertEqual(600, self.tracker.status()["total_count"])

    def test_identity_and_byte_capacity_fail_without_partial_mutation(self):
        first = {
            "metric": "rework-rate", "value": 0.5, "domain": "cli",
            "project_id": f"p-{3901:032x}", "evidence_id": "capacity-1",
            "recorded_at": "2030-02-01T00:00:00Z",
        }
        with mock.patch.object(loom_improvement, "MAX_EVIDENCE_IDS", 1):
            self.tracker.record_observations_batch([first])
            with self.assertRaisesRegex(
                    loom_improvement.ImprovementError, "identity capacity"):
                self.tracker.record_observations_batch([{
                    **first, "evidence_id": "capacity-2",
                    "recorded_at": "2030-02-02T00:00:00Z",
                }])
        self.assertEqual(1, self.tracker.status()["total_count"])

        before = self.tracker.path.read_bytes()
        with mock.patch.object(
                loom_improvement, "MAX_STORE_BYTES", len(before) + 1):
            with self.assertRaisesRegex(
                    loom_improvement.ImprovementError, "byte capacity"):
                self.tracker.record_observations_batch([{
                    **first, "evidence_id": "capacity-byte",
                    "recorded_at": "2030-02-03T00:00:00Z",
                }])
        self.assertEqual(before, self.tracker.path.read_bytes())

    def test_metric_registry_and_general_calibration_are_explicitly_separate(self):
        self.assertEqual({
            "prediction-calibration-error", "rework-rate",
            "verification-escape-rate", "incorrect-tier-rate",
            "planning-overhead-ratio", "human-decision-round-trips",
            "unused-artifact-rate", "wo-reopen-rate",
            "drift-caught-before-execution-rate", "release-rollback-rate",
            "memory-help-rate", "memory-hurt-rate",
        }, set(loom_improvement.METRICS))
        for index in range(16):
            stamp = f"2027-12-{index + 1:02d}T12:00:00Z"
            self.tracker.record_observation(
                metric="prediction-calibration-error",
                value=0.6 if index < 8 else 0.2, domain="general",
                project_id=f"p-{index + 1601:032x}",
                evidence_id=f"general-calibration-{index}", recorded_at=stamp)
            self.tracker.record_observation(
                metric="prediction-calibration-error",
                value=0.1 if index < 8 else 0.8, domain="firmware",
                project_id=f"p-{index + 1701:032x}",
                evidence_id=f"firmware-calibration-{index}", recorded_at=stamp)
        general = self.tracker.report(
            metric="prediction-calibration-error", domain="general")
        firmware = self.tracker.report(
            metric="prediction-calibration-error", domain="firmware")
        self.assertEqual("general-calibration", general["scope"])
        self.assertEqual("exact-domain", firmware["scope"])
        self.assertEqual("improved", general["longitudinal"]["status"])
        self.assertEqual("regressed", firmware["longitudinal"]["status"])

    def test_audit_bundle_preserves_total_replay_count_after_compaction(self):
        self._seed_improving_longitudinal()
        for index in range(12):
            self.tracker.record_replay_pair(
                metric="rework-rate", domain="three-d",
                replay_id=f"long-audit-replay-{index}",
                enabled_value=0.2, disabled_value=0.6,
                project_id=f"p-{index + 1801:032x}",
                evidence_ids=[f"long-enabled-{index}", f"long-disabled-{index}"],
                recorded_at=f"2028-01-{index + 1:02d}T12:00:00Z")
        bundle = self.tracker.audit_bundle(metric="rework-rate", domain="three-d")
        self.assertEqual(12, bundle["evidence"]["replay_pair_count"])
        self.assertEqual(8, len(bundle["evidence"]["replay_pairs"]))
        reproduced = loom_improvement_audit.audit_bundle(bundle)
        self.assertEqual("passed", reproduced["status"])
        self.assertEqual(12, reproduced["report"]["replay"]["pair_count"])


if __name__ == "__main__":
    unittest.main()
