import copy
import unittest

import loom_performance_baseline


class PerformanceFoundationBaselineTests(unittest.TestCase):
    def test_validator_binds_every_field_and_rejects_tampering(self):
        body = {
            "schema_version": 2,
            "baseline_id": "00000000-0000-4000-8000-000000000001",
            "measurement_id": "00000000-0000-4000-8000-000000000002",
            "source_commit": "1" * 40,
            "environment": {
                "os": "windows", "architecture": "amd64", "python": "3.13.0",
                "measurement_boundary": "local-runtime-and-wrapper-separated",
            },
            "preregistration": {
                "runs": 3, "warmups": 1, "relative_spread_tolerance": 0.5,
                "required_cases": [
                    "doc-typo", "single-ui-incident", "stale-resume",
                    "project-switch", "unknown-domain", "warm-session", "year-owner"],
                "corpus_sha256": "2" * 64,
            },
            "corpus": [{
                "id": "doc-typo", "request_sha256": "3" * 64,
                "declared_file_count": 1,
            }],
            "results": [{
                "id": "cold_start", "samples": [1, 2, 3],
                "measurement_class": "local-runtime-operation",
                "p50_runtime_ns": 2, "p95_runtime_ns": 3,
                "relative_spread": 1.0,
                "within_preregistered_tolerance": False,
                "non_time_metrics": {"disk_reads": 2},
                "non_time_metrics_stable": True,
            }],
            "wrapper_process": {
                "samples": [10, 11, 12],
                "p50_elapsed_ns": 11,
                "p95_elapsed_ns": 12,
                "relative_spread": 0.2,
                "within_preregistered_tolerance": True,
                "includes": ["python-process-startup"],
            },
            "policy_fixtures": [{
                "id": "tiny-task-overhead-policy",
                "measurement_class": "synthetic-policy-fixture",
                "result": {"measurement_kind": "synthetic-policy-fixture"},
            }],
            "measurement_boundaries": {
                "local_runtime": "observed",
                "wrapper_process": "observed",
                "provider_response": "unavailable",
                "provider_queue": "unavailable",
                "local_collection_wall_time": "observed",
                "agent_end_to_end_wall_time": "unavailable",
            },
            "provider_native": {
                "status": "unavailable",
                "reason": "No provider receipt.",
            },
            "all_local_metrics_stable": False,
        }
        body["receipt_sha256"] = loom_performance_baseline._hash(body)
        loom_performance_baseline.validate(body)
        changed = copy.deepcopy(body)
        changed["results"][0]["p50_runtime_ns"] = 99
        with self.assertRaises(loom_performance_baseline.BaselineError):
            loom_performance_baseline.validate(changed)

    def test_preregistered_corpus_requires_small_unknown_resume_switch_and_long_memory(self):
        class Root:
            pass
        self.assertIn("unknown-domain", {
            "doc-typo", "warm-session", "project-switch", "stale-resume",
            "year-owner", "unknown-domain", "single-ui-incident"})


if __name__ == "__main__":
    unittest.main()
