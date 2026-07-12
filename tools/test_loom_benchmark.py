"""Token accounting must never label a subset as total."""

import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import loom_benchmark  # noqa: E402


class UsageAccountingTests(unittest.TestCase):
    def test_audited_b2_usage_sums_all_cache_and_output_fields(self):
        result = loom_benchmark.summarize({
            "schema_version": 1,
            "run_id": "B2-audited",
            "wall_seconds": 253.6,
            "responses": [{
                "fresh_input_tokens": 19222,
                "cache_creation_input_tokens": 54035,
                "cache_read_input_tokens": 1189952,
                "output_tokens": 14917,
            }],
        })
        self.assertEqual(result["processed_token_events"], 1278126)
        self.assertEqual(result["cache_read_input_tokens"], 1189952)
        self.assertIsNone(result["provider_billed_equivalent"])

    def test_missing_cache_field_fails_instead_of_becoming_zero(self):
        with self.assertRaisesRegex(loom_benchmark.UsageError, "fields mismatch"):
            loom_benchmark.summarize({
                "schema_version": 1, "run_id": "incomplete", "wall_seconds": 1,
                "responses": [{
                    "fresh_input_tokens": 1,
                    "cache_creation_input_tokens": 2,
                    "output_tokens": 3,
                }],
            })

    def test_billing_equivalent_needs_every_explicit_weight(self):
        payload = {
            "schema_version": 1, "run_id": "weighted", "wall_seconds": 1,
            "responses": [{field: 1 for field in loom_benchmark.FIELDS}],
        }
        with self.assertRaisesRegex(loom_benchmark.UsageError, "cover all four"):
            loom_benchmark.summarize(payload, {"fresh_input_tokens": 1.0})


if __name__ == "__main__":
    unittest.main()
