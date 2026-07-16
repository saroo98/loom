import datetime as dt
import unittest

import domain_test_support
import loom_domain_freshness


class DomainFreshnessTests(unittest.TestCase):
    def test_unchanged_claim_is_retained(self):
        bundle = domain_test_support.gate_ready_bundle()
        result = loom_domain_freshness.regate(
            bundle, target_fingerprint=domain_test_support.TARGET,
            now=domain_test_support.NOW)
        self.assertEqual(1, len(result["retained"]))
        self.assertEqual([], result["revalidate"])
        self.assertEqual([], result["blocked"])

    def test_target_change_revalidates_only_affected_claim(self):
        bundle = domain_test_support.gate_ready_bundle()
        result = loom_domain_freshness.regate(
            bundle, target_fingerprint="b" * 64, now=domain_test_support.NOW)
        self.assertEqual([], result["retained"])
        self.assertEqual("target-fingerprint-changed", result["revalidate"][0]["reason"])

    def test_two_month_gap_blocks_expired_claim(self):
        bundle = domain_test_support.gate_ready_bundle()
        result = loom_domain_freshness.regate(
            bundle, target_fingerprint=domain_test_support.TARGET,
            now=dt.datetime(2030, 3, 1, tzinfo=dt.timezone.utc), offline=True)
        self.assertEqual("freshness-expired", result["blocked"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
