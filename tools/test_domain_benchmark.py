import unittest

import loom_domain_benchmark


class DomainBenchmarkTests(unittest.TestCase):
    def test_locked_corpus_meets_release_thresholds(self):
        report = loom_domain_benchmark.run()
        self.assertEqual(240, report["case_count"])
        self.assertEqual(120, report["hidden_cue_cases"])
        self.assertEqual(0, report["critical_high_unsafe_authorizations"])
        self.assertEqual(0, report["material_boundary_misses"])
        self.assertGreaterEqual(report["macro_recall"], .98)
        self.assertGreaterEqual(report["macro_precision"], .97)
        self.assertTrue(report["passed"], report["failures"])

    def test_scope_firewall_has_zero_wrong_domain_selection(self):
        report = loom_domain_benchmark.scope_firewall_traces(100_000)
        self.assertEqual(0, report["wrong_domain_selections"])
        self.assertTrue(report["passed"])

    def test_known_route_stays_bounded_and_network_free(self):
        report = loom_domain_benchmark.performance(200)
        self.assertLess(report["known_p95_ms"], 20)
        self.assertLessEqual(report["unknown_capsule_bytes"], 8192)
        self.assertEqual(0, report["known_external_retrievals"])
        self.assertTrue(report["passed"])


if __name__ == "__main__":
    unittest.main()
