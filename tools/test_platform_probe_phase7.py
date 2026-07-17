import unittest

import loom_platform_probe


class PlatformProbePhase7Tests(unittest.TestCase):
    def test_local_probe_is_honest_and_content_bound(self):
        result = loom_platform_probe.collect()
        self.assertEqual("mechanical-local", result["evidence_class"])
        self.assertEqual("supported", result["filesystem_capabilities"]["atomic_replace"])
        self.assertIn(result["filesystem_capabilities"]["fifo"],
                      {"supported", "unavailable"})
        self.assertEqual(64, len(result["receipt_sha256"]))

    def test_named_runner_requires_a_bound_workflow_digest(self):
        with self.assertRaises(ValueError):
            loom_platform_probe.collect(runner="test-runner")
        result = loom_platform_probe.collect(
            runner="test-runner", workflow_digest="a" * 64)
        self.assertEqual("ci-reproduced", result["evidence_class"])
        self.assertEqual("test-runner", result["runner"])

    def test_workflow_digest_without_runner_is_refused(self):
        with self.assertRaises(ValueError):
            loom_platform_probe.collect(workflow_digest="a" * 64)


if __name__ == "__main__":
    unittest.main()
