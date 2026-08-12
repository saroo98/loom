"""Fixed general-lane canonical and skip-policy workload."""

import unittest

import loom_suite_harness
from fixture_support import canonical_sha256


class QualificationGeneralATests(unittest.TestCase):
    def test_canonical_projection(self):
        self.assertEqual(64, len(canonical_sha256(["general", "a"])))

    def test_skip_policy_projection(self):
        self.assertEqual(
            "platform-boundary",
            loom_suite_harness.skip_reason_code(
                "native Windows platform boundary"))
