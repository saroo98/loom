"""Fixed exclusive-lane workload."""

import unittest

from fixture_support import canonical_sha256, parallel_hold


class QualificationExclusiveTests(unittest.TestCase):
    def test_exclusive_lane(self):
        parallel_hold(3000)
        self.assertEqual(
            canonical_sha256({"exclusive": True}),
            "a7ba80d1b6b90554588dd3fd72e9906b976b88ce3a454c9edc91b522c8776324")
