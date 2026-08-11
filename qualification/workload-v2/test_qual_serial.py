"""Fixed serial discovery and exact-selection workload."""

import unittest

from fixture_support import canonical_sha256


class QualificationSerialTests(unittest.TestCase):
    def test_serial_baseline(self):
        self.assertEqual(
            canonical_sha256({"lane": "serial", "value": 1}),
            canonical_sha256({"value": 1, "lane": "serial"}))
