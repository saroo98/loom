"""Real forced-process-termination probes for durable pointer writes."""

import unittest
from pathlib import Path

import loom_fault_harness


ROOT = Path(__file__).resolve().parents[1]


class CrashRecoveryTests(unittest.TestCase):
    def test_process_death_before_and_after_replace_is_old_or_new_never_partial(self):
        result = loom_fault_harness.atomic_pointer_probe(ROOT)
        self.assertEqual("passed", result["status"])
        self.assertEqual(2, len(result["boundaries"]))


if __name__ == "__main__":
    unittest.main()
