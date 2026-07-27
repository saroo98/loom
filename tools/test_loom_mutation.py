"""Trust-critical mutation gate contract tests."""

import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_mutation


ROOT = Path(__file__).resolve().parents[1]


class MutationGateTests(unittest.TestCase):
    def test_each_mutant_owns_an_isolated_native_helper_cache(self):
        mutation = loom_mutation.MUTATIONS[0]
        _, relative, original, _, _ = mutation
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_text(original, encoding="utf-8")
            observed = {}

            def run(*_args, **kwargs):
                observed.update(kwargs["env"])
                return subprocess.CompletedProcess([], 1)

            with mock.patch.object(loom_mutation.subprocess, "run",
                                   side_effect=run):
                loom_mutation._run_mutation(root, mutation, 1)

        cache = Path(observed["LOOM_TEST_CACHE_ROOT"])
        self.assertEqual(".test-cache", cache.name)
        self.assertEqual("loom", cache.parent.name)

    def test_every_named_trust_guard_mutation_is_killed(self):
        result = loom_mutation.run(ROOT, minimum_score=90, timeout=120)
        self.assertEqual("passed", result["status"])
        self.assertGreaterEqual(result["score"], 90)
        self.assertTrue(all(item["killed"] for item in result["receipts"]))


if __name__ == "__main__":
    unittest.main()
