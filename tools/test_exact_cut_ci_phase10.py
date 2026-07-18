import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_exact_cut_ci


class ExactCutCiPhase10Tests(unittest.TestCase):
    def test_verifier_failure_still_emits_actionable_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "receipt.json"
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=RuntimeError("injected exact-cut failure")):
                result = loom_exact_cut_ci.run(root, root / "cut", output)
            self.assertEqual("failed", result["status"])
            self.assertEqual("RuntimeError", result["error_type"])
            self.assertRegex(result["error_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn(str(root), "".join(result["traceback_tail"]))
            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))

    def test_success_receipt_binds_built_and_verified_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "receipt.json"
            suite_output = root / "suite.json"
            verified = {"root_sha256": "a" * 64, "suite": {"tests": 7}}
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        return_value=verified):
                result = loom_exact_cut_ci.run(
                    root, root / "cut", output, suite_output=suite_output)
            self.assertEqual("verified", result["status"])
            self.assertEqual(result["build_root_sha256"], result["verified_root_sha256"])
            suite = json.loads(suite_output.read_text(encoding="utf-8"))
            self.assertEqual(7, suite["tests"])
            self.assertEqual("a" * 64, suite["binding"]["public_root_sha256"])


if __name__ == "__main__":
    unittest.main()
