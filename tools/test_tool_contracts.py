"""Generated maintenance CLI inventory and help-contract conformance tests."""

import subprocess
import unittest
from pathlib import Path
from unittest import mock

import loom_cli_contract


ROOT = Path(__file__).resolve().parents[1]


class ToolContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verification = loom_cli_contract.verify(ROOT)

    def test_every_executable_loom_tool_has_a_closed_contract(self):
        value = self.verification["inventory"]
        discovered = {path.stem for path in loom_cli_contract._entrypoints(ROOT)}
        contracted = {item["name"] for item in value["tools"]}
        self.assertEqual(discovered, contracted)
        self.assertGreaterEqual(len(contracted), 20)

    def test_every_advertised_help_surface_is_real_and_non_mutating(self):
        result = self.verification
        self.assertEqual("verified", result["status"])
        self.assertEqual(len(result["inventory"]["tools"]), result["tools"])
        self.assertTrue(all(item["invalid_exit"] == 2 for item in result["receipts"]))
        self.assertTrue(all(item["options"] >= 2 for item in result["receipts"]))

    def test_windows_probe_concurrency_is_bounded_for_hosted_runners(self):
        self.assertEqual(2, loom_cli_contract._worker_count(100, platform="nt"))
        self.assertEqual(8, loom_cli_contract._worker_count(100, platform="posix"))
        self.assertEqual(1, loom_cli_contract._worker_count(1, platform="nt"))

    def test_probe_timeout_fails_closed_with_exact_diagnostics(self):
        command = ["python", "-B", "tool.py", "--help"]
        with mock.patch(
                "loom_cli_contract.subprocess.run",
                side_effect=subprocess.TimeoutExpired(
                    command, loom_cli_contract.CLI_PROBE_TIMEOUT_SECONDS)):
            with self.assertRaisesRegex(
                    loom_cli_contract.ContractError,
                    "loom_example --help exceeded the bounded 30-second CLI probe budget"):
                loom_cli_contract._run_probe(
                    command, cwd=ROOT, environment={},
                    label="loom_example --help")


if __name__ == "__main__":
    unittest.main()
