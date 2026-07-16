"""Generated maintenance CLI inventory and help-contract conformance tests."""

import unittest
from pathlib import Path

import loom_cli_contract


ROOT = Path(__file__).resolve().parents[1]


class ToolContractTests(unittest.TestCase):
    def test_every_executable_loom_tool_has_a_closed_contract(self):
        value = loom_cli_contract.inventory(ROOT)
        discovered = {path.stem for path in loom_cli_contract._entrypoints(ROOT)}
        contracted = {item["name"] for item in value["tools"]}
        self.assertEqual(discovered, contracted)
        self.assertGreaterEqual(len(contracted), 20)

    def test_every_advertised_help_surface_is_real_and_non_mutating(self):
        result = loom_cli_contract.verify(ROOT)
        self.assertEqual("verified", result["status"])
        self.assertEqual(len(result["inventory"]["tools"]), result["tools"])
        self.assertTrue(all(item["invalid_exit"] == 2 for item in result["receipts"]))
        self.assertTrue(all(item["options"] >= 2 for item in result["receipts"]))


if __name__ == "__main__":
    unittest.main()
