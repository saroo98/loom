import unittest

import loom_adapter_bridge


class AdapterOwnerErrorTests(unittest.TestCase):
    def test_runtime_block_explains_consequence_and_preserves_safe_reason(self):
        message = loom_adapter_bridge._runtime_block_message({
            "error": (
                "direct source crypto helper build failed: locked dependencies "
                "are unavailable in the local Cargo cache")
        })
        self.assertIn("Loom could not start", message)
        self.assertIn("locked dependencies", message)
        self.assertIn("No plan or project files were changed", message)
        self.assertNotIn("adapter probe", message)

    def test_runtime_block_redacts_local_paths(self):
        message = loom_adapter_bridge._runtime_block_message({
            "error": r"runtime C:\Users\Owner\private\file.json is invalid"
        })
        self.assertIn("[local path]", message)
        self.assertNotIn("Owner", message)


if __name__ == "__main__":
    unittest.main()
