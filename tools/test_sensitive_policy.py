import json
import shutil
import tempfile
import unittest
from pathlib import Path

import loom_sensitive_policy


class SensitivePolicyTests(unittest.TestCase):
    def fixture(self, root):
        policy = json.loads(
            (loom_sensitive_policy.ROOT / "contracts" /
             "sensitive-operation-policy-v1.json").read_text(encoding="utf-8"))
        target = root / "contracts" / "sensitive-operation-policy-v1.json"
        target.parent.mkdir(parents=True)
        shutil.copy2(
            loom_sensitive_policy.ROOT / "contracts" /
            "sensitive-operation-policy-v1.json", target)
        for relative in policy["designated_modules"]:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(loom_sensitive_policy.ROOT / relative, destination)

    def test_current_designated_modules_have_no_unregistered_bypass(self):
        self.assertEqual("passed", loom_sensitive_policy.inspect()["status"])

    def test_new_direct_process_or_delete_bypass_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            target = root / "tools" / "loom_exact_cut_ci.py"
            target.write_text(
                target.read_text(encoding="utf-8")
                + "\ndef bypass():\n    subprocess.run(['unsafe'])\n",
                encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_sensitive_policy.SensitivePolicyError,
                    "subprocess.run"):
                loom_sensitive_policy.inspect(root)

    def test_stale_exception_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            target = root / "tools" / "loom_release.py"
            target.write_text(
                target.read_text(encoding="utf-8").replace(
                    "result = subprocess.run(", "result = supervised_run("),
                encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_sensitive_policy.SensitivePolicyError,
                    "stale_exceptions"):
                loom_sensitive_policy.inspect(root)


if __name__ == "__main__":
    unittest.main()
