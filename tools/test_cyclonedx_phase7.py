import json
import tempfile
import unittest
from pathlib import Path

import loom_cyclonedx


class CycloneDxPhase7Tests(unittest.TestCase):
    def test_final_helper_and_lockfile_are_reconciled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "source"
            (source / "vault-helper").mkdir(parents=True)
            (source / "VERSION").write_text("1.6.0\n", encoding="utf-8")
            (source / "vault-helper" / "Cargo.lock").write_text(
                'version = 3\n\n[[package]]\nname = "alpha"\nversion = "1.2.3"\n',
                encoding="utf-8")
            helper = root / "helper"; helper.write_bytes(b"exact-helper")
            output = root / "bom.json"
            result = loom_cyclonedx.create(
                source, helper, output, platform_id="linux-x64",
                namespace_seed="a" * 64)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("CycloneDX", value["bomFormat"])
            self.assertEqual(2, result["components"])
            self.assertEqual("alpha", value["components"][1]["name"])


if __name__ == "__main__":
    unittest.main()
