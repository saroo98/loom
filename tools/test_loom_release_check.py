"""Release coherence tests."""

import json
import shutil
import sys
import tempfile
import unittest
import contextlib
import io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_release_check  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class ReleaseCoherenceTests(unittest.TestCase):
    def test_source_tree_is_version_coherent(self):
        self.assertEqual(loom_release_check.source_findings(ROOT), [])

    def test_stale_public_changelog_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "tools", root / "tools")
            shutil.copytree(ROOT / "templates", root / "templates")
            (root / "public").mkdir()
            (root / "loom" / "intake").mkdir(parents=True)
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            (root / "CHANGELOG.md").write_text("## 9.9.9\n", encoding="utf-8")
            (root / "public" / "CHANGELOG.md").write_text("## 9.9.8\n", encoding="utf-8")
            findings = loom_release_check.source_findings(root)
            self.assertTrue(any("public/CHANGELOG.md" in item for item in findings), findings)

    def test_json_cli_reports_real_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("bad\n", encoding="utf-8")
            self.assertEqual(
                loom_release_check.source_findings(root),
                ["VERSION is not semantic x.y.z"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = loom_release_check.main(["--root", str(root), "--json"])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(payload["status"], "fail")
            self.assertIsNone(payload["version"])
            self.assertIn("VERSION is not semantic x.y.z", payload["findings"])

    def test_every_shipped_schema_is_parseable_and_declared(self):
        schemas = sorted((ROOT / "schemas").glob("*.json"))
        self.assertTrue(schemas)
        for path in schemas:
            with self.subTest(path=path.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)
                self.assertIn("$schema", data)


if __name__ == "__main__":
    unittest.main()
