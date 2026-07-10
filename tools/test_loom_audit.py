"""Tests for loom_audit. Run: python -m unittest discover -s tools -p "test_*.py" """

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_audit  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent


class AuditTests(unittest.TestCase):
    def test_this_tree_passes(self):
        scanned, findings = loom_audit.audit(LOOM_ROOT)
        self.assertGreater(scanned, 10)
        self.assertEqual(findings, [], findings)

    def _tree_with(self, code):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tools = Path(tmp.name) / "tools"
        tools.mkdir()
        (tools / "bad.py").write_text(code, encoding="utf-8")
        return tmp.name

    def test_network_import_fails(self):
        root = self._tree_with("import urllib.request\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("urllib" in f for f in findings))

    def test_from_import_fails(self):
        root = self._tree_with("from http.client import HTTPConnection\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("http" in f for f in findings))

    def test_foreign_subprocess_fails(self):
        root = self._tree_with(
            "import subprocess\nsubprocess.run(['curl', 'x'])\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("curl" in f for f in findings))

    def test_git_subprocess_allowed(self):
        root = self._tree_with(
            "import subprocess\nsubprocess.run(['git', 'status'])\n")
        _, findings = loom_audit.audit(root)
        self.assertEqual(findings, [], findings)

    def test_cli_exit_codes(self):
        self.assertEqual(loom_audit.main([str(LOOM_ROOT)]), 0)
        root = self._tree_with("import socket\n")
        self.assertEqual(loom_audit.main([root]), 1)


if __name__ == "__main__":
    unittest.main()
