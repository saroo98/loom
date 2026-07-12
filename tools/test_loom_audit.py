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

    def test_aliased_subprocess_cannot_hide_foreign_program(self):
        root = self._tree_with(
            "import subprocess as sp\nsp.run(['curl', 'x'])\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("curl" in f for f in findings), findings)

    def test_from_subprocess_import_cannot_hide_foreign_program(self):
        root = self._tree_with(
            "from subprocess import run\nrun(['curl', 'x'])\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("curl" in f for f in findings), findings)

    def test_dynamic_network_import_is_caught(self):
        root = self._tree_with("__import__('urllib.request')\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("urllib" in f for f in findings), findings)

    def test_nonliteral_dynamic_import_fails_closed(self):
        root = self._tree_with("__import__(module_name)\n")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("dynamic import" in f for f in findings), findings)

    def test_nested_python_files_are_scanned(self):
        root = Path(self._tree_with("pass\n"))
        nested = root / "tools" / "nested"
        nested.mkdir()
        (nested / "bad.py").write_text("import socket\n", encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("socket" in f for f in findings), findings)

    def test_workflow_download_command_is_caught(self):
        root = Path(self._tree_with("pass\n"))
        workflow = root / ".github" / "workflows" / "bad.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("run: curl https://example.invalid/x\n", encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("curl" in f for f in findings), findings)

    def test_unapproved_workflow_action_is_caught(self):
        root = Path(self._tree_with("pass\n"))
        workflow = root / ".github" / "workflows" / "bad.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("steps:\n  - uses: stranger/action@v1\n", encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("not allowlisted" in item for item in findings), findings)

    def test_mutable_official_action_tag_is_caught(self):
        root = Path(self._tree_with("pass\n"))
        workflow = root / ".github" / "workflows" / "bad.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("not allowlisted" in item for item in findings), findings)

    def test_exact_pinned_official_actions_are_allowed(self):
        root = Path(self._tree_with("pass\n"))
        workflow = root / ".github" / "workflows" / "good.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "steps:\n"
            "  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
            "  - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\n",
            encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertEqual(findings, [], findings)

    def test_browser_network_apis_and_active_remote_resources_are_caught(self):
        root = Path(self._tree_with("pass\n"))
        web = root / "public" / "docs"
        web.mkdir(parents=True)
        (web / "bad.html").write_text(
            "<img src='https://tracker.invalid/pixel'>"
            "<script>fetch('https://tracker.invalid/event')</script>",
            encoding="utf-8")
        (web / "bad.js").write_text(
            "navigator.sendBeacon('/event', payload);", encoding="utf-8")
        (web / "bad.css").write_text(
            "body { background: url(https://tracker.invalid/pixel); }",
            encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("remote active img[src]" in item for item in findings), findings)
        self.assertTrue(any("browser network API" in item for item in findings), findings)
        self.assertTrue(any("remote CSS resource" in item for item in findings), findings)

    def test_inert_external_links_and_metadata_do_not_claim_network_execution(self):
        root = Path(self._tree_with("pass\n"))
        html = root / "public" / "docs" / "index.html"
        html.parent.mkdir(parents=True)
        html.write_text(
            "<link rel='canonical' href='https://example.invalid/page'>"
            "<a href='https://example.invalid/docs'>docs</a>"
            "<script type='application/ld+json'>"
            "{\"url\":\"https://example.invalid/page\"}</script>",
            encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertEqual(findings, [], findings)

    def test_remote_markdown_images_are_caught_but_links_are_inert(self):
        root = Path(self._tree_with("pass\n"))
        readme = root / "README.md"
        readme.write_text(
            "[ordinary link](https://example.invalid/docs)\n"
            "![tracking pixel](https://tracker.invalid/pixel.png)\n",
            encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertEqual(
            len([item for item in findings if "remote rendered Markdown image" in item]), 1,
            findings)

    def test_installer_test_may_only_launch_the_local_installer_script(self):
        root = Path(self._tree_with("pass\n"))
        path = root / "tools" / "test_loom_install.py"
        path.write_text(
            "import subprocess\n"
            "command = ['powershell', '-File', 'install.ps1']\n"
            "subprocess.run(command + ['-Check'])\n",
            encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertEqual(findings, [], findings)
        path.write_text(
            "import subprocess\n"
            "subprocess.run(['powershell', '-Command', 'do-something'])\n",
            encoding="utf-8")
        _, findings = loom_audit.audit(root)
        self.assertTrue(any("not bound to install.ps1" in item for item in findings),
                        findings)

    def test_cli_exit_codes(self):
        self.assertEqual(loom_audit.main([str(LOOM_ROOT)]), 0)
        root = self._tree_with("import socket\n")
        self.assertEqual(loom_audit.main([root]), 1)


if __name__ == "__main__":
    unittest.main()
