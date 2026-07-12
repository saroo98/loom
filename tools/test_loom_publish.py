"""Tests for loom_publish. Run: python -m unittest discover -s tools -p "test_*.py" """

import sys
import tempfile
import unittest
import re
import json
import io
import subprocess
from pathlib import Path
from unittest import mock
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).parent))
import loom_publish  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent
IS_PRIVATE_UPSTREAM = (LOOM_ROOT / "plans" / "MANIFEST.md").is_file()


class PublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "public"
        cls.rc = loom_publish.build(cls.out, check=False, allow_outside=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_build_is_clean(self):
        self.assertEqual(self.rc, 0, "firewall/link findings or missing entries")

    def test_core_present(self):
        for rel in ["START-HERE.md", "README.md", "PRIVACY.md", "CONTRIBUTING.md",
                    "LICENSE", "FEEDBACK.md", "CHANGELOG.md",
                    "loom/core/epistemics.md", "loom/core/privacy.md",
                    "loom/adaptation/localization-playbook.md",
                    "loom/meta/evolving-loom.md", "loom/meta/v1-scorecard.md",
                    "templates/work-order.md", "templates/hooks/pre-commit",
                    "skill/loom/SKILL.md", "tools/loom_lint.py",
                    "tools/loom_gate.py",
                    "tools/loom_memory.py",
                    "tools/loom_install.py",
                    "tools/loom_publish.py", "tools/publish-tokens.txt",
                    "assets/banner-light.svg", "assets/lifecycle-dark.svg",
                    "docs/index.html", "docs/robots.txt", "docs/sitemap.xml",
                    ".github/workflows/verify.yml", "tools/loom_audit.py"]:
            self.assertTrue((self.out / rel).is_file(), f"missing from cut: {rel}")

    def test_owner_layer_absent(self):
        # note: owner-domain paths are built from fragments so this test file itself
        # never contains a forbidden token contiguously (the firewall scans it too)
        deep_dive = "loom/adaptation/k" + "urdish-localization.md"
        for rel in ["plans", "loom/meta/evidence", "ROADMAP.md", deep_dive,
                    "loom/meta/plan-sharpening.md", "loom/meta/plan-public-cut.md",
                    "loom/meta/plan-learner-public.md", "public", "dist"]:
            self.assertFalse((self.out / rel).exists(), f"owner-layer leaked: {rel}")

    @unittest.skipUnless(IS_PRIVATE_UPSTREAM, "overlay assertions need the upstream tree")
    def test_overlay_won_over_root(self):
        readme = (self.out / "README.md").read_text(encoding="utf-8")
        self.assertIn("Sovereign", readme)               # public README, not owner's
        fb = (self.out / "FEEDBACK.md").read_text(encoding="utf-8")
        self.assertIn("This queue is **yours**", fb)     # fresh header, no entries
        self.assertNotIn("2026-07-09", fb)

    def test_fresh_feedback_has_no_entries(self):
        fb = (self.out / "FEEDBACK.md").read_text(encoding="utf-8")
        self.assertNotIn("Resolution (", fb)

    def test_firewall_catches_a_seeded_leak(self):
        leak = self.out / "loom" / "core" / "principles.md"
        original = leak.read_bytes()
        seeded = "contact: " + "xizir" + "sar" + "o" + "@example.com"  # fragments —
        try:                       # this source file must not carry the token itself
            leak.write_bytes(original + b"\n" + seeded.encode("utf-8") + b"\n")
            tokens, allowed = loom_publish.load_tokens(
                LOOM_ROOT / "tools" / "publish-tokens.txt")
            if not tokens:  # public tree ships a placeholder token file
                self.skipTest("no owner tokens in this tree")
            findings = loom_publish.scan(self.out, tokens, allowed)
            self.assertTrue(any("FIREWALL" in f for f in findings))
        finally:
            leak.write_bytes(original)

    def test_private_project_token_from_owner_feedback_is_firewalled(self):
        leak = self.out / "loom" / "core" / "principles.md"
        original = leak.read_bytes()
        seeded = "Korean" + "-Flashcard"  # split so the private token is absent from source
        try:
            leak.write_bytes(original + b"\n" + seeded.encode("utf-8") + b"\n")
            tokens, allowed = loom_publish.load_tokens(
                LOOM_ROOT / "tools" / "publish-tokens.txt")
            if not tokens:
                self.skipTest("public template intentionally ships no private owner tokens")
            findings = loom_publish.scan(self.out, tokens, allowed)
            self.assertTrue(any("FIREWALL" in item and "korean" in item.lower()
                                for item in findings), findings)
        finally:
            leak.write_bytes(original)

    def test_no_pycache_or_reports(self):
        self.assertFalse(list(self.out.rglob("__pycache__")))
        self.assertFalse(list(self.out.rglob("report.html")))

    def test_existing_unowned_output_is_never_deleted(self):
        """Regression C-01: an arbitrary existing directory is user-owned."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "existing"
            out.mkdir()
            sentinel = out / "preexisting-user-file.txt"
            sentinel.write_text("must survive", encoding="utf-8")

            rc = loom_publish.build(
                out, check=False, allow_outside=True, replace_existing=True)

            self.assertEqual(rc, 2)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "must survive")

    def test_protected_paths_are_rejected_before_build(self):
        protected = {
            LOOM_ROOT.resolve(),
            LOOM_ROOT.resolve().parent,
            Path.cwd().resolve(),
            Path.home().resolve(),
            Path(LOOM_ROOT.resolve().anchor),
        }
        for path in protected:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    loom_publish.validate_output_path(
                        path, allow_outside=True, replace_existing=True)

    def test_only_exact_macos_var_alias_is_exempt_from_symlink_refusal(self):
        with mock.patch.object(loom_publish.sys, "platform", "darwin"), \
                mock.patch.object(Path, "resolve", return_value=Path("/private/var")):
            self.assertTrue(loom_publish._is_macos_system_var_alias(Path("/var")))
            self.assertFalse(loom_publish._is_macos_system_var_alias(Path("/tmp")))
        with mock.patch.object(loom_publish.sys, "platform", "linux"), \
                mock.patch.object(Path, "resolve", return_value=Path("/private/var")):
            self.assertFalse(loom_publish._is_macos_system_var_alias(Path("/var")))

    def test_custom_output_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "new-public"
            self.assertEqual(loom_publish.build(out), 2)
            self.assertFalse(out.exists())

    def test_marker_records_and_verifies_every_generated_file(self):
        marker = self.out / loom_publish.OUTPUT_MARKER
        self.assertTrue(marker.is_file())
        self.assertTrue(loom_publish._marker_is_valid(self.out))
        self.assertNotIn(b"\r\n", marker.read_bytes())

    def test_foreign_addition_to_marked_output_blocks_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            self.assertEqual(loom_publish.build(out, allow_outside=True), 0)
            sentinel = out / "user-added.txt"
            sentinel.write_text("must survive", encoding="utf-8")

            rc = loom_publish.build(
                out, allow_outside=True, replace_existing=True)

            self.assertEqual(rc, 2)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "must survive")

    def test_failed_rebuild_keeps_previous_generated_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            self.assertEqual(loom_publish.build(out, allow_outside=True), 0)
            marker_before = (out / loom_publish.OUTPUT_MARKER).read_bytes()
            with mock.patch.object(
                    loom_publish, "ALLOWLIST",
                    loom_publish.ALLOWLIST + ["does-not-exist"]):
                rc = loom_publish.build(
                    out, allow_outside=True, replace_existing=True)

            self.assertEqual(rc, 2)
            self.assertEqual(
                (out / loom_publish.OUTPUT_MARKER).read_bytes(), marker_before)
            self.assertTrue((out / "START-HERE.md").is_file())

    def test_copy_io_failure_keeps_previous_output_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            self.assertEqual(loom_publish.build(out, allow_outside=True), 0)
            marker_before = (out / loom_publish.OUTPUT_MARKER).read_bytes()
            with mock.patch.object(
                    loom_publish, "copy_path", side_effect=OSError("seeded copy failure")):
                rc = loom_publish.build(
                    out, allow_outside=True, replace_existing=True)
            self.assertEqual(rc, 2)
            self.assertEqual(
                (out / loom_publish.OUTPUT_MARKER).read_bytes(), marker_before)
            self.assertEqual(list(Path(tmp).glob(".public.loom-stage-*")), [])

    def test_activation_io_failure_keeps_previous_output_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            self.assertEqual(loom_publish.build(out, allow_outside=True), 0)
            marker_before = (out / loom_publish.OUTPUT_MARKER).read_bytes()
            with mock.patch.object(
                    loom_publish, "_activate_staged_output",
                    side_effect=OSError("seeded activation failure")):
                rc = loom_publish.build(
                    out, allow_outside=True, replace_existing=True)
            self.assertEqual(rc, 2)
            self.assertEqual(
                (out / loom_publish.OUTPUT_MARKER).read_bytes(), marker_before)
            self.assertEqual(list(Path(tmp).glob(".public.loom-stage-*")), [])

    def test_check_refuses_any_non_cache_suite_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"

            def mutate_stage(*args, **kwargs):
                stage = Path(kwargs["cwd"])
                (stage / "late-suite-file.html").write_text(
                    "late mutation", encoding="utf-8")
                return subprocess.CompletedProcess(args[0], 0, "", "OK\n")

            with mock.patch.object(loom_publish.subprocess, "run", side_effect=mutate_stage):
                rc = loom_publish.build(out, check=True, allow_outside=True)
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists())
            self.assertEqual(list(Path(tmp).glob(".public.loom-stage-*")), [])

    def test_allowlisted_source_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / "allowlisted.txt"
            link.write_text("simulated link target", encoding="utf-8")
            with mock.patch.object(loom_publish, "ROOT", root), \
                    mock.patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaisesRegex(OSError, "symlink"):
                    loom_publish._assert_source_tree_safe(link)

    def test_firewall_scans_every_supported_text_extension(self):
        extensions = [
            ".html", ".htm", ".svg", ".css", ".js", ".mjs", ".cjs",
            ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".csv",
            ".md", ".py", ".json", ".txt", ".ps1", ".sh", "",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, extension in enumerate(extensions):
                (root / f"leak-{index}{extension}").write_text(
                    "PRIVATE-MARKER", encoding="utf-8")
            findings = loom_publish.scan(
                root, [("marker", re.compile("PRIVATE-MARKER"))])
            leaked_files = {f.split()[1].split(":", 1)[0] for f in findings
                            if f.startswith("FIREWALL")}
            self.assertEqual(len(leaked_files), len(extensions), findings)

    def test_non_utf8_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "opaque.html").write_bytes(b"\xff\xfe\x00\x81")
            findings = loom_publish.scan(root, [])
            self.assertTrue(any(f.startswith("ENCODING") for f in findings), findings)

    def test_forbidden_token_in_filename_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "PRIVATE-MARKER.svg").write_text("<svg/>", encoding="utf-8")
            findings = loom_publish.scan(
                root, [("marker", re.compile("PRIVATE-MARKER"))])
            self.assertTrue(any(f.startswith("FIREWALL-PATH") for f in findings), findings)

    def test_secret_before_placeholder_on_same_line_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = "pass" + "word: fake-but-secret-shaped-12345 <VALUE>"
            (root / "x.txt").write_text(
                fixture, encoding="utf-8")
            findings = loom_publish.scan(root, [])
            self.assertTrue(any(f.startswith("SECRET") for f in findings), findings)

    @unittest.skipUnless(IS_PRIVATE_UPSTREAM, "owner-mode assertion needs private source")
    def test_owner_build_with_zero_forbidden_tokens_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            with mock.patch.object(loom_publish, "load_tokens", return_value=([], [])):
                rc = loom_publish.build(out, allow_outside=True)
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists())

    def test_json_cli_is_machine_readable_and_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = loom_publish.main([
                    "--out", str(out), "--allow-outside-dist", "--json",
                ])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(rc, 0)
            self.assertEqual(payload["exit_code"], 0)
            self.assertEqual(payload["status"], "built")
            self.assertEqual(payload["output"], str(out.resolve()))
            self.assertEqual(
                payload["shipped_file_count"],
                sum(1 for path in out.rglob("*") if path.is_file()))
            self.assertTrue(payload["output_exists"])

    def test_html_file_and_anchor_links_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text(
                '<a href="missing.html">missing</a>'
                '<a href="#missing-anchor">anchor</a>', encoding="utf-8")
            findings = loom_publish.scan(root, [])
            self.assertEqual(sum(f.startswith("LINK") for f in findings), 2, findings)

    def test_markdown_heading_anchors_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "# Existing heading\n[ok](#existing-heading)\n[bad](#absent)\n",
                encoding="utf-8")
            findings = loom_publish.scan(root, [])
            links = [f for f in findings if f.startswith("LINK")]
            self.assertEqual(len(links), 1, findings)
            self.assertIn("absent", links[0])

    def test_css_local_urls_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "site.css").write_text(
                "body { background: url('./missing.png'); }", encoding="utf-8")
            findings = loom_publish.scan(root, [])
            self.assertTrue(any(f.startswith("LINK") for f in findings), findings)


if __name__ == "__main__":
    unittest.main()
