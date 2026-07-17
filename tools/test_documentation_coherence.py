import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import loom_docs


ROOT = Path(__file__).resolve().parents[1]


class _SiteParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = []
        self.links = []
        self.scripts = []
        self.meta = {}
        self.has_main = False
        self.has_nav = False
        self.has_skip_link = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "main":
            self.has_main = True
        if tag == "nav":
            self.has_nav = True
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
            if values.get("class") == "skip-link":
                self.has_skip_link = True
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        if tag == "link" and values.get("href"):
            self.links.append(values["href"])
        if tag == "meta":
            key = values.get("name") or values.get("property")
            if key:
                self.meta[key] = values.get("content")


class DocumentationCoherenceTests(unittest.TestCase):
    def test_every_published_schema_is_valid_json(self):
        for path in sorted((ROOT / "schemas").glob("*.json")):
            with self.subTest(schema=path.name):
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertIsInstance(value, dict)

    def test_public_website_is_self_contained_accessible_and_share_ready(self):
        docs = ROOT / "docs"
        index = docs / "index.html"
        parser = _SiteParser()
        parser.feed(index.read_text(encoding="utf-8"))

        self.assertTrue(parser.has_main)
        self.assertTrue(parser.has_nav)
        self.assertTrue(parser.has_skip_link)
        self.assertEqual(len(parser.ids), len(set(parser.ids)), "duplicate HTML id")
        self.assertEqual(["site.js"], [urlparse(path).path for path in parser.scripts])
        self.assertIn("description", parser.meta)
        self.assertIn("og:title", parser.meta)
        self.assertIn("og:image", parser.meta)
        self.assertEqual("summary_large_image", parser.meta.get("twitter:card"))

        required = {
            ".nojekyll", "404.html", "favicon.svg", "readme-hero.svg", "robots.txt",
            "site.css", "site.js", "sitemap.xml", "social-card.svg",
        }
        self.assertEqual([], sorted(name for name in required if not (docs / name).is_file()))
        self.assertLess((docs / "social-card.svg").stat().st_size, 25_000)

        for reference in parser.links + parser.scripts:
            parsed = urlparse(reference)
            if parsed.scheme or reference.startswith(("#", "//")):
                continue
            target = (docs / parsed.path).resolve()
            self.assertTrue(target.is_file(), reference)

    def test_public_surface_teaches_one_command_without_internal_command_sprawl(self):
        report = loom_docs.audit_docs(ROOT)
        self.assertEqual([], report["findings"], report)
        for relative in loom_docs.PUBLIC_SURFACE:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("/loom <request>", text)
            for forbidden in loom_docs.FORBIDDEN_PUBLIC_COMMANDS:
                self.assertNotIn(forbidden, text.lower())

    def test_every_capability_is_mechanical_with_existing_proof_or_advisory(self):
        registry = loom_docs.load_capabilities(ROOT)
        self.assertGreaterEqual(len(registry["capabilities"]), 10)
        for capability in registry["capabilities"]:
            if capability["kind"] == "mechanical":
                self.assertTrue(capability["enforcement"])
                self.assertTrue(capability["tests"])
                for relative in capability["enforcement"] + capability["tests"]:
                    self.assertTrue((ROOT / relative).is_file(), relative)
            else:
                self.assertEqual("advisory", capability["kind"])

    def test_contradiction_scanner_catches_legacy_manual_learning_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text(
                "Run /loom <request>. Then manually update FEEDBACK.md after every run.",
                encoding="utf-8")
            findings = loom_docs.scan_contradictions(root, ["README.md"])
            self.assertTrue(any(item["code"] == "LEGACY_MANUAL_LEARNING" for item in findings))

    def test_generated_evidence_is_derived_from_live_inventory(self):
        evidence = loom_docs.generate_evidence(ROOT)
        discovered = sum(
            1 for path in (ROOT / "tools").glob("test_*.py")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.lstrip().startswith("def test_"))
        self.assertEqual(discovered, evidence["discovered_test_methods"])
        self.assertEqual(
            len(list((ROOT / "schemas").glob("*.schema.json"))),
            evidence["schema_documents"])
        self.assertNotIn("passing_tests", evidence)

    def test_docs_audit_rejects_stale_generated_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
            for relative in loom_docs.PUBLIC_SURFACE + ("docs/architecture.md",):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Loom 1.0.0 /loom <request>\n", encoding="utf-8")
            capabilities = {
                "schema_version": 1, "version": "1.0.0", "capabilities": [],
            }
            (root / "docs" / "capabilities.json").write_text(
                json.dumps(capabilities), encoding="utf-8")
            (root / "tools").mkdir(exist_ok=True)
            (root / "tools" / "loom_sample.py").write_text(
                "VALUE = 1\n", encoding="utf-8")
            (root / "tools" / "test_sample.py").write_text(
                "def test_live_inventory():\n    pass\n", encoding="utf-8")
            (root / "schemas").mkdir()
            (root / "schemas" / "sample.schema.json").write_text(
                "{}\n", encoding="utf-8")
            (root / "docs" / "generated-evidence.json").write_text(
                json.dumps({"schema_version": 1, "discovered_test_methods": 0}),
                encoding="utf-8")

            report = loom_docs.audit_docs(root)

            self.assertIn("GENERATED_EVIDENCE_STALE", {
                item["code"] for item in report["findings"]})

    def test_non_link_repository_document_reference_must_exist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "note.md").write_text(
                "Follow `loom/execution/missing.md` before work.\n",
                encoding="utf-8")
            self.assertEqual([{
                "code": "REPO_REFERENCE_MISSING",
                "path": "note.md",
                "target": "loom/execution/missing.md",
            }], loom_docs._repo_reference_findings(root))

    def test_nested_skill_path_is_not_misread_as_a_missing_loom_document(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            skill = root / "skill" / "loom" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("# Loom skill\n", encoding="utf-8")
            (root / "BUILD-MANIFEST.json").write_text(json.dumps({
                "schema_version": 1,
                "files": [{"path": "skill/loom/SKILL.md"}],
            }), encoding="utf-8")

            self.assertEqual([], loom_docs._repo_reference_findings(root))

    def test_version_is_single_source_and_all_entry_points_match(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual([], loom_docs.check_version_coherence(ROOT, version))

    def test_visible_version_badge_cannot_hide_a_stale_short_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            index = root / "docs" / "index.html"
            index.parent.mkdir(parents=True)
            index.write_text(
                '<span data-loom-version="1.6.0">1.0</span>',
                encoding="utf-8",
            )
            findings = loom_docs.check_version_coherence(root, "1.6.0")
            self.assertEqual(
                ["VERSION_BADGE_DRIFT"],
                [item["code"] for item in findings
                 if item["code"].startswith("VERSION_BADGE")],
            )

    def test_minimal_public_cut_needs_no_decorative_version_assets_or_badge(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in loom_docs.VERSION_SURFACE:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Loom 1.6.0\n", encoding="utf-8")

            self.assertEqual([], loom_docs.check_version_coherence(root, "1.6.0"))

    def test_optional_visual_asset_is_checked_when_it_ships(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in loom_docs.VERSION_SURFACE:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Loom 1.6.0\n", encoding="utf-8")
            hero = root / "docs" / "readme-hero.svg"
            hero.write_text("<svg><text>Loom 1.0</text></svg>", encoding="utf-8")

            findings = loom_docs.check_version_coherence(root, "1.6.0")
            self.assertEqual(
                [{"code": "VERSION_DRIFT", "path": "docs/readme-hero.svg",
                  "expected": "1.6.0"}],
                findings,
            )


if __name__ == "__main__":
    unittest.main()
