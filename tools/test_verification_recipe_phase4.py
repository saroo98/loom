import json
import sys
import tempfile
import unittest
from pathlib import Path

import loom_lifecycle
import loom_proofline
import loom_verification_recipe


ROOT = Path(__file__).resolve().parent.parent


class VerificationRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pack = self.root / "plans"
        self.pack.mkdir()
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_sample.py").write_text(
            "import unittest\n\n"
            "class SampleTests(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertEqual(2, 1 + 1)\n",
            encoding="utf-8")
        self.registry = loom_verification_recipe.load_registry(
            ROOT / "contracts" / "verification-recipes-v1.json")

    def tearDown(self):
        self.temp.cleanup()

    def compile(self, requests, sections=None, tools=None):
        return loom_verification_recipe.compile_recipe(
            root=self.root, pack=self.pack, requests=requests,
            expected_sections=sections or [
                item["section"] for item in requests],
            risk="medium", registry=self.registry,
            available_tools=tools or {"python": sys.executable})

    def test_compiles_and_executes_a_closed_real_medium_recipe(self):
        recipe = self.compile([{
            "section": "testing", "template_id": "python-unittest-v1",
            "target": "tests.test_sample", "timeout_seconds": 30,
        }])
        self.assertFalse(recipe["implementation_authorized"])
        self.assertEqual("exit-code-zero-v1",
                         recipe["steps"][0]["evidence_parser"])
        entries = loom_verification_recipe.execute_recipe(
            recipe=recipe, registry=self.registry,
            root=self.root, pack=self.pack,
            evidence_root=self.root / "private-evidence")
        self.assertEqual(1, len(entries))
        self.assertTrue(entries[0]["passed"])
        self.assertEqual("testing", entries[0]["section"])
        self.assertEqual(
            "loom-compiled-executed-local",
            entries[0]["attestation_status"])

    def test_deduplicates_equal_checks_without_losing_section_coverage(self):
        request = {
            "template_id": "python-unittest-v1",
            "target": "tests.test_sample", "timeout_seconds": 30,
        }
        recipe = self.compile([
            {"section": "accounting", **request},
            {"section": "testing", **request},
        ])
        self.assertEqual(1, len(recipe["steps"]))
        self.assertEqual(
            ["accounting", "testing"], recipe["steps"][0]["sections"])

    def test_unsupported_media_and_missing_project_authority_stay_unsupported(self):
        recipe = self.compile([
            {"section": "browser", "template_id": "browser-e2e-v1",
             "target": "login", "timeout_seconds": 30},
            {"section": "package", "template_id": "npm-script-v1",
             "target": "test", "timeout_seconds": 30},
        ], tools={"python": sys.executable, "npm": sys.executable})
        self.assertEqual([], recipe["steps"])
        self.assertEqual(
            ["authority-missing", "template-unsupported"],
            sorted(item["reason_code"] for item in recipe["unsupported"]))
        with self.assertRaisesRegex(
                loom_verification_recipe.RecipeError, "unsupported"):
            loom_verification_recipe.execute_recipe(
                recipe=recipe, registry=self.registry,
                root=self.root, pack=self.pack,
                evidence_root=self.root / "evidence")

    def test_host_pass_flags_commands_and_tampering_are_rejected(self):
        with self.assertRaisesRegex(
                loom_verification_recipe.RecipeError, "request"):
            self.compile([{
                "section": "testing", "template_id": "python-unittest-v1",
                "target": "tests.test_sample", "timeout_seconds": 30,
                "passed": True,
            }])
        recipe = self.compile([{
            "section": "testing", "template_id": "python-unittest-v1",
            "target": "tests.test_sample", "timeout_seconds": 30,
        }])
        recipe["steps"][0]["command"].append("--invented")
        with self.assertRaisesRegex(
                loom_verification_recipe.RecipeError, "digest"):
            loom_verification_recipe.validate_recipe(recipe)

    def test_changed_subject_refuses_execution(self):
        recipe = self.compile([{
            "section": "testing", "template_id": "python-unittest-v1",
            "target": "tests.test_sample", "timeout_seconds": 30,
        }])
        (self.root / "source.py").write_text("changed = True\n", encoding="utf-8")
        with self.assertRaisesRegex(
                loom_verification_recipe.RecipeError, "subject changed"):
            loom_verification_recipe.execute_recipe(
                recipe=recipe, registry=self.registry,
                root=self.root, pack=self.pack,
                evidence_root=self.root / "evidence")

    def test_current_package_script_authority_is_content_bound(self):
        package = self.root / "package.json"
        package.write_text(json.dumps({
            "name": "proof-project",
            "scripts": {"test": "node test.js"},
        }), encoding="utf-8")
        recipe = self.compile([{
            "section": "package", "template_id": "npm-script-v1",
            "target": "test", "timeout_seconds": 30,
        }], tools={"python": sys.executable, "npm": sys.executable})
        step = recipe["steps"][0]
        self.assertEqual("current-project-authority", step["authority"])
        self.assertEqual(
            [sys.executable, "run", "--silent", "test"],
            step["command"])
        package.write_text(json.dumps({
            "name": "proof-project",
            "scripts": {"test": "node changed.js"},
        }), encoding="utf-8")
        recipe["subject_state_sha256"] = (
            loom_lifecycle.inspect_world(self.root, self.pack)["state_hash"])
        unsigned = dict(recipe)
        unsigned.pop("recipe_sha256")
        recipe["recipe_sha256"] = loom_proofline.digest(unsigned)
        with self.assertRaisesRegex(
                loom_verification_recipe.RecipeError, "authority changed"):
            loom_verification_recipe.execute_recipe(
                recipe=recipe, registry=self.registry,
                root=self.root, pack=self.pack,
                evidence_root=self.root / "evidence")

    def test_failing_compiled_check_never_produces_passed_evidence(self):
        (self.root / "tests" / "test_failure.py").write_text(
            "import unittest\n\n"
            "class FailureTests(unittest.TestCase):\n"
            "    def test_failure(self):\n"
            "        self.fail('expected failure')\n",
            encoding="utf-8")
        recipe = self.compile([{
            "section": "testing", "template_id": "python-unittest-v1",
            "target": "tests.test_failure", "timeout_seconds": 30,
        }])
        with self.assertRaisesRegex(
                loom_verification_recipe.RecipeError,
                "selected-unittest-target-failed"):
            loom_verification_recipe.execute_recipe(
                recipe=recipe, registry=self.registry,
                root=self.root, pack=self.pack,
                evidence_root=self.root / "evidence")
        self.assertFalse((self.root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
