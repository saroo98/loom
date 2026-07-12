"""Guard the compact Tier-S context against silent growth."""

import unittest
from pathlib import Path
import json
import contextlib
import io

import sys
sys.path.insert(0, str(Path(__file__).parent))
import loom_context  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class ContextBudgetTests(unittest.TestCase):
    def test_small_kernel_is_bounded(self):
        kernel = (ROOT / "loom" / "core" / "small-kernel.md").read_text(encoding="utf-8")
        self.assertLessEqual(len(kernel), 6500)

    def test_small_ui_context_is_bounded(self):
        paths = (
            ROOT / "loom" / "core" / "small-kernel.md",
            ROOT / "loom" / "execution" / "design-floor-small.md",
        )
        total = sum(len(path.read_text(encoding="utf-8")) for path in paths)
        self.assertLessEqual(total, 10000)

    def test_full_tier_s_dispatch_routes_are_hard_bounded(self):
        core = loom_context.measure("session-tier-s-core", ROOT)
        ui = loom_context.measure("session-tier-s-ui", ROOT)
        self.assertLessEqual(core["unicode_characters"], 20000)
        self.assertLessEqual(ui["unicode_characters"], 24000)

    def test_context_inventory_is_exact_and_never_invents_tokens(self):
        result = loom_context.measure("session-tier-s-ui", ROOT)
        expected = sum((ROOT / item["path"]).stat().st_size for item in result["files"])
        self.assertEqual(result["utf8_bytes"], expected)
        self.assertIsNone(result["tokenizer_tokens"])
        self.assertIsNone(result["cache_read_tokens"])

    def test_mplus_inventory_names_the_complete_fixed_repo_planning_base(self):
        result = loom_context.measure("session-tier-mplus", ROOT)
        paths = [item["path"] for item in result["files"]]
        required = {
            "skill/loom/SKILL.md", "START-HERE.md", "loom/core/user-memory.md",
            "loom/intake/artifact-matrix.md", "loom/planning/plan-authoring.md",
            "loom/execution/work-orders.md", "loom/review/gates.md",
            "loom/review/rubric.md", "loom/verification/self-verification.md",
        }
        self.assertTrue(required.issubset(paths))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn(
            "route-dependent artifact/domain guides and templates", result["excluded"])
        self.assertLessEqual(result["unicode_characters"], 160000)

    def test_json_output_names_its_measurement_scope(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = loom_context.main(["tier-s-core", "--root", str(ROOT), "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        self.assertIn("static Loom source", payload["result"]["scope"])


if __name__ == "__main__":
    unittest.main()
