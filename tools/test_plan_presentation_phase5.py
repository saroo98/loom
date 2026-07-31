import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import loom_lint
import loom_plan_presentation


def semantic_draft(work_orders=1):
    return {
        "schema_version": 1,
        "title": "Add a safe preview",
        "summary": "Show the validated plan before implementation starts.",
        "assumptions": ["The host can render ordinary Markdown."],
        "decisions": ["Keep the sealed plan as the only execution authority."],
        "current_facts": [],
        "release_exposure": {
            "external_users": 0,
            "irreversible": False,
            "data_migration": False,
            "regulated": False,
        },
        "work_orders": [
            {
                "id": f"WO-{index:03d}",
                "title": f"Review slice {index}",
                "outcome": f"Slice {index} has a reviewable outcome.",
                "tasks": [f"Implement slice {index}.", f"Test slice {index}."],
                "acceptance": [f"Observed result: slice {index} passes its checks."],
                "negative_acceptance": [
                    f"Observed rejection: slice {index} cannot bypass validation."
                ],
                "out_of_scope": [f"Unrelated slice {index} changes."],
                "escalation": [f"Stop if slice {index} requires a new authority."],
                "touches": [f"src/slice-{index}.py", f"tests/test_slice_{index}.py"],
                "depends_on": [] if index == 1 else [f"WO-{index - 1:03d}"],
                "routing": "strong-coding",
                "size": "S",
            }
            for index in range(1, work_orders + 1)
        ],
        "domain_bundle": None,
    }


def binding():
    return {
        "action_id": "action-123",
        "project_id": "p-123",
        "world_fingerprint": "a" * 64,
        "plan_contract_hash": "b" * 64,
        "pack_sha256": "c" * 64,
        "revision": 1,
        "relative_path": "plans/MANIFEST.md",
        "manifest_sha256": "d" * 64,
    }


class PlanPresentationTests(unittest.TestCase):
    def test_small_plan_is_complete_deterministic_and_schema_valid(self):
        first = loom_plan_presentation.compile_presentation(
            semantic_draft(), tier="S", binding=binding())
        second = loom_plan_presentation.compile_presentation(
            copy.deepcopy(semantic_draft()), tier="S",
            binding=copy.deepcopy(binding()))

        self.assertEqual(first, second)
        self.assertEqual("plan-presentation-v1", first["format"])
        self.assertEqual("complete", first["preview_mode"])
        self.assertEqual(1, len(first["steps"]))
        self.assertEqual(
            ["src/slice-1.py", "tests/test_slice_1.py"],
            first["expected_touch_paths"])
        self.assertEqual(
            binding(), first["binding"])
        loom_plan_presentation.validate(first)
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "plan-presentation.schema.json", first,
            "plan-presentation.schema.json")
        self.assertEqual([], report.errors)

    def test_medium_and_large_previews_are_bounded_without_hiding_full_plan_access(self):
        medium = loom_plan_presentation.compile_presentation(
            semantic_draft(7), tier="M", binding=binding())
        large = loom_plan_presentation.compile_presentation(
            semantic_draft(12), tier="L", binding=binding())

        self.assertEqual("bounded", medium["preview_mode"])
        self.assertEqual(5, len(medium["steps"]))
        self.assertEqual(2, medium["omitted_step_count"])
        self.assertEqual("frontier", large["preview_mode"])
        self.assertEqual(5, len(large["steps"]))
        self.assertEqual(7, large["omitted_step_count"])
        for value in (medium, large):
            self.assertEqual("plans/MANIFEST.md", value["full_plan"]["relative_path"])
            self.assertEqual("d" * 64, value["full_plan"]["sha256"])
            self.assertIn("complete_inline_markdown", value)
            self.assertIn("WO-012" if value is large else "WO-007",
                          value["complete_inline_markdown"])

    def test_canonical_projection_never_contains_an_absolute_path(self):
        value = loom_plan_presentation.compile_presentation(
            semantic_draft(), tier="S", binding=binding())
        encoded = json.dumps(value, sort_keys=True)

        self.assertNotIn("C:\\", encoded)
        self.assertNotIn("/Users/", encoded)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn("file://", encoded)

    def test_host_projection_emits_clickable_contained_link_and_complete_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "plans" / "MANIFEST.md"
            manifest.parent.mkdir()
            manifest.write_text("# Complete plan\n", encoding="utf-8")
            bound = binding()
            bound["manifest_sha256"] = hashlib.sha256(
                manifest.read_bytes()).hexdigest()
            value = loom_plan_presentation.compile_presentation(
                semantic_draft(), tier="S", binding=bound)

            projected = loom_plan_presentation.project_for_host(
                value, project_root=root, host_id="codex")

        self.assertEqual("codex", projected["host_id"])
        self.assertIn("[Open the complete plan](", projected["markdown"])
        self.assertIn(manifest.as_posix(), projected["markdown"])
        self.assertIn("## Add a safe preview", projected["markdown"])
        self.assertIn("Request a change", projected["markdown"])
        self.assertIn("Start this exact plan", projected["markdown"])
        self.assertEqual(value["complete_inline_markdown"],
                         projected["complete_inline_markdown"])

    def test_host_projection_quotes_special_characters_in_clickable_plan_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Project (draft) [owner] café"
            manifest = root / "plans" / "MANIFEST.md"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("# Complete plan\n", encoding="utf-8")
            bound = binding()
            bound["manifest_sha256"] = hashlib.sha256(
                manifest.read_bytes()).hexdigest()
            value = loom_plan_presentation.compile_presentation(
                semantic_draft(), tier="S", binding=bound)

            projected = loom_plan_presentation.project_for_host(
                value, project_root=root, host_id="codex")

        self.assertIn("%20", projected["markdown"])
        self.assertIn("%28draft%29", projected["markdown"])
        self.assertIn("%5Bowner%5D", projected["markdown"])
        self.assertIn("caf%C3%A9", projected["markdown"])
        self.assertIn(
            "[Open the complete plan](<", projected["markdown"])

    def test_host_projection_refuses_escape_symlink_and_changed_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root.parent / "outside-plan.md"
            outside.write_text("# Outside\n", encoding="utf-8")
            value = loom_plan_presentation.compile_presentation(
                semantic_draft(), tier="S", binding=binding())

            with self.assertRaises(loom_plan_presentation.PresentationError):
                loom_plan_presentation.project_for_host(
                    value, project_root=root, host_id="codex")

            manifest = root / "plans" / "MANIFEST.md"
            manifest.parent.mkdir()
            manifest.write_text("# Different bytes\n", encoding="utf-8")
            with self.assertRaises(loom_plan_presentation.PresentationError):
                loom_plan_presentation.project_for_host(
                    value, project_root=root, host_id="codex")

    def test_hostile_markdown_is_rendered_as_inert_text(self):
        draft = semantic_draft()
        draft["title"] = "<script>alert(1)</script> [x](file:///secret)"
        draft["summary"] = "Close </details> and run <img src=x onerror=alert(1)>."
        draft["work_orders"][0]["tasks"] = [
            "Use `safe()` and [do not open](javascript:alert(1))."
        ]
        value = loom_plan_presentation.compile_presentation(
            draft, tier="S", binding=binding())
        markdown = value["complete_inline_markdown"]

        self.assertNotIn("<script>", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("javascript:", markdown)
        self.assertNotIn("file://", markdown)
        self.assertNotIn("[x](", markdown)
        self.assertNotIn("[do not open](", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn("javascript&#58;", markdown)

    def test_projection_is_storage_independent(self):
        value = loom_plan_presentation.compile_presentation(
            semantic_draft(), tier="S", binding=binding())

        self.assertNotIn("project_root", value)
        self.assertNotIn("storage_mode", value)
        self.assertNotIn("absolute_path", value["full_plan"])

    def test_validation_rejects_a_self_consistent_but_false_preview_inventory(self):
        value = loom_plan_presentation.compile_presentation(
            semantic_draft(), tier="S", binding=binding())
        value["preview_mode"] = "frontier"
        unsigned = dict(value)
        unsigned.pop("presentation_sha256")
        value["presentation_sha256"] = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()

        with self.assertRaisesRegex(
                loom_plan_presentation.PresentationError,
                "preview mode does not match"):
            loom_plan_presentation.validate(value)


if __name__ == "__main__":
    unittest.main()
