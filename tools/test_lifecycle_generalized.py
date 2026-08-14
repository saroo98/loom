import datetime as dt
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).parent))

import loom_lint  # noqa: E402
import loom_gate  # noqa: E402
import loom_lifecycle_kernel as kernel  # noqa: E402
import loom_lifecycle  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_plan_author  # noqa: E402
import loom_runtime  # noqa: E402
from test_lifecycle_kernel import _canonical_state_inputs  # noqa: E402


TODAY = dt.date(2026, 8, 14).isoformat()


def _work_order(identifier, *, depends_on=()):
    return {
        "id": identifier,
        "title": f"Deliver {identifier}",
        "outcome": f"{identifier} is complete.",
        "tasks": [f"Implement {identifier}."],
        "acceptance": [f"{identifier} verification passes."],
        "negative_acceptance": [f"{identifier} failure is contained."],
        "out_of_scope": ["Unrelated product behavior."],
        "escalation": ["Stop if the reviewed world changes."],
        "touches": [f"src/{identifier.casefold()}.py"],
        "depends_on": list(depends_on),
        "routing": "strong-coding",
        "size": "S",
    }


class GeneralizedLifecycleRegressionTests(unittest.TestCase):
    def test_author_and_linter_share_one_executable_touch_pattern_bound(self):
        """Break caught: author accepts a pack that its own linter rejects."""
        policy = loom_plan_author._execution_policy()
        self.assertEqual(5, policy.max_touch_patterns_per_work_order)
        self.assertEqual(
            policy.max_touch_patterns_per_work_order,
            loom_lint.HEFT_MAX_TOUCHES)
        self.assertEqual(
            ["src/a.py", "src/b.py"],
            loom_plan_author._bounded_touch_patterns(
                ["src/a.py", "src/b.py"], "work-order touches"))
        with self.assertRaisesRegex(
                loom_plan_author.PlanAuthorError, "split"):
            loom_plan_author._bounded_touch_patterns(
                [f"src/part-{index}.py" for index in range(6)],
                "work-order touches")

    def test_natural_medium_aliases_seal_only_canonical_identifiers(self):
        """Break caught: valid evidence is rejected because a label is not an ID."""
        self.assertEqual(
            "python-unittest",
            loom_lifecycle.canonical_medium_input("Python unittest"))
        self.assertEqual(
            "cli-process",
            loom_lifecycle.canonical_medium_input("CLI process"))
        self.assertEqual(
            "python-unittest",
            loom_lifecycle.canonical_medium_input("python-unittest"))
        with self.assertRaisesRegex(
                loom_lifecycle.LifecycleError, "canonical|alias"):
            loom_lifecycle.canonical_medium_input("some test runner")

    def test_completion_evaluation_is_pure_and_binds_only_declared_change(self):
        """Break caught: completion validation mutates authority before acceptance."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product = root / "src" / "feature.py"
            product.parent.mkdir()
            product.write_text("VALUE = 1\n", encoding="utf-8")
            pack = root / "plans" / "generations" / "generation-1"
            work_orders = pack / "work-orders"
            work_orders.mkdir(parents=True)
            work_order = work_orders / "WO-001-feature.md"
            work_order.write_text(
                "---\n"
                "id: WO-001\n"
                "status: done\n"
                "touches: [src/feature.py]\n"
                "depends_on: []\n"
                "---\n\n"
                "# Feature\n\n"
                "- [x] deterministic verification passes\n\n"
                "## Close-out\n\n"
                "Evidence: isolated unittest exited 0.\n",
                encoding="utf-8")
            baseline = loom_gate._snapshot_files(
                root, exclude_prefixes=(root / "plans",))
            product.write_text("VALUE = 2\n", encoding="utf-8")
            loom_lifecycle.capture_acceptance(
                pack, root, "WO-001", medium="python-unittest",
                command=[sys.executable, "-c", "print('verified')"])
            before = {
                path.relative_to(pack).as_posix(): hashlib.sha256(
                    path.read_bytes()).hexdigest()
                for path in pack.rglob("*") if path.is_file()
            }

            result = loom_gate.evaluate_work_order_completion(
                pack, root, work_order,
                project_id="project-1", generation_id="generation-1",
                reviewed_world_observation_sha256="a" * 64,
                baseline_files=baseline, prior_completions=())

            after = {
                path.relative_to(pack).as_posix(): hashlib.sha256(
                    path.read_bytes()).hexdigest()
                for path in pack.rglob("*") if path.is_file()
            }
        self.assertEqual(before, after)
        self.assertEqual(["src/feature.py"], result["changed_paths"])
        self.assertEqual("implementation", result["causal_scope"])
        self.assertRegex(result["completion_sha256"], r"^[0-9a-f]{64}$")

    def test_reviewed_world_excludes_control_and_staging_but_binds_product_bytes(self):
        """Break caught: plan state pollutes or weakens the reviewed product world."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product = root / "src" / "feature.py"
            product.parent.mkdir()
            product.write_text("VALUE = 1\n", encoding="utf-8")
            plans = root / "plans"
            plans.mkdir()
            (plans / "control.json").write_text("{}\n", encoding="utf-8")
            stage = root / ".loom-plan-stage-action"
            stage.mkdir()
            (stage / "MANIFEST.md").write_text("# draft\n", encoding="utf-8")

            first = loom_orchestrator._reviewed_world_observation(
                root, project_id="project-1", generation_id="generation-1",
                excluded_paths=(plans, stage))
            (plans / "control.json").write_text("{\"changed\":true}\n", encoding="utf-8")
            (stage / "MANIFEST.md").write_text("# revised draft\n", encoding="utf-8")
            control_only = loom_orchestrator._reviewed_world_observation(
                root, project_id="project-1", generation_id="generation-1",
                excluded_paths=(plans, stage))
            product.write_text("VALUE = 2\n", encoding="utf-8")
            product_changed = loom_orchestrator._reviewed_world_observation(
                root, project_id="project-1", generation_id="generation-1",
                excluded_paths=(plans, stage))

        self.assertEqual(first, control_only)
        self.assertNotEqual(
            first["observation_sha256"],
            product_changed["observation_sha256"])
        self.assertEqual(["src/feature.py"], list(first["files"]))

    def test_author_projection_seals_reviewed_sequence_and_shared_policy(self):
        """Break caught: executor priority is inferred instead of review-bound."""
        self.assertTrue(
            hasattr(loom_plan_author, "execution_projection"),
            "author execution projection is required",
        )
        work_orders = [
            _work_order("WO-001"),
            _work_order("WO-002", depends_on=("WO-001",)),
        ]

        projection = loom_plan_author.execution_projection(work_orders)

        self.assertEqual("strict-serial-sequence-v1", projection["policy"])
        self.assertEqual(["WO-001", "WO-002"], projection["sequence"])
        self.assertEqual(
            {"WO-001": "ready", "WO-002": "blocked"},
            projection["statuses"],
        )

    def test_real_author_projects_one_executable_work_order_from_reviewed_chain(self):
        """Break caught: author/executor disagreement makes a valid chain unstartable."""
        work_orders = [
            _work_order("WO-001"),
            _work_order("WO-002", depends_on=("WO-001",)),
            _work_order("WO-003", depends_on=("WO-002",)),
        ]
        contract = {
            "tier": "M",
            "planning_intelligence": {"program": None},
        }
        draft = {
            "summary": "Deliver the reviewed three-step chain.",
            "assumptions": [],
            "domain_bundle": None,
            "work_orders": work_orders,
        }
        assignments = {item["id"]: [] for item in work_orders}

        with tempfile.TemporaryDirectory() as temporary:
            pack = Path(temporary)
            loom_plan_author._write_work_orders(
                pack, contract, draft, TODAY, assignments)
            execution = loom_plan_author.execution_projection(work_orders)
            (pack / "MANIFEST.md").write_text(
                "---\n"
                f"execution_policy: {execution['policy']}\n"
                "execution_sequence: [WO-001, WO-002, WO-003]\n"
                f"execution_policy_sha256: {execution['policy_sha256']}\n"
                "---\n\n# Plan\n",
                encoding="utf-8",
            )
            paths = sorted((pack / "work-orders").glob("WO-*.md"))
            statuses = [
                loom_lint.parse_frontmatter(
                    path.read_text(encoding="utf-8"))[0]["status"]
                for path in paths
            ]

            self.assertEqual(["ready", "blocked", "blocked"], statuses)
            self.assertEqual(
                ("WO-001", paths[0].relative_to(pack).as_posix()),
                loom_orchestrator._active_work_order(pack, "M"),
            )

    def test_plan_only_control_outweighs_descriptive_create_verb(self):
        """Break caught: a project-description verb contradicts explicit plan-only authority."""
        request = (
            "/loom Create a tiny local-only Python continuity-probe project in this fresh "
            "task. The deliverable should be a deterministic command-line program that "
            "writes and reads one JSON status record, with standard-library-only tests and "
            "a short README. Plan the work only, present the complete inline plan, and do "
            "not implement until I explicitly ask to revise and then start the exact plan."
        )

        decision = loom_runtime.resolve_intent(request)

        self.assertFalse(decision["blocked"])
        self.assertEqual("plan", decision["intent"])
        self.assertEqual("ROUTE_PLAN", decision["code"])

    def test_executor_rejects_status_projection_that_disagrees_with_sequence(self):
        """Break caught: hand-edited status, rather than reviewed order, selects work."""
        with tempfile.TemporaryDirectory() as temporary:
            pack = Path(temporary)
            work_orders = pack / "work-orders"
            work_orders.mkdir()
            (pack / "MANIFEST.md").write_text(
                "---\n"
                "execution_policy: strict-serial-sequence-v1\n"
                "execution_sequence: [WO-900, WO-100]\n"
                "---\n\n"
                "# Plan\n",
                encoding="utf-8",
            )
            (work_orders / "WO-900.md").write_text(
                "---\nid: WO-900\nstatus: blocked\ndepends_on: []\n---\n",
                encoding="utf-8",
            )
            (work_orders / "WO-100.md").write_text(
                "---\nid: WO-100\nstatus: ready\ndepends_on: []\n---\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                    loom_orchestrator.OrchestratorError,
                    "reviewed execution sequence") as caught:
                loom_orchestrator._active_work_order(pack, "M")

            self.assertEqual("WORK_ORDER_PROJECTION_INVALID", caught.exception.code)

    def test_historical_multi_work_order_adoption_uses_verified_presentation_order(self):
        """Break caught: legacy adoption invents order outside the sealed presentation."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            plans = root / "plans"
            work_order_root = plans / "work-orders"
            work_order_root.mkdir(parents=True)
            manifest = plans / "MANIFEST.md"
            manifest.write_text("---\nstatus: gated\n---\n# Historical plan\n",
                                encoding="utf-8")
            for identifier in ("WO-001", "WO-002"):
                (work_order_root / f"{identifier}.md").write_text(
                    f"---\nid: {identifier}\nstatus: ready\ndepends_on: []\n---\n",
                    encoding="utf-8")
            (plans / "lifecycle.json").write_text(
                '{"schema_version":2,"events":[]}\n', encoding="utf-8")
            action_id = "historical-action-1"
            project_id = "project-1"
            generation_id = loom_orchestrator._derived_generation_id(
                project_id, action_id)
            world = loom_orchestrator._reviewed_world_observation(
                root, project_id=project_id, generation_id=generation_id,
                excluded_paths=(plans,))
            draft = {
                "schema_version": 1,
                "title": "Historical nonlexical order",
                "summary": "Preserve the exact owner-reviewed serial order.",
                "assumptions": [],
                "decisions": [],
                "work_orders": [
                    _work_order("WO-001"),
                    _work_order("WO-002", depends_on=("WO-001",)),
                ],
            }
            semantics = \
                loom_orchestrator.loom_plan_presentation.extract_semantics(draft)
            binding = {
                "action_id": action_id,
                "project_id": project_id,
                "world_fingerprint": world["state_sha256"],
                "plan_contract_hash": "a" * 64,
                "pack_sha256": loom_orchestrator._pack_hash(plans),
                "revision": 1,
                "relative_path": "plans/MANIFEST.md",
                "manifest_sha256": hashlib.sha256(
                    manifest.read_bytes()).hexdigest(),
            }
            presentation = \
                loom_orchestrator.loom_plan_presentation.compile_presentation(
                    semantics, tier="M", binding=binding)
            action = {
                "action_id": action_id,
                "project_id": project_id,
                "intent": "plan",
                "tier": "M",
                "survey_hash": world["state_sha256"],
                "domain_contract": None,
                "host_result": {"plan_review": {
                    "schema_version": 1,
                    "state": "completed",
                    "revision": 1,
                    "semantics": semantics,
                }},
            }

            decision = loom_orchestrator._v1_generation_decision(
                action, presentation, root,
                loom_orchestrator._pack_hash(plans))

        self.assertEqual(3, decision["schema_version"])
        self.assertEqual(
            loom_orchestrator.loom_lifecycle_kernel.digest(
                ["WO-001", "WO-002"]),
            decision["execution_sequence_sha256"])

    def test_historical_one_work_order_can_use_its_exact_presentation(self):
        """One fully presented historical step is unambiguous without hidden order."""
        semantics = {
            "schema_version": 1,
            "title": "Historical single step",
            "summary": "Preserve the only reviewed work order.",
            "assumptions": [],
            "decisions": [],
            "work_orders": [_work_order("WO-001")],
        }
        binding = {
            "action_id": "historical-action-single",
            "project_id": "project-1",
            "world_fingerprint": "a" * 64,
            "plan_contract_hash": "b" * 64,
            "pack_sha256": "c" * 64,
            "revision": 1,
            "relative_path": "plans/MANIFEST.md",
            "manifest_sha256": "d" * 64,
        }
        presentation = \
            loom_orchestrator.loom_plan_presentation.compile_presentation(
                semantics, tier="M", binding=binding)

        restored = loom_orchestrator._verified_historical_plan_semantics(
            {"host_result": None, "tier": "M"}, presentation)

        self.assertEqual(["WO-001"], [
            item["id"] for item in restored["work_orders"]])

    def test_historical_multi_work_order_without_verified_order_is_rejected(self):
        """Legacy selection never falls back to IDs, filesystem, or dict order."""
        semantics = {
            "schema_version": 1,
            "title": "Historical ambiguous steps",
            "summary": "Two steps need renewed owner-reviewed order.",
            "assumptions": [],
            "decisions": [],
            "work_orders": [
                _work_order("WO-001"),
                _work_order("WO-002", depends_on=("WO-001",)),
            ],
        }
        binding = {
            "action_id": "historical-action-ambiguous",
            "project_id": "project-1",
            "world_fingerprint": "a" * 64,
            "plan_contract_hash": "b" * 64,
            "pack_sha256": "c" * 64,
            "revision": 1,
            "relative_path": "plans/MANIFEST.md",
            "manifest_sha256": "d" * 64,
        }
        presentation = \
            loom_orchestrator.loom_plan_presentation.compile_presentation(
                semantics, tier="M", binding=binding)

        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._verified_historical_plan_semantics(
                {"host_result": None}, presentation)

        self.assertEqual("PLAN_REVIEW_SEQUENCE_REQUIRED", caught.exception.code)

    def test_historical_gate_writer_refuses_v3_lifecycle_without_mutation(self):
        """Read-old/write-new compatibility cannot let the old gate append v3 events."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "plans" / "generations" / "generation-1"
            pack.mkdir(parents=True)
            _index, _semantics, ledger, _witness = \
                _canonical_state_inputs(kernel)
            lifecycle = pack / "lifecycle.json"
            lifecycle.write_text(
                json.dumps(ledger, sort_keys=True) + "\n",
                encoding="utf-8")
            (pack / "MANIFEST.md").write_text(
                "---\nexecution_policy: strict-serial-sequence-v1\n"
                "execution_sequence: [WO-001, WO-002]\n---\n",
                encoding="utf-8")
            before = lifecycle.read_bytes()

            result = loom_gate.authorize(pack, root, TODAY + "T00:00:00Z")
            self.assertNotEqual(0, result)
            self.assertEqual(before, lifecycle.read_bytes())

    def test_execution_preflight_rejects_before_legacy_authorization_mutation(self):
        """Break caught: authorization is persisted before work selection is legal."""
        with mock.patch.object(
                loom_orchestrator, "_active_work_order",
                side_effect=loom_orchestrator.OrchestratorError(
                    "WORK_ORDER_PROJECTION_INVALID",
                    "reviewed execution sequence is invalid")), \
                mock.patch.object(loom_orchestrator.loom_gate, "authorize") as authorize:
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator._prepare_execution_pack(
                    Path("plans"), Path("project"), "M", "2026-08-14T00:00:00Z")

        authorize.assert_not_called()

    def test_terminality_is_preserved_independently_of_historical_world_drift(self):
        """Break caught: a completed generation becomes active repair after a commit."""
        observed = loom_runtime.normalize_lifecycle_axes({
            "pack_exists": True,
            "terminal": True,
            "active_frontier": False,
            "authorized": False,
            "drift": True,
            "failed": False,
            "state_error": "STALE_LIFECYCLE",
            "state_detail": "repository changed after completion",
            "state_path": "plans/lifecycle.json",
            "state_lifecycle": "stale",
            "state_finding_codes": ["REPOSITORY_DRIFT"],
            "state_finding_count": 1,
        })

        self.assertTrue(observed["terminal"])
        self.assertFalse(observed["drift"])
        self.assertTrue(observed["historical_drift"])
        self.assertNotIn("state_error", observed)
        self.assertEqual("terminal-historical-drift", observed["state_lifecycle"])


if __name__ == "__main__":
    unittest.main()
