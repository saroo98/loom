"""Phase 1 acceptance tests for Loom's one-command routing boundary."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_runtime


class OneCommandRoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.cwd = self.root / "invocation"
        self.cwd.mkdir()
        self.target = self.cwd / "target"
        self.target.mkdir()
        self.owner = self.cwd / "owner"
        self.owner.mkdir()
        self.instance = "00000000-0000-4000-8000-000000000001"

    def tearDown(self):
        self.tmp.cleanup()

    def test_relative_explicit_target_and_owner_use_supplied_cwd(self):
        with mock.patch.object(os, "getcwd", side_effect=AssertionError("ambient cwd")):
            result = loom_runtime.resolve_project(
                self.instance, explicit_target="target", cwd=self.cwd)
            self.assertEqual(result.root, self.target)
            prepared = loom_runtime.prepare_invocation(
                "Build a command-line tool",
                instance_id=self.instance,
                invocation_id="00000000-0000-4000-8000-000000000002",
                cwd=self.cwd,
                explicit_target="target",
                owner_home="owner",
                now="2026-07-14T12:00:00Z",
            )
        self.assertEqual(prepared.route_contract["intent"], "plan")
        self.assertRegex(prepared.world_fingerprint, r"^[0-9a-f]{64}$")

    def test_invalid_invocation_cwd_never_falls_back_to_process_cwd(self):
        bad_values = (
            None,
            "relative-cwd",
            self.root / "does-not-exist",
            self.root / "cwd-file.txt",
        )
        (self.root / "cwd-file.txt").write_text("not a directory", encoding="utf-8")
        for value in bad_values:
            with self.subTest(value=value), mock.patch.object(
                    os, "getcwd", side_effect=AssertionError("ambient cwd")):
                with self.assertRaisesRegex(
                        loom_runtime.RuntimeBlocked,
                        "missing_or_invalid_invocation_cwd"):
                    loom_runtime.resolve_project(
                        self.instance, explicit_target="target", cwd=value)

    def test_twelve_build_requests_ignore_control_nouns(self):
        requests = (
            "Build a review dashboard",
            "Create a status page",
            "Implement an undo feature",
            "Make a repair utility",
            "Build an audit log",
            "Create a forget-me-not app",
            "Build a closeout report",
            "Write a why-explanation screen",
            "Design a resume assistant",
            "Add a continue button",
            "Develop a publish checklist",
            "Create a delete-preview tool",
        )
        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertEqual(decision["intent"], "plan")
                self.assertFalse(decision["blocked"])

    def test_eight_conversational_controls_route_exactly(self):
        cases = (
            ("Continue", {"pack_exists": True}, "resume"),
            ("Resume the plan", {"pack_exists": True}, "resume"),
            ("Show me where we are", {}, "status"),
            ("Review this", {}, "review"),
            ("Repair the stale plan", {"drift": True}, "repair"),
            ("Remember that I prefer concise reports", {}, "remember"),
            ("Forget that preference", {}, "forget"),
            ("Undo the last Loom change", {}, "undo"),
        )
        for request, state, expected in cases:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, state)
                self.assertEqual(decision["intent"], expected)
                self.assertFalse(decision["blocked"])

    def test_memory_wrappers_never_authorize_forget(self):
        for request in (
                "Don't forget that I prefer careful review",
                "I don't want you to forget that I prefer careful review",
                "Never forget my review rule"):
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["code"], "INTENT_NEGATED")
                self.assertNotEqual(decision["intent"], "forget")

    def test_high_consequence_effects_block_independent_of_route(self):
        requests = (
            "Deploy to production",
            "Publish this release",
            "Delete the database",
            "Send this email",
            "Spend 100 dollars",
            "Pay the invoice",
            "Rotate the credentials",
            "Force-push the branch",
            "Reset --hard the repository",
            "Flash the firmware",
        )
        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["code"], "HIGH_CONSEQUENCE_UNCERTAIN")
                self.assertTrue(decision["needs_owner"])

    def test_implementation_plan_request_is_not_misread_as_release_execution(self):
        request = (
            "Now please implement C:\\Users\\Owner\\Documents\\Engineering Research\\"
            "Phase 1 - Tool Correctness and Release Engineering\\"
            "LOOM-PHASE-1-IMPLEMENTATION-PLAN.md")

        decision = loom_runtime.resolve_intent(request, {})

        self.assertEqual("plan", decision["intent"])
        self.assertFalse(decision["blocked"])
        self.assertFalse(decision["needs_owner"])

    def test_effect_after_control_is_still_blocked(self):
        for request in ("Review this, then deploy it", "Show status and send email"):
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request, {})
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["code"], "HIGH_CONSEQUENCE_UNCERTAIN")

    def test_non_plan_routes_have_stable_request_evidence_and_reason(self):
        cases = (
            ("Continue", {"pack_exists": True}),
            ("Show me where we are", {}),
            ("Review this", {}),
            ("Repair the stale plan", {"drift": True}),
            ("Remember that I prefer concise reports", {}),
            ("Forget that preference", {}),
            ("Undo the last Loom change", {}),
        )
        for request, state in cases:
            with self.subTest(request=request):
                first = loom_runtime.resolve_intent(request, state)
                second = loom_runtime.resolve_intent(request, state)
                self.assertNotEqual(first["intent"], "plan")
                self.assertTrue(first["evidence"])
                self.assertTrue(all(item.strip() for item in first["evidence"]))
                self.assertEqual(first["evidence"], second["evidence"])
                self.assertEqual(first["code"], second["code"])

    def test_memory_and_action_is_one_safe_checkpoint(self):
        decision = loom_runtime.resolve_intent(
            "Remember that I prefer careful review, then continue",
            {"pack_exists": True})
        self.assertTrue(decision["blocked"])
        self.assertEqual(decision["code"], "INTENT_AMBIGUOUS")
        self.assertEqual(decision["target_mutation_count"], 0)


if __name__ == "__main__":
    unittest.main()
