import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import loom_block_reason
import loom_install
import loom_message
import loom_orchestrator
import loom_release
import loom_runtime
import loom_session
import loom_terminal_authority


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        text=True, encoding="utf-8")


def _invalid_pack(project):
    orders = project / "plans" / "work-orders"
    orders.mkdir(parents=True)
    (orders / "WO-001.md").write_text("status: ready\n", encoding="utf-8")


class ControlPlaneMessageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        _git(self.project, "init", "-q")
        _git(self.project, "config", "user.email", "test@example.invalid")
        _git(self.project, "config", "user.name", "test")
        _git(self.project, "add", "-A")
        _git(self.project, "commit", "-qm", "baseline")
        self.home = self.root / "home"
        self.instance_id = str(uuid.uuid4())

    def tearDown(self):
        self.temp.cleanup()

    def test_lifecycle_block_preserves_exact_bounded_safe_reason(self):
        _invalid_pack(self.project)
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance_id, handlers={},
            memory=loom_session.NoopMemoryAdapter())
        receipt = controller.run(
            "Continue", invocation_id=str(uuid.uuid4()), cwd=self.project)

        self.assertEqual("blocked", receipt.status)
        reason = dict(receipt.block_reason)
        self.assertEqual("invalid-lifecycle", reason["code"])
        self.assertEqual("lifecycle", reason["category"])
        self.assertEqual("plans/lifecycle.json", reason["safe_path"])
        self.assertEqual("missing", reason["lifecycle_state"])
        self.assertEqual(["MISSING_LIFECYCLE"], list(reason["finding_codes"]))
        self.assertEqual(1, reason["finding_count"])
        self.assertEqual("unknown", reason["ownership"])
        self.assertEqual("unknown", reason["pristine_proof"])
        self.assertFalse(reason["changes_made"])
        self.assertEqual("unsafe", reason["automatic_recovery"])
        self.assertFalse(reason["implementation_authorized"])
        self.assertTrue(reason["requires_new_action"])
        self.assertIn("fresh Loom request", reason["next_action"])
        self.assertEqual("not-applicable", receipt.owner_message["undo_status"])
        self.assertIn("plans/lifecycle.json", receipt.owner_message["human"])
        self.assertIn("No implementation or fallback", receipt.owner_message["human"])
        self.assertLessEqual(receipt.owner_message["human"].count("\n"), 1)

    def test_diagnostics_reject_secrets_absolute_owner_paths_and_oversize(self):
        valid = loom_block_reason.build(
            code="INVALID_LIFECYCLE", category="lifecycle",
            expected="A valid current lifecycle.", observed="Lifecycle JSON is invalid.",
            safe_path="plans/lifecycle.json", lifecycle_state="invalid",
            finding_codes=["INVALID_JSON"], finding_count=1,
            ownership="unknown", pristine_proof="unknown",
            automatic_recovery="unsafe", next_action="Repair it and invoke Loom again.")
        forbidden = [
            ("observed", "pass" + "word=owner-secret-value"),
            ("observed", "C:\\Users\\Owner\\.loom\\vault.sqlite3"),
            ("safe_path", "../../owner/private.txt"),
            ("next_action", "x" * 241),
        ]
        for field, value in forbidden:
            with self.subTest(field=field):
                tampered = dict(valid)
                tampered[field] = value
                with self.assertRaises(loom_block_reason.BlockReasonError) as caught:
                    loom_block_reason.validate(tampered)
                self.assertNotIn(value[:24], str(caught.exception))

    def test_current_undo_states_distinguish_all_three_mutation_outcomes(self):
        common = {
            "status": "completed", "code": "execute-complete", "intent": "execute",
            "tier": "M", "owner_input_required": False, "detail": "",
            "receipt_id": "session-0123456789abcdef", "block_reason": None,
        }
        reversible = loom_message.from_session(
            **common, reversible_action_ids=["undo-1"])
        unavailable = loom_message.from_session(
            **common, reversible_action_ids=[])
        no_change = loom_message.from_session(
            **{**common, "intent": "status", "code": "status-complete"},
            reversible_action_ids=[])
        self.assertEqual("available", reversible["undo_status"])
        self.assertEqual("unavailable", unavailable["undo_status"])
        self.assertEqual("not-applicable", no_change["undo_status"])

    def test_maximum_safe_handler_detail_still_produces_a_bounded_message(self):
        reason = loom_block_reason.generic("HANDLER_BLOCKED", "x" * 240,
                                           category="handler")
        message = loom_message.from_session(
            status="blocked", code="handler-blocked", intent="execute", tier="M",
            owner_input_required=False, reversible_action_ids=[], detail="",
            receipt_id="session-0123456789abcdef", block_reason=reason)
        self.assertLessEqual(len(message["human"]), loom_message.MAX_HUMAN_CHARS)
        self.assertLessEqual(message["human"].count("\n"), 1)


class ControlPlaneAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        root = Path(cls.fixture.name)
        source = Path(__file__).resolve().parents[1]
        public = root / "public"
        cls.installed = root / "installed"
        loom_release.build_public(
            source, public,
            forbidden_tokens=[
                "-".join(("private", "fixture", "token")),
                "-".join(("owner", "fixture", "token")),
            ],
            source_classification="public-release")
        loom_install.install(public, cls.installed)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.old_backend = os.environ.get("LOOM_TEST_ALLOW_LEGACY_BACKEND")
        os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = "1"
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        (self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        _git(self.project, "init", "-q")
        _git(self.project, "config", "user.email", "test@example.invalid")
        _git(self.project, "config", "user.name", "test")
        _git(self.project, "add", "-A")
        _git(self.project, "commit", "-qm", "baseline")

    def tearDown(self):
        if self.old_backend is None:
            os.environ.pop("LOOM_TEST_ALLOW_LEGACY_BACKEND", None)
        else:
            os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = self.old_backend
        self.temp.cleanup()

    def invoke(self, request):
        return loom_orchestrator.invoke(
            request=request, cwd=self.project, home=self.home,
            install_root=self.installed, explicit_target=self.project,
            timeout_seconds=300)

    def _action_files(self):
        return [path for path in self.home.rglob("*.json")
                if path.parent.name == "orchestrations"
                and path.name != loom_orchestrator.ACTIVE_POINTER_FILE]

    def test_terminal_block_cannot_authorize_implementation(self):
        _invalid_pack(self.project)
        before = _git(self.project, "status", "--porcelain=v1", "-uall").stdout
        blocked = self.invoke("Continue")

        self.assertEqual("blocked", blocked["status"])
        self.assertNotIn("action_path", blocked)
        authority = blocked["terminal_authority"]
        loom_terminal_authority.validate(authority)
        self.assertFalse(authority["implementation_authorized"])
        self.assertTrue(authority["requires_new_action"])
        actions = self._action_files()
        self.assertEqual(1, len(actions))
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError, "ACTION_TERMINAL"):
            loom_orchestrator.complete(
                actions[0], owner_home=self.home, install_root=self.installed)
        after = _git(self.project, "status", "--porcelain=v1", "-uall").stdout
        self.assertEqual(before, after)

    def test_fresh_valid_action_hash_links_resolution_of_prior_terminal_block(self):
        _invalid_pack(self.project)
        blocked = self.invoke("Continue")
        prior_hash = blocked["receipt_hash"]
        for path in sorted((self.project / "plans").rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        (self.project / "plans").rmdir()

        opened = self.invoke("Build a command-line tool")
        self.assertEqual("action-required", opened["status"])
        resolution = opened["resolved_terminal_block"]
        self.assertEqual(prior_hash, resolution["prior_receipt_hash"])
        self.assertEqual("fresh-valid-invocation", resolution["resolution"])
        journal = json.loads(Path(opened["session_environment"][
            "LOOM_SESSION_JOURNAL"]).read_text(encoding="utf-8"))
        events = [item for item in journal["events"]
                  if item["kind"] == "terminal-block-resolved"]
        self.assertEqual(1, len(events))

    def test_tampered_terminal_authority_is_rejected_even_if_outer_hash_is_resealed(self):
        _invalid_pack(self.project)
        blocked = self.invoke("Continue")
        tampered = json.loads(json.dumps(blocked))
        tampered["terminal_authority"]["implementation_authorized"] = True
        tampered["receipt_hash"] = loom_session._receipt_hash(tampered)
        with self.assertRaisesRegex(loom_session.SessionBlocked, "terminal receipt"):
            loom_session._receipt_from_data(tampered, repeated=False)

    def test_multiline_roles_preserve_one_software_outcome(self):
        request = (
            "Fix the Windows request-transport defect.\n"
            "Prefer process isolation for this fix.\n"
            "Correct the failing test.\n"
            "Verify, implement, test, and report.\n"
            "Do not commit, publish, release, or install.")
        prepared = loom_runtime.prepare_invocation(
            request, instance_id=str(uuid.uuid4()), invocation_id=str(uuid.uuid4()),
            cwd=self.project, explicit_target=self.project,
            owner_home=self.home)
        self.assertEqual("plan", prepared.intent)
        self.assertFalse(prepared.route_contract["blocked"])
        self.assertIsNone(prepared.route_contract["block_reason"])


if __name__ == "__main__":
    unittest.main()
