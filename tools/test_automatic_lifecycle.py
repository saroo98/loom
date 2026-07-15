"""Behavioral tests for automatic lifecycle preflight and real-medium evidence."""

import json
import dataclasses
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import loom_lifecycle
import loom_survey


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True, timeout=20)


class AutomaticLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.pack = self.repo / "plans"
        self.pack.mkdir()
        (self.pack / "MANIFEST.md").write_text("# fixture\n", encoding="utf-8")
        (self.repo / "app.py").write_text("print('baseline')\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_medium_capture_runs_command_and_binds_current_world(self):
        evidence = loom_lifecycle.capture_acceptance(
            self.pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('observed-real-process')"])
        self.assertEqual(evidence["exit_code"], 0)
        self.assertIn("observed-real-process", evidence["stdout"])
        validated = loom_lifecycle.validate_acceptance_evidence(
            self.pack, "WO-001", self.repo, require_current=True)
        self.assertEqual(validated["evidence_hash"], evidence["evidence_hash"])

        (self.repo / "app.py").write_text("print('drift')\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_lifecycle.LifecycleError, "world changed"):
            loom_lifecycle.validate_acceptance_evidence(
                self.pack, "WO-001", self.repo, require_current=True)

    def test_world_hash_ignores_volatile_platform_metadata_but_not_content(self):
        empty = self.repo / "empty"
        empty.mkdir()
        entries = loom_survey._workspace_census(self.repo, ("plans",))
        baseline = loom_survey._hash_workspace(entries)
        altered = tuple(
            dataclasses.replace(
                item, uid=item.uid + 17, gid=item.gid + 19,
                flags=item.flags ^ 4, attributes=item.attributes ^ 32)
            if item.rel == "empty" else item
            for item in entries)
        self.assertEqual(baseline, loom_survey._hash_workspace(altered))

        (self.repo / "app.py").write_text("print('material change')\n", encoding="utf-8")
        changed = loom_survey._hash_workspace(
            loom_survey._workspace_census(self.repo, ("plans",)))
        self.assertNotEqual(baseline, changed)

    @unittest.skipUnless(
        hasattr(os, "setxattr") and hasattr(os, "removexattr"),
        "extended attributes require POSIX support")
    def test_platform_indexing_xattr_does_not_invalidate_acceptance(self):
        evidence = loom_lifecycle.capture_acceptance(
            self.pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('stable')"])
        try:
            os.setxattr(self.repo / "app.py", "user.loom-indexer", b"indexed")
        except OSError as exc:
            self.skipTest(f"user xattrs unavailable: {exc}")
        try:
            validated = loom_lifecycle.validate_acceptance_evidence(
                self.pack, "WO-001", self.repo, require_current=True)
            self.assertEqual(evidence["evidence_hash"], validated["evidence_hash"])
        finally:
            os.removexattr(self.repo / "app.py", "user.loom-indexer")

    def test_failed_or_generic_verification_cannot_be_acceptance_evidence(self):
        with self.assertRaisesRegex(loom_lifecycle.LifecycleError, "real medium"):
            loom_lifecycle.capture_acceptance(
                self.pack, self.repo, "WO-001", medium="checklist",
                command=[sys.executable, "-c", "print('not enough')"])
        with self.assertRaisesRegex(loom_lifecycle.LifecycleError, "command failed"):
            loom_lifecycle.capture_acceptance(
                self.pack, self.repo, "WO-001", medium="cli-process",
                command=[sys.executable, "-c", "raise SystemExit(7)"])
        self.assertFalse((self.pack / "evidence" / "WO-001.json").exists())

        with self.assertRaisesRegex(loom_lifecycle.LifecycleError, "changed"):
            loom_lifecycle.capture_acceptance(
                self.pack, self.repo, "WO-001", medium="cli-process",
                command=[sys.executable, "-c",
                         "from pathlib import Path; Path('app.py').write_text('changed')"])
        self.assertFalse((self.pack / "evidence" / "WO-001.json").exists())

    def test_selective_regate_maps_only_changed_consumers_and_unmapped_is_full(self):
        baseline = {"src/api.py": "a", "src/ui.py": "b", "README.md": "c"}
        current = {"src/api.py": "changed", "src/ui.py": "b", "README.md": "c"}
        mapping = {"schema_version": 1, "sections": [
            {"id": "architecture", "target_patterns": ["src/api.py"]},
            {"id": "testing", "target_patterns": ["src/**"]},
            {"id": "uiux", "target_patterns": ["src/ui.py"]}]}
        plan = loom_lifecycle.plan_regate(baseline, current, mapping)
        self.assertEqual(plan["regate_scope"], "selective")
        self.assertEqual(plan["affected_plan_sections"], ["architecture", "testing"])

        current["unknown.bin"] = "new"
        full = loom_lifecycle.plan_regate(baseline, current, mapping)
        self.assertEqual(full["regate_scope"], "full")
        self.assertEqual(full["affected_plan_sections"], ["full-pack"])

    def test_complete_world_summary_distinguishes_all_git_states_and_filesystem(self):
        if git(self.repo, "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "test")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "baseline")
        (self.repo / "staged.txt").write_text("staged", encoding="utf-8")
        git(self.repo, "add", "staged.txt")
        (self.repo / "app.py").write_text("unstaged", encoding="utf-8")
        (self.repo / "untracked.txt").write_text("untracked", encoding="utf-8")
        summary = loom_lifecycle.inspect_world(self.repo, self.pack)
        self.assertEqual(summary["mode"], "git")
        self.assertEqual(summary["staged_count"], 1)
        self.assertEqual(summary["unstaged_count"], 1)
        self.assertEqual(summary["untracked_count"], 1)

        non_git = Path(self.tmp.name) / "filesystem"
        non_git.mkdir()
        (non_git / "one.txt").write_text("one", encoding="utf-8")
        filesystem = loom_lifecycle.inspect_world(non_git, non_git / "plans")
        self.assertEqual(filesystem["mode"], "filesystem")
        self.assertEqual(filesystem["untracked_count"], 1)

    def test_release_and_rollback_scale_to_exposure(self):
        self.assertEqual(loom_lifecycle.release_policy(
            external_users=0, irreversible=False, data_migration=False,
            regulated=False)["level"], "none")
        self.assertEqual(loom_lifecycle.release_policy(
            external_users=20, irreversible=False, data_migration=False,
            regulated=False)["level"], "staged")
        full = loom_lifecycle.release_policy(
            external_users=1, irreversible=True, data_migration=True,
            regulated=True)
        self.assertEqual(full["level"], "controlled")
        self.assertIn("tested rollback", full["requirements"])

    def test_capture_cli_is_the_real_user_facing_evidence_path(self):
        result = subprocess.run([
            sys.executable, "-B", str(Path(loom_lifecycle.__file__)), "capture",
            "--repo", str(self.repo), "--pack", str(self.pack),
            "--wo", "WO-009", "--medium", "cli-process", "--",
            sys.executable, "-c", "print('cli evidence')"],
            capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertIn("cli evidence", payload["result"]["stdout"])
        self.assertTrue((self.pack / "evidence" / "WO-009.json").is_file())

    def test_phase_ten_persisted_contract_schemas_are_valid_json(self):
        root = Path(loom_lifecycle.__file__).parent.parent / "schemas"
        for name in (
                "acceptance-evidence.schema.json", "plan-dependencies.schema.json",
                "regate-receipt.schema.json", "release-exposure.schema.json"):
            with self.subTest(name=name):
                schema = json.loads((root / name).read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"],
                                 "https://json-schema.org/draft/2020-12/schema")
                self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
