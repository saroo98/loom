"""Behavioral tests for Git-aware workspace observation boundaries."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_project_inspection
import loom_lint
import loom_survey


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )


class WorkspaceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "project"
        self.repo.mkdir()
        git(self.repo, "init")
        git(self.repo, "config", "user.name", "Loom Test")
        git(self.repo, "config", "user.email", "loom@example.invalid")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-m", "fixture")

    def tearDown(self):
        self.tmp.cleanup()

    def add_nested_worktree(self, name="child"):
        boundary = self.repo / ".claude" / "worktrees" / name
        boundary.parent.mkdir(parents=True, exist_ok=True)
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/.claude/worktrees/\n")
        git(self.repo, "worktree", "add", "-b", f"fixture-{name}", str(boundary))
        return boundary

    def test_registered_nested_worktree_is_independent_of_parent_world(self):
        boundary = self.add_nested_worktree()
        payload = boundary / "independent.bin"
        payload.write_bytes(b"before")

        before = loom_survey.workspace_snapshot(self.repo)
        payload.write_bytes(b"after")
        after = loom_survey.workspace_snapshot(self.repo)

        self.assertEqual(before.state.state_hash, after.state.state_hash)
        self.assertFalse(any(
            entry.rel.startswith(".claude/worktrees/child")
            for entry in after.entries))

    def test_registered_boundary_does_not_create_an_inspection_obligation(self):
        self.add_nested_worktree()

        snapshot = loom_survey.workspace_snapshot(self.repo)
        receipt = loom_project_inspection.inspect(
            snapshot, target_identity="target-sha256:" + "1" * 64)

        self.assertEqual("complete", receipt["state"])
        self.assertTrue(receipt["implementation_eligible"])
        self.assertEqual([], receipt["unresolved_roots"])
        self.assertEqual(1, receipt["external_boundaries"]["count"])
        self.assertFalse(receipt["external_boundaries"]["records_saturated"])
        self.assertEqual(
            [{"kind": "registered-linked-worktree",
              "path": ".claude/worktrees/child"}],
            receipt["external_boundaries"]["records"])
        capsule = loom_project_inspection.capsule(receipt)
        self.assertEqual(
            {"count": 1, "digest": receipt["external_boundaries"]["digest"]},
            capsule["external_boundaries"])
        for schema, value in (
                ("project-inspection.schema.json", receipt),
                ("project-inspection-capsule.schema.json", capsule)):
            report = loom_lint.Report()
            loom_lint.validate_schema(report, schema, value, schema)
            self.assertEqual([], report.errors)

    def test_unclassified_ignored_directory_remains_content_bound(self):
        lookalike = self.repo / ".claude" / "worktrees" / "not-registered"
        lookalike.mkdir(parents=True)
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/.claude/worktrees/\n")
        payload = lookalike / "payload.bin"
        payload.write_bytes(b"before")

        before = loom_survey.workspace_snapshot(self.repo)
        payload.write_bytes(b"after")
        after = loom_survey.workspace_snapshot(self.repo)

        self.assertNotEqual(before.state.state_hash, after.state.state_hash)
        receipt = loom_project_inspection.inspect(
            after, target_identity="target-sha256:" + "2" * 64)
        self.assertEqual("complete", receipt["state"])
        self.assertTrue(receipt["implementation_eligible"])
        self.assertNotIn("external_boundaries", receipt)
        self.assertEqual([], receipt["unresolved_roots"])

    def test_ignored_directory_in_declared_touch_scope_remains_content_bound(self):
        ignored = self.repo / ".cache"
        ignored.mkdir()
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/.cache/\n")
        payload = ignored / "payload.bin"
        payload.write_bytes(b"before")

        before = loom_survey.workspace_snapshot(
            self.repo, touch_paths=(".cache",))
        payload.write_bytes(b"after")
        after = loom_survey.workspace_snapshot(
            self.repo, touch_paths=(".cache",))

        self.assertNotEqual(before.state.state_hash, after.state.state_hash)
        receipt = loom_project_inspection.inspect(
            after, target_identity="target-sha256:" + "3" * 64)
        self.assertEqual("complete", receipt["state"])
        self.assertTrue(receipt["implementation_eligible"])

    def test_policy_proven_local_toolchain_cache_is_excluded(self):
        ignored = self.repo / ".tools"
        nested = ignored / "sdk"
        nested.mkdir(parents=True)
        (self.repo / "go.mod").write_text(
            "module example.invalid/fixture\n\ngo 1.22\n", encoding="utf-8")
        git(self.repo, "add", "go.mod")
        git(self.repo, "commit", "-m", "add go authority")
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/.tools/\n")
        manifest = nested / "package.json"
        manifest.write_text('{"private": true}\n', encoding="utf-8")

        before = loom_survey.workspace_snapshot(self.repo)
        manifest.write_text('{"private": false}\n', encoding="utf-8")
        after = loom_survey.workspace_snapshot(self.repo)

        self.assertEqual(before.state.state_hash, after.state.state_hash)
        receipt = loom_project_inspection.inspect(
            after, target_identity="target-sha256:" + "4" * 64)
        self.assertEqual("complete", receipt["state"])
        self.assertTrue(receipt["implementation_eligible"])
        self.assertEqual([], receipt["unresolved_roots"])
        self.assertEqual(
            [(".tools", "local-toolchain-cache")],
            [(item["path"], item["rule_id"])
             for item in receipt["generated_exclusions"]])

    def test_local_toolchain_cache_in_touch_scope_remains_content_bound(self):
        ignored = self.repo / ".tools"
        ignored.mkdir()
        (self.repo / "go.mod").write_text(
            "module example.invalid/fixture\n\ngo 1.22\n", encoding="utf-8")
        git(self.repo, "add", "go.mod")
        git(self.repo, "commit", "-m", "add go authority")
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/.tools/\n")
        payload = ignored / "tool.bin"
        payload.write_bytes(b"before")

        before = loom_survey.workspace_snapshot(
            self.repo, touch_paths=(".tools/tool.bin",))
        payload.write_bytes(b"after")
        after = loom_survey.workspace_snapshot(
            self.repo, touch_paths=(".tools/tool.bin",))
        receipt = loom_project_inspection.inspect(
            after, target_identity="target-sha256:" + "8" * 64)

        self.assertNotEqual(before.state.state_hash, after.state.state_hash)
        self.assertEqual([], receipt["generated_exclusions"])
        self.assertEqual("complete", receipt["state"])

    def test_direct_authority_prevents_local_toolchain_cache_exclusion(self):
        ignored = self.repo / ".tools"
        ignored.mkdir()
        (self.repo / "go.mod").write_text(
            "module example.invalid/fixture\n\ngo 1.22\n", encoding="utf-8")
        git(self.repo, "add", "go.mod")
        git(self.repo, "commit", "-m", "add go authority")
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/.tools/\n")
        authority = ignored / "AGENTS.md"
        authority.write_text("local authority\n", encoding="utf-8")

        snapshot = loom_survey.workspace_snapshot(self.repo)
        receipt = loom_project_inspection.inspect(
            snapshot, target_identity="target-sha256:" + "9" * 64)

        self.assertEqual([], receipt["generated_exclusions"])
        self.assertEqual("complete", receipt["state"])

    def test_ignored_authority_file_is_hashed_without_disclosing_content(self):
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            stream.write("/AGENTS.md\n")
        authority = self.repo / "AGENTS.md"
        secret = "private local instruction 7b64df"
        authority.write_text(secret, encoding="utf-8")

        before = loom_survey.workspace_snapshot(self.repo)
        authority.write_text("updated local instruction\n", encoding="utf-8")
        after = loom_survey.workspace_snapshot(self.repo)
        receipt = loom_project_inspection.inspect(
            after, target_identity="target-sha256:" + "7" * 64)

        self.assertNotEqual(before.state.state_hash, after.state.state_hash)
        self.assertEqual("complete", receipt["state"])
        self.assertNotIn(secret, str(receipt))

    def test_ignored_content_beyond_disclosure_budget_remains_content_bound(self):
        info_exclude = self.repo / ".git" / "info" / "exclude"
        with info_exclude.open("a", encoding="utf-8") as stream:
            for index in range(33):
                name = f".cache-{index:02d}"
                stream.write(f"/{name}/\n")
                directory = self.repo / name
                directory.mkdir()
                (directory / "payload.bin").write_bytes(b"before")

        before = loom_survey.workspace_snapshot(self.repo)
        (self.repo / ".cache-32" / "payload.bin").write_bytes(b"after")
        after = loom_survey.workspace_snapshot(self.repo)

        self.assertNotEqual(before.state.state_hash, after.state.state_hash)
        receipt = loom_project_inspection.inspect(
            after, target_identity="target-sha256:" + "6" * 64)
        self.assertEqual("complete", receipt["state"])
        self.assertEqual([], receipt["unresolved_roots"])

    def test_content_deadline_returns_bounded_partial_observation(self):
        with mock.patch.object(loom_survey, "STATE_HASH_DEADLINE_SECONDS", -1):
            snapshot = loom_survey.workspace_snapshot(self.repo)

        receipt = loom_project_inspection.inspect(
            snapshot, target_identity="target-sha256:" + "5" * 64)
        self.assertEqual("partial-requires-discovery", receipt["state"])
        self.assertTrue(receipt["draft_planning_eligible"])
        self.assertFalse(receipt["g1_eligible"])
        self.assertFalse(receipt["implementation_eligible"])
        self.assertIn(
            "content-hash-time-bound",
            {item["reason"] for item in receipt["unresolved_roots"]})

    def test_registering_a_nested_worktree_changes_parent_boundary_evidence(self):
        before = loom_survey.workspace_snapshot(self.repo)
        self.add_nested_worktree()
        after = loom_survey.workspace_snapshot(self.repo)

        self.assertNotEqual(before.state.state_hash, after.state.state_hash)
        self.assertEqual((), before.boundaries)
        self.assertEqual(
            (loom_survey.WorkspaceBoundary(
                ".claude/worktrees/child"),),
            after.boundaries)

    def test_boundary_registry_change_during_observation_fails_closed(self):
        changed = loom_survey.WorkspaceBoundary(".independent/child")
        with mock.patch.object(
                loom_survey, "_registered_worktree_boundaries",
                side_effect=[(), (changed,)]):
            with self.assertRaisesRegex(
                    loom_survey.SurveyError,
                    "boundaries changed during observation"):
                loom_survey.workspace_snapshot(self.repo)

    def test_worktree_porcelain_parser_rejects_unknown_or_ambiguous_records(self):
        bad_values = (
            b"worktree /tmp/project\0future-field value\0\0",
            b"worktree /tmp/project\0worktree /tmp/duplicate\0\0",
            b"HEAD " + b"a" * 40 + b"\0\0",
        )
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(loom_survey.SurveyError):
                loom_survey._parse_worktree_registry(value)

    def test_worktree_identity_normalizes_filesystem_aliases(self):
        with mock.patch.object(
                loom_survey.os.path, "realpath",
                side_effect=lambda value: str(value).replace(
                    "alias-root", "physical-root")):
            self.assertEqual(
                loom_survey._path_key(self.repo / "alias-root"),
                loom_survey._path_key(self.repo / "physical-root"))
            self.assertEqual(
                Path("child"),
                loom_survey._physical_relative(
                    self.repo / "alias-root" / "child",
                    self.repo / "physical-root"))

    def test_repeated_registered_worktree_root_fails_closed(self):
        duplicate = loom_survey.WorkspaceBoundary(".independent/child")
        with mock.patch.object(
                loom_survey, "_parse_worktree_registry",
                return_value=(
                    {"path": self.repo, "bare": False, "prunable": False},
                    {"path": self.repo / duplicate.rel,
                     "bare": False, "prunable": False},
                    {"path": self.repo / duplicate.rel,
                     "bare": False, "prunable": False},
                )):
            with self.assertRaisesRegex(
                    loom_survey.SurveyError, "repeats a project root"):
                loom_survey._registered_worktree_boundaries(self.repo)

    def test_parent_observation_never_opens_a_registered_worktree_file(self):
        boundary = self.add_nested_worktree()
        protected = boundary / "must-not-be-read.bin"
        protected.write_bytes(b"private independent state")
        original_open = os.open

        def guarded_open(path, *args, **kwargs):
            try:
                Path(path).relative_to(boundary)
            except ValueError:
                return original_open(path, *args, **kwargs)
            raise AssertionError(f"parent observation opened independent worktree: {path}")

        with mock.patch.object(loom_survey.os, "open", side_effect=guarded_open):
            snapshot = loom_survey.workspace_snapshot(self.repo)

        self.assertEqual(
            (loom_survey.WorkspaceBoundary(
                ".claude/worktrees/child"),),
            snapshot.boundaries)

    def test_replaced_registered_worktree_directory_is_not_excluded(self):
        boundary = self.add_nested_worktree()
        shutil.rmtree(boundary)
        boundary.mkdir(parents=True)
        (boundary / "untrusted.txt").write_text("not a worktree\n", encoding="utf-8")

        with self.assertRaisesRegex(
                loom_survey.SurveyError,
                "prunable but present|does not resolve to its registered root"):
            loom_survey.workspace_snapshot(self.repo)


if __name__ == "__main__":
    unittest.main()
