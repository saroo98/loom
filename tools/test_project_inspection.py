"""Adversarial contract tests for bounded, fail-closed project inspection."""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import loom_project_inspection as inspection
import loom_survey
import loom_domain
import loom_domain_contract
import loom_release


def git(repo, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=check, capture_output=True,
        text=True, encoding="utf-8", timeout=30)


class ProjectInspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "project"
        self.repo.mkdir()
        git(self.repo, "init")
        git(self.repo, "config", "user.name", "Loom Test")
        git(self.repo, "config", "user.email", "loom@example.invalid")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self):
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "fixture")

    def receipt(self):
        snapshot = loom_survey.workspace_snapshot(self.repo)
        return inspection.inspect(
            snapshot, target_identity="target-sha256:" + "1" * 64)

    def test_generated_tree_above_old_limit_is_excluded_with_proof(self):
        (self.repo / "Cargo.toml").write_text(
            "[package]\nname='fixture'\nversion='0.1.0'\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.commit()
        target = self.repo / "target" / "debug" / "objects"
        target.mkdir(parents=True)
        for index in range(4100):
            (target / f"{index:04d}.o").write_bytes(b"generated")

        value = self.receipt()

        self.assertEqual("complete", value["state"])
        self.assertTrue(value["g1_eligible"])
        self.assertGreater(value["counters"]["entries_seen"], 4096)
        self.assertEqual(1, value["counters"]["generated_subtrees_excluded"])
        self.assertEqual("target", value["generated_exclusions"][0]["path"])
        self.assertLess(len(json.dumps(inspection.capsule(value))), 2048)

    def test_ignored_target_without_owner_marker_degrades_and_blocks_g1(self):
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self.commit()
        target = self.repo / "target"
        target.mkdir()
        (target / "payload.bin").write_bytes(b"not proven generated")

        value = self.receipt()

        self.assertEqual("partial-requires-discovery", value["state"])
        self.assertTrue(value["routing_eligible"])
        self.assertTrue(value["draft_planning_eligible"])
        self.assertFalse(value["g1_eligible"])
        self.assertFalse(value["implementation_eligible"])
        self.assertEqual("L", value["tier_floor"])
        self.assertEqual("ignored-unclassified", value["unresolved_roots"][0]["reason"])

    def test_known_authority_inside_generated_basename_is_never_excluded(self):
        (self.repo / "Cargo.toml").write_text(
            "[package]\nname='fixture'\nversion='0.1.0'\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        self.commit()
        target = self.repo / "target"
        target.mkdir()
        (target / "AGENTS.md").write_text("authority\n", encoding="utf-8")

        value = self.receipt()

        self.assertEqual([], value["generated_exclusions"])
        self.assertFalse(value["g1_eligible"])
        self.assertIn("target", [item["path"] for item in value["unresolved_roots"]])

    def test_request_touch_intersection_prevents_generated_exclusion(self):
        (self.repo / "Cargo.toml").write_text(
            "[package]\nname='fixture'\nversion='0.1.0'\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        self.commit()
        target = self.repo / "target"
        target.mkdir()
        (target / "configuration.json").write_text("{}\n", encoding="utf-8")

        snapshot = loom_survey.workspace_snapshot(
            self.repo, touch_paths=("target/configuration.json",))
        value = inspection.inspect(
            snapshot, target_identity="target-sha256:" + "4" * 64)

        self.assertEqual([], value["generated_exclusions"])
        self.assertFalse(value["g1_eligible"])
        self.assertIn("target", [item["path"] for item in value["unresolved_roots"]])

    def test_large_tracked_repository_uses_bounded_facts_without_losing_coverage(self):
        paths = tuple(f"sources/module_{index:04d}.txt" for index in range(600))
        entries = tuple(loom_survey._WorkspaceEntry(
            rel=path, path=self.repo / path, kind="file", device=1, inode=index + 1,
            mode=0o644, size=1, mtime_ns=1, uid=0, gid=0, flags=0, attributes=0)
            for index, path in enumerate(paths))
        frozen = {
            "policy_version": inspection.POLICY_VERSION,
            "exclusions": (), "unresolved": (), "ignored_roots": (),
        }
        snapshot = loom_survey.WorkspaceSnapshot(
            self.repo,
            loom_survey.RepoState(is_git=True, state_hash="a" * 64),
            entries, tracked=paths, generated_classification=frozen)
        first = inspection.inspect(
            snapshot, target_identity="target-sha256:" + "3" * 64)
        second = inspection.inspect(
            snapshot, target_identity="target-sha256:" + "3" * 64)

        self.assertEqual("complete", first["state"])
        self.assertEqual(1, first["counters"]["detailed_facts_saturated"])
        self.assertEqual(512, len(first["facts"]["file_names"]))
        self.assertEqual(first["receipt_digest"], second["receipt_digest"])
        self.assertLessEqual(len(first["partitions"]), 256)

    def test_adversarial_long_fact_names_cannot_overflow_private_action_budget(self):
        paths = tuple(
            "sources/" + ("n" * 180) + f"_{index:04d}.txt" for index in range(600))
        entries = tuple(loom_survey._WorkspaceEntry(
            rel=path, path=self.repo / path, kind="file", device=1, inode=index + 1,
            mode=0o644, size=1, mtime_ns=1, uid=0, gid=0, flags=0, attributes=0)
            for index, path in enumerate(paths))
        snapshot = loom_survey.WorkspaceSnapshot(
            self.repo, loom_survey.RepoState(is_git=True, state_hash="f" * 64),
            entries, tracked=paths, generated_classification={
                "policy_version": inspection.POLICY_VERSION,
                "exclusions": (), "unresolved": (), "ignored_roots": (),
            })

        value = inspection.inspect(
            snapshot, target_identity="target-sha256:" + "5" * 64)

        self.assertEqual("complete", value["state"])
        self.assertEqual(1, value["counters"]["detailed_facts_saturated"])
        self.assertLessEqual(
            sum(len(item) for items in value["facts"].values() for item in items),
            32768)
        self.assertLess(len(json.dumps(value).encode("utf-8")), 64 * 1024)

    def test_non_git_generated_claim_remains_partial(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        (plain / "Cargo.toml").write_text("[package]\nname='plain'\n", encoding="utf-8")
        (plain / "target").mkdir()
        (plain / "target" / "output").write_text("x", encoding="utf-8")

        snapshot = loom_survey.workspace_snapshot(plain)
        value = inspection.inspect(
            snapshot, target_identity="target-sha256:" + "2" * 64)

        self.assertEqual("partial-requires-discovery", value["state"])
        self.assertEqual("unsupported", value["source_states"]["tracked"])
        self.assertFalse(value["g1_eligible"])

    def test_large_untracked_tree_routes_but_cannot_authorize_g1(self):
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self.commit()
        unknown = self.repo / "incoming"
        unknown.mkdir()
        for index in range(600):
            (unknown / f"candidate_{index:04d}.txt").write_text("x", encoding="utf-8")

        value = self.receipt()

        self.assertEqual("partial-requires-discovery", value["state"])
        self.assertTrue(value["routing_eligible"])
        self.assertTrue(value["draft_planning_eligible"])
        self.assertFalse(value["g1_eligible"])
        self.assertIn(
            ("incoming", "untracked-volume"),
            [(item["path"], item["reason"]) for item in value["unresolved_roots"]])

    def test_receipt_validation_rejects_contradictory_or_duplicate_claims(self):
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self.commit()
        value = self.receipt()

        contradictory = copy.deepcopy(value)
        contradictory["state"] = "partial-requires-discovery"
        contradictory["receipt_digest"] = inspection._digest(
            {key: item for key, item in contradictory.items()
             if key != "receipt_digest"})
        with self.assertRaises(inspection.InspectionError):
            inspection.validate(contradictory)

        duplicate = copy.deepcopy(value)
        duplicate["partitions"].append(copy.deepcopy(duplicate["partitions"][0]))
        duplicate["receipt_digest"] = inspection._digest(
            {key: item for key, item in duplicate.items()
             if key != "receipt_digest"})
        with self.assertRaises(inspection.InspectionError):
            inspection.validate(duplicate)

    def test_domain_route_v2_binds_the_exact_inspection_capsule(self):
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self.commit()
        value = self.receipt()
        route = loom_domain.select_domains(
            "Build a command-line tool", project_facts=inspection.facts(value),
            project_inspection=value)["domain_contract"]

        self.assertEqual(2, route["schema_version"])
        self.assertEqual(value["receipt_digest"],
                         route["project_inspection"]["receipt_digest"])
        changed = copy.deepcopy(route)
        changed["project_inspection"]["g1_eligible"] = False
        with self.assertRaises(loom_domain_contract.DomainContractError):
            loom_domain_contract.validate_route(changed)

    def test_windows_posix_exclusion_boundary_is_separator_independent(self):
        self.assertTrue(loom_survey._is_excluded(
            "target/debug/output.o", ("target",)))
        self.assertFalse(loom_survey._is_excluded(
            "targeted/output.o", ("target",)))

    def test_publication_stays_positive_allowlist_not_generated_permission(self):
        from pathlib import PurePosixPath

        self.assertTrue(loom_release._eligible(
            PurePosixPath("schemas/project-inspection.schema.json")))
        self.assertFalse(loom_release._eligible(
            PurePosixPath("private/generated/target/output.bin")))
        self.assertFalse(loom_release._eligible(
            PurePosixPath("vault-helper/target/release/loom-vault")))


if __name__ == "__main__":
    unittest.main()
