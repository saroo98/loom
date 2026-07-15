"""Behavioral tests for automatic lifecycle preflight and real-medium evidence."""

import json
import dataclasses
import hashlib
import os
import subprocess
import sys
import tempfile
import time
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

    def test_acceptance_evidence_identity_is_content_bound(self):
        evidence = loom_lifecycle.capture_acceptance(
            self.pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('content-bound')"])

        self.assertEqual(
            "sha256-" + evidence["evidence_hash"], evidence["evidence_id"])
        validated = loom_lifecycle.validate_acceptance_evidence(
            self.pack, "WO-001", self.repo, require_current=True)
        self.assertEqual(evidence["evidence_id"], validated["evidence_id"])

    def test_acceptance_evidence_id_cannot_be_reused_after_rehashing_content(self):
        evidence = loom_lifecycle.capture_acceptance(
            self.pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('original')"])
        path = self.pack / "evidence" / "WO-001.json"
        altered = json.loads(path.read_text(encoding="utf-8"))
        altered["stdout"] = "fabricated\n"
        altered["stdout_sha256"] = hashlib.sha256(
            altered["stdout"].encode("utf-8")).hexdigest()
        body = {key: value for key, value in altered.items()
                if key not in {"evidence_id", "evidence_hash"}}
        altered["evidence_hash"] = loom_lifecycle._digest(body)
        self.assertEqual(evidence["evidence_id"], altered["evidence_id"])
        path.write_text(json.dumps(altered), encoding="utf-8")

        with self.assertRaisesRegex(loom_lifecycle.LifecycleError, "contract or hash"):
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

    def test_porcelain_v2_snapshot_parses_branch_and_complete_change_classes(self):
        oid = b"a" * 40
        raw = b"\0".join((
            b"# branch.oid " + oid,
            b"# branch.head feature/safe-state",
            b"1 M. N... 100644 100644 100644 " + oid + b" " + oid
            + b" staged name.txt",
            b"1 .M N... 100644 100644 100644 " + oid + b" " + oid
            + b" unstaged.txt",
            b"u UU N... 100644 100644 100644 100644 " + oid + b" "
            + oid + b" " + oid + b" conflict.txt",
            b"? untracked space.txt",
            b"",
        ))
        parsed = loom_survey._parse_porcelain_v2(raw)
        self.assertEqual(oid.decode("ascii"), parsed["head"])
        self.assertEqual(b"feature/safe-state", parsed["branch_raw"])
        self.assertEqual(
            (b"conflict.txt", b"staged name.txt"), parsed["staged"])
        self.assertEqual(
            (b"conflict.txt", b"unstaged.txt"), parsed["unstaged"])
        self.assertEqual((b"untracked space.txt",), parsed["untracked"])

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
        self.assertEqual("print('baseline')\n",
                         (self.repo / "app.py").read_text(encoding="utf-8"))

    def test_verification_command_cannot_mutate_parent_of_real_target(self):
        outside = self.repo.parent / "owner-data.txt"
        outside.write_text("must survive", encoding="utf-8")
        with self.assertRaisesRegex(loom_lifecycle.LifecycleError, "command failed"):
            loom_lifecycle.capture_acceptance(
                self.pack, self.repo, "WO-001", medium="cli-process",
                command=[sys.executable, "-c",
                         "from pathlib import Path; Path('../owner-data.txt').unlink()"])
        self.assertEqual("must survive", outside.read_text(encoding="utf-8"))
        self.assertFalse((self.pack / "evidence" / "WO-001.json").exists())

    @unittest.skipUnless(os.name == "nt", "Windows Job Object containment")
    def test_detached_verifier_descendants_are_dead_before_evidence_is_sealed(self):
        marker = self.repo / "delayed-verifier-escape.txt"
        child = (
            "import pathlib,time; time.sleep(1.0); "
            f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
        )
        launcher = (
            "import subprocess,sys,tempfile; "
            "subprocess.Popen([sys.executable,'-c'," + repr(child) + "], "
            "cwd=tempfile.gettempdir(), close_fds=True, "
            "creationflags=getattr(subprocess,'DETACHED_PROCESS',0) | "
            "getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0))"
        )

        evidence = loom_lifecycle.capture_acceptance(
            self.pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", launcher], timeout=10)
        self.assertEqual(0, evidence["exit_code"])
        time.sleep(1.5)
        self.assertFalse(
            marker.exists(),
            "a verifier descendant changed the original target after evidence was sealed")

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
                "regate-receipt.schema.json", "release-exposure.schema.json",
                "repair-result.schema.json", "host-outcome.schema.json",
                "plan-contract.schema.json"):
            with self.subTest(name=name):
                schema = json.loads((root / name).read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"],
                                 "https://json-schema.org/draft/2020-12/schema")
                self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
