import hashlib
import json
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_subject_identity
import loom_self_hosting


class SubjectIdentityPhase4Tests(unittest.TestCase):
    def git_repo(self, root):
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"],
                       cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        (root / "source.txt").write_text("same bytes\n", encoding="utf-8")
        subprocess.run(["git", "add", "source.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            capture_output=True, text=True).stdout.strip()

    def test_main_and_candidate_are_distinct_even_for_same_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commit = self.git_repo(root)
            main = loom_subject_identity.main_source(root, commit)
            candidate = loom_subject_identity.candidate_source(
                root, base_commit=commit, commit=commit)
        self.assertEqual(main["tree_sha256"], candidate["tree_sha256"])
        self.assertNotEqual(main["kind"], candidate["kind"])
        self.assertNotEqual(main["subject_digest"], candidate["subject_digest"])
        findings = loom_subject_identity.match_expected(
            [main], [candidate], required=[("main-source", "main")])
        self.assertEqual("WRONG_SUBJECT", findings[0]["reason"])

    def test_git_inventory_ignores_ambient_untracked_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commit = self.git_repo(root)
            first = loom_subject_identity.git_tree_inventory(root, commit)
            ambient = root / "ignored" / "deep"
            ambient.mkdir(parents=True)
            (ambient / "not-part-of-subject.txt").write_text(
                "ambient", encoding="utf-8")
            second = loom_subject_identity.git_tree_inventory(root, commit)
        self.assertEqual(first, second)
        self.assertEqual(["source.txt"], [
            item["path"] for item in first["entries"]])

    def test_git_inventory_rejects_redirect_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git_repo(root)
            object_id = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"], cwd=root,
                input="../outside", capture_output=True, text=True,
                check=True).stdout.strip()
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo",
                 f"120000,{object_id},redirect"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "redirect fixture"],
                cwd=root, check=True)
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True,
                capture_output=True, text=True).stdout.strip()
            with self.assertRaisesRegex(
                    loom_subject_identity.SubjectIdentityError, "unsafe"):
                loom_subject_identity.git_tree_inventory(root, commit)

    def test_generated_inventory_reads_declared_paths_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "declared.json").write_text(
                "{}\n", encoding="utf-8")
            (root / "secret.txt").write_text("not inspected", encoding="utf-8")
            registry = {"generated_outputs": [{
                "path": "docs/declared.json",
                "generator": "tools/loom_truth.py",
                "inputs": ["fixture"],
            }]}
            result = loom_subject_identity.generated_inventory(root, registry)
        self.assertEqual(
            ["docs/declared.json"],
            [item["path"] for item in result["outputs"]])

    def test_expected_subjects_require_external_ci_attestation(self):
        subject = loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "plugin-zip",
            "subject_id": "loom.zip", "filename": "loom.zip",
            "bytes": 4, "sha256": hashlib.sha256(b"loom").hexdigest(),
        })
        body = {
            "schema_version": 1,
            "expectation_id": str(uuid.uuid4()),
            "issuer_kind": "ci",
            "issuer_id": "github-actions",
            "repository": loom_subject_identity.REPOSITORY,
            "run_id": "123",
            "job_id": "subject-test",
            "workflow_digest": "1" * 64,
            "base_commit": "2" * 40,
            "candidate_commit": "3" * 40,
            "issued_at": "2026-07-28T00:00:00Z",
            "expires_at": "2026-07-29T00:00:00Z",
            "evaluation_epoch": "2026-07-28T12:00:00Z",
            "subjects": [subject],
            "authority": {
                "kind": "ci-attestation", "attestation_sha256": "4" * 64},
        }
        body["expectation_sha256"] = loom_subject_identity.digest({
            key: value for key, value in body.items()
            if key not in {"authority", "expectation_sha256"}})
        with self.assertRaisesRegex(
                loom_subject_identity.SubjectIdentityError, "unavailable"):
            loom_subject_identity.validate_expected_subjects(body)
        observed = loom_subject_identity.validate_expected_subjects(
            body, ci_attestation_verifier=lambda _value: True)
        self.assertEqual("2026-07-28T12:00:00Z",
                         observed["evaluation_epoch"])
        authorized = loom_self_hosting.authorize_expected_subjects(
            body, [subject], required=[("plugin-zip", "loom.zip")],
            now="2026-07-28T12:00:00Z",
            ci_attestation_verifier=lambda _value: True)
        self.assertEqual(body["expectation_sha256"],
                         authorized["expectation_sha256"])
        self.assertEqual(2, authorized["schema_version"])
        self.assertEqual(
            "plugin-zip",
            authorized["subject_bindings"][0]["kind"])

    def test_candidate_cannot_substitute_same_bytes_as_expected_kind(self):
        raw_hash = hashlib.sha256(b"same").hexdigest()
        plugin = loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "plugin-zip",
            "subject_id": "same.zip", "filename": "same.zip",
            "bytes": 4, "sha256": raw_hash,
        })
        helper = loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "native-helper",
            "subject_id": "linux-x64", "platform": "linux-x64",
            "filename": "loom-vault", "bytes": 4, "sha256": raw_hash,
            "sbom_sha256": "1" * 64, "provenance_sha256": "2" * 64,
        })
        findings = loom_subject_identity.match_expected(
            [plugin], [helper], required=[("plugin-zip", "same.zip")])
        self.assertEqual(
            [{"kind": "plugin-zip", "subject_id": "same.zip",
              "reason": "WRONG_SUBJECT"}], findings)

    def test_public_cut_is_a_distinct_closed_subject(self):
        subject = loom_subject_identity.public_cut(
            root_sha256="1" * 64, manifest_sha256="2" * 64,
            file_count=117)
        self.assertEqual("public-cut", subject["kind"])
        self.assertEqual("public-cut", subject["subject_id"])
        self.assertEqual(117, subject["file_count"])
        self.assertEqual(subject, loom_subject_identity.validate_subject(subject))
        invalid = dict(subject)
        invalid["owner_path"] = "C:/private"
        invalid["subject_digest"] = loom_subject_identity.digest({
            key: value for key, value in invalid.items()
            if key != "subject_digest"})
        with self.assertRaisesRegex(
                loom_subject_identity.SubjectIdentityError, "fields are invalid"):
            loom_subject_identity.validate_subject(invalid)


if __name__ == "__main__":
    unittest.main()
