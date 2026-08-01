"""Privacy-safe Codex App release observation tests."""

import unittest

import loom_codex_release_evidence
import loom_subject_identity


class CodexReleaseEvidenceTests(unittest.TestCase):
    def installed(self):
        return loom_subject_identity.installed_runtime(
            version="1.9.0", release_sequence=1, payload_sha256="a" * 64,
            install_receipt_sha256="b" * 64, activation_receipt_sha256="c" * 64)

    def test_receipt_contains_digests_not_private_bodies(self):
        value = loom_codex_release_evidence.create(
            release_subject_sha256="d" * 64,
            installed_runtime_subject=self.installed(), request_sha256="e" * 64,
            response_sha256="f" * 64, task_sha256="1" * 64,
            observed_at="2026-08-01T12:00:00Z")
        self.assertEqual("passed", value["status"])
        self.assertFalse(any(value["privacy"].values()))
        for forbidden in ("prompt", "request_text", "project_path", "task_id"):
            self.assertNotIn(forbidden, value)

    def test_non_installed_subject_is_refused(self):
        plugin = loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "plugin-zip", "subject_id": "loom.zip",
            "filename": "loom.zip", "bytes": 1, "sha256": "a" * 64})
        with self.assertRaises(loom_codex_release_evidence.CodexReleaseEvidenceError):
            loom_codex_release_evidence.create(
                release_subject_sha256="d" * 64,
                installed_runtime_subject=plugin, request_sha256="e" * 64,
                response_sha256="f" * 64, task_sha256="1" * 64,
                observed_at="2026-08-01T12:00:00Z")

    def test_invalid_observation_time_is_refused(self):
        with self.assertRaises(loom_codex_release_evidence.CodexReleaseEvidenceError):
            loom_codex_release_evidence.create(
                release_subject_sha256="d" * 64,
                installed_runtime_subject=self.installed(), request_sha256="e" * 64,
                response_sha256="f" * 64, task_sha256="1" * 64,
                observed_at="not-a-timeZ")


if __name__ == "__main__":
    unittest.main()
