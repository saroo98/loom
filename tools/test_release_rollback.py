"""Bounded public release rollback evidence tests."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import loom_release_rollback


class ReleaseRollbackTests(unittest.TestCase):
    def root(self, temporary):
        root = Path(temporary)
        for name in loom_release_rollback.TESTS:
            (root / name).write_text("# fixture\n", encoding="utf-8")
        return root

    def test_passing_battery_emits_digest_without_raw_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            completed = mock.Mock(returncode=0, stdout=b"private path", stderr=b"ok")
            with mock.patch.object(
                    loom_release_rollback.subprocess, "run", return_value=completed):
                value = loom_release_rollback.run(
                    root, commit="a" * 40, public_root_sha256="b" * 64)
            self.assertEqual("passed", value["status"])
            self.assertNotIn("output", value)
            self.assertNotIn("private path", str(value))
            self.assertEqual(hashlib.sha256(b"private path\nok").hexdigest(),
                             value["transcript_sha256"])

    def test_failed_battery_cannot_be_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            completed = mock.Mock(returncode=1, stdout=b"", stderr=b"failure")
            with mock.patch.object(
                    loom_release_rollback.subprocess, "run", return_value=completed):
                value = loom_release_rollback.run(
                    root, commit="a" * 40, public_root_sha256="b" * 64)
            self.assertEqual("failed", value["status"])

    def test_wrong_subject_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            with mock.patch.object(loom_release_rollback.subprocess, "run") as runner:
                with self.assertRaises(loom_release_rollback.RollbackEvidenceError):
                    loom_release_rollback.run(
                        root, commit="not-a-commit", public_root_sha256="b" * 64)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
