#!/usr/bin/env python3
"""Focused adversarial tests for exact-tree deletion-authority evidence."""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_reliability  # noqa: E402


class _ChangedStat:
    def __init__(self, original, **changes):
        self._original = original
        self._changes = changes

    def __getattr__(self, name):
        if name in self._changes:
            return self._changes[name]
        return getattr(self._original, name)


class ExactTreeManifestTests(unittest.TestCase):
    def test_cross_volume_materializer_remains_retired(self):
        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError,
                "cross-volume exact-tree materialization is retired"):
            loom_reliability.materialize_exact_tree("source", "destination")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "tree"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, content=b"content\n"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_manifest_v2_records_root_empty_directories_modes_and_files(self):
        empty = self.root / "empty"
        empty.mkdir()
        source = self.write("nested/value.txt", b"value\n")

        first = loom_reliability.exact_tree_manifest(self.root)
        second = loom_reliability.exact_tree_manifest(self.root)

        self.assertEqual(first, second)
        self.assertEqual(2, first["schema_version"])
        self.assertEqual("exact-tree-no-extended-data-v1", first["policy"])
        self.assertEqual("windows" if os.name == "nt" else "posix", first["platform"])
        self.assertEqual(1, first["file_count"])
        self.assertEqual(3, first["directory_count"])
        self.assertEqual(len(b"value\n"), first["total_bytes"])
        by_path = {entry["path"]: entry for entry in first["entries"]}
        self.assertEqual("directory", by_path["."]["kind"])
        self.assertEqual(stat.S_IMODE(empty.lstat().st_mode), by_path["empty"]["mode"])
        self.assertEqual(stat.S_IMODE(source.lstat().st_mode),
                         by_path["nested/value.txt"]["mode"])
        self.assertEqual(1, by_path["nested/value.txt"]["links"])
        self.assertIs(first, loom_reliability.validate_exact_tree_manifest(first))

        legacy = loom_reliability.deterministic_manifest(self.root)
        self.assertEqual(1, legacy["schema_version"])
        self.assertEqual(["nested/value.txt"], [item["path"] for item in legacy["files"]])

    def test_entry_bound_is_enforced_during_enumeration(self):
        for index in range(4):
            (self.root / f"entry-{index}").mkdir()
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "entry bound"):
            loom_reliability.exact_tree_manifest(self.root, max_entries=2)

    def test_exact_equality_and_partial_subset_are_separate_proofs(self):
        expected_root = self.root / "expected"
        actual_root = self.root / "actual"
        expected_root.mkdir()
        actual_root.mkdir()
        (expected_root / "sub").mkdir()
        (actual_root / "sub").mkdir()
        (expected_root / "sub" / "value.txt").write_bytes(b"value")
        if os.name == "posix":
            os.chmod(expected_root, 0o700)
            os.chmod(actual_root, 0o700)
            os.chmod(expected_root / "sub", 0o755)
            os.chmod(actual_root / "sub", 0o755)

        expected = loom_reliability.exact_tree_manifest(expected_root)
        actual = loom_reliability.exact_tree_manifest(actual_root)

        self.assertFalse(loom_reliability.exact_tree_manifests_equal(actual, expected))
        self.assertTrue(loom_reliability.exact_tree_manifest_is_subset(actual, expected))
        self.assertFalse(loom_reliability.exact_tree_manifest_is_subset(expected, actual))

    def test_added_empty_directory_is_not_an_exact_match_or_subset(self):
        self.write("value.txt")
        expected = loom_reliability.exact_tree_manifest(self.root)
        (self.root / "owner-empty").mkdir()
        actual = loom_reliability.exact_tree_manifest(self.root)

        self.assertFalse(loom_reliability.exact_tree_manifests_equal(actual, expected))
        self.assertFalse(loom_reliability.exact_tree_manifest_is_subset(actual, expected))

    def test_manifest_validation_rejects_tampering_and_unsafe_paths(self):
        self.write("value.txt")
        original = loom_reliability.exact_tree_manifest(self.root)
        tampered = json.loads(json.dumps(original))
        tampered["entries"][-1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "digest"):
            loom_reliability.validate_exact_tree_manifest(tampered)

        escaped = json.loads(json.dumps(original))
        escaped["entries"][-1]["path"] = "../outside"
        body = {key: value for key, value in escaped.items() if key != "root_sha256"}
        escaped["root_sha256"] = loom_reliability._canonical_hash(body)
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "relative|escapes"):
            loom_reliability.validate_exact_tree_manifest(escaped)

    def test_per_entry_validation_detects_file_and_directory_mode_changes(self):
        directory = self.root / "nested"
        directory.mkdir()
        source = self.write("nested/value.txt")
        manifest = loom_reliability.exact_tree_manifest(self.root)
        entries = {entry["path"]: entry for entry in manifest["entries"]}
        loom_reliability.validate_exact_tree_entry(self.root, entries["nested"])
        loom_reliability.validate_exact_tree_entry(self.root, entries["nested/value.txt"])

        if os.name != "posix":
            self.skipTest("portable mode mutation assertions require POSIX chmod semantics")
        os.chmod(source, entries["nested/value.txt"]["mode"] ^ stat.S_IXUSR)
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "does not match"):
            loom_reliability.validate_exact_tree_entry(
                self.root, entries["nested/value.txt"])
        os.chmod(directory, entries["nested"]["mode"] ^ stat.S_IXUSR)
        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError, "metadata|does not match"):
            loom_reliability.validate_exact_tree_entry(self.root, entries["nested"])

    def test_hardlinks_are_rejected_instead_of_flattened(self):
        source = self.write("value.txt")
        outside = Path(self.temporary.name) / "outside-link.txt"
        try:
            os.link(source, outside)
        except OSError as exc:
            self.skipTest(f"hardlinks unavailable: {exc}")
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "hardlink"):
            loom_reliability.exact_tree_manifest(self.root)

    def test_redirects_are_rejected(self):
        target = self.write("target.txt")
        link = self.root / "link.txt"
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "redirected"):
            loom_reliability.exact_tree_manifest(self.root)

    @unittest.skipUnless(hasattr(os, "mkfifo") and os.name == "posix",
                         "FIFO verification requires POSIX")
    def test_special_files_are_rejected(self):
        os.mkfifo(self.root / "owner.fifo")
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "special"):
            loom_reliability.exact_tree_manifest(self.root)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "setxattr"),
                         "extended attributes require POSIX support")
    def test_posix_xattrs_on_root_directory_or_file_are_rejected(self):
        directory = self.root / "nested"
        directory.mkdir()
        source = self.write("nested/value.txt")
        for candidate in (self.root, directory, source):
            with self.subTest(candidate=candidate.name):
                try:
                    os.setxattr(candidate, "user.loom-test", b"owner-data")
                except OSError as exc:
                    self.skipTest(f"user xattrs unavailable: {exc}")
                try:
                    with self.assertRaisesRegex(
                            loom_reliability.ReliabilityError, "extended attribute"):
                        loom_reliability.exact_tree_manifest(self.root)
                finally:
                    os.removexattr(candidate, "user.loom-test")

    @unittest.skipUnless(os.name == "nt", "alternate data streams require Windows")
    def test_windows_ads_on_root_directory_or_file_are_rejected(self):
        directory = self.root / "nested"
        directory.mkdir()
        source = self.write("nested/value.txt")
        for candidate in (self.root, directory, source):
            with self.subTest(candidate=candidate.name):
                stream = str(candidate) + ":loom-test"
                try:
                    with open(stream, "wb") as handle:
                        handle.write(b"owner-data")
                except OSError as exc:
                    self.skipTest(f"alternate data streams unavailable: {exc}")
                try:
                    with self.assertRaisesRegex(
                            loom_reliability.ReliabilityError, "alternate data stream"):
                        loom_reliability.exact_tree_manifest(self.root)
                finally:
                    os.unlink(stream)

    def test_nested_mount_boundary_is_rejected(self):
        nested = self.root / "nested"
        nested.mkdir()
        real_ismount = os.path.ismount

        def simulated(path):
            return Path(path) == nested or real_ismount(path)

        with mock.patch("loom_reliability.os.path.ismount", side_effect=simulated):
            with self.assertRaisesRegex(loom_reliability.ReliabilityError, "mount boundary"):
                loom_reliability.exact_tree_manifest(self.root)

    def test_file_identity_change_during_read_is_rejected(self):
        self.write("value.txt", b"value")
        real_fstat = os.fstat
        calls = 0

        def changed(descriptor):
            nonlocal calls
            calls += 1
            observed = real_fstat(descriptor)
            if calls == 2:
                return _ChangedStat(observed, st_size=observed.st_size + 1)
            return observed

        with mock.patch("loom_reliability.os.fstat", side_effect=changed):
            with self.assertRaisesRegex(loom_reliability.ReliabilityError,
                                        "changed while it was read"):
                loom_reliability.exact_tree_manifest(self.root)


if __name__ == "__main__":
    unittest.main()
