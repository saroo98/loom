import os
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_path_authority


class PathAuthorityTests(unittest.TestCase):
    def test_owned_staging_path_can_be_authorized_and_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            staging = root / "staging"
            receipt = loom_path_authority.create_owned_directory(
                path=staging, root=root)
            authority = loom_path_authority.authorize(
                operation_class="staging", path=staging, root=root,
                expected_type="directory", replacement_policy="owned-exact",
                cleanup_disposition="remove-if-owned",
                ownership_receipt=receipt)
            self.assertEqual("primary-effect-before-cleanup",
                             authority["failure_precedence"])
            self.assertTrue(loom_path_authority.remove_owned_tree(
                staging, root=root, ownership_receipt=receipt))

    def test_absent_destination_and_same_volume_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            destination = root / "destination"
            authority = loom_path_authority.authorize(
                operation_class="release-package", path=destination, root=root,
                expected_type="absent", replacement_policy="atomic-no-replace",
                cleanup_disposition="preserve", peer_path=source,
                require_same_volume=True)
            self.assertTrue(authority["same_volume"])

    def test_traversal_redirected_parent_and_wrong_receipt_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outside = root.parent / f"outside-{uuid.uuid4().hex}"
            with self.assertRaises(loom_path_authority.PathAuthorityError):
                loom_path_authority.authorize(
                    operation_class="staging", path=outside, root=root,
                    expected_type="absent", replacement_policy="forbid",
                    cleanup_disposition="preserve")
            target = root / "owned"
            receipt = loom_path_authority.create_owned_directory(
                path=target, root=root)
            other = root / "other"
            other.mkdir()
            with self.assertRaises(loom_path_authority.PathAuthorityError):
                loom_path_authority.remove_owned_tree(
                    other, root=root, ownership_receipt=receipt)
            if hasattr(os, "symlink"):
                redirected = root / "redirected"
                try:
                    os.symlink(target, redirected, target_is_directory=True)
                except OSError:
                    redirected = None
                if redirected is not None:
                    with self.assertRaises(loom_path_authority.PathAuthorityError):
                        loom_path_authority.authorize(
                            operation_class="staging", path=redirected / "child",
                            root=root, expected_type="absent",
                            replacement_policy="forbid",
                            cleanup_disposition="preserve")

    def test_changed_object_identity_invalidates_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "owned"
            receipt = loom_path_authority.create_owned_directory(
                path=target, root=root)
            target.rmdir()
            target.mkdir()
            with self.assertRaises(loom_path_authority.PathAuthorityError):
                loom_path_authority.validate_ownership_receipt(
                    receipt, path=target, root=root)

    def test_preexisting_path_cannot_be_claimed_or_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "preexisting"
            target.mkdir()
            sentinel = target / "sentinel.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaises(loom_path_authority.PathAuthorityError):
                loom_path_authority.create_owned_directory(
                    path=target, root=root)
            with self.assertRaises(loom_path_authority.PathAuthorityError):
                loom_path_authority.create_ownership_receipt(
                    path=target, root=root, operation_id="0" * 36,
                    expected_type="directory")
            self.assertEqual("preserve", sentinel.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
