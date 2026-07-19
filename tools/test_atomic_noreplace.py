#!/usr/bin/env python3
"""Focused adversarial tests for exclusive, identity-bound filesystem moves."""

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_reliability  # noqa: E402


class AtomicNoReplaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source_parent = self.base / "source-parent"
        self.destination_parent = self.base / "destination-parent"
        self.source_parent.mkdir()
        self.destination_parent.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def move(self, source, destination):
        identity = loom_reliability.observe_root_identity(source)
        outcome = loom_reliability.atomic_rename_noreplace(
            source, destination, expected_source_identity=identity)
        self.assertIsInstance(outcome, loom_reliability.AtomicRenameOutcome)
        self.assertEqual("committed", outcome.state["namespace_state"])

    def test_root_identity_is_path_bound_and_detects_replacement(self):
        source = self.source_parent / "source.txt"
        other = self.source_parent / "other.txt"
        replacement = self.source_parent / "replacement.txt"
        source.write_bytes(b"original")
        other.write_bytes(b"original")
        replacement.write_bytes(b"replacement")
        identity = loom_reliability.observe_root_identity(source)

        self.assertEqual(identity, loom_reliability.validate_root_identity(source, identity))
        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError, "identity changed"):
            loom_reliability.validate_root_identity(other, identity)

        os.replace(replacement, source)
        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError, "identity changed"):
            loom_reliability.validate_root_identity(source, identity)

    def test_regular_file_moves_without_replacing(self):
        source = self.source_parent / "source.txt"
        destination = self.destination_parent / "destination.txt"
        source.write_bytes(b"owner bytes")

        self.move(source, destination)

        self.assertFalse(source.exists())
        self.assertEqual(b"owner bytes", destination.read_bytes())

    def test_directory_moves_without_replacing(self):
        source = self.source_parent / "source"
        destination = self.destination_parent / "destination"
        source.mkdir()
        (source / "nested").mkdir()
        (source / "nested" / "value.txt").write_bytes(b"owner bytes")

        self.move(source, destination)

        self.assertFalse(source.exists())
        self.assertEqual(
            b"owner bytes", (destination / "nested" / "value.txt").read_bytes())

    def test_existing_file_and_directory_destinations_preserve_both_trees(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                source = self.source_parent / f"source-{kind}"
                destination = self.destination_parent / f"destination-{kind}"
                if kind == "file":
                    source.write_bytes(b"source")
                    destination.write_bytes(b"destination")
                else:
                    source.mkdir()
                    destination.mkdir()
                    (source / "source.txt").write_bytes(b"source")
                    (destination / "destination.txt").write_bytes(b"destination")
                identity = loom_reliability.observe_root_identity(source)

                with self.assertRaises(loom_reliability.ReliabilityError):
                    loom_reliability.atomic_rename_noreplace(
                        source, destination, expected_source_identity=identity)

                self.assertTrue(source.exists())
                self.assertTrue(destination.exists())
                if kind == "file":
                    self.assertEqual(b"source", source.read_bytes())
                    self.assertEqual(b"destination", destination.read_bytes())
                else:
                    self.assertEqual(b"source", (source / "source.txt").read_bytes())
                    self.assertEqual(
                        b"destination", (destination / "destination.txt").read_bytes())

    def test_destination_created_at_native_boundary_is_never_replaced(self):
        if os.name == "nt":
            backend_name = "_windows_atomic_rename_noreplace"
        elif sys.platform.startswith("linux"):
            backend_name = "_linux_renameat2_noreplace"
        elif sys.platform == "darwin":
            backend_name = "_macos_renameatx_noreplace"
        else:
            self.skipTest("no supported native atomic no-replace backend")
        real_native = getattr(loom_reliability, backend_name)
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                source = self.source_parent / f"race-source-{kind}"
                destination = self.destination_parent / f"race-destination-{kind}"
                if kind == "file":
                    source.write_bytes(b"source")
                else:
                    source.mkdir()
                    (source / "source.txt").write_bytes(b"source")
                identity = loom_reliability.observe_root_identity(source)

                def inject_race(*arguments):
                    if kind == "file":
                        destination.write_bytes(b"racer")
                    else:
                        destination.mkdir()
                        (destination / "racer.txt").write_bytes(b"racer")
                    return real_native(*arguments)

                with mock.patch(
                        f"loom_reliability.{backend_name}",
                        side_effect=inject_race):
                    with self.assertRaises(loom_reliability.ReliabilityError):
                        loom_reliability.atomic_rename_noreplace(
                            source, destination, expected_source_identity=identity)

                self.assertTrue(source.exists())
                if kind == "file":
                    self.assertEqual(b"racer", destination.read_bytes())
                else:
                    self.assertEqual(b"racer", (destination / "racer.txt").read_bytes())

    def test_concurrent_moves_have_exactly_one_winner(self):
        destination = self.destination_parent / "winner"
        sources = []
        identities = []
        for index in range(2):
            source = self.source_parent / f"source-{index}"
            source.mkdir()
            (source / "identity.txt").write_text(str(index), encoding="utf-8")
            sources.append(source)
            identities.append(loom_reliability.observe_root_identity(source))
        barrier = threading.Barrier(3)
        results = []
        lock = threading.Lock()

        def contender(index):
            barrier.wait()
            try:
                loom_reliability.atomic_rename_noreplace(
                    sources[index], destination,
                    expected_source_identity=identities[index])
                result = "moved"
            except loom_reliability.ReliabilityError:
                result = "refused"
            with lock:
                results.append(result)

        threads = [threading.Thread(target=contender, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(["moved", "refused"], sorted(results))
        self.assertTrue(destination.is_dir())
        self.assertEqual(1, sum(source.exists() for source in sources))

    def test_source_swap_at_native_boundary_is_refused(self):
        source = self.source_parent / "source.txt"
        destination = self.destination_parent / "destination.txt"
        displaced = self.source_parent / "displaced.txt"
        source.write_bytes(b"scanned")
        identity = loom_reliability.observe_root_identity(source)
        real_native = loom_reliability._native_atomic_rename_noreplace

        def inject_swap(*arguments):
            source.rename(displaced)
            source.write_bytes(b"replacement")
            return real_native(*arguments)

        with mock.patch(
                "loom_reliability._native_atomic_rename_noreplace",
                side_effect=inject_swap):
            with self.assertRaisesRegex(
                    loom_reliability.ReliabilityError, "identity changed"):
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity)

        self.assertEqual(b"replacement", source.read_bytes())
        self.assertEqual(b"scanned", displaced.read_bytes())
        self.assertFalse(destination.exists())

    def test_destination_parent_swap_at_native_boundary_is_refused(self):
        source = self.source_parent / "source.txt"
        destination = self.destination_parent / "destination.txt"
        displaced_parent = self.base / "displaced-destination-parent"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        real_native = loom_reliability._native_atomic_rename_noreplace

        def inject_swap(*arguments):
            self.destination_parent.rename(displaced_parent)
            self.destination_parent.mkdir()
            return real_native(*arguments)

        with mock.patch(
                "loom_reliability._native_atomic_rename_noreplace",
                side_effect=inject_swap):
            with self.assertRaisesRegex(
                    loom_reliability.ReliabilityError, "identity changed"):
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity)

        self.assertEqual(b"source", source.read_bytes())
        self.assertFalse(destination.exists())

    def test_cross_filesystem_evidence_fails_before_native_move(self):
        source = self.source_parent / "source.txt"
        destination = self.destination_parent / "destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        real_observe = loom_reliability.observe_root_identity

        def report_other_device(path):
            observed = real_observe(path)
            if Path(path) == self.destination_parent:
                observed = {**observed, "device": observed["device"] + 1}
            return observed

        with mock.patch(
                "loom_reliability.observe_root_identity",
                side_effect=report_other_device), mock.patch(
                    "loom_reliability._native_atomic_rename_noreplace") as native:
            with self.assertRaisesRegex(
                    loom_reliability.ReliabilityError, "different filesystems"):
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity)

        native.assert_not_called()
        self.assertTrue(source.exists())
        self.assertFalse(destination.exists())

    def test_redirected_destination_parent_is_refused(self):
        source = self.source_parent / "source.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        redirected = self.base / "redirected-parent"
        try:
            os.symlink(self.destination_parent, redirected, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")

        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError, "symlink|reparse"):
            loom_reliability.atomic_rename_noreplace(
                source, redirected / "destination.txt",
                expected_source_identity=identity)

        self.assertTrue(source.exists())

    def test_unavailable_native_primitive_has_no_fallback(self):
        source = self.source_parent / "source.txt"
        destination = self.destination_parent / "destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)

        with mock.patch(
                "loom_reliability._native_atomic_rename_noreplace",
                side_effect=loom_reliability.ReliabilityError(
                    "atomic no-replace move is unavailable")):
            with self.assertRaisesRegex(
                    loom_reliability.ReliabilityError, "unavailable"):
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity)

        self.assertTrue(source.exists())
        self.assertFalse(destination.exists())

    def test_success_requests_sync_for_both_distinct_parents(self):
        source = self.source_parent / "source.txt"
        destination = self.destination_parent / "destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        real_sync = loom_reliability._sync_parent

        with mock.patch(
                "loom_reliability._sync_parent", wraps=real_sync) as sync:
            outcome = loom_reliability.atomic_rename_noreplace(
                source, destination, expected_source_identity=identity)

        if os.name == "nt":
            sync.assert_not_called()
        else:
            self.assertEqual(
                {source.parent, destination.parent},
                {Path(call.args[0]).parent for call in sync.call_args_list})

    def test_parent_sync_failure_reports_committed_bounded_state(self):
        if os.name == "nt":
            self.skipTest("POSIX parent-sync fault injection")
        source = self.source_parent / "sync-source.txt"
        destination = self.destination_parent / "sync-destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        calls = []

        def fail_first(path):
            calls.append(Path(path).parent)
            if len(calls) == 1:
                raise OSError(5, "owner path and arbitrary diagnostics must not leak")

        with mock.patch("loom_reliability._sync_parent", side_effect=fail_first):
            with self.assertRaises(
                    loom_reliability.AtomicRenameDurabilityUnconfirmed) as caught:
                loom_reliability.atomic_rename_noreplace(
                    source, destination,
                    expected_source_identity=identity,
                    source_role="prepared_stage",
                    destination_role="active_plan")

        state = caught.exception.state
        self.assertFalse(source.exists())
        self.assertEqual(b"source", destination.read_bytes())
        self.assertEqual("committed", state["namespace_state"])
        self.assertEqual("unconfirmed", state["durability"])
        self.assertTrue(state["changes_made"])
        self.assertEqual("prepared_stage", state["source_role"])
        self.assertEqual("active_plan", state["destination_role"])
        self.assertEqual("absent", state["source_observed"])
        self.assertEqual("expected_object", state["destination_observed"])
        self.assertEqual(
            ["failed", "confirmed"],
            [item["status"] for item in state["parent_sync"]])
        self.assertEqual(5, state["parent_sync"][0]["errno"])
        self.assertNotIn("diagnostics", str(state))
        self.assertEqual(64, len(state["operation_id"]))
        self.assertEqual(
            {self.source_parent, self.destination_parent}, set(calls))

    def test_same_parent_sync_failure_is_reported_once_with_alias(self):
        if os.name == "nt":
            self.skipTest("POSIX parent-sync fault injection")
        source = self.source_parent / "same-parent-source.txt"
        destination = self.source_parent / "same-parent-destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)

        with mock.patch(
                "loom_reliability._sync_parent",
                side_effect=OSError(28, "unbounded detail")) as sync:
            with self.assertRaises(
                    loom_reliability.AtomicRenameDurabilityUnconfirmed) as caught:
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity)

        sync.assert_called_once()
        self.assertEqual(
            [
                {"role": "source_parent", "status": "failed",
                 "error_type": "OSError", "errno": 28},
                {"role": "destination_parent", "status": "same_parent",
                 "same_as": "source_parent"},
            ],
            caught.exception.state["parent_sync"])

    def test_invalid_roles_fail_before_namespace_change(self):
        source = self.source_parent / "invalid-role-source.txt"
        destination = self.destination_parent / "invalid-role-destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)

        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError, "role is invalid"):
            loom_reliability.atomic_rename_noreplace(
                source, destination, expected_source_identity=identity,
                source_role="owner path")

        self.assertTrue(source.exists())
        self.assertFalse(destination.exists())

    def test_injected_post_move_sync_failure_is_never_ordinary_failure(self):
        source = self.source_parent / "portable-sync-source.txt"
        destination = self.destination_parent / "portable-sync-destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        failed_sync = [
            {"role": "source_parent", "status": "failed",
             "error_type": "OSError", "errno": 5},
            {"role": "destination_parent", "status": "confirmed"},
        ]

        with mock.patch(
                "loom_reliability._sync_rename_parents",
                return_value=failed_sync):
            with self.assertRaises(
                    loom_reliability.AtomicRenameDurabilityUnconfirmed) as caught:
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity,
                    source_role="prepared_stage",
                    destination_role="active_plan")

        self.assertIsInstance(
            caught.exception, loom_reliability.ReliabilityError)
        self.assertEqual("committed", caught.exception.state["namespace_state"])
        self.assertEqual("unconfirmed", caught.exception.state["durability"])
        self.assertTrue(caught.exception.state["changes_made"])
        self.assertFalse(source.exists())
        self.assertEqual(b"source", destination.read_bytes())

    def test_ambiguous_post_move_observation_is_typed_reconciliation_state(self):
        source = self.source_parent / "ambiguous-source.txt"
        destination = self.destination_parent / "ambiguous-destination.txt"
        displaced = self.destination_parent / "displaced-source.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)
        confirmed_sync = [
            {"role": "source_parent", "status": "confirmed"},
            {"role": "destination_parent", "status": "confirmed"},
        ]

        def substitute_after_move(_source, _destination):
            destination.rename(displaced)
            destination.write_bytes(b"replacement")
            return confirmed_sync

        with mock.patch(
                "loom_reliability._sync_rename_parents",
                side_effect=substitute_after_move):
            with self.assertRaises(
                    loom_reliability.AtomicRenameNamespaceIndeterminate) as caught:
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity,
                    source_role="prepared_stage",
                    destination_role="active_plan")

        self.assertIsInstance(
            caught.exception,
            loom_reliability.AtomicRenameReconciliationRequired)
        self.assertEqual("ambiguous", caught.exception.state["namespace_state"])
        self.assertEqual("confirmed", caught.exception.state["durability"])
        self.assertEqual("other_object", caught.exception.state["destination_observed"])
        self.assertEqual(b"source", displaced.read_bytes())
        self.assertEqual(b"replacement", destination.read_bytes())

    def test_reconciliation_state_property_cannot_mutate_exception(self):
        if os.name == "nt":
            self.skipTest("POSIX parent-sync fault injection")
        source = self.source_parent / "copy-source.txt"
        destination = self.destination_parent / "copy-destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)

        with mock.patch(
                "loom_reliability._sync_parent", side_effect=OSError(5, "fail")):
            with self.assertRaises(
                    loom_reliability.AtomicRenameDurabilityUnconfirmed) as caught:
                loom_reliability.atomic_rename_noreplace(
                    source, destination, expected_source_identity=identity)

        first = caught.exception.state
        first["namespace_state"] = "ambiguous"
        first["parent_sync"].clear()
        self.assertEqual("committed", caught.exception.state["namespace_state"])
        self.assertEqual(2, len(caught.exception.state["parent_sync"]))

    @unittest.skipUnless(os.name == "nt", "Windows durability contract")
    def test_windows_namespace_success_is_honestly_unconfirmed(self):
        source = self.source_parent / "windows-source.txt"
        destination = self.destination_parent / "windows-destination.txt"
        source.write_bytes(b"source")
        identity = loom_reliability.observe_root_identity(source)

        outcome = loom_reliability.atomic_rename_noreplace(
            source, destination, expected_source_identity=identity,
            source_role="prepared_stage", destination_role="active_plan")

        self.assertFalse(outcome.durability_confirmed)
        self.assertEqual("committed", outcome.state["namespace_state"])
        self.assertEqual(
            ["unconfirmed", "unconfirmed"],
            [item["status"] for item in outcome.state["parent_sync"]])
        self.assertTrue(destination.exists())


class PrivateDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "owner-root"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def test_creates_and_reuses_bounded_private_components(self):
        expected = self.root / ".loom-recovery" / "action-123"

        first = loom_reliability.ensure_private_directory(
            self.root, (".loom-recovery", "action-123"))
        second = loom_reliability.ensure_private_directory(
            self.root, [".loom-recovery", "action-123"])

        self.assertEqual(expected, first)
        self.assertEqual(first, second)
        self.assertTrue(first.is_dir())
        self.assertFalse(first.is_symlink())
        if os.name == "posix":
            self.assertEqual(0, first.stat().st_mode & 0o077)

    def test_rejects_unbounded_or_unsafe_components(self):
        invalid = [
            (),
            tuple(f"part-{index}" for index in range(17)),
            ("..",),
            ("nested/path",),
            ("nested\\path",),
            ("space name",),
        ]
        for components in invalid:
            with self.subTest(components=components):
                with self.assertRaises(loom_reliability.ReliabilityError):
                    loom_reliability.ensure_private_directory(self.root, components)

    def test_existing_non_directory_component_is_refused(self):
        (self.root / ".loom-recovery").write_bytes(b"owner data")

        with self.assertRaises(loom_reliability.ReliabilityError):
            loom_reliability.ensure_private_directory(
                self.root, (".loom-recovery", "action-123"))

        self.assertEqual(b"owner data", (self.root / ".loom-recovery").read_bytes())

    def test_existing_redirect_component_is_refused(self):
        outside = self.base / "outside"
        outside.mkdir()
        redirected = self.root / ".loom-recovery"
        try:
            os.symlink(outside, redirected, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")

        with self.assertRaises(loom_reliability.ReliabilityError):
            loom_reliability.ensure_private_directory(
                self.root, (".loom-recovery", "action-123"))

        self.assertEqual([], list(outside.iterdir()))

    def test_root_substitution_during_creation_cannot_redirect_mutation(self):
        displaced = self.base / "displaced-owner-root"
        if os.name == "nt":
            real_create = loom_reliability._windows_create_or_open_relative_directory
            injected = False

            def swap_root(parent_handle, component, security_descriptor):
                nonlocal injected
                if not injected:
                    injected = True
                    self.root.rename(displaced)
                    self.root.mkdir()
                return real_create(
                    parent_handle, component, security_descriptor)

            patcher = mock.patch(
                "loom_reliability._windows_create_or_open_relative_directory",
                side_effect=swap_root)
        else:
            real_mkdir = os.mkdir
            injected = False

            def swap_root(component, mode=0o777, *, dir_fd=None):
                nonlocal injected
                if not injected and dir_fd is not None:
                    injected = True
                    os.rename(self.root, displaced)
                    real_mkdir(self.root)
                return real_mkdir(component, mode, dir_fd=dir_fd)

            patcher = mock.patch("loom_reliability.os.mkdir", side_effect=swap_root)

        with patcher:
            with self.assertRaises(loom_reliability.ReliabilityError):
                loom_reliability.ensure_private_directory(
                    self.root, (".loom-recovery",))

        self.assertFalse((self.root / ".loom-recovery").exists())
        self.assertTrue((displaced / ".loom-recovery").is_dir())


if __name__ == "__main__":
    unittest.main()
