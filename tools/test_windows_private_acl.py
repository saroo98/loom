#!/usr/bin/env python3
"""Native acceptance tests for Loom's exact Windows private-directory DACL."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_windows_acl  # noqa: E402
import loom_reliability  # noqa: E402


@unittest.skipUnless(os.name == "nt", "requires native Windows ACL APIs")
class WindowsPrivateAclTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="loom-private-acl-")
        self.base = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _libraries():
        import ctypes

        return (
            ctypes,
            ctypes.WinDLL("kernel32", use_last_error=True),
            ctypes.WinDLL("advapi32", use_last_error=True),
        )

    @classmethod
    def _local_free(cls, pointer):
        if not pointer:
            return
        ctypes, kernel, _advapi = cls._libraries()
        from ctypes import wintypes

        free = kernel.LocalFree
        free.argtypes = [wintypes.HLOCAL]
        free.restype = wintypes.HLOCAL
        free(ctypes.cast(pointer, wintypes.HLOCAL))

    @classmethod
    def _sid_text(cls, sid):
        ctypes, _kernel, advapi = cls._libraries()
        from ctypes import wintypes

        convert = advapi.ConvertSidToStringSidW
        convert.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        convert.restype = wintypes.BOOL
        text = wintypes.LPWSTR()
        if not convert(sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
        try:
            return text.value
        finally:
            cls._local_free(text)

    @classmethod
    def _open_directory(cls, path):
        ctypes, kernel, _advapi = cls._libraries()
        from ctypes import wintypes

        open_file = kernel.CreateFileW
        open_file.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        open_file.restype = wintypes.HANDLE
        handle = open_file(
            str(path), 0x00020000 | 0x00000080, 0x1 | 0x2 | 0x4,
            None, 3, 0x02000000 | 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "CreateFileW")
        return handle

    @classmethod
    def _close_handle(cls, handle):
        ctypes, kernel, _advapi = cls._libraries()
        from ctypes import wintypes

        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        if not close(handle):
            raise OSError(ctypes.get_last_error(), "CloseHandle")

    @classmethod
    def _raw_acl(cls, path):
        """Inspect the actual handle ACL without calling the production verifier."""
        ctypes, _kernel, advapi = cls._libraries()
        from ctypes import wintypes

        class Acl(ctypes.Structure):
            _fields_ = [
                ("revision", ctypes.c_ubyte), ("sbz1", ctypes.c_ubyte),
                ("size", wintypes.WORD), ("ace_count", wintypes.WORD),
                ("sbz2", wintypes.WORD),
            ]

        class AceHeader(ctypes.Structure):
            _fields_ = [
                ("type", ctypes.c_ubyte), ("flags", ctypes.c_ubyte),
                ("size", wintypes.WORD),
            ]

        class AllowedAce(ctypes.Structure):
            _fields_ = [
                ("header", AceHeader), ("mask", wintypes.DWORD),
                ("sid_start", wintypes.DWORD),
            ]

        get_security = advapi.GetSecurityInfo
        get_security.argtypes = [
            wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_security.restype = wintypes.DWORD
        handle = cls._open_directory(path)
        descriptor = wintypes.LPVOID()
        owner = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        try:
            status = get_security(
                handle, 1, 0x1 | 0x4, ctypes.byref(owner), None,
                ctypes.byref(dacl), None, ctypes.byref(descriptor))
            if status:
                raise OSError(status, "GetSecurityInfo")
            get_control = advapi.GetSecurityDescriptorControl
            get_control.argtypes = [
                wintypes.LPVOID, ctypes.POINTER(wintypes.WORD),
                ctypes.POINTER(wintypes.DWORD)]
            get_control.restype = wintypes.BOOL
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not get_control(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise OSError(
                    ctypes.get_last_error(), "GetSecurityDescriptorControl")
            acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
            get_ace = advapi.GetAce
            get_ace.argtypes = [
                wintypes.LPVOID, wintypes.DWORD,
                ctypes.POINTER(wintypes.LPVOID)]
            get_ace.restype = wintypes.BOOL
            entries = []
            for index in range(acl.ace_count):
                pointer = wintypes.LPVOID()
                if not get_ace(dacl, index, ctypes.byref(pointer)):
                    raise OSError(ctypes.get_last_error(), "GetAce")
                ace = ctypes.cast(pointer, ctypes.POINTER(AllowedAce)).contents
                sid = wintypes.LPVOID(
                    pointer.value + AllowedAce.sid_start.offset)
                entries.append((
                    ace.header.type, ace.header.flags, int(ace.mask),
                    cls._sid_text(sid)))
            return {
                "owner": cls._sid_text(owner),
                "protected": bool(control.value & 0x1000),
                "entries": entries,
            }
        finally:
            if descriptor:
                cls._local_free(descriptor)
            cls._close_handle(handle)

    @classmethod
    def _set_permissive_acl(cls, path):
        """Add an explicit Everyone ACE using Win32 independently of production."""
        ctypes, _kernel, advapi = cls._libraries()
        from ctypes import wintypes

        user = loom_windows_acl.current_user_sid_string()
        sddl = (
            f"O:{user}G:{user}D:P(A;OICI;FA;;;{user})"
            "(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)"
        )
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD),
        ]
        convert.restype = wintypes.BOOL
        get_dacl = advapi.GetSecurityDescriptorDacl
        get_dacl.argtypes = [
            wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL),
        ]
        get_dacl.restype = wintypes.BOOL
        set_named = advapi.SetNamedSecurityInfoW
        set_named.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
            wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID,
        ]
        set_named.restype = wintypes.DWORD
        descriptor = wintypes.LPVOID()
        size = wintypes.DWORD()
        if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)):
            raise OSError(
                ctypes.get_last_error(),
                "ConvertStringSecurityDescriptorToSecurityDescriptorW")
        try:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            dacl = wintypes.LPVOID()
            if not get_dacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl),
                    ctypes.byref(defaulted)) or not present or not dacl:
                raise OSError(
                    ctypes.get_last_error(), "GetSecurityDescriptorDacl")
            mutable_path = ctypes.create_unicode_buffer(str(path))
            status = set_named(
                mutable_path, 1, 0x4 | 0x80000000,
                None, None, dacl, None)
            if status:
                raise OSError(status, "SetNamedSecurityInfoW")
        finally:
            cls._local_free(descriptor)

    def assertExactPrivateAcl(self, path):
        raw = self._raw_acl(path)
        user = loom_windows_acl.current_user_sid_string()
        self.assertEqual(user, raw["owner"])
        self.assertTrue(raw["protected"])
        self.assertEqual({
            (0, 0x3, 0x001F01FF, user),
            (0, 0x3, 0x001F01FF, "S-1-5-18"),
        }, set(raw["entries"]))
        self.assertEqual(2, len(raw["entries"]))

    def test_protected_root_is_accepted_and_independently_exact(self):
        root = loom_windows_acl.create_private_directory(self.base / "private")

        self.assertTrue(loom_windows_acl.verify_private_directory(root))
        self.assertExactPrivateAcl(root)

    def test_created_child_has_exact_creation_time_dacl(self):
        root = loom_windows_acl.create_private_directory(self.base / "private")
        child = loom_windows_acl.create_private_directory(root / "child")

        self.assertTrue(loom_windows_acl.verify_private_directory(child))
        self.assertExactPrivateAcl(child)

    def test_permissive_root_is_rejected_before_use(self):
        root = loom_windows_acl.create_private_directory(self.base / "private")
        self._set_permissive_acl(root)
        sentinel = root / "owner.txt"
        sentinel.write_text("preserve", encoding="utf-8")

        with self.assertRaisesRegex(
                loom_windows_acl.WindowsAclError,
                "extra principals|unapproved principal"):
            loom_windows_acl.verify_private_directory(root)

        self.assertEqual("preserve", sentinel.read_text(encoding="utf-8"))

    def test_permissive_intermediate_is_rejected(self):
        root = loom_windows_acl.create_private_directory(self.base / "private")
        intermediate = loom_windows_acl.create_private_directory(root / "actions")
        self._set_permissive_acl(intermediate)

        with self.assertRaises(loom_windows_acl.WindowsAclError):
            loom_windows_acl.verify_private_directory(intermediate)
        self.assertTrue(loom_windows_acl.verify_private_directory(root))

    def test_handle_verifier_detects_acl_mutation(self):
        root = loom_windows_acl.create_private_directory(self.base / "private")
        handle = self._open_directory(root)
        try:
            self.assertTrue(
                loom_windows_acl.verify_private_directory_handle(handle))
            self._set_permissive_acl(root)
            with self.assertRaises(loom_windows_acl.WindowsAclError):
                loom_windows_acl.verify_private_directory_handle(handle)
        finally:
            self._close_handle(handle)

    def test_handle_verifier_rejects_a_regular_file(self):
        target = self.base / "not-a-directory.txt"
        target.write_text("fixture", encoding="utf-8")
        handle = self._open_directory(target)
        try:
            with self.assertRaisesRegex(
                    loom_windows_acl.WindowsAclError, "not a directory"):
                loom_windows_acl.verify_private_directory_handle(handle)
        finally:
            self._close_handle(handle)

    def test_volume_without_persistent_acls_fails_closed(self):
        with mock.patch.object(loom_windows_acl, "_volume_flags", return_value=0):
            with self.assertRaisesRegex(
                    loom_windows_acl.WindowsAclError, "persistent ACL"):
                loom_windows_acl.require_persistent_acls(self.base)
            with self.assertRaisesRegex(
                    loom_windows_acl.WindowsAclError, "persistent ACL"):
                with loom_windows_acl.private_directory_security_descriptor(
                        self.base):
                    self.fail("unsupported volume yielded a security descriptor")

    def test_reliability_creates_every_owner_private_component_with_exact_acl(self):
        owner_home = self.base / "owner-home"
        owner_home.mkdir()

        action_root = loom_reliability.ensure_private_directory(
            owner_home, ["recovery", "action-123"])

        self.assertExactPrivateAcl(owner_home / "recovery")
        self.assertExactPrivateAcl(action_root)

    def test_reliability_rejects_existing_permissive_private_component_unchanged(self):
        owner_home = self.base / "owner-home"
        owner_home.mkdir()
        recovery = owner_home / "recovery"
        recovery.mkdir()
        sentinel = recovery / "owner.txt"
        sentinel.write_text("preserve", encoding="utf-8")

        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError,
                "owner-private ACL cannot be proven"):
            loom_reliability.ensure_private_directory(
                owner_home, ["recovery", "action-123"])

        self.assertEqual("preserve", sentinel.read_text(encoding="utf-8"))
        self.assertFalse((recovery / "action-123").exists())

    def test_reliability_reserves_stage_leaf_with_exact_acl(self):
        private = loom_windows_acl.create_private_directory(
            self.base / "private")

        stage = loom_reliability.reserve_private_stage_leaf(
            private, ["actions", "action-123"])

        self.assertExactPrivateAcl(private / "actions")
        self.assertExactPrivateAcl(stage)

    def test_reliability_rejects_permissive_stage_root_without_mutation(self):
        private = self.base / "private"
        private.mkdir()

        with self.assertRaisesRegex(
                loom_reliability.ReliabilityError,
                "private stage root ACL cannot be proven"):
            loom_reliability.reserve_private_stage_leaf(
                private, ["actions", "action-123"])

        self.assertEqual([], list(private.iterdir()))

    def test_project_stage_reservation_inherits_project_policy_without_private_claim(self):
        project = self.base / "project"
        project.mkdir()

        with mock.patch.object(
                loom_windows_acl, "private_directory_security_descriptor",
                side_effect=AssertionError("private ACL applied to project stage")):
            stage = loom_reliability.reserve_directory_leaf(
                project, ".loom-plan-stage-action-123")

        self.assertTrue(stage.is_dir())
        with self.assertRaises(loom_windows_acl.WindowsAclError):
            loom_windows_acl.verify_private_directory(stage)

    def test_acl_descriptor_failure_precedes_private_component_creation(self):
        owner_home = self.base / "owner-home"
        owner_home.mkdir()

        with mock.patch.object(
                loom_windows_acl, "private_directory_security_descriptor",
                side_effect=loom_windows_acl.WindowsAclError("injected ACL failure")):
            with self.assertRaisesRegex(
                    loom_reliability.ReliabilityError,
                    "owner-private ACL cannot be applied"):
                loom_reliability.ensure_private_directory(
                    owner_home, ["recovery"])

        self.assertFalse((owner_home / "recovery").exists())


@unittest.skipIf(os.name == "nt", "non-Windows fail-closed contract")
class NonWindowsAclContractTests(unittest.TestCase):
    def test_import_is_safe_and_operations_report_unsupported(self):
        self.assertFalse(loom_windows_acl.supported())
        with self.assertRaisesRegex(
                loom_windows_acl.WindowsAclError, "unavailable"):
            loom_windows_acl.current_user_sid_string()
        with self.assertRaisesRegex(
                loom_windows_acl.WindowsAclError, "unavailable"):
            loom_windows_acl.verify_private_directory(Path("."))

    def test_posix_private_directory_path_does_not_depend_on_windows_acl(self):
        with tempfile.TemporaryDirectory(prefix="loom-posix-private-") as temporary:
            root = Path(temporary) / "owner-home"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            with mock.patch.object(
                    loom_windows_acl, "verify_private_directory",
                    side_effect=AssertionError("Windows ACL path was called")):
                result = loom_reliability.ensure_private_directory(
                    root, ["recovery", "action-123"])
            self.assertEqual(0, result.stat().st_mode & 0o077)

    def test_posix_project_stage_reservation_uses_requested_mode(self):
        with tempfile.TemporaryDirectory(prefix="loom-posix-project-") as temporary:
            project = Path(temporary) / "project"
            project.mkdir(mode=0o755)
            os.chmod(project, 0o755)

            stage = loom_reliability.reserve_directory_leaf(
                project, ".loom-plan-stage-action-123", mode=0o750)

            self.assertEqual(0o750, stage.stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
