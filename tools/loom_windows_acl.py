#!/usr/bin/env python3
"""Fail-closed Windows owner-private directory ACL primitives.

The accepted descriptor is intentionally narrow: a protected DACL with explicit,
inheritable full-control ACEs only for the current token user and LocalSystem.
Operating-system administrators remain outside Loom's enforceable threat boundary.
"""

import contextlib
import os
from pathlib import Path


FILE_PERSISTENT_ACLS = 0x00000008
FILE_ALL_ACCESS = 0x001F01FF
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
EXPECTED_ACE_FLAGS = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
SE_DACL_PROTECTED = 0x1000
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_FILE_OBJECT = 1
SYSTEM_SID = "S-1-5-18"


class WindowsAclError(RuntimeError):
    """Raised when an owner-private Windows ACL cannot be proven exactly."""


def supported():
    return os.name == "nt"


def _require_windows():
    if os.name != "nt":
        raise WindowsAclError("Windows private ACL enforcement is unavailable")


def _libraries():
    _require_windows()
    import ctypes

    return (
        ctypes,
        ctypes.WinDLL("kernel32", use_last_error=True),
        ctypes.WinDLL("advapi32", use_last_error=True),
    )


def _close_handle(handle):
    ctypes, kernel, _advapi = _libraries()
    from ctypes import wintypes

    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    if handle and not close(handle):
        error = ctypes.get_last_error()
        raise WindowsAclError(
            f"cannot close Windows security handle (error {error})")


def _local_free(pointer):
    if not pointer:
        return
    ctypes, kernel, _advapi = _libraries()
    from ctypes import wintypes

    free = kernel.LocalFree
    free.argtypes = [wintypes.HLOCAL]
    free.restype = wintypes.HLOCAL
    free(pointer)


def _sid_to_string(sid):
    ctypes, kernel, advapi = _libraries()
    from ctypes import wintypes

    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    convert.restype = wintypes.BOOL
    text = wintypes.LPWSTR()
    if not convert(sid, ctypes.byref(text)):
        error = ctypes.get_last_error()
        raise WindowsAclError(f"cannot encode Windows SID (error {error})")
    try:
        return text.value
    finally:
        _local_free(text)


def _sid_from_string(value):
    ctypes, kernel, advapi = _libraries()
    from ctypes import wintypes

    convert = advapi.ConvertStringSidToSidW
    convert.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    convert.restype = wintypes.BOOL
    sid = wintypes.LPVOID()
    if not convert(value, ctypes.byref(sid)):
        error = ctypes.get_last_error()
        raise WindowsAclError(f"cannot decode Windows SID (error {error})")
    return sid


def current_user_sid_string():
    """Return the SID of the effective process token user."""
    ctypes, kernel, advapi = _libraries()
    from ctypes import wintypes

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

    open_token = advapi.OpenProcessToken
    open_token.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    inspect = advapi.GetTokenInformation
    inspect.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    inspect.restype = wintypes.BOOL
    current_process = kernel.GetCurrentProcess
    current_process.argtypes = []
    current_process.restype = wintypes.HANDLE

    token = wintypes.HANDLE()
    if not open_token(current_process(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        error = ctypes.get_last_error()
        raise WindowsAclError(f"cannot open current Windows token (error {error})")
    try:
        required = wintypes.DWORD()
        inspect(token, 1, None, 0, ctypes.byref(required))  # TokenUser
        if required.value <= 0 or required.value > 65536:
            raise WindowsAclError("current Windows token user is unbounded")
        buffer = ctypes.create_string_buffer(required.value)
        if not inspect(
                token, 1, buffer, required.value, ctypes.byref(required)):
            error = ctypes.get_last_error()
            raise WindowsAclError(
                f"cannot inspect current Windows token (error {error})")
        token_user = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents
        return _sid_to_string(token_user.user.sid)
    finally:
        _close_handle(token)


def _existing_path(value):
    try:
        path = Path(os.path.abspath(os.fspath(value)))
    except (TypeError, ValueError, OSError) as exc:
        raise WindowsAclError(f"Windows ACL path is invalid: {exc}") from exc
    if not path.exists() or path.is_symlink():
        raise WindowsAclError("Windows ACL path is missing or redirected")
    return path


def _volume_flags(path):
    ctypes, kernel, _advapi = _libraries()
    from ctypes import wintypes

    path = _existing_path(path)
    get_volume_path = kernel.GetVolumePathNameW
    get_volume_path.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_path.restype = wintypes.BOOL
    volume_path = ctypes.create_unicode_buffer(32768)
    if not get_volume_path(str(path), volume_path, len(volume_path)):
        error = ctypes.get_last_error()
        raise WindowsAclError(
            f"cannot locate Windows ACL volume (error {error})")

    get_information = kernel.GetVolumeInformationW
    get_information.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    flags = wintypes.DWORD()
    if not get_information(
            volume_path.value, None, 0, None, None, ctypes.byref(flags), None, 0):
        error = ctypes.get_last_error()
        raise WindowsAclError(
            f"cannot inspect Windows ACL volume (error {error})")
    return int(flags.value)


def require_persistent_acls(path):
    """Fail closed unless the containing volume reports persistent ACL support."""
    if not _volume_flags(path) & FILE_PERSISTENT_ACLS:
        raise WindowsAclError("Windows volume does not provide persistent ACLs")
    return True


def _private_sddl(user_sid):
    if not isinstance(user_sid, str) or not user_sid.startswith("S-1-"):
        raise WindowsAclError("current Windows user SID is invalid")
    return (
        f"O:{user_sid}G:{user_sid}D:P"
        f"(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)"
    )


@contextlib.contextmanager
def private_directory_security_descriptor(volume_path):
    """Yield a creation-time protected owner-private security descriptor pointer."""
    ctypes, kernel, advapi = _libraries()
    from ctypes import wintypes

    require_persistent_acls(volume_path)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    descriptor = wintypes.LPVOID()
    size = wintypes.DWORD()
    sddl = _private_sddl(current_user_sid_string())
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)):
        error = ctypes.get_last_error()
        raise WindowsAclError(
            f"cannot create owner-private security descriptor (error {error})")
    if not descriptor or size.value <= 0 or size.value > 65536:
        _local_free(descriptor)
        raise WindowsAclError("owner-private security descriptor is invalid")
    try:
        yield descriptor
    finally:
        _local_free(descriptor)


def _equal_sid(left, right):
    ctypes, _kernel, advapi = _libraries()
    from ctypes import wintypes

    equal = advapi.EqualSid
    equal.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    equal.restype = wintypes.BOOL
    return bool(equal(left, right))


def _verify_directory_handle_kind(handle):
    ctypes, kernel, _advapi = _libraries()
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    inspect = kernel.GetFileInformationByHandle
    inspect.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    inspect.restype = wintypes.BOOL
    information = ByHandleFileInformation()
    if not inspect(handle, ctypes.byref(information)):
        error = ctypes.get_last_error()
        raise WindowsAclError(
            f"cannot inspect owner-private directory handle (error {error})")
    if not information.attributes & 0x10 or information.attributes & 0x400:
        raise WindowsAclError(
            "owner-private handle is redirected or is not a directory")


def verify_private_directory_handle(handle):
    """Prove one open directory handle has exactly Loom's private DACL contract."""
    ctypes, _kernel, advapi = _libraries()
    from ctypes import wintypes

    _verify_directory_handle_kind(handle)

    get_security = advapi.GetSecurityInfo
    get_security.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_security.restype = wintypes.DWORD
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    status = get_security(
        handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner), None, ctypes.byref(dacl), None,
        ctypes.byref(descriptor))
    if status != 0:
        raise WindowsAclError(
            f"cannot inspect owner-private directory ACL (error {status})")
    user_sid = None
    system_sid = None
    try:
        if not owner or not dacl or not descriptor:
            raise WindowsAclError("owner-private directory has a missing or null DACL")
        user_sid = _sid_from_string(current_user_sid_string())
        system_sid = _sid_from_string(SYSTEM_SID)
        if not _equal_sid(owner, user_sid):
            raise WindowsAclError("owner-private directory owner SID is not current user")

        get_control = advapi.GetSecurityDescriptorControl
        get_control.argtypes = [
            wintypes.LPVOID, ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD)]
        get_control.restype = wintypes.BOOL
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            error = ctypes.get_last_error()
            raise WindowsAclError(
                f"cannot inspect owner-private DACL control (error {error})")
        if not control.value & SE_DACL_PROTECTED:
            raise WindowsAclError("owner-private directory DACL is not protected")

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

        acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
        if acl.ace_count != 2 or acl.size < ctypes.sizeof(Acl):
            raise WindowsAclError("owner-private directory DACL has extra principals")
        get_ace = advapi.GetAce
        get_ace.argtypes = [
            wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID)]
        get_ace.restype = wintypes.BOOL
        seen = set()
        for index in range(acl.ace_count):
            ace_pointer = wintypes.LPVOID()
            if not get_ace(dacl, index, ctypes.byref(ace_pointer)):
                error = ctypes.get_last_error()
                raise WindowsAclError(
                    f"cannot inspect owner-private DACL ACE (error {error})")
            ace = ctypes.cast(
                ace_pointer, ctypes.POINTER(AllowedAce)).contents
            if ace.header.type != 0 or ace.header.flags != EXPECTED_ACE_FLAGS \
                    or ace.mask != FILE_ALL_ACCESS:
                raise WindowsAclError("owner-private directory DACL ACE is not exact")
            sid = wintypes.LPVOID(
                ace_pointer.value + AllowedAce.sid_start.offset)
            if _equal_sid(sid, user_sid):
                principal = "user"
            elif _equal_sid(sid, system_sid):
                principal = "system"
            else:
                raise WindowsAclError(
                    "owner-private directory DACL grants an unapproved principal")
            if principal in seen:
                raise WindowsAclError("owner-private directory DACL duplicates a principal")
            seen.add(principal)
        if seen != {"user", "system"}:
            raise WindowsAclError("owner-private directory DACL is incomplete")
        return True
    finally:
        if user_sid:
            _local_free(user_sid)
        if system_sid:
            _local_free(system_sid)
        _local_free(descriptor)


def _open_directory(path):
    ctypes, kernel, _advapi = _libraries()
    from ctypes import wintypes

    path = _existing_path(path)
    open_file = kernel.CreateFileW
    open_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    open_file.restype = wintypes.HANDLE
    handle = open_file(
        str(path), 0x00020000 | 0x00000080, 0x1 | 0x2 | 0x4,
        None, 3, 0x02000000 | 0x00200000, None)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = ctypes.get_last_error()
        raise WindowsAclError(
            f"cannot open owner-private directory (error {error})")
    return handle


def verify_private_directory(path):
    """Verify persistent ACL support and the exact protected DACL on one path."""
    path = _existing_path(path)
    require_persistent_acls(path)
    if not path.is_dir():
        raise WindowsAclError("owner-private path is not a directory")
    handle = _open_directory(path)
    try:
        return verify_private_directory_handle(handle)
    finally:
        _close_handle(handle)


def create_private_directory(path):
    """Create one directory with the private descriptor applied at creation time."""
    ctypes, kernel, _advapi = _libraries()
    from ctypes import wintypes

    try:
        path = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as exc:
        raise WindowsAclError(f"owner-private creation path is invalid: {exc}") from exc
    if path.exists() or path.is_symlink():
        raise WindowsAclError("owner-private creation path already exists")
    parent = _existing_path(path.parent)
    if not parent.is_dir():
        raise WindowsAclError("owner-private creation parent is not a directory")

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("security_descriptor", wintypes.LPVOID),
            ("inherit_handle", wintypes.BOOL),
        ]

    create = kernel.CreateDirectoryW
    create.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    create.restype = wintypes.BOOL
    with private_directory_security_descriptor(parent) as descriptor:
        attributes = SecurityAttributes(
            ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not create(str(path), ctypes.byref(attributes)):
            error = ctypes.get_last_error()
            raise WindowsAclError(
                f"cannot create owner-private directory (error {error})")
    verify_private_directory(path)
    return path
