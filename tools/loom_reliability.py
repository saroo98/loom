#!/usr/bin/env python3
"""Crash-safe local writes, reversible migrations, and proven-ownership removal."""

import base64
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_MIGRATION_FILES = 256
MAX_EXACT_TREE_ENTRIES = 256
MAX_EXACT_TREE_FILE_BYTES = 256 * 1024
MAX_EXACT_TREE_TOTAL_BYTES = 2 * 1024 * 1024
MAX_EXACT_TREE_PATH_BYTES = 512
EXACT_TREE_POLICY = "exact-tree-no-extended-data-v1"
ROOT_IDENTITY_SCHEMA_VERSION = 1
MAX_PRIVATE_DIRECTORY_COMPONENTS = 16
PRIVATE_DIRECTORY_COMPONENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
ATOMIC_RENAME_STATE_SCHEMA_VERSION = 1
ATOMIC_RENAME_ROLE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
ATOMIC_RENAME_ERROR_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_ATOMIC_RENAME_STATE_BYTES = 4096


class ReliabilityError(RuntimeError):
    pass


class AtomicRenameOutcome:
    """Typed bounded result for an atomically committed namespace move.

    ``durability_confirmed`` is false on Windows until Loom implements and
    proves a directory-flush primitive.  That is an honest capability result,
    not an execution failure: the caller's action journal is responsible for
    next-invocation namespace reconciliation.
    """

    def __init__(self, state):
        _validate_atomic_rename_reconciliation_state(state)
        if state["namespace_state"] != "committed":
            raise ReliabilityError("atomic rename outcome is not committed")
        self._state = json.loads(json.dumps(state, sort_keys=True))

    @property
    def state(self):
        return json.loads(json.dumps(self._state, sort_keys=True))

    @property
    def durability_confirmed(self):
        return self._state["durability"] == "confirmed"


class AtomicRenameReconciliationRequired(ReliabilityError):
    """Base for post-rename states that require action-led reconciliation."""

    def __init__(self, state, reason):
        _validate_atomic_rename_reconciliation_state(state)
        self._state = json.loads(json.dumps(state, sort_keys=True))
        namespace = state["namespace_state"]
        super().__init__(
            f"atomic no-replace {reason} after namespace state {namespace}; "
            "reconciliation is required")

    @property
    def state(self):
        """Return an isolated JSON-safe copy suitable for a recovery receipt."""
        return json.loads(json.dumps(self._state, sort_keys=True))


class AtomicRenameDurabilityUnconfirmed(AtomicRenameReconciliationRequired):
    """A no-replace rename changed the namespace then a sync attempt failed.

    This exception is intentionally distinct from an ordinary reliability
    failure: callers must reconcile the already-attempted namespace change
    before retrying or reporting that no change occurred. ``state`` contains
    only bounded enums, roles, digests, and numeric OS error evidence. It never
    contains owner paths or unbounded exception text.
    """

    def __init__(self, state):
        _validate_atomic_rename_reconciliation_state(state)
        if state["durability"] != "unconfirmed":
            raise ReliabilityError(
                "atomic rename indeterminate state has confirmed durability")
        super().__init__(state, "durability is unconfirmed")


class AtomicRenameNamespaceIndeterminate(AtomicRenameReconciliationRequired):
    """The post-rename namespace cannot be proven to contain the source object."""

    def __init__(self, state):
        _validate_atomic_rename_reconciliation_state(state)
        if state["namespace_state"] != "ambiguous":
            raise ReliabilityError("atomic rename namespace state is not ambiguous")
        super().__init__(state, "namespace observation is ambiguous")


@contextmanager
def exclusive_file_lock(path, *, timeout=10.0):
    """Acquire one user-scoped interprocess lock or fail within a bounded timeout.

    The operating system owns stale-lock recovery: process termination releases the
    descriptor lock. The lock file itself is only a stable inode and carries no
    authority or owner state.
    """
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        raise ReliabilityError("lock timeout is invalid")
    path = _absolute(path, "interprocess lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    _absolute(path.parent, "interprocess lock parent", must_exist=True)
    handle = open(path, "a+b")
    if handle.seek(0, os.SEEK_END) == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    deadline = time.monotonic() + float(timeout)
    acquired = False
    try:
        while not acquired:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise ReliabilityError("interprocess lock acquisition timed out")
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


def _is_redirect(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ReliabilityError(f"cannot inspect path: {path}: {exc}") from exc


def _is_trusted_os_alias(path):
    """Allow only Apple's documented root aliases while retaining redirect checks.

    macOS exposes ``/var`` and ``/tmp`` as symlinks into ``/private``.  They are
    OS-owned aliases, not user-controlled project redirects, and hosted runners
    routinely place temporary directories beneath them.  We still verify the
    exact target so a modified alias fails closed.
    """
    if sys.platform != "darwin":
        return False
    expected = {
        Path("/var"): Path("/private/var"),
        Path("/tmp"): Path("/private/tmp"),
    }.get(Path(path))
    if expected is None:
        return False
    try:
        return Path(path).resolve(strict=False) == expected
    except OSError as exc:
        raise ReliabilityError(f"cannot resolve operating-system alias: {path}: {exc}") from exc


def _absolute(path, label, *, must_exist=False):
    try:
        value = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise ReliabilityError(f"{label} is invalid: {exc}") from exc
    if must_exist and not value.exists():
        raise ReliabilityError(f"{label} does not exist: {value}")
    for component in [*reversed(value.parents), value]:
        if _is_redirect(component) and not _is_trusted_os_alias(component):
            raise ReliabilityError(f"{label} traverses a symlink or reparse point: {component}")
    return value


def _safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReliabilityError("owned/migration paths must be non-empty POSIX-relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReliabilityError("owned/migration path escapes its root")
    return path.as_posix()


def _target(root, relative):
    root = _absolute(root, "state root", must_exist=True)
    relative = _safe_relative(relative)
    target = _absolute(root.joinpath(*PurePosixPath(relative).parts), "state target")
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ReliabilityError("state target escapes its root") from exc
    return target


def _sync_parent(path):
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _identity_path_sha256(path):
    canonical = os.path.normcase(os.path.normpath(os.fspath(path)))
    return hashlib.sha256(os.fsencode(canonical)).hexdigest()


def _root_identity_from_stat(path, info):
    if stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
    else:
        raise ReliabilityError("root identity requires a regular file or directory")
    return {
        "schema_version": ROOT_IDENTITY_SCHEMA_VERSION,
        "platform": "windows" if os.name == "nt" else "posix",
        # Retain the legacy field name for receipt compatibility, but bind it to
        # the filesystem object rather than its mutable pathname. Callers still
        # supply the path to validation, which must resolve to this same object.
        "path_sha256": hashlib.sha256(
            f"{int(info.st_dev)}:{int(info.st_ino)}:{kind}".encode("ascii")
        ).hexdigest(),
        "kind": kind,
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(info.st_mode),
        # Identity tokens deliberately exclude mutable metadata. Exact-tree
        # manifests bind content, link counts, modes, and timestamps where
        # relevant; this token only proves object continuity across renames and
        # child creation.
        "links": 1,
        "size": 0,
        "mtime_ns": 0,
        "ctime_ns": 0,
        "file_attributes": int(getattr(info, "st_file_attributes", 0)),
    }


def _validate_root_identity_token(value):
    fields = {
        "schema_version", "platform", "path_sha256", "kind", "device",
        "inode", "mode", "links", "size", "mtime_ns", "ctime_ns",
        "file_attributes",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != ROOT_IDENTITY_SCHEMA_VERSION \
            or value.get("platform") not in {"windows", "posix"} \
            or value.get("kind") not in {"file", "directory"} \
            or not DIGEST.fullmatch(str(value.get("path_sha256", ""))):
        raise ReliabilityError("root identity token is invalid")
    for field in {
            "device", "inode", "mode", "links", "size", "mtime_ns",
            "ctime_ns", "file_attributes"}:
        if type(value.get(field)) is not int:
            raise ReliabilityError("root identity token is invalid")
    if value["device"] < 0 or value["inode"] < 0 or value["mode"] < 0 \
            or value["links"] < 1 or value["size"] < 0 \
            or value["file_attributes"] < 0:
        raise ReliabilityError("root identity token is invalid")
    return value


def observe_root_identity(path):
    """Return an opaque object token for one non-redirected filesystem root."""
    path = _absolute(path, "root identity path", must_exist=True)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReliabilityError(f"cannot inspect root identity: {exc}") from exc
    if _is_redirect(path):
        raise ReliabilityError("root identity path is redirected")
    return _root_identity_from_stat(path, info)


def validate_root_identity(path, expected):
    """Fail closed unless a root still has exactly the observed path identity."""
    _validate_root_identity_token(expected)
    observed = observe_root_identity(path)
    if observed != expected:
        raise ReliabilityError("root identity changed before atomic move")
    return observed


def _validate_directory_object_continuity(path, expected):
    """Verify directory object continuity while allowing child-list metadata changes."""
    _validate_root_identity_token(expected)
    observed = observe_root_identity(path)
    stable_fields = {
        "schema_version", "platform", "path_sha256", "kind", "device",
        "inode",
    }
    if expected.get("kind") != "directory" \
            or any(observed[field] != expected[field] for field in stable_fields):
        raise ReliabilityError("directory identity changed during child creation")
    return observed


def _sync_rename_parents(source, destination):
    """Attempt every distinct parent sync and return bounded status evidence.

    Windows currently has no implemented, proven directory-flush primitive in
    Loom.  Treating its historical no-op as success would overstate power-loss
    durability, so it is reported as ``unconfirmed``.  On POSIX, one failed
    parent sync does not prevent attempting the other parent.
    """
    statuses = []
    seen = {}
    for role, path in (("source_parent", source),
                       ("destination_parent", destination)):
        key = os.path.normcase(os.path.normpath(os.fspath(path.parent)))
        if key in seen:
            statuses.append({
                "role": role,
                "status": "same_parent",
                "same_as": seen[key],
            })
            continue
        seen[key] = role
        if os.name == "nt":
            statuses.append({
                "role": role,
                "status": "unconfirmed",
                "reason": "windows_directory_flush_unimplemented",
            })
            continue
        try:
            _sync_parent(path)
        except OSError as exc:
            status = {
                "role": role,
                "status": "failed",
                "error_type": type(exc).__name__[:64],
            }
            error_number = getattr(exc, "errno", None)
            if isinstance(error_number, int):
                status["errno"] = error_number
            statuses.append(status)
        else:
            statuses.append({"role": role, "status": "confirmed"})
    return statuses


def _atomic_rename_observation(path, expected_identity):
    """Return a bounded observation without treating absence as an error."""
    try:
        if not os.path.lexists(path):
            return "absent"
        if _is_redirect(path):
            return "redirected"
        observed = observe_root_identity(path)
    except (OSError, ReliabilityError):
        return "unknown"
    if observed == expected_identity:
        return "expected_object"
    return "other_object"


def _validate_atomic_rename_role(value, label):
    if not isinstance(value, str) or not ATOMIC_RENAME_ROLE.fullmatch(value):
        raise ReliabilityError(f"atomic no-replace {label} role is invalid")
    return value


def _validate_atomic_rename_reconciliation_state(state):
    required = {
        "schema_version", "operation_id", "source_role", "destination_role",
        "namespace_state", "durability", "changes_made", "source_observed",
        "destination_observed", "parent_sync",
    }
    if not isinstance(state, dict) or set(state) != required \
            or state.get("schema_version") != ATOMIC_RENAME_STATE_SCHEMA_VERSION \
            or not DIGEST.fullmatch(str(state.get("operation_id", ""))) \
            or state.get("namespace_state") not in {"committed", "ambiguous"} \
            or state.get("durability") not in {"confirmed", "unconfirmed"} \
            or state.get("changes_made") is not True \
            or state.get("source_observed") not in {
                "absent", "expected_object", "other_object", "redirected", "unknown",
            } \
            or state.get("destination_observed") not in {
                "absent", "expected_object", "other_object", "redirected", "unknown",
            }:
        raise ReliabilityError("atomic rename reconciliation state is invalid")
    _validate_atomic_rename_role(state.get("source_role"), "source")
    _validate_atomic_rename_role(state.get("destination_role"), "destination")
    statuses = state.get("parent_sync")
    if not isinstance(statuses, list) or len(statuses) != 2:
        raise ReliabilityError("atomic rename parent-sync state is invalid")
    seen = set()
    for status in statuses:
        if not isinstance(status, dict):
            raise ReliabilityError("atomic rename parent-sync state is invalid")
        role = status.get("role")
        if role not in {"source_parent", "destination_parent"} or role in seen:
            raise ReliabilityError("atomic rename parent-sync role is invalid")
        seen.add(role)
        value = status.get("status")
        allowed_fields = {"role", "status"}
        if value == "same_parent":
            allowed_fields.add("same_as")
            if status.get("same_as") not in {"source_parent", "destination_parent"}:
                raise ReliabilityError("atomic rename parent-sync alias is invalid")
        elif value == "unconfirmed":
            allowed_fields.add("reason")
            if status.get("reason") != "windows_directory_flush_unimplemented":
                raise ReliabilityError("atomic rename parent-sync reason is invalid")
        elif value == "failed":
            allowed_fields.add("error_type")
            if not isinstance(status.get("error_type"), str) \
                    or not ATOMIC_RENAME_ERROR_TYPE.fullmatch(status["error_type"]):
                raise ReliabilityError("atomic rename parent-sync error is invalid")
            if "errno" in status:
                allowed_fields.add("errno")
                if type(status["errno"]) is not int \
                        or not -(2 ** 31) <= status["errno"] < 2 ** 31:
                    raise ReliabilityError("atomic rename parent-sync errno is invalid")
        elif value != "confirmed":
            raise ReliabilityError("atomic rename parent-sync status is invalid")
        if set(status) != allowed_fields:
            raise ReliabilityError("atomic rename parent-sync fields are invalid")
    if seen != {"source_parent", "destination_parent"}:
        raise ReliabilityError("atomic rename parent-sync roles are incomplete")
    derived_durability = (
        "confirmed" if all(
            item["status"] in {"confirmed", "same_parent"}
            for item in statuses)
        else "unconfirmed")
    if state["durability"] != derived_durability:
        raise ReliabilityError("atomic rename durability state is inconsistent")
    encoded = json.dumps(
        state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_ATOMIC_RENAME_STATE_BYTES:
        raise ReliabilityError("atomic rename reconciliation state is oversized")
    return state


def validate_atomic_rename_state(state):
    """Return an isolated validated copy of a bounded rename reconciliation state."""
    _validate_atomic_rename_reconciliation_state(state)
    return json.loads(json.dumps(state, sort_keys=True))


def _atomic_rename_reconciliation_state(source, destination, expected_identity,
                                        source_role, destination_role,
                                        parent_sync):
    source_observed = _atomic_rename_observation(source, expected_identity)
    destination_observed = _atomic_rename_observation(
        destination, expected_identity)
    namespace_state = (
        "committed" if destination_observed == "expected_object"
        else "ambiguous")
    operation_material = json.dumps({
        "destination_path_sha256": _identity_path_sha256(destination),
        "destination_role": destination_role,
        "expected_identity": expected_identity,
        "source_path_sha256": _identity_path_sha256(source),
        "source_role": source_role,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    state = {
        "schema_version": ATOMIC_RENAME_STATE_SCHEMA_VERSION,
        "operation_id": hashlib.sha256(operation_material).hexdigest(),
        "source_role": source_role,
        "destination_role": destination_role,
        "namespace_state": namespace_state,
        "durability": (
            "confirmed" if all(
                item["status"] in {"confirmed", "same_parent"}
                for item in parent_sync)
            else "unconfirmed"),
        "changes_made": True,
        "source_observed": source_observed,
        "destination_observed": destination_observed,
        "parent_sync": parent_sync,
    }
    return _validate_atomic_rename_reconciliation_state(state)


def _windows_extended_path(path):
    value = os.fspath(path)
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_set_file_rename_noreplace(source_handle, destination_parent_handle,
                                       destination_name):
    """Rename an already-open object relative to an already-open directory.

    Both handles are retained by the caller from identity verification through
    this syscall. FileRenameInfo with ReplaceIfExists=false is the only Windows
    activation primitive used here. Unsupported hosts fail closed.
    """
    import ctypes
    from ctypes import wintypes

    encoded = destination_name.encode("utf-16-le")
    if not encoded or len(encoded) > 255 * 2 or any(
            character in destination_name for character in "\\/\0"):
        raise ReliabilityError("atomic no-replace destination leaf is invalid")

    class IoStatusValue(ctypes.Union):
        _fields_ = [("status", wintypes.LONG), ("pointer", wintypes.LPVOID)]

    class IoStatusBlock(ctypes.Structure):
        _anonymous_ = ("value",)
        _fields_ = [("value", IoStatusValue), ("information", ctypes.c_size_t)]

    class FileRenameInformation(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", ctypes.c_ubyte),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * (len(destination_name) + 1)),
        ]

    information = FileRenameInformation()
    information.replace_if_exists = False
    information.root_directory = destination_parent_handle
    information.file_name_length = len(encoded)
    information.file_name = destination_name
    status_block = IoStatusBlock()
    try:
        rename = ctypes.WinDLL("ntdll").NtSetInformationFile
    except (OSError, AttributeError) as exc:
        raise ReliabilityError(
            "atomic handle-relative no-replace rename is unavailable") from exc
    rename.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(IoStatusBlock), wintypes.LPVOID,
        wintypes.ULONG, ctypes.c_int,
    ]
    rename.restype = wintypes.LONG
    information_size = ctypes.sizeof(information)
    status_code = rename(
        source_handle, ctypes.byref(status_block), ctypes.byref(information),
        information_size, 10)  # FileRenameInformation
    if status_code >= 0:
        return
    status = status_code & 0xffffffff
    if status in {0xC0000035, 0xC0000056}:  # NAME_COLLISION / DELETE_PENDING
        raise ReliabilityError("atomic no-replace destination already exists")
    if status == 0xC00000D4:  # STATUS_NOT_SAME_DEVICE
        raise ReliabilityError("atomic no-replace paths are on different filesystems")
    if status in {0xC0000002, 0xC00000BB, 0xC000000D}:
        raise ReliabilityError("atomic no-replace move is unavailable on this filesystem")
    raise ReliabilityError(
        f"atomic no-replace move failed (NTSTATUS 0x{status:08x})")


def _windows_atomic_rename_noreplace(source, destination,
                                     expected_source_identity,
                                     source_parent_identity,
                                     destination_parent_identity):
    """Perform a verified handle-relative Windows rename without replacement."""
    source_parent_handle = None
    destination_parent_handle = None
    source_handle = None
    try:
        source_parent_handle, source_parent_handle_identity = \
            _windows_open_path_handle(
                source.parent, require_directory=True)
        destination_parent_handle, destination_parent_handle_identity = \
            _windows_open_path_handle(
                destination.parent, require_directory=True)
        source_handle, source_handle_identity = _windows_open_path_handle(
            source, require_directory=expected_source_identity["kind"] == "directory",
            delete_access=True)

        # The retained handles anchor all three objects. Revalidating the paths
        # after opening them closes the path-to-handle substitution window; a
        # later parent rename cannot redirect the handle-relative destination.
        _validate_directory_object_continuity(
            source.parent, source_parent_identity)
        _validate_directory_object_continuity(
            destination.parent, destination_parent_identity)
        if expected_source_identity["kind"] == "directory":
            _validate_directory_object_continuity(source, expected_source_identity)
        else:
            validate_root_identity(source, expected_source_identity)

        current_source_handle, current_source_identity = _windows_open_path_handle(
            source, require_directory=expected_source_identity["kind"] == "directory")
        try:
            if current_source_identity != source_handle_identity:
                raise ReliabilityError("atomic no-replace source handle identity changed")
        finally:
            _windows_close_handle(current_source_handle)
        if source_parent_handle_identity != _windows_directory_handle_identity(
                source_parent_handle):
            raise ReliabilityError("atomic no-replace source parent handle changed")
        if destination_parent_handle_identity != _windows_directory_handle_identity(
                destination_parent_handle):
            raise ReliabilityError("atomic no-replace destination parent handle changed")

        _windows_set_file_rename_noreplace(
            source_handle, destination_parent_handle, destination.name)
    finally:
        if source_handle is not None:
            _windows_close_handle(source_handle)
        if destination_parent_handle is not None:
            _windows_close_handle(destination_parent_handle)
        if source_parent_handle is not None:
            _windows_close_handle(source_parent_handle)


def _open_verified_directory(path, expected):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        observed = _root_identity_from_stat(path, os.fstat(descriptor))
        if observed != expected:
            raise ReliabilityError("atomic no-replace parent identity changed")
        return descriptor
    except ReliabilityError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        raise ReliabilityError(f"cannot open atomic no-replace parent: {exc}") from exc


def _linux_renameat2_noreplace(source_parent, source_name,
                               destination_parent, destination_name):
    import ctypes

    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        raise ReliabilityError("atomic no-replace renameat2 is unavailable") from exc
    rename = getattr(library, "renameat2", None)
    if rename is None:
        raise ReliabilityError("atomic no-replace renameat2 is unavailable")
    rename.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(source_parent, source_name,
              destination_parent, destination_name, 1) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise ReliabilityError("atomic no-replace destination already exists")
    if error == errno.EXDEV:
        raise ReliabilityError("atomic no-replace paths are on different filesystems")
    if error in {errno.ENOSYS, errno.EINVAL,
                 errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
        raise ReliabilityError("atomic no-replace move is unavailable on this filesystem")
    raise ReliabilityError(
        f"atomic no-replace move failed (errno {error}: {os.strerror(error)})")


def _linux_atomic_rename_noreplace(source, destination, expected_source_identity,
                                   source_parent_identity,
                                   destination_parent_identity):
    source_parent = _open_verified_directory(source.parent, source_parent_identity)
    destination_parent = None
    try:
        destination_parent = _open_verified_directory(
            destination.parent, destination_parent_identity)
        if expected_source_identity["kind"] == "directory":
            _validate_directory_object_continuity(source, expected_source_identity)
        else:
            validate_root_identity(source, expected_source_identity)
        _linux_renameat2_noreplace(
            source_parent, os.fsencode(source.name),
            destination_parent, os.fsencode(destination.name))
    finally:
        os.close(source_parent)
        if destination_parent is not None:
            os.close(destination_parent)


def _macos_renameatx_noreplace(source_parent, source_name,
                               destination_parent, destination_name):
    import ctypes

    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        raise ReliabilityError("atomic no-replace renameatx_np is unavailable") from exc
    rename = getattr(library, "renameatx_np", None)
    if rename is None:
        raise ReliabilityError("atomic no-replace renameatx_np is unavailable")
    rename.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(source_parent, source_name,
              destination_parent, destination_name, 0x4) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise ReliabilityError("atomic no-replace destination already exists")
    if error == errno.EXDEV:
        raise ReliabilityError("atomic no-replace paths are on different filesystems")
    if error in {errno.ENOSYS, errno.EINVAL,
                 errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
        raise ReliabilityError("atomic no-replace move is unavailable on this filesystem")
    raise ReliabilityError(
        f"atomic no-replace move failed (errno {error}: {os.strerror(error)})")


def _macos_atomic_rename_noreplace(source, destination, expected_source_identity,
                                   source_parent_identity,
                                   destination_parent_identity):
    source_parent = _open_verified_directory(source.parent, source_parent_identity)
    destination_parent = None
    try:
        destination_parent = _open_verified_directory(
            destination.parent, destination_parent_identity)
        if expected_source_identity["kind"] == "directory":
            _validate_directory_object_continuity(source, expected_source_identity)
        else:
            validate_root_identity(source, expected_source_identity)
        _macos_renameatx_noreplace(
            source_parent, os.fsencode(source.name),
            destination_parent, os.fsencode(destination.name))
    finally:
        os.close(source_parent)
        if destination_parent is not None:
            os.close(destination_parent)


def _native_atomic_rename_noreplace(source, destination, expected_source_identity,
                                    source_parent_identity,
                                    destination_parent_identity):
    if os.name == "nt":
        _windows_atomic_rename_noreplace(
            source, destination, expected_source_identity,
            source_parent_identity, destination_parent_identity)
        return
    if sys.platform.startswith("linux"):
        _linux_atomic_rename_noreplace(
            source, destination, expected_source_identity, source_parent_identity,
            destination_parent_identity)
        return
    if sys.platform == "darwin":
        _macos_atomic_rename_noreplace(
            source, destination, expected_source_identity,
            source_parent_identity, destination_parent_identity)
        return
    raise ReliabilityError("atomic no-replace move is unavailable on this platform")


def atomic_rename_noreplace(source, destination, *, expected_source_identity,
                            source_role="source",
                            destination_role="destination"):
    """Atomically move one regular file/directory without replacing any target.

    ``expected_source_identity`` must have been observed before any potentially
    expensive scan. It is revalidated inside the platform backend immediately
    before the exclusive native rename. No check-then-replace fallback exists.
    A successful native move returns :class:`AtomicRenameOutcome`. A failed
    post-move sync raises :class:`AtomicRenameDurabilityUnconfirmed`, which must
    never be reported as a no-change failure.
    """
    _validate_root_identity_token(expected_source_identity)
    source_role = _validate_atomic_rename_role(source_role, "source")
    destination_role = _validate_atomic_rename_role(
        destination_role, "destination")
    source = _absolute(source, "atomic no-replace source", must_exist=True)
    destination = _absolute(destination, "atomic no-replace destination")
    if source == destination or source.parent == source:
        raise ReliabilityError("atomic no-replace paths are invalid")
    if expected_source_identity["kind"] == "directory":
        source_identity = _validate_directory_object_continuity(
            source, expected_source_identity)
    else:
        source_identity = validate_root_identity(source, expected_source_identity)
    if source_identity["kind"] == "directory":
        try:
            destination.relative_to(source)
        except ValueError:
            pass
        else:
            raise ReliabilityError("atomic no-replace destination is inside its source")
        if os.path.ismount(source):
            raise ReliabilityError("atomic no-replace source is a mount point")
    source_parent_identity = observe_root_identity(source.parent)
    destination_parent_identity = observe_root_identity(destination.parent)
    if source_parent_identity["kind"] != "directory" \
            or destination_parent_identity["kind"] != "directory":
        raise ReliabilityError("atomic no-replace parent is not a directory")
    if source_identity["device"] != source_parent_identity["device"] \
            or source_identity["device"] != destination_parent_identity["device"]:
        raise ReliabilityError("atomic no-replace paths are on different filesystems")
    _native_atomic_rename_noreplace(
        source, destination, expected_source_identity,
        source_parent_identity, destination_parent_identity)
    parent_sync = _sync_rename_parents(source, destination)
    state = _atomic_rename_reconciliation_state(
        source, destination, expected_source_identity,
        source_role, destination_role, parent_sync)
    if state["namespace_state"] != "committed":
        raise AtomicRenameNamespaceIndeterminate(state)
    if any(status["status"] == "failed" for status in parent_sync):
        raise AtomicRenameDurabilityUnconfirmed(state)
    return AtomicRenameOutcome(state)


def _private_directory_components(values):
    if not isinstance(values, (list, tuple)) \
            or not 1 <= len(values) <= MAX_PRIVATE_DIRECTORY_COMPONENTS:
        raise ReliabilityError("private directory components are invalid or unbounded")
    components = []
    for value in values:
        if not isinstance(value, str) or value in {".", ".."} \
                or not PRIVATE_DIRECTORY_COMPONENT.fullmatch(value):
            raise ReliabilityError("private directory component is unsafe")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise ReliabilityError("private directory component is not UTF-8") from exc
        if len(encoded) > 128:
            raise ReliabilityError("private directory component exceeds its byte bound")
        components.append(value)
    return tuple(components)


def _posix_ensure_private_directory(root, components, root_identity):
    current_path = root
    current_handle = _open_verified_directory(root, root_identity)
    root_device = root_identity["device"]
    try:
        for component in components:
            created = False
            try:
                os.mkdir(component, 0o700, dir_fd=current_handle)
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise ReliabilityError(
                    f"cannot create private directory component: {exc}") from exc
            if created:
                try:
                    os.fsync(current_handle)
                except OSError as exc:
                    raise ReliabilityError(
                        f"cannot sync private directory parent: {exc}") from exc
            current_path = current_path / component
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            child_handle = None
            try:
                child_handle = os.open(component, flags, dir_fd=current_handle)
                child_info = os.fstat(child_handle)
                child_identity = _root_identity_from_stat(current_path, child_info)
                if child_identity["kind"] != "directory" \
                        or child_identity["device"] != root_device:
                    raise ReliabilityError(
                        "private directory component crosses a filesystem boundary")
                if stat.S_IMODE(child_info.st_mode) & 0o077:
                    raise ReliabilityError(
                        "private directory component has non-private permissions")
                if observe_root_identity(current_path) != child_identity:
                    raise ReliabilityError(
                        "private directory component identity changed after creation")
            except ReliabilityError:
                if child_handle is not None:
                    os.close(child_handle)
                raise
            except OSError as exc:
                if child_handle is not None:
                    os.close(child_handle)
                raise ReliabilityError(
                    f"cannot verify private directory component: {exc}") from exc
            os.close(current_handle)
            current_handle = child_handle
        return current_path
    finally:
        os.close(current_handle)


def _windows_close_handle(handle):
    import ctypes
    from ctypes import wintypes

    close = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    close(handle)


def _windows_handle_identity(handle, *, require_directory=None):
    import ctypes
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

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    inspect = kernel.GetFileInformationByHandle
    inspect.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    inspect.restype = wintypes.BOOL
    information = ByHandleFileInformation()
    if not inspect(handle, ctypes.byref(information)):
        error = ctypes.get_last_error()
        raise ReliabilityError(
            f"cannot inspect private directory handle (Windows error {error})")
    is_directory = bool(information.attributes & 0x10)
    if information.attributes & 0x400:
        raise ReliabilityError("Windows handle refers to a reparse point")
    if require_directory is True and not is_directory:
        raise ReliabilityError("Windows handle does not refer to a directory")
    if require_directory is False and is_directory:
        raise ReliabilityError("Windows handle unexpectedly refers to a directory")
    return (
        int(information.volume_serial),
        (int(information.file_index_high) << 32) | int(information.file_index_low),
        int(information.attributes),
    )


def _windows_directory_handle_identity(handle):
    return _windows_handle_identity(handle, require_directory=True)


def _windows_open_path_handle(
        path, *, require_directory, delete_access=False, read_control=False):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_file = kernel.CreateFileW
    open_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    open_file.restype = wintypes.HANDLE
    desired_access = 0x80 | 0x100000  # FILE_READ_ATTRIBUTES | SYNCHRONIZE
    if read_control:
        desired_access |= 0x20000  # READ_CONTROL
    if require_directory:
        desired_access |= 0x20  # FILE_TRAVERSE
    if delete_access:
        desired_access |= 0x10000  # DELETE
    share_all = 0x1 | 0x2 | 0x4
    flags = 0x00200000  # OPEN_REPARSE_POINT
    if require_directory:
        flags |= 0x02000000  # BACKUP_SEMANTICS
    handle = open_file(
        _windows_extended_path(path), desired_access, share_all, None, 3, flags, None)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = ctypes.get_last_error()
        raise ReliabilityError(
            f"cannot open verified Windows path (Windows error {error})")
    try:
        identity = _windows_handle_identity(
            handle, require_directory=require_directory)
    except BaseException:
        _windows_close_handle(handle)
        raise
    return handle, identity


def _windows_open_directory_handle(path, *, read_control=False):
    return _windows_open_path_handle(
        path, require_directory=True, read_control=read_control)


def _windows_create_or_open_relative_directory(
        parent_handle, component, security_descriptor):
    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class IoStatusValue(ctypes.Union):
        _fields_ = [("status", wintypes.LONG), ("pointer", wintypes.LPVOID)]

    class IoStatusBlock(ctypes.Structure):
        _anonymous_ = ("value",)
        _fields_ = [("value", IoStatusValue), ("information", ctypes.c_size_t)]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    buffer = ctypes.create_unicode_buffer(component)
    name = UnicodeString(
        len(component.encode("utf-16-le")),
        len(component.encode("utf-16-le")) + 2,
        ctypes.cast(buffer, wintypes.LPWSTR),
    )
    attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes), parent_handle, ctypes.pointer(name),
        0x40, security_descriptor, None)
    status_block = IoStatusBlock()
    handle = wintypes.HANDLE()
    create = ctypes.WinDLL("ntdll", use_last_error=True).NtCreateFile
    create.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatusBlock),
        wintypes.LPVOID, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
        wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
    ]
    create.restype = wintypes.LONG
    desired_access = 0x1 | 0x4 | 0x20 | 0x80 | 0x20000 | 0x100000
    status_code = create(
        ctypes.byref(handle), desired_access, ctypes.byref(attributes),
        ctypes.byref(status_block), None, 0, 0x1 | 0x2 | 0x4, 3,
        0x1 | 0x20 | 0x00200000, None, 0)
    if status_code < 0:
        raise ReliabilityError(
            "cannot create private directory component "
            f"(NTSTATUS 0x{status_code & 0xffffffff:08x})")
    try:
        identity = _windows_directory_handle_identity(handle)
    except BaseException:
        _windows_close_handle(handle)
        raise
    return handle, identity, int(status_block.information) == 2  # FILE_CREATED


def _windows_acl_module():
    try:
        import loom_windows_acl
    except (ImportError, OSError) as exc:
        raise ReliabilityError(
            f"Windows owner-private ACL enforcement is unavailable: {exc}") from exc
    return loom_windows_acl


def _windows_verify_private_directory_handle(handle):
    acl = _windows_acl_module()
    try:
        acl.verify_private_directory_handle(handle)
    except acl.WindowsAclError as exc:
        raise ReliabilityError(
            f"Windows owner-private ACL cannot be proven: {exc}") from exc


def _windows_ensure_private_directory(root, components, root_identity):
    validate_root_identity(root, root_identity)
    current_handle, root_handle_identity = _windows_open_directory_handle(root)
    current_path = root
    root_volume = root_handle_identity[0]
    try:
        for component in components:
            child_handle = None
            try:
                acl = _windows_acl_module()
                try:
                    with acl.private_directory_security_descriptor(
                            current_path) as descriptor:
                        child_handle, child_identity, _created = \
                            _windows_create_or_open_relative_directory(
                                current_handle, component, descriptor)
                except acl.WindowsAclError as exc:
                    raise ReliabilityError(
                        f"Windows owner-private ACL cannot be applied: {exc}") from exc
                if child_identity[0] != root_volume:
                    raise ReliabilityError(
                        "private directory component crosses a filesystem boundary")
                _windows_verify_private_directory_handle(child_handle)
                current_path = current_path / component
                path_handle, path_identity = _windows_open_directory_handle(current_path)
                try:
                    if path_identity != child_identity:
                        raise ReliabilityError(
                            "private directory component identity changed after creation")
                finally:
                    _windows_close_handle(path_handle)
                observe_root_identity(current_path)
            except BaseException:
                if child_handle is not None:
                    _windows_close_handle(child_handle)
                raise
            _windows_close_handle(current_handle)
            current_handle = child_handle
        return current_path
    finally:
        _windows_close_handle(current_handle)


def ensure_private_directory(root, relative_components):
    """Create a bounded private directory path without following mutable parents."""
    components = _private_directory_components(relative_components)
    root = _absolute(root, "private directory root", must_exist=True)
    root_identity = observe_root_identity(root)
    if root_identity["kind"] != "directory":
        raise ReliabilityError("private directory root is not a directory")
    if os.name == "nt":
        result = _windows_ensure_private_directory(root, components, root_identity)
    elif os.name == "posix":
        result = _posix_ensure_private_directory(root, components, root_identity)
    else:
        raise ReliabilityError("private directory creation is unavailable on this platform")
    observed = observe_root_identity(result)
    if observed["kind"] != "directory" \
            or observed["device"] != root_identity["device"]:
        raise ReliabilityError("private directory result is unsafe")
    if os.name == "nt":
        acl = _windows_acl_module()
        try:
            acl.verify_private_directory(result)
        except acl.WindowsAclError as exc:
            raise ReliabilityError(
                f"Windows owner-private ACL cannot be proven: {exc}") from exc
    return result


def _posix_reserve_directory_leaf(parent, leaf, mode, parent_identity):
    """Create one directory relative to a verified descriptor, exclusively."""
    parent_handle = _open_verified_directory(parent, parent_identity)
    try:
        try:
            os.mkdir(leaf, mode, dir_fd=parent_handle)
        except FileExistsError as exc:
            raise ReliabilityError(
                "private stage leaf already exists; refusing to reuse it") from exc
        except OSError as exc:
            raise ReliabilityError(f"cannot reserve private stage leaf: {exc}") from exc
        try:
            os.fsync(parent_handle)
        except OSError as exc:
            raise ReliabilityError(
                f"cannot sync private stage parent after reservation: {exc}") from exc

        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        child_handle = None
        try:
            child_handle = os.open(leaf, flags, dir_fd=parent_handle)
            os.fchmod(child_handle, mode)
            os.fsync(child_handle)
            child_info = os.fstat(child_handle)
            child_path = parent / leaf
            child_identity = _root_identity_from_stat(child_path, child_info)
            if child_identity["kind"] != "directory" \
                    or child_identity["device"] != parent_identity["device"] \
                    or stat.S_IMODE(child_info.st_mode) != mode:
                raise ReliabilityError("reserved private stage leaf is unsafe")
            if observe_root_identity(child_path) != child_identity:
                raise ReliabilityError(
                    "reserved private stage leaf identity changed during creation")
            return child_path
        finally:
            if child_handle is not None:
                os.close(child_handle)
    finally:
        os.close(parent_handle)


def _windows_create_relative_directory_exclusive(
        parent_handle, component, security_descriptor=None):
    """Create one Windows directory relative to a verified handle, never open-if."""
    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class IoStatusValue(ctypes.Union):
        _fields_ = [("status", wintypes.LONG), ("pointer", wintypes.LPVOID)]

    class IoStatusBlock(ctypes.Structure):
        _anonymous_ = ("value",)
        _fields_ = [("value", IoStatusValue), ("information", ctypes.c_size_t)]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    buffer = ctypes.create_unicode_buffer(component)
    encoded_length = len(component.encode("utf-16-le"))
    name = UnicodeString(
        encoded_length, encoded_length + 2,
        ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes), parent_handle, ctypes.pointer(name),
        0x40, security_descriptor, None)
    status_block = IoStatusBlock()
    handle = wintypes.HANDLE()
    create = ctypes.WinDLL("ntdll", use_last_error=True).NtCreateFile
    create.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatusBlock),
        wintypes.LPVOID, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
        wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
    ]
    create.restype = wintypes.LONG
    desired_access = 0x1 | 0x4 | 0x20 | 0x80 | 0x20000 | 0x100000
    status_code = create(
        ctypes.byref(handle), desired_access, ctypes.byref(attributes),
        ctypes.byref(status_block), None, 0, 0x1 | 0x2 | 0x4,
        2,  # FILE_CREATE, never FILE_OPEN_IF.
        0x1 | 0x20 | 0x00200000, None, 0)
    if status_code < 0:
        if status_code & 0xffffffff == 0xC0000035:  # STATUS_OBJECT_NAME_COLLISION
            raise ReliabilityError(
                "private stage leaf already exists; refusing to reuse it")
        raise ReliabilityError(
            "cannot reserve private stage leaf "
            f"(NTSTATUS 0x{status_code & 0xffffffff:08x})")
    try:
        identity = _windows_directory_handle_identity(handle)
    except BaseException:
        _windows_close_handle(handle)
        raise
    return handle, identity


def _windows_reserve_directory_leaf(
        parent, leaf, _mode, parent_identity, *, private_acl=False):
    validate_root_identity(parent, parent_identity)
    parent_handle, parent_handle_identity = _windows_open_directory_handle(
        parent, read_control=private_acl)
    child_handle = None
    try:
        if private_acl:
            _windows_verify_private_directory_handle(parent_handle)
            acl = _windows_acl_module()
            try:
                with acl.private_directory_security_descriptor(parent) as descriptor:
                    child_handle, child_identity = \
                        _windows_create_relative_directory_exclusive(
                            parent_handle, leaf, descriptor)
            except acl.WindowsAclError as exc:
                raise ReliabilityError(
                    f"Windows owner-private ACL cannot be applied: {exc}") from exc
            _windows_verify_private_directory_handle(child_handle)
        else:
            child_handle, child_identity = \
                _windows_create_relative_directory_exclusive(parent_handle, leaf)
        if child_identity[0] != parent_handle_identity[0]:
            raise ReliabilityError(
                "private stage leaf crosses a filesystem boundary")
        child_path = parent / leaf
        path_handle, path_identity = _windows_open_directory_handle(child_path)
        try:
            if path_identity != child_identity:
                raise ReliabilityError(
                    "reserved private stage leaf identity changed during creation")
        finally:
            _windows_close_handle(path_handle)
        observed = observe_root_identity(child_path)
        if observed["kind"] != "directory" \
                or observed["device"] != parent_identity["device"]:
            raise ReliabilityError("reserved private stage leaf is unsafe")
        return child_path
    finally:
        if child_handle is not None:
            _windows_close_handle(child_handle)
        _windows_close_handle(parent_handle)


def _reserve_directory_leaf(parent, leaf, *, mode=0o700, private_acl=False):
    components = _private_directory_components([leaf])
    leaf = components[0]
    if type(mode) is not int or not 0 <= mode <= 0o7777:
        raise ReliabilityError("reserved directory leaf mode is invalid")
    parent = _absolute(parent, "reserved directory parent", must_exist=True)
    parent_identity = observe_root_identity(parent)
    if parent_identity["kind"] != "directory":
        raise ReliabilityError("reserved directory parent is not a directory")
    if os.name == "nt":
        result = _windows_reserve_directory_leaf(
            parent, leaf, mode, parent_identity, private_acl=private_acl)
    elif os.name == "posix":
        result = _posix_reserve_directory_leaf(
            parent, leaf, mode, parent_identity)
    else:
        raise ReliabilityError(
            "exclusive directory reservation is unavailable on this platform")
    _validate_directory_object_continuity(parent, parent_identity)
    return result


def reserve_directory_leaf(parent, leaf, *, mode=0o700):
    """Reserve one project-local directory without changing parent ACL semantics.

    This is the handle-relative, exclusive primitive for repository-owned stages.
    On Windows the directory inherits the verified project parent's ACL policy.
    It deliberately makes no owner-private claim. Use
    :func:`reserve_private_stage_leaf` for owner-private Loom state.
    """
    return _reserve_directory_leaf(parent, leaf, mode=mode, private_acl=False)


def reserve_private_stage_leaf(private_root, relative_components):
    """Exclusively reserve one bounded stage leaf beneath a verified private root.

    Existing intermediate components may be reused only after the same private,
    no-redirect verification as :func:`ensure_private_directory`. The final leaf
    is always created with exclusive native semantics and is never reopened.
    """
    components = _private_directory_components(relative_components)
    private_root = _absolute(
        private_root, "private stage root", must_exist=True)
    root_identity = observe_root_identity(private_root)
    if root_identity["kind"] != "directory":
        raise ReliabilityError("private stage root is not a directory")
    if os.name == "posix" \
            and stat.S_IMODE(private_root.lstat().st_mode) & 0o077:
        raise ReliabilityError("private stage root has non-private permissions")
    if os.name == "nt":
        acl = _windows_acl_module()
        try:
            acl.verify_private_directory(private_root)
        except acl.WindowsAclError as exc:
            raise ReliabilityError(
                f"Windows private stage root ACL cannot be proven: {exc}") from exc
    if len(components) == 1:
        parent = private_root
    else:
        parent = ensure_private_directory(private_root, components[:-1])
    _validate_directory_object_continuity(private_root, root_identity)
    result = _reserve_directory_leaf(
        parent, components[-1], mode=0o700, private_acl=True)
    observed = observe_root_identity(result)
    if observed["kind"] != "directory" \
            or observed["device"] != root_identity["device"]:
        raise ReliabilityError("reserved private stage leaf is unsafe")
    return result


def atomic_write_bytes(path, content):
    """Durably replace one regular file; the old file survives every pre-replace failure."""
    if not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES:
        raise ReliabilityError("atomic content must be bounded bytes")
    path = _absolute(path, "atomic target")
    path.parent.mkdir(parents=True, exist_ok=True)
    _absolute(path.parent, "atomic target parent", must_exist=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("atomic write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        _sync_parent(path)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path, text):
    if not isinstance(text, str):
        raise ReliabilityError("atomic text must be a string")
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path, value):
    atomic_write_text(path, json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _content_hash(content):
    return None if content is None else hashlib.sha256(content).hexdigest()


def _canonical_hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def plan_migration(root, changes):
    """Return a deterministic dry-run plan. This function never writes."""
    root = _absolute(root, "migration root", must_exist=True)
    if not isinstance(changes, dict) or not 1 <= len(changes) <= MAX_MIGRATION_FILES:
        raise ReliabilityError("migration changes must be a bounded non-empty mapping")
    entries = []
    for relative in sorted(changes):
        relative = _safe_relative(relative)
        after = changes[relative]
        if not isinstance(after, bytes) or len(after) > MAX_FILE_BYTES:
            raise ReliabilityError("migration content must be bounded bytes")
        target = _target(root, relative)
        if target.exists() and not target.is_file():
            raise ReliabilityError(f"migration target is not a regular file: {relative}")
        before = target.read_bytes() if target.exists() else None
        entries.append({
            "path": relative,
            "before_sha256": _content_hash(before),
            "after_sha256": _content_hash(after),
            "before_base64": (base64.b64encode(before).decode("ascii")
                              if before is not None else None),
            "after_base64": base64.b64encode(after).decode("ascii"),
        })
    body = {"schema_version": 1, "kind": "loom-migration-plan", "changes": entries}
    return {**body, "plan_id": _canonical_hash(body)}


def _validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {
            "schema_version", "kind", "changes", "plan_id"} \
            or plan.get("schema_version") != 1 \
            or plan.get("kind") != "loom-migration-plan" \
            or not isinstance(plan.get("changes"), list) \
            or not 1 <= len(plan["changes"]) <= MAX_MIGRATION_FILES:
        raise ReliabilityError("migration plan contract is invalid")
    body = {key: value for key, value in plan.items() if key != "plan_id"}
    if plan["plan_id"] != _canonical_hash(body):
        raise ReliabilityError("migration plan hash is invalid")
    seen = set()
    for entry in plan["changes"]:
        if not isinstance(entry, dict) or set(entry) != {
                "path", "before_sha256", "after_sha256", "before_base64", "after_base64"}:
            raise ReliabilityError("migration change contract is invalid")
        relative = _safe_relative(entry["path"])
        if relative in seen or not DIGEST.fullmatch(str(entry["after_sha256"])):
            raise ReliabilityError("migration change identity is invalid")
        seen.add(relative)
        try:
            before = (base64.b64decode(entry["before_base64"], validate=True)
                      if entry["before_base64"] is not None else None)
            after = base64.b64decode(entry["after_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ReliabilityError("migration content encoding is invalid") from exc
        if _content_hash(before) != entry["before_sha256"] \
                or _content_hash(after) != entry["after_sha256"]:
            raise ReliabilityError("migration content hash is invalid")
    return plan


def _recovery_path(root, recovery_root, plan_id):
    root = _absolute(root, "migration root", must_exist=True)
    recovery = _absolute(recovery_root, "recovery root", must_exist=True)
    if recovery == root or recovery.is_relative_to(root):
        raise ReliabilityError("recovery storage must be outside the project tree")
    return recovery / f"{plan_id}.json"


def _read_journal(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReliabilityError(f"migration recovery journal is corrupt: {exc}") from exc


def apply_migration(root, plan, recovery_root):
    plan = _validate_plan(plan)
    journal_path = _recovery_path(root, recovery_root, plan["plan_id"])
    if journal_path.exists():
        journal = _read_journal(journal_path)
        if journal.get("plan") != plan or journal.get("status") == "rolled-back":
            raise ReliabilityError("migration journal conflicts with the requested plan")
        if journal.get("status") == "applied":
            return {"status": "applied", "plan_id": plan["plan_id"],
                    "idempotent": True, "files": len(plan["changes"])}
    else:
        journal = {"schema_version": 1, "status": "prepared", "plan": plan,
                   "applied_paths": []}
        atomic_write_json(journal_path, journal)
    for entry in plan["changes"]:
        target = _target(root, entry["path"])
        current = file_sha256(target) if target.exists() else None
        if current == entry["after_sha256"]:
            pass
        elif current == entry["before_sha256"]:
            atomic_write_bytes(target, base64.b64decode(entry["after_base64"], validate=True))
        else:
            raise ReliabilityError(
                f"migration target changed outside the journal: {entry['path']}")
        if entry["path"] not in journal["applied_paths"]:
            journal["applied_paths"].append(entry["path"])
            atomic_write_json(journal_path, journal)
    journal["status"] = "applied"
    atomic_write_json(journal_path, journal)
    return {"status": "applied", "plan_id": plan["plan_id"],
            "idempotent": False, "files": len(plan["changes"])}


def rollback_migration(root, plan_id, recovery_root):
    if not isinstance(plan_id, str) or not DIGEST.fullmatch(plan_id):
        raise ReliabilityError("migration plan id is invalid")
    journal_path = _recovery_path(root, recovery_root, plan_id)
    if not journal_path.is_file():
        raise ReliabilityError("migration recovery journal is missing")
    journal = _read_journal(journal_path)
    plan = _validate_plan(journal.get("plan"))
    if plan["plan_id"] != plan_id:
        raise ReliabilityError("migration journal identity is invalid")
    if journal.get("status") == "rolled-back":
        return {"status": "rolled-back", "plan_id": plan_id, "idempotent": True}
    for entry in reversed(plan["changes"]):
        target = _target(root, entry["path"])
        current = file_sha256(target) if target.exists() else None
        if current == entry["before_sha256"]:
            continue
        if current != entry["after_sha256"]:
            raise ReliabilityError(
                f"rollback target changed outside the journal: {entry['path']}")
        if entry["before_base64"] is None:
            target.unlink()
            _sync_parent(target)
        else:
            atomic_write_bytes(
                target, base64.b64decode(entry["before_base64"], validate=True))
    journal["status"] = "rolled-back"
    atomic_write_json(journal_path, journal)
    return {"status": "rolled-back", "plan_id": plan_id, "idempotent": False}


def quarantine_corrupt(path, quarantine_root, *, reason):
    """Copy corrupt bytes outside the project; do not delete or silently replace the source."""
    source = _absolute(path, "corrupt source", must_exist=True)
    if not source.is_file() or not isinstance(reason, str) or not SAFE_ID.fullmatch(reason):
        raise ReliabilityError("corruption quarantine inputs are invalid")
    quarantine = _absolute(quarantine_root, "quarantine root")
    quarantine.mkdir(parents=True, exist_ok=True)
    quarantine = _absolute(quarantine, "quarantine root", must_exist=True)
    if quarantine == source.parent or quarantine.is_relative_to(source.parent):
        raise ReliabilityError("corruption quarantine must be outside the source tree")
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    destination = quarantine / f"{source.name}.{digest}.corrupt"
    atomic_write_bytes(destination, raw)
    receipt = {"schema_version": 1, "source_name": source.name, "reason": reason,
               "sha256": digest, "quarantine_path": str(destination),
               "source_preserved": True}
    atomic_write_json(quarantine / f"{source.name}.{digest}.receipt.json", receipt)
    return receipt


def _regular_files(root):
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in sorted(os.scandir(directory), key=lambda item: item.name.casefold()):
            path = Path(entry.path)
            if entry.name == ".git" and entry.is_dir(follow_symlinks=False):
                continue
            if entry.is_symlink() or _is_redirect(path):
                raise ReliabilityError(f"tree contains a redirected entry: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                yield path
            else:
                raise ReliabilityError(f"tree contains a non-regular entry: {path}")


def _exact_tree_platform():
    if os.name == "nt":
        return "windows"
    if os.name == "posix":
        return "posix"
    raise ReliabilityError(f"exact-tree manifests do not support platform {os.name!r}")


def _validate_exact_tree_bounds(max_entries, max_file_bytes, max_total_bytes):
    limits = (
        (max_entries, MAX_EXACT_TREE_ENTRIES, "entry"),
        (max_file_bytes, MAX_EXACT_TREE_FILE_BYTES, "per-file byte"),
        (max_total_bytes, MAX_EXACT_TREE_TOTAL_BYTES, "aggregate byte"),
    )
    for value, ceiling, label in limits:
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ReliabilityError(
                f"exact-tree {label} bound must be between 1 and {ceiling}")


def _exact_relative(value, *, allow_root=False):
    if allow_root and value == ".":
        return value
    try:
        relative = _safe_relative(value)
        encoded = relative.encode("utf-8")
    except UnicodeError as exc:
        raise ReliabilityError("exact-tree paths must be canonical UTF-8") from exc
    if len(encoded) > MAX_EXACT_TREE_PATH_BYTES:
        raise ReliabilityError("exact-tree path exceeds its byte bound")
    return relative


def _entry_sort_key(entry):
    return b"" if entry["path"] == "." else entry["path"].encode("utf-8")


def _stat_time_ns(info, field):
    value = getattr(info, field + "_ns", None)
    if value is not None:
        return int(value)
    return int(getattr(info, field) * 1_000_000_000)


def _stat_identity(info):
    return (
        int(info.st_dev), int(info.st_ino), int(info.st_mode),
        int(info.st_nlink), int(info.st_size),
        # Windows lstat() and fstat() expose different ctime semantics for the
        # same handle on supported Python builds. mtime, identity, size, mode,
        # link count, attributes, and the content digest are stable across both.
        _stat_time_ns(info, "st_mtime"),
        int(getattr(info, "st_file_attributes", 0)),
    )


def _windows_named_stream_count(path):
    """Count non-default NTFS streams without exposing their names or contents."""
    if os.name != "nt":
        return 0
    import ctypes
    from ctypes import wintypes

    class StreamData(ctypes.Structure):
        _fields_ = [
            ("size", ctypes.c_longlong),
            ("name", wintypes.WCHAR * 296),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    first_stream = kernel.FindFirstStreamW
    first_stream.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(StreamData), wintypes.DWORD,
    ]
    first_stream.restype = wintypes.HANDLE
    next_stream = kernel.FindNextStreamW
    next_stream.argtypes = [wintypes.HANDLE, ctypes.POINTER(StreamData)]
    next_stream.restype = wintypes.BOOL
    close = kernel.FindClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    data = StreamData()
    handle = first_stream(str(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = ctypes.get_last_error()
        if error in {1, 38}:  # unsupported filesystem or no streams
            return 0
        if error in {2, 3} and not Path(path).exists():
            raise ReliabilityError("exact-tree entry disappeared during ADS inspection")
        raise ReliabilityError(
            f"cannot enumerate exact-tree alternate data streams (error {error})")
    count = 0
    try:
        while True:
            if data.name != "::$DATA":
                count += 1
            if not next_stream(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 38:
                    raise ReliabilityError(
                        "alternate data stream enumeration changed or failed "
                        f"(error {error})")
                break
    finally:
        close(handle)
    return count


def _darwin_xattrs(path):
    """Enumerate macOS xattrs without following redirects when Python omits os.listxattr."""
    import ctypes

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        listxattr = libc.listxattr
    except (AttributeError, OSError) as exc:
        raise ReliabilityError(
            "cannot certify exact-tree macOS extended attributes") from exc
    listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                          ctypes.c_size_t, ctypes.c_int]
    listxattr.restype = ctypes.c_ssize_t
    encoded = os.fsencode(path)
    nofollow = 0x0001
    unsupported = {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                   errno.EPERM}
    for _attempt in range(3):
        ctypes.set_errno(0)
        required = listxattr(encoded, None, 0, nofollow)
        if required < 0:
            error = ctypes.get_errno()
            if error in unsupported:
                return ()
            raise ReliabilityError(
                f"cannot enumerate exact-tree macOS extended attributes (error {error})")
        if required == 0:
            return ()
        buffer = ctypes.create_string_buffer(required)
        ctypes.set_errno(0)
        observed = listxattr(encoded, buffer, required, nofollow)
        if observed < 0:
            error = ctypes.get_errno()
            if error == errno.ERANGE:
                continue
            if error in unsupported:
                return ()
            raise ReliabilityError(
                f"cannot enumerate exact-tree macOS extended attributes (error {error})")
        if observed > required:
            continue
        raw = buffer.raw[:observed]
        if raw and not raw.endswith(b"\0"):
            raise ReliabilityError(
                "cannot certify exact-tree macOS extended attribute framing")
        return tuple(name for name in raw.split(b"\0") if name)
    raise ReliabilityError(
        "cannot certify exact-tree macOS extended attributes after concurrent changes")


def _posix_xattrs(path):
    if os.name != "posix":
        return ()
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        if sys.platform == "darwin":
            return _darwin_xattrs(path)
        raise ReliabilityError("cannot certify exact-tree POSIX extended attributes")
    try:
        try:
            names = listxattr(path, follow_symlinks=False)
        except TypeError:
            names = listxattr(path)
    except OSError as exc:
        unsupported = {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}
        if exc.errno in unsupported:
            return ()
        raise ReliabilityError(
            f"cannot enumerate exact-tree POSIX extended attributes: {exc}") from exc
    return tuple(names)


def _reject_exact_tree_extended_data(path):
    if _windows_named_stream_count(path):
        raise ReliabilityError(
            f"exact-tree entry has an alternate data stream: {path}")
    if _posix_xattrs(path):
        raise ReliabilityError(
            f"exact-tree entry has a POSIX extended attribute: {path}")


def _exact_directory_entry(path, relative, root_device, *, root_path):
    try:
        before = path.lstat()
    except OSError as exc:
        raise ReliabilityError(f"cannot inspect exact-tree directory: {path}: {exc}") from exc
    if _is_redirect(path) or not stat.S_ISDIR(before.st_mode):
        raise ReliabilityError(f"exact-tree directory is redirected or invalid: {path}")
    if int(before.st_dev) != root_device:
        raise ReliabilityError(f"exact-tree entry crosses a device boundary: {path}")
    if path != root_path and os.path.ismount(path):
        raise ReliabilityError(f"exact-tree entry crosses a mount boundary: {path}")
    _reject_exact_tree_extended_data(path)
    return before, {
        "path": relative,
        "kind": "directory",
        "mode": stat.S_IMODE(before.st_mode),
    }


def _verify_exact_directory(path, expected, root_device, *, root_path):
    before, observed = _exact_directory_entry(
        path, expected["path"], root_device, root_path=root_path)
    if observed != expected:
        raise ReliabilityError(f"exact-tree directory metadata changed: {path}")
    return before


def _exact_file_entry(path, relative, initial, root_device, max_file_bytes):
    if _is_redirect(path) or not stat.S_ISREG(initial.st_mode):
        raise ReliabilityError(f"exact-tree file is redirected or invalid: {path}")
    if int(initial.st_dev) != root_device:
        raise ReliabilityError(f"exact-tree entry crosses a device boundary: {path}")
    if int(initial.st_nlink) != 1:
        raise ReliabilityError(f"exact-tree file has an unsupported hardlink: {path}")
    if int(initial.st_size) > max_file_bytes:
        raise ReliabilityError(f"exact-tree file exceeds its byte bound: {path}")
    _reject_exact_tree_extended_data(path)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) \
                or _stat_identity(opened) != _stat_identity(initial):
            raise ReliabilityError(f"exact-tree file identity changed before read: {path}")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_file_bytes + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > max_file_bytes or size > int(initial.st_size):
                raise ReliabilityError(f"exact-tree file grew beyond its bound: {path}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(after) != _stat_identity(opened):
            raise ReliabilityError(f"exact-tree file changed while it was read: {path}")
    except ReliabilityError:
        raise
    except OSError as exc:
        raise ReliabilityError(f"cannot read exact-tree file {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if size != int(initial.st_size):
        raise ReliabilityError(f"exact-tree file size changed while it was read: {path}")
    try:
        latest = path.lstat()
    except OSError as exc:
        raise ReliabilityError(f"cannot re-inspect exact-tree file {path}: {exc}") from exc
    if _is_redirect(path) or _stat_identity(latest) != _stat_identity(initial):
        raise ReliabilityError(f"exact-tree file changed after it was read: {path}")
    _reject_exact_tree_extended_data(path)
    return {
        "path": relative,
        "kind": "file",
        "mode": stat.S_IMODE(initial.st_mode),
        "bytes": size,
        "sha256": digest.hexdigest(),
        "links": 1,
    }


def _validate_exact_tree_entry_shape(value, *, allow_root=True):
    if not isinstance(value, dict):
        raise ReliabilityError("exact-tree entry must be an object")
    kind = value.get("kind")
    common = {"path", "kind", "mode"}
    expected = common if kind == "directory" else common | {"bytes", "sha256", "links"}
    if kind not in {"directory", "file"} or set(value) != expected:
        raise ReliabilityError("exact-tree entry fields are invalid")
    path = _exact_relative(value.get("path"), allow_root=allow_root)
    if path == "." and kind != "directory":
        raise ReliabilityError("exact-tree root entry must be a directory")
    if type(value.get("mode")) is not int or not 0 <= value["mode"] <= 0o7777:
        raise ReliabilityError("exact-tree entry mode is invalid")
    if kind == "file":
        if path == "." \
                or type(value.get("bytes")) is not int or value["bytes"] < 0 \
                or not DIGEST.fullmatch(str(value.get("sha256", ""))) \
                or value.get("links") != 1:
            raise ReliabilityError("exact-tree file entry is invalid")
    return value


def _exact_tree_body(entries, platform):
    files = [entry for entry in entries if entry["kind"] == "file"]
    directories = [entry for entry in entries if entry["kind"] == "directory"]
    return {
        "schema_version": 2,
        "policy": EXACT_TREE_POLICY,
        "platform": platform,
        "entries": entries,
        "file_count": len(files),
        "directory_count": len(directories),
        "total_bytes": sum(entry["bytes"] for entry in files),
    }


def exact_tree_manifest(root, *, max_entries=MAX_EXACT_TREE_ENTRIES,
                        max_file_bytes=MAX_EXACT_TREE_FILE_BYTES,
                        max_total_bytes=MAX_EXACT_TREE_TOTAL_BYTES):
    """Return bounded deletion-authority evidence for a metadata-simple exact tree.

    The manifest deliberately refuses extended filesystem semantics instead of
    pretending that a byte copy could preserve them. Enumeration is bounded before
    sorting, and files are read through stable no-follow descriptors.
    """
    _validate_exact_tree_bounds(max_entries, max_file_bytes, max_total_bytes)
    root = _absolute(root, "exact-tree root", must_exist=True)
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ReliabilityError(f"cannot inspect exact-tree root: {exc}") from exc
    if _is_redirect(root) or not stat.S_ISDIR(root_info.st_mode):
        raise ReliabilityError("exact-tree root must be a non-redirected directory")
    root_device = int(root_info.st_dev)
    _reject_exact_tree_extended_data(root)
    root_entry = {
        "path": ".", "kind": "directory", "mode": stat.S_IMODE(root_info.st_mode)}
    entries = [root_entry]
    directories = [(root, root_entry, _stat_identity(root_info))]
    directory_records = {root: (root_entry, _stat_identity(root_info))}
    pending = [root]
    total_bytes = 0

    while pending:
        directory = pending.pop()
        expected_directory, expected_identity = directory_records[directory]
        current = _verify_exact_directory(
            directory, expected_directory, root_device, root_path=root)
        if _stat_identity(current) != expected_identity:
            raise ReliabilityError(
                f"exact-tree directory changed before enumeration: {directory}")
        children = []
        try:
            with os.scandir(directory) as iterator:
                for child in iterator:
                    if len(entries) + len(children) >= max_entries:
                        raise ReliabilityError("exact-tree exceeds its entry bound")
                    children.append(child)
        except ReliabilityError:
            raise
        except OSError as exc:
            raise ReliabilityError(f"cannot enumerate exact-tree directory: {exc}") from exc
        current = _verify_exact_directory(
            directory, expected_directory, root_device, root_path=root)
        if _stat_identity(current) != expected_identity:
            raise ReliabilityError(
                f"exact-tree directory changed during enumeration: {directory}")
        children.sort(key=lambda child: os.fsencode(child.name))
        for child in children:
            path = Path(child.path)
            try:
                relative = _exact_relative(path.relative_to(root).as_posix())
                initial = path.lstat()
            except (OSError, ValueError) as exc:
                raise ReliabilityError(f"cannot inspect exact-tree entry: {path}: {exc}") from exc
            if _is_redirect(path):
                raise ReliabilityError(f"exact-tree contains a redirected entry: {path}")
            if int(initial.st_dev) != root_device:
                raise ReliabilityError(f"exact-tree entry crosses a device boundary: {path}")
            if stat.S_ISDIR(initial.st_mode):
                if os.path.ismount(path):
                    raise ReliabilityError(
                        f"exact-tree entry crosses a mount boundary: {path}")
                _reject_exact_tree_extended_data(path)
                entry = {
                    "path": relative, "kind": "directory",
                    "mode": stat.S_IMODE(initial.st_mode),
                }
                entries.append(entry)
                identity = _stat_identity(initial)
                directories.append((path, entry, identity))
                directory_records[path] = (entry, identity)
                pending.append(path)
            elif stat.S_ISREG(initial.st_mode):
                entry = _exact_file_entry(
                    path, relative, initial, root_device, max_file_bytes)
                total_bytes += entry["bytes"]
                if total_bytes > max_total_bytes:
                    raise ReliabilityError("exact-tree exceeds its aggregate byte bound")
                entries.append(entry)
            else:
                raise ReliabilityError(f"exact-tree contains a special entry: {path}")

    for path, expected, identity in reversed(directories):
        current = _verify_exact_directory(
            path, expected, root_device, root_path=root)
        if _stat_identity(current) != identity:
            raise ReliabilityError(f"exact-tree directory changed during traversal: {path}")
    entries.sort(key=_entry_sort_key)
    body = _exact_tree_body(entries, _exact_tree_platform())
    return {**body, "root_sha256": _canonical_hash(body)}


def validate_exact_tree_manifest(value, *, max_entries=MAX_EXACT_TREE_ENTRIES,
                                 max_file_bytes=MAX_EXACT_TREE_FILE_BYTES,
                                 max_total_bytes=MAX_EXACT_TREE_TOTAL_BYTES):
    """Validate one exact-tree v2 manifest without touching its source tree."""
    _validate_exact_tree_bounds(max_entries, max_file_bytes, max_total_bytes)
    fields = {
        "schema_version", "policy", "platform", "entries", "file_count",
        "directory_count", "total_bytes", "root_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 2 \
            or value.get("policy") != EXACT_TREE_POLICY \
            or value.get("platform") not in {"windows", "posix"} \
            or not isinstance(value.get("entries"), list) \
            or not 1 <= len(value["entries"]) <= max_entries \
            or not DIGEST.fullmatch(str(value.get("root_sha256", ""))):
        raise ReliabilityError("exact-tree manifest fields are invalid")
    entries = value["entries"]
    seen = set()
    previous = None
    total_bytes = 0
    file_count = 0
    directory_count = 0
    directories = {"."}
    for index, entry in enumerate(entries):
        _validate_exact_tree_entry_shape(entry)
        path = entry["path"]
        key = _entry_sort_key(entry)
        if path in seen or (previous is not None and key <= previous):
            raise ReliabilityError("exact-tree entries are duplicate or noncanonical")
        if index == 0 and path != ".":
            raise ReliabilityError("exact-tree manifest has no canonical root entry")
        if index and path == ".":
            raise ReliabilityError("exact-tree root entry is duplicated")
        if path != ".":
            parent = PurePosixPath(path).parent.as_posix()
            parent = "." if parent == "." else parent
            if parent not in directories:
                raise ReliabilityError("exact-tree entry has no manifested parent directory")
        if entry["kind"] == "directory":
            directories.add(path)
            directory_count += 1
        else:
            if entry["bytes"] > max_file_bytes:
                raise ReliabilityError("exact-tree file exceeds its manifest byte bound")
            file_count += 1
            total_bytes += entry["bytes"]
            if total_bytes > max_total_bytes:
                raise ReliabilityError("exact-tree manifest exceeds its aggregate byte bound")
        seen.add(path)
        previous = key
    body = _exact_tree_body(entries, value["platform"])
    if value["file_count"] != file_count \
            or value["directory_count"] != directory_count \
            or value["total_bytes"] != total_bytes \
            or value["root_sha256"] != _canonical_hash(body):
        raise ReliabilityError("exact-tree manifest counts or digest are invalid")
    return value


def exact_tree_manifests_equal(actual, expected, **bounds):
    """Return true only when two independently valid exact-tree manifests are identical."""
    validate_exact_tree_manifest(actual, **bounds)
    validate_exact_tree_manifest(expected, **bounds)
    return actual == expected


def exact_tree_manifest_is_subset(actual, expected, **bounds):
    """Return true when every observed entry is an exact member of the expected tree."""
    validate_exact_tree_manifest(actual, **bounds)
    validate_exact_tree_manifest(expected, **bounds)
    if actual["policy"] != expected["policy"] \
            or actual["platform"] != expected["platform"] \
            or actual["entries"][0] != expected["entries"][0]:
        return False
    expected_entries = {entry["path"]: entry for entry in expected["entries"]}
    return all(expected_entries.get(entry["path"]) == entry
               for entry in actual["entries"])


def validate_exact_tree_entry(root, expected, *,
                              max_file_bytes=MAX_EXACT_TREE_FILE_BYTES):
    """Re-observe one manifested entry safely; never deletes or recursively traverses."""
    if type(max_file_bytes) is not int \
            or not 1 <= max_file_bytes <= MAX_EXACT_TREE_FILE_BYTES:
        raise ReliabilityError("exact-tree per-file byte bound is invalid")
    _validate_exact_tree_entry_shape(expected)
    root = _absolute(root, "exact-tree validation root", must_exist=True)
    root_info = root.lstat()
    if _is_redirect(root) or not stat.S_ISDIR(root_info.st_mode):
        raise ReliabilityError("exact-tree validation root is unsafe")
    root_device = int(root_info.st_dev)
    relative = expected["path"]
    path = root if relative == "." else _target(root, relative)
    if expected["kind"] == "directory":
        _before, observed = _exact_directory_entry(
            path, relative, root_device, root_path=root)
    else:
        try:
            initial = path.lstat()
        except OSError as exc:
            raise ReliabilityError(f"cannot inspect exact-tree file: {path}: {exc}") from exc
        observed = _exact_file_entry(
            path, relative, initial, root_device, max_file_bytes)
    if observed != expected:
        raise ReliabilityError(f"exact-tree entry does not match its manifest: {relative}")
    return observed


def materialize_exact_tree(*args, **kwargs):
    """Refuse the retired cross-volume materializer on every platform."""
    raise ReliabilityError(
        "cross-volume exact-tree materialization is retired; use one action-owned "
        "same-volume stage and atomic no-replace activation")


def deterministic_manifest(root):
    root = _absolute(root, "manifest root", must_exist=True)
    files = []
    for path in _regular_files(root):
        raw = path.read_bytes()
        files.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    files.sort(key=lambda item: item["path"])
    body = {"schema_version": 1, "files": files}
    return {**body, "root_sha256": _canonical_hash(body)}


def installation_receipt(root, owned_paths, *, install_id):
    root = _absolute(root, "installation root", must_exist=True)
    if not isinstance(install_id, str) or not SAFE_ID.fullmatch(install_id) \
            or not isinstance(owned_paths, (list, tuple)) or not owned_paths:
        raise ReliabilityError("installation receipt inputs are invalid")
    files = []
    for relative in sorted(set(owned_paths)):
        target = _target(root, relative)
        if not target.is_file():
            raise ReliabilityError(f"owned installation file is missing: {relative}")
        files.append({"path": _safe_relative(relative), "sha256": file_sha256(target)})
    body = {"schema_version": 1, "install_id": install_id, "files": files}
    return {**body, "receipt_hash": _canonical_hash(body)}


def uninstall_owned_files(root, receipt, *, confirmation):
    if not isinstance(receipt, dict) or set(receipt) != {
            "schema_version", "install_id", "files", "receipt_hash"}:
        raise ReliabilityError("installation receipt is invalid")
    body = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    if receipt["receipt_hash"] != _canonical_hash(body) \
            or confirmation != receipt.get("install_id"):
        raise ReliabilityError("uninstall confirmation or ownership receipt is invalid")
    targets = []
    for item in receipt.get("files", []):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} \
                or not DIGEST.fullmatch(str(item.get("sha256", ""))):
            raise ReliabilityError("owned file receipt is invalid")
        target = _target(root, item["path"])
        if not target.is_file() or file_sha256(target) != item["sha256"]:
            raise ReliabilityError(f"owned file changed or is missing: {item['path']}")
        targets.append(target)
    for target in targets:
        target.unlink()
        _sync_parent(target)
    return {"install_id": receipt["install_id"], "removed_files": len(targets),
            "scope": "receipt-proven-files-only"}
