#!/usr/bin/env python3
"""Hermetic, contained subprocess boundary for sensitive Loom operations."""

import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from ctypes import wintypes
from pathlib import Path


MAX_ARGUMENTS = 64
MAX_ARGUMENT_CHARS = 4096
MAX_TRANSCRIPT_BYTES = 256 * 1024
MAX_SENTINEL_ENTRIES = 50_000
MAX_SENTINEL_BYTES = 512 * 1024 * 1024
SAFE_CAPABILITY = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_FIELDS = {
    "schema_version", "operation_id", "operation_class", "command_sha256",
    "executable", "cwd", "environment_keys", "allowed_roots",
    "protected_roots", "timeout_seconds", "capabilities",
    "network_isolation_proven", "containment_provider", "status",
    "returncode", "stdout_sha256", "stderr_sha256", "stdout_bytes",
    "stderr_bytes", "survivors_confirmed_zero", "protected_roots_unchanged",
    "primary_failure", "secondary_failures", "started_at", "completed_at",
    "receipt_sha256",
}
PRIMARY_FAILURES = {
    "cancelled", "nonzero-exit", "protected-root-changed", "start-failed",
    "survivor-census-indeterminate", "timed-out", "transcript-limit",
}
CONTAINMENT_PROVIDERS = {"posix-process-group", "windows-job-object"}
SYSTEM_ENVIRONMENT = (
    "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH", "LANG", "LC_ALL", "TZ",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432",
)


class SupervisorError(RuntimeError):
    def __init__(self, message, *, receipt=None):
        super().__init__(message)
        self.receipt = receipt


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def verify_receipt(receipt):
    """Strictly verify one closed supervisor receipt, including its digest."""
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS \
            or receipt.get("schema_version") != 1:
        raise SupervisorError("operation receipt is invalid", receipt=receipt)
    try:
        operation_id = str(uuid.UUID(str(receipt.get("operation_id"))))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SupervisorError("operation receipt is invalid", receipt=receipt) \
            from exc
    environment_keys = receipt.get("environment_keys")
    allowed_roots = receipt.get("allowed_roots")
    protected_roots = receipt.get("protected_roots")
    capabilities = receipt.get("capabilities")
    secondary = receipt.get("secondary_failures")
    timeout = receipt.get("timeout_seconds")
    returncode = receipt.get("returncode")
    primary = receipt.get("primary_failure")
    valid = (
        operation_id == receipt["operation_id"]
        and isinstance(receipt.get("operation_class"), str)
        and SAFE_CAPABILITY.fullmatch(receipt["operation_class"]) is not None
        and HEX64.fullmatch(str(receipt.get("command_sha256", ""))) is not None
        and all(isinstance(receipt.get(field), str)
                and 1 <= len(receipt[field]) <= 4096
                for field in ("executable", "cwd"))
        and isinstance(environment_keys, list)
        and len(environment_keys) <= 64
        and len(environment_keys) == len(set(environment_keys))
        and all(isinstance(item, str) and 1 <= len(item) <= 128
                for item in environment_keys)
        and all(isinstance(rows, list) and len(rows) <= 32
                and len(rows) == len(set(rows))
                and all(isinstance(item, str) and 1 <= len(item) <= 4096
                        for item in rows)
                for rows in (allowed_roots, protected_roots))
        and isinstance(capabilities, list)
        and len(capabilities) <= 32
        and len(capabilities) == len(set(capabilities))
        and all(isinstance(item, str)
                and SAFE_CAPABILITY.fullmatch(item) is not None
                for item in capabilities)
        and type(timeout) in {int, float} and 0 < timeout <= 3600
        and receipt.get("containment_provider") in CONTAINMENT_PROVIDERS
        and type(receipt.get("network_isolation_proven")) is bool
        and receipt.get("status") in {"passed", "failed"}
        and (returncode is None or type(returncode) is int)
        and all(type(receipt.get(field)) is bool for field in (
            "survivors_confirmed_zero", "protected_roots_unchanged"))
        and (primary is None or primary in PRIMARY_FAILURES)
        and isinstance(secondary, list) and len(secondary) <= 32
        and all(isinstance(item, str) and 1 <= len(item) <= 240
                for item in secondary)
        and all(HEX64.fullmatch(str(receipt.get(field, ""))) is not None
                for field in ("stdout_sha256", "stderr_sha256"))
        and all(type(receipt.get(field)) is int
                and 0 <= receipt[field] <= MAX_TRANSCRIPT_BYTES
                for field in ("stdout_bytes", "stderr_bytes"))
        and all(isinstance(receipt.get(field), str) and receipt[field]
                for field in ("started_at", "completed_at"))
        and receipt["status"] == ("passed" if primary is None else "failed")
        and HEX64.fullmatch(str(receipt.get("receipt_sha256", ""))) is not None
        and receipt["receipt_sha256"] == _hash({
            key: item for key, item in receipt.items()
            if key != "receipt_sha256"})
    )
    if not valid:
        raise SupervisorError("operation receipt is invalid", receipt=receipt)
    return receipt


def _safe_path(value, label, *, directory=False):
    path = Path(value)
    if not path.is_absolute():
        raise SupervisorError(f"{label} must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SupervisorError(f"{label} is unavailable: {exc}") from exc
    if directory and not resolved.is_dir():
        raise SupervisorError(f"{label} must be a directory")
    if path.is_symlink():
        raise SupervisorError(f"{label} must not be a link")
    return resolved


def minimal_environment(overrides=None):
    """Return a closed child environment without owner/provider secrets."""
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            or "\x00" in key or "\x00" in value
            for key, value in overrides.items()):
        raise SupervisorError("operation environment is invalid")
    environment = {
        key: os.environ[key] for key in SYSTEM_ENVIRONMENT if os.environ.get(key)
    }
    environment.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    environment.update(overrides)
    forbidden = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "CREDENTIAL")
    if any(any(marker in key.upper() for marker in forbidden)
           for key in environment):
        raise SupervisorError("operation environment contains a secret-bearing key")
    return environment


def _sentinel(path):
    path = Path(path)
    if not path.exists():
        return {"kind": "absent"}
    resolved = _safe_path(path, "protected root")
    digest = hashlib.sha256(b"loom-protected-root-v1\0")
    count = 0
    total = 0
    entries = [resolved] if resolved.is_file() else [resolved, *sorted(resolved.rglob("*"))]
    for item in entries:
        count += 1
        if count > MAX_SENTINEL_ENTRIES:
            raise SupervisorError("protected root exceeds its entry bound")
        try:
            info = item.lstat()
        except OSError as exc:
            raise SupervisorError(f"protected root is unreadable: {exc}") from exc
        if item.is_symlink():
            kind = "link"
            size = 0
            content = os.readlink(item).encode("utf-8", errors="surrogateescape")
        elif item.is_file():
            kind = "file"
            size = info.st_size
            total += size
            if total > MAX_SENTINEL_BYTES:
                raise SupervisorError("protected root exceeds its byte bound")
            try:
                content = item.read_bytes()
            except OSError as exc:
                raise SupervisorError(f"protected root file is unreadable: {exc}") from exc
        elif item.is_dir():
            kind = "directory"
            size = 0
            content = b""
        else:
            raise SupervisorError("protected root contains an unsupported entry")
        relative = "." if item == resolved else item.relative_to(resolved).as_posix()
        row = _canonical({
            "path": relative, "kind": kind, "size": size,
            "mode": info.st_mode, "content_sha256": hashlib.sha256(content).hexdigest(),
        })
        digest.update(len(row).to_bytes(8, "big") + row)
    return {
        "kind": "present", "entries": count, "bytes": total,
        "tree_sha256": digest.hexdigest(),
    }


if os.name == "nt":
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS = 1

    class _JobBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JobExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobBasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JobBasicAccountingInformation(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64),
            ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64),
            ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _KERNEL32.CreateJobObjectW.restype = wintypes.HANDLE
    _KERNEL32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _KERNEL32.SetInformationJobObject.restype = wintypes.BOOL
    _KERNEL32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _KERNEL32.AssignProcessToJobObject.restype = wintypes.BOOL
    _KERNEL32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _KERNEL32.TerminateJobObject.restype = wintypes.BOOL
    _KERNEL32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    _KERNEL32.QueryInformationJobObject.restype = wintypes.BOOL
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE

    _DELETE_ACCESS = 0x00010000
    _FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _ERROR_SHARING_VIOLATION = 32
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _BOOTSTRAP = (
        "import json,subprocess,sys;"
        "command=json.load(sys.stdin);"
        "raise SystemExit(subprocess.run(command,shell=False).returncode)"
    )


def _windows_error(action):
    return SupervisorError(
        f"operation containment could not {action}: WinError {ctypes.get_last_error()}")


def _windows_delete_ready(path):
    """Return whether a Windows directory can be opened with delete access."""
    if os.name != "nt":
        return None
    ctypes.set_last_error(0)
    handle = _KERNEL32.CreateFileW(
        str(path), _DELETE_ACCESS, _FILE_SHARE_ALL, None, _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        return False if error == _ERROR_SHARING_VIOLATION else None
    _KERNEL32.CloseHandle(handle)
    return True


def _wait_for_windows_cwd_release(path, timeout=5):
    """Wait until terminated Windows children release their cwd directory handle."""
    if os.name != "nt":
        return True
    deadline = time.monotonic() + timeout
    while True:
        ready = _windows_delete_ready(path)
        if ready is not False:
            return ready
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _terminate_and_settle(process, containment, cwd, release_observable):
    survivors_zero, secondary = _terminate(process, containment)
    if survivors_zero and release_observable:
        released = _wait_for_windows_cwd_release(cwd)
        if released is not True:
            survivors_zero = False
            secondary.append(
                "cwd-release-timeout" if released is False
                else "cwd-release-census:unavailable")
    return survivors_zero, secondary


def _start(command, cwd, environment, stdout_file, stderr_file):
    if os.name != "nt":
        process = subprocess.Popen(
            command, cwd=cwd, env=environment, stdout=stdout_file,
            stderr=stderr_file, shell=False, start_new_session=True)
        return process, None, "posix-process-group"
    job = _KERNEL32.CreateJobObjectW(None, None)
    if not job:
        raise _windows_error("create a Job Object")
    limits = _JobExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not _KERNEL32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits), ctypes.sizeof(limits)):
        _KERNEL32.CloseHandle(job)
        raise _windows_error("configure a Job Object")
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", _BOOTSTRAP], cwd=cwd, env=environment,
            stdin=subprocess.PIPE, stdout=stdout_file, stderr=stderr_file, shell=False)
        if not _KERNEL32.AssignProcessToJobObject(
                job, wintypes.HANDLE(int(process._handle))):
            raise _windows_error("assign the child before execution")
        process.stdin.write(_canonical(command))
        process.stdin.close()
        process.stdin = None
        return process, job, "windows-job-object"
    except BaseException:
        if process is not None:
            process.kill()
            process.wait()
        _KERNEL32.CloseHandle(job)
        raise


def _posix_group_live_state(process_group):
    """Return True for a live member, False for none, and None if census is unknown."""
    proc = Path("/proc")
    if proc.is_dir():
        uncertain = False
        for entry in proc.iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                raw = (entry / "stat").read_text(encoding="ascii")
                fields = raw[raw.rfind(")") + 2:].split()
                state = fields[0]
                group = int(fields[2])
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError, ValueError, IndexError):
                uncertain = True
                continue
            if group == process_group and state != "Z":
                return True
        return None if uncertain else False
    observed = _ps_group_live_state(process_group)
    if observed is not None:
        return observed
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None
    return True


def _ps_group_live_state(process_group):
    """Census a process group on POSIX hosts without a Linux /proc filesystem."""
    executable = shutil.which("ps")
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "-axo", "pid=,pgid=,stat="],
            capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    uncertain = False
    for line in result.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3:
            if line.strip():
                uncertain = True
            continue
        try:
            group = int(fields[1])
        except ValueError:
            uncertain = True
            continue
        if group == process_group and not fields[2].startswith("Z"):
            return True
    return None if uncertain else False


def _terminate(process, containment):
    secondary = []
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            secondary.append(f"process-group-termination:{exc}")
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            secondary.append(f"process-wait:{exc}")
        survivors_zero = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            live = _posix_group_live_state(process.pid)
            if live is False:
                survivors_zero = True
                break
            if live is None:
                secondary.append("process-group-census:unavailable")
                break
            time.sleep(0.01)
        return survivors_zero, secondary
    try:
        if not _KERNEL32.TerminateJobObject(containment, 1):
            secondary.append(
                f"job-termination:WinError {ctypes.get_last_error()}")
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            secondary.append(f"process-wait:{exc}")
        deadline = time.monotonic() + 5
        survivors_zero = False
        while time.monotonic() < deadline:
            accounting = _JobBasicAccountingInformation()
            returned = wintypes.DWORD()
            if not _KERNEL32.QueryInformationJobObject(
                    containment, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
                    ctypes.byref(accounting), ctypes.sizeof(accounting),
                    ctypes.byref(returned)):
                secondary.append(
                    f"job-census:WinError {ctypes.get_last_error()}")
                break
            if accounting.ActiveProcesses == 0:
                survivors_zero = True
                break
            time.sleep(0.01)
        return survivors_zero, secondary
    finally:
        _KERNEL32.CloseHandle(containment)


def run(*, operation_class, command, cwd, timeout, environment=None,
        allowed_roots=(), protected_roots=(), capabilities=(),
        cancel_requested=None, max_transcript_bytes=MAX_TRANSCRIPT_BYTES,
        capture_output=False, operation_id=None):
    """Run one command and return a closed content-bound containment receipt."""
    if not isinstance(operation_class, str) \
            or SAFE_CAPABILITY.fullmatch(operation_class) is None \
            or not isinstance(command, (list, tuple)) \
            or not 1 <= len(command) <= MAX_ARGUMENTS \
            or any(not isinstance(item, str) or not item
                   or len(item) > MAX_ARGUMENT_CHARS or "\x00" in item
                   for item in command) \
            or type(timeout) not in {int, float} or not 0 < timeout <= 3600 \
            or type(max_transcript_bytes) is not int \
            or not 1024 <= max_transcript_bytes <= MAX_TRANSCRIPT_BYTES \
            or type(capture_output) is not bool \
            or not isinstance(capabilities, (list, tuple)) \
            or any(not isinstance(item, str)
                   or SAFE_CAPABILITY.fullmatch(item) is None for item in capabilities) \
            or (cancel_requested is not None and not callable(cancel_requested)):
        raise SupervisorError("operation specification is invalid")
    if operation_id is None:
        operation_id = str(uuid.uuid4())
    try:
        if str(uuid.UUID(str(operation_id))) != str(operation_id):
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise SupervisorError("operation identity is invalid") from exc
    cwd = _safe_path(cwd, "operation cwd", directory=True)
    release_observable = _windows_delete_ready(cwd) is True
    allowed = [_safe_path(item, "allowed root") for item in allowed_roots]
    if allowed and not any(cwd == root or root in cwd.parents for root in allowed):
        raise SupervisorError("operation cwd is outside its allowed roots")
    protected = [Path(item) for item in protected_roots]
    protected_before = {str(item): _sentinel(item) for item in protected}
    env = minimal_environment(environment)
    body = {
        "schema_version": 1,
        "operation_id": operation_id,
        "operation_class": operation_class,
        "command_sha256": hashlib.sha256(_canonical(list(command))).hexdigest(),
        "executable": str(command[0]),
        "cwd": str(cwd),
        "environment_keys": sorted(env),
        "allowed_roots": [str(item) for item in allowed],
        "protected_roots": sorted(protected_before),
        "timeout_seconds": float(timeout),
        "capabilities": sorted(set(capabilities)),
        "network_isolation_proven": False,
        "containment_provider": None,
        "status": "started",
        "returncode": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "survivors_confirmed_zero": False,
        "protected_roots_unchanged": False,
        "primary_failure": None,
        "secondary_failures": [],
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat().replace(
            "+00:00", "Z"),
        "completed_at": None,
    }
    process = containment = None
    stdout = stderr = b""
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                process, containment, provider = _start(
                    list(command), cwd, env, stdout_file, stderr_file)
                body["containment_provider"] = provider
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if cancel_requested is not None and cancel_requested():
                        body["primary_failure"] = "cancelled"
                        break
                    if time.monotonic() >= deadline:
                        body["primary_failure"] = "timed-out"
                        break
                    if os.fstat(stdout_file.fileno()).st_size > max_transcript_bytes \
                            or os.fstat(stderr_file.fileno()).st_size > max_transcript_bytes:
                        body["primary_failure"] = "transcript-limit"
                        break
                    time.sleep(0.02)
                returncode = process.returncode
                survivors_zero, cleanup = _terminate_and_settle(
                    process, containment, cwd, release_observable)
                process = containment = None
                body["survivors_confirmed_zero"] = survivors_zero
                body["secondary_failures"].extend(cleanup)
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read(max_transcript_bytes + 1)
                stderr = stderr_file.read(max_transcript_bytes + 1)
                transcript_exceeded = len(stdout) > max_transcript_bytes \
                    or len(stderr) > max_transcript_bytes
                if body["primary_failure"] is None and transcript_exceeded:
                    body["primary_failure"] = "transcript-limit"
                stdout = stdout[:max_transcript_bytes]
                stderr = stderr[:max_transcript_bytes]
                if body["primary_failure"] is None and returncode != 0:
                    body["primary_failure"] = "nonzero-exit"
                body["returncode"] = returncode
            except (OSError, SupervisorError) as exc:
                body["primary_failure"] = body["primary_failure"] or "start-failed"
                body["secondary_failures"].append(
                    f"{type(exc).__name__}:{str(exc)[:240]}")
                if process is not None:
                    survivors_zero, cleanup = _terminate_and_settle(
                        process, containment, cwd, release_observable)
                    body["survivors_confirmed_zero"] = survivors_zero
                    body["secondary_failures"].extend(cleanup)
                    process = containment = None
        protected_after = {str(item): _sentinel(item) for item in protected}
        body["protected_roots_unchanged"] = protected_before == protected_after
        if not body["protected_roots_unchanged"]:
            if body["primary_failure"] is None:
                body["primary_failure"] = "protected-root-changed"
            else:
                body["secondary_failures"].append("protected-root-changed")
        if not body["survivors_confirmed_zero"] and body["primary_failure"] is None:
            body["primary_failure"] = "survivor-census-indeterminate"
        body["stdout_bytes"] = len(stdout)
        body["stderr_bytes"] = len(stderr)
        body["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        body["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
        body["status"] = "passed" if body["primary_failure"] is None else "failed"
        body["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat().replace(
            "+00:00", "Z")
        body["receipt_sha256"] = _hash(body)
        return (body, stdout, stderr) if capture_output else body
    finally:
        if process is not None:
            _terminate(process, containment)


def require_passed(receipt):
    if not isinstance(receipt, dict) or receipt.get("receipt_sha256") != _hash({
            key: item for key, item in receipt.items() if key != "receipt_sha256"}):
        raise SupervisorError("operation receipt is invalid", receipt=receipt)
    if receipt.get("status") != "passed":
        raise SupervisorError(
            f"operation failed: {receipt.get('primary_failure')}", receipt=receipt)
    return receipt
