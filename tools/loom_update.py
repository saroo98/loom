#!/usr/bin/env python3
"""TUF-style staged Loom runtime activation with session pinning and rollback."""

import datetime as dt
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import uuid
import zipfile
from pathlib import Path, PurePosixPath

import loom_reliability


MAX_TARGET_BYTES = 128 * 1024 * 1024
MAX_TARGETS = 16
MAX_ARCHIVE_FILES = 512
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")


class UpdateError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _time(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise UpdateError("release metadata time is invalid") from exc
    if parsed.tzinfo is None:
        raise UpdateError("release metadata time has no timezone")
    return parsed.astimezone(dt.timezone.utc)


def platform_id():
    systems = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}
    machines = {
        "x86_64": "x64", "AMD64": "x64", "aarch64": "arm64",
        "arm64": "arm64", "ARM64": "arm64",
    }
    try:
        return f"{systems[platform.system()]}-{machines[platform.machine()]}"
    except KeyError as exc:
        raise UpdateError("this operating system or architecture is unsupported") from exc


def _relative(value):
    if not isinstance(value, str) or "\\" in value:
        raise UpdateError("release target path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise UpdateError("release target path traverses or is ambiguous")
    return path


def _redirect(path):
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


def _extract_runtime_archive(archive, destination):
    """Extract one deterministic runtime archive without following archive paths or links."""
    total = 0
    seen = set()
    try:
        with zipfile.ZipFile(archive) as package:
            entries = package.infolist()
            if not 1 <= len(entries) <= MAX_ARCHIVE_FILES:
                raise UpdateError("runtime archive file count is outside its bound")
            for entry in entries:
                relative = _relative(entry.filename)
                name = relative.as_posix()
                if entry.is_dir() or name in seen:
                    raise UpdateError("runtime archive contains a directory or duplicate path")
                seen.add(name)
                mode = (entry.external_attr >> 16) & 0o170000
                if mode not in {0, stat.S_IFREG}:
                    raise UpdateError("runtime archive contains a non-regular file")
                if entry.file_size < 0 or entry.file_size > MAX_TARGET_BYTES:
                    raise UpdateError("runtime archive entry exceeds its size bound")
                total += entry.file_size
                if total > MAX_TARGET_BYTES:
                    raise UpdateError("runtime archive expands beyond its total size bound")
                target = destination.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o700 if name.startswith("bin/") else 0o600)
                try:
                    with package.open(entry) as source, os.fdopen(descriptor, "wb") as output:
                        descriptor = None
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, UpdateError):
            raise
        raise UpdateError(f"runtime archive is invalid: {exc}") from exc
    return {"files": len(seen), "bytes": total}


def _verify_envelope(envelope, root, verify_signature, label):
    if not isinstance(envelope, dict) or set(envelope) != {"signed", "signatures"} \
            or not isinstance(envelope["signatures"], list):
        raise UpdateError(f"{label} metadata envelope is invalid")
    threshold = root.get("threshold")
    keys = root.get("keys")
    if type(threshold) is not int or not 2 <= threshold <= 3 \
            or not isinstance(keys, dict) or len(keys) < threshold:
        raise UpdateError("trusted root threshold is invalid")
    valid = set()
    message = _canonical(envelope["signed"])
    for signature in envelope["signatures"]:
        if not isinstance(signature, dict) or set(signature) != {"key_id", "signature"}:
            raise UpdateError(f"{label} signature entry is invalid")
        key_id = signature["key_id"]
        public = keys.get(key_id)
        if public is not None and key_id not in valid \
                and verify_signature(message, signature["signature"], public):
            valid.add(key_id)
    if len(valid) < threshold:
        raise UpdateError(f"{label} metadata lacks threshold signatures")
    return envelope["signed"]


def _root_contract(root, label):
    required = {"version", "threshold", "keys", "expires"}
    if not isinstance(root, dict) or set(root) != required \
            or type(root.get("version")) is not int or root["version"] < 1 \
            or root.get("threshold") != 2 or not isinstance(root.get("keys"), dict) \
            or len(root["keys"]) != 3:
        raise UpdateError(f"{label} root policy is invalid")
    _time(root["expires"])
    return root


def _verify_root_envelope(envelope, trusted_root, verify_signature, now):
    trusted_root = _root_contract(trusted_root, "trusted")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("signed"), dict):
        raise UpdateError("root metadata envelope is invalid")
    candidate = _root_contract(envelope["signed"], "candidate")
    instant = _time(now)
    if candidate == trusted_root:
        _verify_envelope(envelope, trusted_root, verify_signature, "root")
    else:
        if candidate["version"] != trusted_root["version"] + 1:
            raise UpdateError("trusted root transition skipped or rolled back a version")
        # One transition envelope must carry independent old-root and new-root thresholds.
        _verify_envelope(envelope, trusted_root, verify_signature, "old-root transition")
        _verify_envelope(envelope, candidate, verify_signature, "new-root transition")
    if instant > _time(candidate["expires"]):
        raise UpdateError("trusted root metadata is expired")
    return candidate


def verify_metadata(bundle, *, trusted_root, verify_signature, now):
    if not isinstance(bundle, dict) or set(bundle) != {"root", "targets", "snapshot", "timestamp"}:
        raise UpdateError("release metadata bundle is incomplete")
    if not callable(verify_signature):
        raise UpdateError("release signature verifier is unavailable")
    instant = _time(now)
    root = _verify_root_envelope(bundle["root"], trusted_root, verify_signature, now)
    targets = _verify_envelope(bundle["targets"], root, verify_signature, "targets")
    snapshot = _verify_envelope(bundle["snapshot"], root, verify_signature, "snapshot")
    timestamp = _verify_envelope(bundle["timestamp"], root, verify_signature, "timestamp")
    if instant > _time(timestamp.get("expires")):
        raise UpdateError("timestamp metadata is expired or frozen")
    if timestamp.get("snapshot_sha256") != _sha(snapshot):
        raise UpdateError("snapshot metadata hash does not match timestamp")
    if snapshot.get("targets_sha256") != _sha(targets):
        raise UpdateError("targets metadata hash does not match snapshot")
    versions = [targets.get("version"), snapshot.get("version"), timestamp.get("version")]
    if any(type(value) is not int or value < 1 for value in versions) \
            or versions != sorted(versions) or len(set(versions)) != 1:
        raise UpdateError("release metadata versions are mixed")
    manifest = targets.get("manifest")
    if not isinstance(manifest, dict):
        raise UpdateError("targets metadata has no release manifest")
    return manifest


class SharedRuntime:
    def __init__(self, home, *, plugin_roots=(), pid_alive=None):
        self.home = loom_reliability._absolute(home, "Loom home")
        self.runtime = self.home / "runtime"
        self.versions = self.runtime / "versions"
        self.sessions = self.runtime / "sessions"
        self.current_path = self.runtime / "current.json"
        self.pending_path = self.runtime / "pending.json"
        self.failure_path = self.runtime / "trust-failures.json"
        self.usage = self.runtime / "usage"
        roots = [loom_reliability._absolute(path, "plugin root", must_exist=True)
                 for path in plugin_roots]
        self.plugin_roots = tuple(roots)
        self.pid_alive = pid_alive or self._pid_alive
        self.versions.mkdir(parents=True, exist_ok=True)
        self.sessions.mkdir(parents=True, exist_ok=True)
        self.usage.mkdir(parents=True, exist_ok=True)

    def _usage_path(self, version):
        if not VERSION_RE.fullmatch(str(version)):
            raise UpdateError("runtime usage version is invalid")
        return self.usage / f"{version}.json"

    def _initialize_usage(self, version):
        path = self._usage_path(version)
        if not path.exists():
            loom_reliability.atomic_write_json(path, {
                "version": version, "activated_at": dt.datetime.now(dt.timezone.utc).replace(
                    microsecond=0).isoformat().replace("+00:00", "Z"),
                "successful_sessions": 0})

    def install_baseline(self, version, content, *, release_sequence):
        if self.current_path.exists() or not VERSION_RE.fullmatch(version) \
                or not isinstance(content, bytes) or not content \
                or type(release_sequence) is not int or release_sequence < 1:
            raise UpdateError("baseline runtime inputs are invalid or already initialized")
        target = self.versions / version
        target.mkdir()
        loom_reliability.atomic_write_bytes(target / "loom-runtime.txt", content)
        digest = hashlib.sha256(content).hexdigest()
        loom_reliability.atomic_write_json(target / ".loom-baseline-receipt.json", {
            "version": version, "path": "loom-runtime.txt", "sha256": digest})
        pointer = {"version": version, "path": version,
                   "payload_sha256": digest, "release_sequence": release_sequence,
                   "previous": None}
        loom_reliability.atomic_write_json(self.current_path, pointer)
        self._initialize_usage(version)
        return pointer

    def current(self):
        try:
            value = json.loads(self.current_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError(f"active runtime pointer is invalid: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "version", "path", "payload_sha256", "release_sequence", "previous"} \
                or not VERSION_RE.fullmatch(str(value["version"])) \
                or value["path"] != value["version"] \
                or not (self.versions / value["path"]).is_dir():
            raise UpdateError("active runtime pointer is unsafe or incomplete")
        return value

    def _plugin_payload(self, path):
        if not self.plugin_roots:
            raise UpdateError("no installed-plugin root is allowlisted for staging")
        value = loom_reliability._absolute(path, "plugin payload", must_exist=True)
        if not value.is_dir() or not any(value.is_relative_to(root) for root in self.plugin_roots):
            raise UpdateError("runtime payload is outside allowlisted plugin caches")
        for component in [*reversed(value.parents), value]:
            if _redirect(component):
                raise UpdateError("runtime payload traverses a symlink or junction")
        return value

    @staticmethod
    def _read_receipt(path, label):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError(f"existing runtime {label} is invalid: {exc}") from exc
        if not isinstance(value, dict):
            raise UpdateError(f"existing runtime {label} is invalid")
        return value

    def _verify_existing_runtime(self, final, *, version, manifest, selected):
        """Accept only an exact receipt-owned runtime left by this release's staging path."""
        if not final.is_dir() or _redirect(final):
            raise UpdateError("existing staged runtime is unsafe")
        runtime_receipt = self._read_receipt(
            final / ".loom-runtime-receipt.json", "release receipt")
        expected_runtime = {
            "version": version,
            "release_sequence": manifest["release_sequence"],
            "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
            "targets": selected,
        }
        if runtime_receipt != expected_runtime:
            raise UpdateError("existing runtime release receipt does not match this release")
        install = self._read_receipt(
            final / ".loom-install-receipt.json", "installation receipt")
        if set(install) != {"schema_version", "install_id", "files", "receipt_hash"} \
                or install.get("schema_version") != 1 \
                or not isinstance(install.get("files"), list) \
                or install.get("receipt_hash") != _sha({
                    key: install[key] for key in (
                        "schema_version", "install_id", "files")
                }):
            raise UpdateError("existing runtime installation receipt is invalid")
        owned = set()
        for item in install["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"} \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
                raise UpdateError("existing runtime owned-file receipt is invalid")
            relative = _relative(item["path"])
            path = final.joinpath(*relative.parts)
            if not path.is_file() or _redirect(path) \
                    or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                raise UpdateError("existing runtime owned bytes do not match their receipt")
            owned.add(relative.as_posix())
        ignored = {
            ".loom-install-receipt.json", ".loom-runtime-receipt.json",
            ".loom-health-receipt.json",
        }
        observed = {
            path.relative_to(final).as_posix()
            for path in loom_reliability._regular_files(final)
            if path.name not in ignored
        }
        if observed != owned:
            raise UpdateError("existing runtime has unowned, missing, or substituted files")
        health = self._read_receipt(
            final / ".loom-health-receipt.json", "health receipt")
        required_health = {
            "schema_version", "version", "manifest_sha256", "healthy",
            "migration_complete", "disposable_request_passed",
            "before_inventory_sha256", "after_inventory_sha256",
        }
        if set(health) != required_health or health["schema_version"] != 1 \
                or health["version"] != version \
                or health["manifest_sha256"] != expected_runtime["manifest_sha256"] \
                or health["healthy"] is not True \
                or health["migration_complete"] is not True \
                or health["disposable_request_passed"] is not True \
                or health["before_inventory_sha256"] != health["after_inventory_sha256"] \
                or not re.fullmatch(
                    r"[0-9a-f]{64}", str(health["before_inventory_sha256"])):
            raise UpdateError("existing runtime has no matching verified health receipt")
        return expected_runtime

    @staticmethod
    def _pid_alive(pid):
        if type(pid) is not int or pid <= 0:
            return False
        if os.name == "nt":
            process_query_limited_information = 0x1000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            handle = kernel32.OpenProcess(
                process_query_limited_information, False, pid)
            if not handle:
                return False
            kernel32.CloseHandle(handle)
            return True
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    def _active_sessions(self):
        active = []
        for path in sorted(self.sessions.glob("*.json")):
            if _redirect(path) or not path.is_file():
                raise UpdateError("session lease directory contains an unsafe entry")
            try:
                lease = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise UpdateError(f"session lease is invalid; freshness is unknown: {exc}") from exc
            required = {"session_id", "version", "release_sequence", "pid", "started_at"}
            if not isinstance(lease, dict) or set(lease) != required \
                    or path.stem != lease.get("session_id") \
                    or not VERSION_RE.fullmatch(str(lease.get("version"))) \
                    or type(lease.get("release_sequence")) is not int \
                    or type(lease.get("pid")) is not int:
                raise UpdateError("session lease is invalid; freshness is unknown")
            _time(lease["started_at"])
            if self.pid_alive(lease["pid"]):
                active.append(path)
            else:
                path.unlink()
        return active

    def begin_session(self):
        if self.pending_path.is_file() and not self._active_sessions():
            self.activate_pending()
        current = self.current()
        session_id = str(uuid.uuid4())
        lease = {"session_id": session_id, "version": current["version"],
                 "release_sequence": current["release_sequence"], "pid": os.getpid(),
                 "started_at": dt.datetime.now(dt.timezone.utc).replace(
                     microsecond=0).isoformat().replace("+00:00", "Z")}
        path = self.sessions / f"{session_id}.json"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, _canonical(lease) + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return lease

    def end_session(self, session_id, *, successful=True):
        try:
            canonical = str(uuid.UUID(session_id))
        except ValueError as exc:
            raise UpdateError("session id is invalid") from exc
        path = self.sessions / f"{canonical}.json"
        if not path.is_file() or _redirect(path):
            raise UpdateError("session lease is missing or unsafe")
        path.unlink()
        if successful:
            current = self.current()
            usage_path = self._usage_path(current["version"])
            try:
                usage = json.loads(usage_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise UpdateError(f"runtime usage receipt is invalid: {exc}") from exc
            if not isinstance(usage, dict) or set(usage) != {
                    "version", "activated_at", "successful_sessions"} \
                    or usage["version"] != current["version"] \
                    or type(usage["successful_sessions"]) is not int:
                raise UpdateError("runtime usage receipt contract is invalid")
            _time(usage["activated_at"])
            usage["successful_sessions"] += 1
            loom_reliability.atomic_write_json(usage_path, usage)
        return {"session_id": canonical, "status": "ended"}

    def stage_update(self, plugin_payload, bundle, *, trusted_root, verify_signature,
                     vault_schema, health_check, now):
        source = self._plugin_payload(plugin_payload)
        manifest = verify_metadata(
            bundle, trusted_root=trusted_root,
            verify_signature=verify_signature, now=now)
        required = {"package", "release_sequence", "version", "targets", "schema_range",
                    "migration_chain", "adapter_range"}
        if set(manifest) != required or manifest["package"] != "loom":
            raise UpdateError("release manifest is for the wrong package or has unknown fields")
        if self.current_path.exists():
            current = self.current()
        else:
            current = None
        if type(manifest["release_sequence"]) is not int \
                or manifest["release_sequence"] < 1 \
                or (current is not None
                    and manifest["release_sequence"] <= current["release_sequence"]):
            raise UpdateError("release sequence is not newer than the active runtime")
        version = manifest["version"]
        if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
            raise UpdateError("release version is invalid")
        schema_range = manifest["schema_range"]
        if not isinstance(schema_range, dict) or set(schema_range) != {"minimum", "maximum"} \
                or not schema_range["minimum"] <= vault_schema <= schema_range["maximum"]:
            raise UpdateError("release is incompatible with the owner-vault schema")
        targets = manifest["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
            raise UpdateError("release target list is invalid")
        selected = [item for item in targets if isinstance(item, dict)
                    and item.get("platform") == platform_id()]
        if not selected:
            raise UpdateError("release has no target for this platform")
        expected_paths = set()
        total = 0
        for item in selected:
            if set(item) != {"platform", "path", "sha256", "bytes"}:
                raise UpdateError("release target has unknown or missing fields")
            relative = _relative(item["path"])
            if relative.as_posix() in expected_paths:
                raise UpdateError("release target path is duplicated")
            expected_paths.add(relative.as_posix())
            if type(item["bytes"]) is not int or not 1 <= item["bytes"] <= MAX_TARGET_BYTES:
                raise UpdateError("release target size is invalid")
            total += item["bytes"]
            if total > MAX_TARGET_BYTES:
                raise UpdateError("release payload exceeds total size bound")
            path = source.joinpath(*relative.parts)
            if not path.is_file() or _redirect(path):
                raise UpdateError("release target is missing or redirected")
            raw = path.read_bytes()
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise UpdateError("release target size or hash is invalid")
        observed = set()
        for path in loom_reliability._regular_files(source):
            observed.add(path.relative_to(source).as_posix())
        if observed != expected_paths:
            raise UpdateError("release payload contains unlisted files")

        final = self.versions / version
        staging = self.versions / f".{version}.staged-{uuid.uuid4().hex}"
        try:
            if final.exists():
                self._verify_existing_runtime(
                    final, version=version, manifest=manifest, selected=selected)
            else:
                staging.mkdir()
                archives = [path for path in expected_paths if path.endswith(".zip")]
                if archives:
                    if len(expected_paths) != 1:
                        raise UpdateError("an archived runtime must be the only platform target")
                    archive = source.joinpath(*PurePosixPath(archives[0]).parts)
                    _extract_runtime_archive(archive, staging)
                else:
                    for relative in sorted(expected_paths):
                        source_path = source.joinpath(*PurePosixPath(relative).parts)
                        target_path = staging.joinpath(*PurePosixPath(relative).parts)
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source_path, target_path)
                owned = [path.relative_to(staging).as_posix()
                         for path in loom_reliability._regular_files(staging)
                         if path.name not in {
                             ".loom-install-receipt.json", ".loom-runtime-receipt.json"}]
                install_receipt = loom_reliability.installation_receipt(
                    staging, owned, install_id=str(uuid.uuid4()))
                loom_reliability.atomic_write_json(
                    staging / ".loom-install-receipt.json", install_receipt)
                receipt = {"version": version, "release_sequence": manifest["release_sequence"],
                           "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
                           "targets": selected}
                loom_reliability.atomic_write_json(staging / ".loom-runtime-receipt.json", receipt)
                health = health_check(staging)
                health_fields = {"healthy", "migration_complete", "disposable_request_passed",
                                 "before_inventory_sha256", "after_inventory_sha256"}
                if not isinstance(health, dict) or set(health) != health_fields \
                        or health.get("healthy") is not True \
                        or health.get("migration_complete") is not True \
                        or health.get("disposable_request_passed") is not True \
                        or not re.fullmatch(
                            r"[0-9a-f]{64}", str(health.get("before_inventory_sha256", ""))) \
                        or health["before_inventory_sha256"] != health["after_inventory_sha256"]:
                    raise UpdateError("staged runtime health check failed")
                loom_reliability.atomic_write_json(
                    staging / ".loom-health-receipt.json", {
                        "schema_version": 1,
                        "version": version,
                        "manifest_sha256": receipt["manifest_sha256"],
                        **health,
                    })
                os.replace(staging, final)
            payload_hash = hashlib.sha256(_canonical(selected)).hexdigest()
            pending = {"version": version, "path": version,
                       "payload_sha256": payload_hash,
                       "release_sequence": manifest["release_sequence"],
                       "previous": ({key: current[key] for key in (
                           "version", "path", "payload_sha256", "release_sequence")}
                                    if current is not None else None)}
            loom_reliability.atomic_write_json(self.pending_path, pending)
            if self._active_sessions():
                return {"status": "staged-active-session", "version": version}
            return self.activate_pending()
        except BaseException:
            if staging.exists() and staging.is_dir() and staging.parent == self.versions:
                shutil.rmtree(staging)
            raise

    def activate_pending(self):
        if self._active_sessions():
            return {"status": "staged-active-session"}
        try:
            pending = json.loads(self.pending_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"status": "no-pending-update"}
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError(f"pending runtime pointer is invalid: {exc}") from exc
        if not isinstance(pending, dict) or set(pending) != {
                "version", "path", "payload_sha256", "release_sequence", "previous"} \
                or not (self.versions / str(pending.get("path"))).is_dir():
            raise UpdateError("pending runtime pointer is unsafe")
        loom_reliability.atomic_write_json(self.current_path, pending)
        self.pending_path.unlink()
        self._initialize_usage(pending["version"])
        return {"status": "activated", "version": pending["version"]}

    def prune_versions(self, *, now=None):
        current = self.current()
        usage = json.loads(self._usage_path(current["version"]).read_text(encoding="utf-8"))
        instant = _time(now) if now is not None else dt.datetime.now(dt.timezone.utc)
        age = instant - _time(usage.get("activated_at"))
        if usage.get("successful_sessions", 0) < 10 or age < dt.timedelta(days=30):
            return {"status": "retained", "removed": []}
        keep = {current["version"]}
        if isinstance(current.get("previous"), dict):
            keep.add(current["previous"]["version"])
        removed = []
        for directory in sorted(self.versions.iterdir()):
            if not directory.is_dir() or directory.name in keep:
                continue
            if _redirect(directory) or not VERSION_RE.fullmatch(directory.name) \
                    or not ((directory / ".loom-runtime-receipt.json").is_file()
                            or (directory / ".loom-baseline-receipt.json").is_file()):
                raise UpdateError("old runtime is not receipt-owned; refusing cleanup")
            shutil.rmtree(directory)
            self._usage_path(directory.name).unlink(missing_ok=True)
            removed.append(directory.name)
        return {"status": "pruned", "removed": removed}

    def rollback(self, reason):
        if not isinstance(reason, str) or not reason or self._active_sessions():
            raise UpdateError("rollback reason is invalid or a session is active")
        current = self.current()
        previous = current["previous"]
        if not isinstance(previous, dict) or set(previous) != {
                "version", "path", "payload_sha256", "release_sequence"} \
                or not (self.versions / previous["path"]).is_dir():
            raise UpdateError("no verified previous runtime is available")
        pointer = {**previous, "previous": None}
        loom_reliability.atomic_write_json(self.current_path, pointer)
        return {"status": "rolled-back", "version": previous["version"], "reason": reason}

    def record_trust_health(self, *, healthy, reason="runtime-health"):
        if type(healthy) is not bool or not isinstance(reason, str) or not reason:
            raise UpdateError("trust-health input is invalid")
        if healthy:
            self.failure_path.unlink(missing_ok=True)
            return {"status": "healthy", "failures": 0}
        current = self.current()
        try:
            receipt = json.loads(self.failure_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            receipt = {"version": current["version"], "failures": 0, "reason_hashes": []}
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError(f"trust failure receipt is invalid: {exc}") from exc
        if not isinstance(receipt, dict) or set(receipt) != {
                "version", "failures", "reason_hashes"}:
            raise UpdateError("trust failure receipt contract is invalid")
        if receipt["version"] != current["version"]:
            receipt = {"version": current["version"], "failures": 0, "reason_hashes": []}
        receipt["failures"] += 1
        receipt["reason_hashes"] = (receipt["reason_hashes"] + [
            hashlib.sha256(reason.encode("utf-8")).hexdigest()])[-3:]
        loom_reliability.atomic_write_json(self.failure_path, receipt)
        if receipt["failures"] >= 3 and current.get("previous") is not None:
            rolled = self.rollback("repeated-trust-health-failure")
            self.failure_path.unlink(missing_ok=True)
            return {**rolled, "failures": receipt["failures"]}
        return {"status": "failure-recorded", "failures": receipt["failures"]}
