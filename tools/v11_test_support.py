"""Shared external build cache for the exact Loom vault-helper test source."""

import hashlib
import json
import os
import struct
import subprocess
import tempfile
import shutil
from functools import lru_cache
from pathlib import Path

import loom_reliability
import loom_operation_supervisor
import loom_update


MAX_CARGO_DIAGNOSTIC_CHARS = 4000
SOURCE_KEY_HEX_LENGTH = 64
RUST_COMPILER_STACK_BYTES = 64 * 1024 * 1024
RUSTC_IDENTITY_TIMEOUT_SECONDS = 60
VAULT_HELPER_BUILD_TIMEOUT_SECONDS = 600 if os.name == "nt" else 300
BUILD_ENVIRONMENT_KEYS = (
    "CARGO", "CARGO_HOME", "CARGO_ENCODED_RUSTFLAGS", "CARGO_INCREMENTAL",
    "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "RUSTC", "RUSTFLAGS",
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUST_MIN_STACK",
    "RUSTUP_TOOLCHAIN",
    "SOURCE_DATE_EPOCH", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE",
    "PATH", "INCLUDE", "LIB", "LIBPATH", "VCINSTALLDIR", "VCToolsInstallDir",
    "WindowsSdkDir", "WindowsSDKVersion", "LOOM_TEST_CACHE_ROOT",
    "CARGO_BUILD_JOBS", "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
    "RUSTUP_HOME", "AR", "CC", "CFLAGS", "CXX", "CXXFLAGS", "LDFLAGS",
    "DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT",
)
NATIVE_HELPER_PUBLIC_ERROR_CODES = frozenset({
    "NATIVE_HELPER_BUILD_CANCELLED",
    "NATIVE_HELPER_BUILD_CONTAINMENT_FAILURE",
    "NATIVE_HELPER_BUILD_NONZERO",
    "NATIVE_HELPER_BUILD_OUTPUT_MISSING",
    "NATIVE_HELPER_BUILD_SOURCE_MUTATION",
    "NATIVE_HELPER_BUILD_START_FAILED",
    "NATIVE_HELPER_BUILD_SURVIVOR",
    "NATIVE_HELPER_BUILD_TIMEOUT",
    "NATIVE_HELPER_BUILD_TRANSCRIPT_LIMIT",
    "NATIVE_HELPER_CACHE_LOCK_FAILED",
    "NATIVE_HELPER_CACHE_ROOT_INVALID",
    "NATIVE_HELPER_PUBLISH_FAILED",
    "NATIVE_HELPER_RUSTC_IDENTITY_FAILED",
    "NATIVE_HELPER_RUSTC_IDENTITY_TIMEOUT",
    "NATIVE_HELPER_SOURCE_INCOMPLETE",
    "NATIVE_HELPER_TARGET_RESET_FAILED",
})


class NativeHelperBuildError(RuntimeError):
    """Privacy-safe native-helper phase failure with a stable public code."""

    def __init__(self, code, message, *, receipt=None):
        if code not in NATIVE_HELPER_PUBLIC_ERROR_CODES:
            raise ValueError("native-helper error code is invalid")
        super().__init__(message)
        self.code = code
        self.receipt = receipt


def native_helper_operation_projection(error):
    """Return only the self-bound public fields of a verified build receipt."""
    if not isinstance(error, NativeHelperBuildError):
        return None
    try:
        receipt = loom_operation_supervisor.verify_receipt(error.receipt)
    except loom_operation_supervisor.SupervisorError:
        return None
    if receipt["operation_class"] != "vault-helper-build":
        return None
    body = {
        "operation_receipt_sha256": receipt["receipt_sha256"],
        "status": receipt["status"],
        "returncode": receipt["returncode"],
        "primary_failure": receipt["primary_failure"],
        "survivors_confirmed_zero": receipt["survivors_confirmed_zero"],
        "protected_roots_unchanged": receipt["protected_roots_unchanged"],
        "network_isolation_proven": receipt["network_isolation_proven"],
        "containment_provider": receipt["containment_provider"],
    }
    return {**body, "projection_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()}


def _cache_entry_valid(binary, receipt, source_key):
    if not binary.is_file() or not receipt.is_file():
        return False
    try:
        value = json.loads(receipt.read_text(encoding="utf-8"))
        return value == {
            "source_key": source_key,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False


def _build_environment_identity(environment=None):
    """Bind cached native bytes to every path or flag that can affect them."""
    environment = os.environ if environment is None else environment
    values = {key: environment.get(key) for key in BUILD_ENVIRONMENT_KEYS}
    cargo_home = environment.get("CARGO_HOME")
    configs = {}
    if cargo_home:
        root = Path(cargo_home)
        for name in ("config", "config.toml"):
            path = root / name
            if path.is_file() and not path.is_symlink():
                configs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return json.dumps(
        {"environment": values, "cargo_configs": configs},
        sort_keys=True, separators=(",", ":")).encode("utf-8")


def _version_key(path):
    pieces = []
    for item in path.name.split("."):
        try:
            pieces.append(int(item))
        except ValueError:
            pieces.append(-1)
    return tuple(pieces)


def _msvc_environment_from_roots(environment, installation, windows_sdk):
    """Build the minimum native x64 environment from verified local roots."""
    installation = Path(installation).resolve()
    windows_sdk = Path(windows_sdk).resolve()
    msvc_parent = installation / "VC" / "Tools" / "MSVC"
    sdk_lib_parent = windows_sdk / "Lib"
    if not msvc_parent.is_dir() or not sdk_lib_parent.is_dir():
        return None
    msvc_candidates = sorted(
        (item for item in msvc_parent.iterdir() if item.is_dir()),
        key=_version_key, reverse=True)
    sdk_candidates = sorted(
        (item for item in sdk_lib_parent.iterdir() if item.is_dir()),
        key=_version_key, reverse=True)
    for msvc in msvc_candidates:
        linker = msvc / "bin" / "Hostx64" / "x64" / "link.exe"
        if not linker.is_file():
            continue
        for sdk_lib in sdk_candidates:
            sdk_version = sdk_lib.name
            sdk_include = windows_sdk / "Include" / sdk_version
            required = (
                msvc / "include",
                msvc / "lib" / "x64",
                sdk_include / "ucrt",
                sdk_include / "shared",
                sdk_include / "um",
                sdk_lib / "ucrt" / "x64",
                sdk_lib / "um" / "x64",
            )
            if not all(path.is_dir() for path in required):
                continue
            result = dict(environment)
            path_entries = [
                msvc / "bin" / "Hostx64" / "x64",
                windows_sdk / "bin" / sdk_version / "x64",
            ]
            result["PATH"] = os.pathsep.join(
                [*(str(path) for path in path_entries if path.is_dir()),
                 environment.get("PATH", "")])
            result["INCLUDE"] = os.pathsep.join(str(path) for path in (
                msvc / "include", sdk_include / "ucrt",
                sdk_include / "shared", sdk_include / "um",
                sdk_include / "winrt") if path.is_dir())
            result["LIB"] = os.pathsep.join(str(path) for path in (
                msvc / "lib" / "x64", sdk_lib / "ucrt" / "x64",
                sdk_lib / "um" / "x64"))
            result["LIBPATH"] = str(msvc / "lib" / "x64")
            result["VCINSTALLDIR"] = str(installation / "VC") + os.sep
            result["VCToolsInstallDir"] = str(msvc) + os.sep
            result["WindowsSdkDir"] = str(windows_sdk) + os.sep
            result["WindowsSDKVersion"] = sdk_version + os.sep
            result["CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"] = str(linker)
            return result
    return None


def _windows_toolchain_roots(environment):
    program_files_x86 = Path(environment.get(
        "ProgramFiles(x86)", r"C:\Program Files (x86)"))
    program_files = Path(environment.get("ProgramFiles", r"C:\Program Files"))
    visual_studio_roots = tuple(dict.fromkeys(
        root / "Microsoft Visual Studio"
        for root in (program_files_x86, program_files)))
    vswhere_candidates = (
        root / "Installer" / "vswhere.exe" for root in visual_studio_roots)
    installations = []
    for vswhere in vswhere_candidates:
        if not vswhere.is_file():
            continue
        try:
            result = subprocess.run([
                str(vswhere), "-latest", "-prerelease", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property", "installationPath",
            ], capture_output=True, text=True, timeout=30, check=False)
            if result.returncode == 0 and result.stdout.strip():
                installations.append(Path(result.stdout.strip()))
        except (OSError, subprocess.TimeoutExpired):
            pass
    for visual_studio in visual_studio_roots:
        if visual_studio.is_dir():
            installations.extend(
                product for year in visual_studio.iterdir() if year.is_dir()
                for product in year.iterdir() if product.is_dir())
    unique = list(dict.fromkeys(
        Path(os.path.abspath(os.fspath(item))) for item in installations))
    sdk_candidates = (
        root / "Windows Kits" / "10"
        for root in (program_files_x86, program_files))
    sdk = next((item for item in sdk_candidates if item.is_dir()),
               program_files_x86 / "Windows Kits" / "10")
    return unique, sdk


def _is_windows_host():
    return os.name == "nt"


def _native_build_environment(environment=None):
    """Return a build environment that is hermetic but can find native tools."""
    environment = dict(os.environ if environment is None else environment)
    if not _is_windows_host():
        return environment
    installations, sdk = _windows_toolchain_roots(environment)
    for installation in installations:
        result = _msvc_environment_from_roots(environment, installation, sdk)
        if result is not None:
            return result
    return environment


def _test_cache_root():
    configured = os.environ.get("LOOM_TEST_CACHE_ROOT")
    if not configured:
        return Path(tempfile.gettempdir()).resolve() / "loom-cargo-test-cache"
    lexical = Path(os.path.abspath(configured))
    if not lexical.is_absolute() or lexical.is_symlink():
        raise RuntimeError("vault-helper test cache root is unsafe")
    lexical.mkdir(parents=True, exist_ok=True)
    resolved = lexical.resolve()
    if resolved != lexical:
        raise RuntimeError("vault-helper test cache root is redirected")
    return resolved


@lru_cache(maxsize=1)
def _rustc_identity():
    """Read the compiler identity once per suite with a contention-tolerant bound."""
    try:
        result = subprocess.run(
            ["rustc", "--version", "--verbose"], capture_output=True, text=True,
            timeout=RUSTC_IDENTITY_TIMEOUT_SECONDS, check=True)
    except subprocess.TimeoutExpired as exc:
        raise NativeHelperBuildError(
            "NATIVE_HELPER_RUSTC_IDENTITY_TIMEOUT",
            "rustc identity probe exceeded its 60-second bound") from exc
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NativeHelperBuildError(
            "NATIVE_HELPER_RUSTC_IDENTITY_FAILED",
            "rustc identity probe failed") from exc
    return result.stdout.encode("utf-8")


def _native_build_child_environment(environment):
    """Project native tool inputs onto the supervisor's closed environment."""
    return {
        key: value for key in BUILD_ENVIRONMENT_KEYS
        if isinstance((value := environment.get(key)), str)
    }


def _native_build_failure(receipt, stdout, stderr):
    primary = receipt.get("primary_failure")
    if receipt.get("protected_roots_unchanged") is not True \
            or primary == "protected-root-changed":
        return NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_SOURCE_MUTATION",
            "vault-helper build changed protected source bytes", receipt=receipt)
    if receipt.get("survivors_confirmed_zero") is not True \
            or primary == "survivor-census-indeterminate":
        return NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_SURVIVOR",
            "vault-helper build descendant cleanup was not proven", receipt=receipt)
    if receipt.get("secondary_failures"):
        return NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_CONTAINMENT_FAILURE",
            "vault-helper build containment did not finish cleanly", receipt=receipt)
    if primary == "timed-out":
        return NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_TIMEOUT",
            "vault-helper build exceeded its "
            f"{VAULT_HELPER_BUILD_TIMEOUT_SECONDS}-second bound",
            receipt=receipt)
    if primary == "nonzero-exit":
        diagnostic = "\n".join(
            item.decode("utf-8", errors="replace").strip()
            for item in (stdout, stderr) if item.strip())
        diagnostic = diagnostic[-MAX_CARGO_DIAGNOSTIC_CHARS:] \
            or "no Cargo diagnostic"
        return NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_NONZERO",
            f"vault-helper build failed with exit {receipt.get('returncode')}: "
            f"{diagnostic}", receipt=receipt)
    code, message = {
        "transcript-limit": (
            "NATIVE_HELPER_BUILD_TRANSCRIPT_LIMIT",
            "vault-helper build exceeded its diagnostic output bound"),
        "start-failed": (
            "NATIVE_HELPER_BUILD_START_FAILED",
            "vault-helper build could not start"),
        "cancelled": (
            "NATIVE_HELPER_BUILD_CANCELLED",
            "vault-helper build was cancelled"),
    }.get(primary, (
        "NATIVE_HELPER_BUILD_CONTAINMENT_FAILURE",
        "vault-helper build containment failed"))
    return NativeHelperBuildError(code, message, receipt=receipt)


def _compile_vault_helper(root, crate, target, environment=None):
    """Build in a caller-owned target and return bounded actionable failures."""
    target = Path(target).resolve()
    target.mkdir(parents=True, exist_ok=True)
    environment = {
        **_native_build_environment(environment),
        "CARGO_TARGET_DIR": str(target),
    }
    environment.setdefault("CARGO_BUILD_JOBS", "1")
    environment["RUST_MIN_STACK"] = str(RUST_COMPILER_STACK_BYTES)
    if os.name == "nt":
        environment["RUSTFLAGS"] = (environment.get("RUSTFLAGS", "")
                                     + " -C link-arg=/Brepro").strip()
    command = [
        "cargo", "build", "--quiet", "--locked", "--release",
        "--manifest-path", str(crate / "Cargo.toml")]
    try:
        receipt, stdout, stderr = loom_operation_supervisor.run(
            operation_class="vault-helper-build", command=command, cwd=root,
            timeout=VAULT_HELPER_BUILD_TIMEOUT_SECONDS,
            environment=_native_build_child_environment(environment),
            allowed_roots=[Path(root).resolve(), target],
            protected_roots=[Path(crate).resolve()],
            capabilities=["local-process", "descendant-containment"],
            max_transcript_bytes=loom_operation_supervisor.MAX_TRANSCRIPT_BYTES,
            capture_output=True)
    except loom_operation_supervisor.SupervisorError as exc:
        raise NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_START_FAILED",
            "vault-helper build could not start") from exc
    if receipt.get("status") != "passed" or receipt.get("returncode") != 0 \
            or receipt.get("primary_failure") is not None \
            or receipt.get("survivors_confirmed_zero") is not True \
            or receipt.get("protected_roots_unchanged") is not True \
            or receipt.get("secondary_failures"):
        raise _native_build_failure(receipt, stdout, stderr)
    binary = target / "release" / (
        "loom-vault.exe" if os.name == "nt" else "loom-vault")
    if not binary.is_file():
        raise NativeHelperBuildError(
            "NATIVE_HELPER_BUILD_OUTPUT_MISSING",
            "vault-helper build produced no executable", receipt=receipt)
    return binary


def _publish_cached_helper(binary, receipt, source_key, built):
    """Publish one complete helper generation while the source lock is held."""
    binary.parent.mkdir(parents=True, exist_ok=True)
    staged = binary.with_name(f".{binary.name}.{os.getpid()}.staged")
    shutil.copy2(built, staged)
    os.replace(staged, binary)
    loom_reliability.atomic_write_json(receipt, {
        "source_key": source_key,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    })
    return binary


def _reset_private_build_target(cache_root, target, source_key):
    """Delete only Loom's source-keyed transient build directory."""
    cache_root = Path(cache_root).resolve()
    lexical_builds = cache_root / "builds"
    lexical_target = Path(os.path.abspath(os.fspath(target)))
    if lexical_builds.is_symlink() or lexical_target.is_symlink():
        raise RuntimeError("vault-helper private build target is redirected")
    builds = lexical_builds.resolve()
    target = lexical_target.resolve()
    if len(source_key) != SOURCE_KEY_HEX_LENGTH \
            or any(character not in "0123456789abcdef" for character in source_key) \
            or target != builds / source_key:
        raise RuntimeError("vault-helper private build target is unsafe")
    if target.exists():
        shutil.rmtree(target)


def build_vault_helper(root):
    root = Path(root).resolve()
    crate = root / "vault-helper"
    source_files = [root / "rust-toolchain.toml", crate / "Cargo.toml",
                    crate / "Cargo.lock", *sorted(
                        (crate / "src").rglob("*.rs"))]
    if any(not path.is_file() for path in source_files):
        raise NativeHelperBuildError(
            "NATIVE_HELPER_SOURCE_INCOMPLETE",
            "vault-helper test source is incomplete")
    build_environment = _native_build_environment()
    build_policy = (b"release-v4-stack64-windows-brepro"
                    if os.name == "nt" else b"release-v4-stack64")
    digest = hashlib.sha256(
        build_policy + b"\x00" + _build_environment_identity(build_environment))
    for path in source_files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big") + relative)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    source_key = digest.hexdigest()
    try:
        cache_root = _test_cache_root()
    except (OSError, RuntimeError) as exc:
        raise NativeHelperBuildError(
            "NATIVE_HELPER_CACHE_ROOT_INVALID",
            "vault-helper test cache root is invalid") from exc
    artifact = cache_root / "artifacts" / source_key
    binary = artifact / "release" / ("loom-vault.exe" if os.name == "nt" else "loom-vault")
    receipt = artifact / "loom-test-helper-receipt.json"
    if not _cache_entry_valid(binary, receipt, source_key):
        lock = cache_root / "locks" / f"{source_key}.lock"
        try:
            with loom_reliability.exclusive_file_lock(lock, timeout=60):
                if not _cache_entry_valid(binary, receipt, source_key):
                    target = cache_root / "builds" / source_key
                    try:
                        _reset_private_build_target(cache_root, target, source_key)
                    except (OSError, RuntimeError) as exc:
                        raise NativeHelperBuildError(
                            "NATIVE_HELPER_TARGET_RESET_FAILED",
                            "vault-helper private build target reset failed") from exc
                    built = _compile_vault_helper(
                        root, crate, target, environment=build_environment)
                    try:
                        _publish_cached_helper(
                            binary, receipt, source_key, built)
                    except (OSError, RuntimeError) as exc:
                        raise NativeHelperBuildError(
                            "NATIVE_HELPER_PUBLISH_FAILED",
                            "vault-helper cache publication failed") from exc
        except NativeHelperBuildError:
            raise
        except (OSError, RuntimeError) as exc:
            raise NativeHelperBuildError(
                "NATIVE_HELPER_CACHE_LOCK_FAILED",
                "vault-helper cache lock failed") from exc
    return binary


def _clean_rebuild_vault_helper(root, helper):
    """Rebuild at the same private path without deleting the shared artifact."""
    helper = Path(helper).resolve()
    expected = hashlib.sha256(helper.read_bytes()).hexdigest()
    root = Path(root).resolve()
    crate = root / "vault-helper"
    source_key = helper.parent.parent.name
    cache_root = helper.parent.parent.parent.parent
    if helper.parent.parent.parent.name != "artifacts":
        raise RuntimeError("vault-helper cache layout is invalid")
    target = cache_root / "builds" / source_key
    lock = cache_root / "locks" / f"{source_key}.lock"
    with loom_reliability.exclusive_file_lock(lock, timeout=60):
        _reset_private_build_target(cache_root, target, source_key)
        rebuilt = _compile_vault_helper(root, crate, target)
        observed = hashlib.sha256(rebuilt.read_bytes()).hexdigest()
    if observed != expected:
        raise RuntimeError("clean vault-helper release rebuild is not reproducible")
    return helper


def _platform_fixture(platform_id):
    """Generate a minimal deterministic 64-bit executable header for package tests."""
    data = bytearray(256)
    if platform_id.startswith("windows-"):
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", data, 0x84,
                         0x8664 if platform_id.endswith("-x64") else 0xAA64)
    elif platform_id.startswith("linux-"):
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18,
                         62 if platform_id.endswith("-x64") else 183)
    elif platform_id.startswith("macos-"):
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4,
                         0x01000007 if platform_id.endswith("-x64") else 0x0100000C)
    else:
        raise RuntimeError(f"unknown package fixture platform: {platform_id}")
    data[224:] = b"LOOM-PACKAGE-TEST-FIXTURE-V1\x00\x00\x00\x00"
    return bytes(data)


def _host_platform():
    try:
        return loom_update.platform_id()
    except loom_update.UpdateError:
        return None


def package_evidence(root, directory, platforms, *, native_helper=None):
    """Create isolated, platform-correct package fixtures and evidence.

    Each helper and rebuild is generated independently.  Real release evidence is
    produced by native CI jobs; these bounded fixtures exercise package contracts
    without relabelling a host executable as another operating system.
    """
    import loom_plugin_package
    import loom_reliability
    import loom_sbom

    root = Path(root).resolve()
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    commit = package_source_commit(root)
    source_digest = loom_plugin_package._source_digest(root)
    lock_digest = loom_reliability.file_sha256(root / "vault-helper" / "Cargo.lock")
    helpers = {}
    evidence = {}
    receipts = {}
    for platform_id in platforms:
        binary_name = loom_plugin_package.PLATFORMS[platform_id]
        is_native = native_helper is not None and platform_id == _host_platform()
        if is_native:
            helper = _clean_rebuild_vault_helper(root, native_helper)
            rebuild = directory / f"{platform_id}-rebuild" / binary_name
            rebuild.parent.mkdir(parents=True)
            shutil.copyfile(helper, rebuild)
        else:
            helper = directory / f"{platform_id}-helper" / binary_name
            helper.parent.mkdir(parents=True)
            helper.write_bytes(_platform_fixture(platform_id))
            rebuild = directory / f"{platform_id}-rebuild" / binary_name
            rebuild.parent.mkdir(parents=True)
            rebuild.write_bytes(_platform_fixture(platform_id))
        binary_digest = loom_reliability.file_sha256(helper)
        if binary_digest != loom_reliability.file_sha256(rebuild):
            raise RuntimeError("independent package fixture generation did not reproduce")
        sbom = directory / f"{platform_id}.spdx.json"
        loom_sbom.generate(
            root, helper, platform_id, sbom, namespace_seed=source_digest)
        provenance = directory / f"{platform_id}.provenance.json"
        provenance.write_text(json.dumps({
            "schema_version": 1,
            "repository": "https://github.com/saroo98/loom",
            "commit": commit,
            "platform": platform_id,
            "binary_sha256": binary_digest,
            "source_sha256": source_digest,
            "cargo_lock_sha256": lock_digest,
            "independent_build": True,
            "builder": {"id": ("test-native-release-build" if is_native
                                 else "test-platform-fixture-generator"),
                "run_id": platform_id},
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        helpers[platform_id] = helper
        evidence[platform_id] = {
            "rebuild": rebuild, "sbom": sbom, "provenance": provenance}
        receipts[platform_id] = {
            "platform": platform_id,
            "binary_sha256": binary_digest,
            "rebuild_sha256": loom_reliability.file_sha256(rebuild),
            "source_sha256": source_digest,
            "cargo_lock_sha256": lock_digest,
            "sbom_sha256": loom_reliability.file_sha256(sbom),
            "provenance_sha256": loom_reliability.file_sha256(provenance),
        }
    return helpers, receipts, evidence


def package_source_commit(root):
    """Return the real commit or a deterministic test identity for a Git-free public cut."""
    root = Path(root).resolve()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=10, check=False)
        candidate = result.stdout.strip()
        if result.returncode == 0 and len(candidate) == 40 \
                and all(character in "0123456789abcdef" for character in candidate):
            return candidate
    except (OSError, subprocess.TimeoutExpired):
        pass
    digest = hashlib.sha256(b"loom-git-free-test-fixture-v1")
    for path in [root / "VERSION", root / "vault-helper" / "Cargo.lock"]:
        raw = path.read_bytes()
        digest.update(len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()[:40]
