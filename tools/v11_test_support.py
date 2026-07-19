"""Shared external build cache for the exact Loom vault-helper test source."""

import hashlib
import json
import os
import platform
import struct
import subprocess
import tempfile
import shutil
from pathlib import Path

import loom_reliability


MAX_CARGO_DIAGNOSTIC_CHARS = 4000
SOURCE_KEY_HEX_LENGTH = 64
RUST_COMPILER_STACK_BYTES = 64 * 1024 * 1024
BUILD_ENVIRONMENT_KEYS = (
    "CARGO", "CARGO_HOME", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTFLAGS",
    "SOURCE_DATE_EPOCH", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE",
)


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


def _compile_vault_helper(root, crate, target):
    """Build in a caller-owned target and return bounded actionable failures."""
    target = Path(target).resolve()
    target.mkdir(parents=True, exist_ok=True)
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    environment["RUST_MIN_STACK"] = str(RUST_COMPILER_STACK_BYTES)
    if os.name == "nt":
        environment["RUSTFLAGS"] = (environment.get("RUSTFLAGS", "")
                                     + " -C link-arg=/Brepro").strip()
    try:
        result = subprocess.run(
            ["cargo", "build", "--quiet", "--locked", "--release",
             "--manifest-path", str(crate / "Cargo.toml")], cwd=root,
            env=environment, capture_output=True, text=True,
            check=False, timeout=180)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("vault-helper build exceeded its 180-second bound") from exc
    if result.returncode != 0:
        diagnostic = "\n".join(
            item.strip() for item in (result.stdout, result.stderr) if item.strip())
        diagnostic = diagnostic[-MAX_CARGO_DIAGNOSTIC_CHARS:] or "no Cargo diagnostic"
        raise RuntimeError(
            f"vault-helper build failed with exit {result.returncode}: {diagnostic}")
    binary = target / "release" / (
        "loom-vault.exe" if os.name == "nt" else "loom-vault")
    if not binary.is_file():
        raise RuntimeError("vault-helper build produced no executable")
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
    source_files = [crate / "Cargo.toml", crate / "Cargo.lock", *sorted(
        (crate / "src").rglob("*.rs"))]
    if any(not path.is_file() for path in source_files):
        raise RuntimeError("vault-helper test source is incomplete")
    rustc = subprocess.run(
        ["rustc", "--version", "--verbose"], capture_output=True, text=True,
        timeout=15, check=True).stdout.encode("utf-8")
    build_policy = (b"release-v4-stack64-windows-brepro"
                    if os.name == "nt" else b"release-v4-stack64")
    digest = hashlib.sha256(
        rustc + b"\x00" + build_policy + b"\x00" + _build_environment_identity())
    for path in source_files:
        relative = path.relative_to(crate).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big") + relative)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    source_key = digest.hexdigest()
    cache_root = Path(tempfile.gettempdir()) / "loom-cargo-test-cache"
    artifact = cache_root / "artifacts" / source_key
    binary = artifact / "release" / ("loom-vault.exe" if os.name == "nt" else "loom-vault")
    receipt = artifact / "loom-test-helper-receipt.json"
    if not _cache_entry_valid(binary, receipt, source_key):
        lock = cache_root / "locks" / f"{source_key}.lock"
        with loom_reliability.exclusive_file_lock(lock, timeout=60):
            if not _cache_entry_valid(binary, receipt, source_key):
                target = cache_root / "builds" / source_key
                _reset_private_build_target(cache_root, target, source_key)
                built = _compile_vault_helper(root, crate, target)
                _publish_cached_helper(binary, receipt, source_key, built)
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
    system = platform.system().lower()
    machine = platform.machine().lower()
    family = {"windows": "windows", "darwin": "macos", "linux": "linux"}.get(system)
    architecture = "arm64" if machine in {"arm64", "aarch64"} else (
        "x64" if machine in {"amd64", "x86_64"} else None)
    return f"{family}-{architecture}" if family and architecture else None


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
