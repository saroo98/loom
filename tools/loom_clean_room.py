#!/usr/bin/env python3
"""Verify an exact public cut under a disposable home without maintainer state."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import loom_reliability
import loom_release_subject


class CleanRoomError(RuntimeError):
    pass


def _tail(value, *, limit=2400):
    value = value or ""
    return value[-limit:].replace("\x00", "\\0")


def _prepare_rust_environment(cut, home, environment):
    """Provision locked Rust inputs without exposing the maintainer home to the test."""
    manifest = cut / "vault-helper" / "Cargo.toml"
    lock = cut / "vault-helper" / "Cargo.lock"
    if not manifest.is_file() and not lock.is_file():
        return {}, None
    if not manifest.is_file() or not lock.is_file():
        raise CleanRoomError("public cut has incomplete Rust helper source")
    rustc = shutil.which("rustc")
    cargo = shutil.which("cargo")
    if not rustc or not cargo:
        raise CleanRoomError("clean-room Rust verification requires rustc and cargo")
    try:
        sysroot_result = subprocess.run(
            [rustc, "--print", "sysroot"], capture_output=True, text=True,
            timeout=30, check=True)
        sysroot = Path(sysroot_result.stdout.strip()).resolve()
        tool_bin = sysroot / "bin"
        direct_rustc = tool_bin / ("rustc.exe" if os.name == "nt" else "rustc")
        direct_cargo = tool_bin / ("cargo.exe" if os.name == "nt" else "cargo")
        if not direct_rustc.is_file() or not direct_cargo.is_file():
            raise CleanRoomError("resolved Rust toolchain is incomplete")
        rustc_version = subprocess.run(
            [str(direct_rustc), "--version", "--verbose"], capture_output=True,
            text=True, timeout=30, check=True).stdout.strip()
        cargo_version = subprocess.run(
            [str(direct_cargo), "--version"], capture_output=True, text=True,
            timeout=30, check=True).stdout.strip()
        vendor = home / "cargo-vendor"
        cargo_home = home / ".cargo"
        cargo_home.mkdir(parents=True)
        provision_home = home / ".cargo-provision"
        provision_environment = {
            key: value for key, value in os.environ.items()
            if not any(token in key.upper() for token in
                       ("TOKEN", "SECRET", "API_KEY", "PASSWORD"))
        }
        provision_environment.update({
            "HOME": str(home), "USERPROFILE": str(home),
            "CARGO_HOME": str(provision_home), "RUSTC": str(direct_rustc),
            "CARGO": str(direct_cargo),
            "PATH": os.pathsep.join([str(tool_bin), environment.get("PATH", "")]),
        })
        vendored = subprocess.run(
            [str(direct_cargo), "vendor", "--locked", "--manifest-path",
             str(manifest), str(vendor)], cwd=cut, env=provision_environment,
            capture_output=True, text=True, timeout=180, check=False)
        if vendored.returncode != 0:
            raise CleanRoomError(
                "could not vendor locked Rust inputs: "
                f"return code {vendored.returncode}; "
                f"stdout tail={_tail(vendored.stdout)!r}; "
                f"stderr tail={_tail(vendored.stderr)!r}")
        config = vendored.stdout.strip()
        if not config or not vendor.is_dir():
            raise CleanRoomError("Cargo did not produce a locked vendor fixture")
        (cargo_home / "config.toml").write_text(config + "\n", encoding="utf-8")
    except CleanRoomError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise CleanRoomError(f"could not provision clean-room Rust inputs: {exc}") from exc
    path_entries = [str(tool_bin)]
    for entry in environment.get("PATH", "").split(os.pathsep):
        if entry and Path(entry).resolve() != Path(cargo).resolve().parent:
            path_entries.append(entry)
    updates = {
        "PATH": os.pathsep.join(path_entries), "RUSTC": str(direct_rustc),
        "CARGO": str(direct_cargo), "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true",
    }
    metadata = {
        "rustc_sha256": hashlib.sha256(direct_rustc.read_bytes()).hexdigest(),
        "cargo_sha256": hashlib.sha256(direct_cargo.read_bytes()).hexdigest(),
        "rustc_version_sha256": hashlib.sha256(rustc_version.encode()).hexdigest(),
        "cargo_version_sha256": hashlib.sha256(cargo_version.encode()).hexdigest(),
        "locked_dependencies_vendored": True,
        "dependency_provisioning_network_blocked": False,
    }
    return updates, metadata


def _bounded_home_inventory(home):
    digest = hashlib.sha256(b"loom-clean-home-v1\0")
    count = 0
    total_bytes = 0
    sample = []
    for path in sorted(item for item in home.rglob("*") if item.is_file()):
        if path.is_symlink():
            raise CleanRoomError("disposable home contains a redirected file")
        relative = path.relative_to(home).as_posix()
        raw = path.read_bytes()
        row = json.dumps({"path": relative, "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()},
                         sort_keys=True, separators=(",", ":")).encode()
        digest.update(len(row).to_bytes(8, "big") + row)
        count += 1
        total_bytes += len(raw)
        if len(sample) < 32:
            sample.append(relative)
    return {"file_count": count, "bytes": total_bytes,
            "tree_sha256": digest.hexdigest(), "path_sample": sample}


def verify(cut, *, timeout=1500):
    cut = Path(cut).resolve()
    if not cut.is_dir() or (cut / ".git").exists() or (cut / ".loom").exists() \
            or not (cut / "tools" / "loom_release.py").is_file():
        raise CleanRoomError("clean-room subject is not an isolated public cut")
    before = loom_release_subject._tree(cut)
    with tempfile.TemporaryDirectory(prefix="loom-clean-home-") as temporary:
        home = Path(temporary)
        environment = {key: value for key, value in os.environ.items()
                       if not any(token in key.upper() for token in
                                  ("TOKEN", "SECRET", "API_KEY", "PASSWORD"))}
        environment.update({"HOME": str(home), "USERPROFILE": str(home),
                            "CODEX_HOME": str(home / ".codex"),
                            "PYTHONDONTWRITEBYTECODE": "1"})
        rust_environment, rust_metadata = _prepare_rust_environment(
            cut, home, environment)
        environment.update(rust_environment)
        try:
            result = subprocess.run(
                [sys.executable, "-B", str(cut / "tools" / "loom_release.py"),
                 "verify-cut", str(cut)], cwd=cut / "tools", env=environment,
                capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise CleanRoomError(f"clean-room verification failed to run: {exc}") from exc
        home_inventory = _bounded_home_inventory(home)
    after = loom_release_subject._tree(cut)
    if before != after:
        raise CleanRoomError("clean-room verification changed the public cut")
    passed = result.returncode == 0
    body = {"schema_version": 1, "evidence_class": "mechanical-local",
            "status": "passed" if passed else "failed", "subject_sha256": before["sha256"],
            "returncode": result.returncode,
            "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            "disposable_home": home_inventory,
            "maintainer_state_loaded": False, "network_isolation_proven": False,
            "rust_toolchain": rust_metadata,
            "limitations": [
                "Standard-library execution does not prove host-level network isolation.",
                "Locked public Rust dependencies may be fetched into the disposable workspace "
                "before the verification subprocess is forced offline.",
            ],
    }
    body["receipt_sha256"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not passed:
        raise CleanRoomError(
            "public cut failed clean-room verification: "
            f"return code {result.returncode}; "
            f"stdout tail={_tail(result.stdout)!r}; "
            f"stderr tail={_tail(result.stderr)!r}")
    return body


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cut")
    parser.add_argument("--timeout", type=int, default=1500)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.cut, timeout=args.timeout)
    except CleanRoomError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    try:
        loom_reliability.atomic_write_json(Path(args.output), result)
    except loom_reliability.ReliabilityError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "verified", "receipt_sha256": result["receipt_sha256"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
