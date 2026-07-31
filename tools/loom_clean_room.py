#!/usr/bin/env python3
"""Verify an exact public cut under a disposable home without maintainer state."""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import loom_reliability
import loom_release
import loom_release_subject
import loom_operation_supervisor
import loom_operation_envelope


class CleanRoomError(RuntimeError):
    pass


MAX_VERIFY_RECEIPT_BYTES = 2 * 1024 * 1024
CLEAN_ROOM_MAX_SECONDS = loom_release.FULL_SUITE_MAX_SECONDS + 300


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
    def run_tool(command, *, cwd=cut, child_environment=environment, timeout=30):
        receipt, stdout, stderr = loom_operation_envelope.run_supervised(
            operation_class="clean-room-toolchain",
            command=command, cwd=Path(cwd).resolve(), environment=child_environment,
            timeout=timeout, allowed_roots=[cut, home],
            capabilities=["local-process", "descendant-containment"],
            capture_output=True)
        return receipt, stdout.decode("utf-8", errors="replace"), \
            stderr.decode("utf-8", errors="replace")
    try:
        sysroot_receipt, sysroot_stdout, sysroot_stderr = run_tool(
            [rustc, "--print", "sysroot"])
        if sysroot_receipt["status"] != "passed":
            raise CleanRoomError(
                "could not resolve the Rust sysroot: " + _tail(sysroot_stderr))
        sysroot = Path(sysroot_stdout.strip()).resolve()
        tool_bin = sysroot / "bin"
        direct_rustc = tool_bin / ("rustc.exe" if os.name == "nt" else "rustc")
        direct_cargo = tool_bin / ("cargo.exe" if os.name == "nt" else "cargo")
        if not direct_rustc.is_file() or not direct_cargo.is_file():
            raise CleanRoomError("resolved Rust toolchain is incomplete")
        rustc_receipt, rustc_stdout, rustc_stderr = run_tool(
            [str(direct_rustc), "--version", "--verbose"])
        cargo_receipt, cargo_stdout, cargo_stderr = run_tool(
            [str(direct_cargo), "--version"])
        if rustc_receipt["status"] != "passed" or cargo_receipt["status"] != "passed":
            raise CleanRoomError(
                "resolved Rust toolchain is not executable: "
                + _tail(rustc_stderr + cargo_stderr))
        rustc_version = rustc_stdout.strip()
        cargo_version = cargo_stdout.strip()
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
        vendored, vendored_stdout, vendored_stderr = run_tool(
            [str(direct_cargo), "vendor", "--locked", "--manifest-path",
             str(manifest), str(vendor)], child_environment=provision_environment,
            timeout=180)
        if vendored["status"] != "passed":
            raise CleanRoomError(
                "could not vendor locked Rust inputs: "
                f"return code {vendored['returncode']}; "
                f"stdout tail={_tail(vendored_stdout)!r}; "
                f"stderr tail={_tail(vendored_stderr)!r}")
        config = vendored_stdout.strip()
        if not config or not vendor.is_dir():
            raise CleanRoomError("Cargo did not produce a locked vendor fixture")
        (cargo_home / "config.toml").write_text(config + "\n", encoding="utf-8")
    except CleanRoomError:
        raise
    except (OSError, loom_operation_supervisor.SupervisorError) as exc:
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


def verify(cut, *, timeout=CLEAN_ROOM_MAX_SECONDS):
    cut = Path(cut).resolve()
    if not cut.is_dir() or (cut / ".git").exists() or (cut / ".loom").exists() \
            or not (cut / "tools" / "loom_release.py").is_file():
        raise CleanRoomError("clean-room subject is not an isolated public cut")
    before = loom_release_subject._tree(cut)
    with tempfile.TemporaryDirectory(prefix="loom-clean-home-") as temporary:
        home = Path(temporary)
        disposable_temp = home / "tmp"
        disposable_temp.mkdir()
        environment = loom_operation_supervisor.minimal_environment({
            "HOME": str(home), "USERPROFILE": str(home),
            "CODEX_HOME": str(home / ".codex"),
            "TMPDIR": str(disposable_temp),
            "TEMP": str(disposable_temp),
            "TMP": str(disposable_temp),
        })
        rust_environment, rust_metadata = _prepare_rust_environment(
            cut, home, environment)
        environment.update(rust_environment)
        real_home = Path.home().resolve()
        protected = [
            path for path in (
                real_home / ".loom",
                real_home / ".codex" / "config.toml",
                real_home / ".codex" / "hooks.json",
            ) if path.exists()
        ]
        try:
            verification_output = home / "verify-cut.json"
            operation, stdout, stderr = loom_operation_envelope.run_supervised(
                operation_class="clean-room-verification",
                command=[
                    sys.executable, "-B", str(cut / "tools" / "loom_release.py"),
                    "verify-cut", str(cut), "--output", str(verification_output),
                ],
                cwd=cut / "tools", environment=environment, timeout=timeout,
                allowed_roots=[cut, home], protected_roots=protected,
                capabilities=["local-process", "descendant-containment"],
                capture_output=True)
            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
        except (OSError, loom_operation_supervisor.SupervisorError) as exc:
            raise CleanRoomError(f"clean-room verification failed to run: {exc}") from exc
        verification = None
        if operation["status"] == "passed":
            try:
                info = verification_output.lstat()
                if verification_output.is_symlink() or not verification_output.is_file() \
                        or info.st_size <= 0 or info.st_size > MAX_VERIFY_RECEIPT_BYTES:
                    raise CleanRoomError(
                        "clean-room verification receipt is missing or unsafe")
                verification = json.loads(
                    verification_output.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise CleanRoomError(
                    f"clean-room verification receipt is unreadable: {exc}") from exc
            if not isinstance(verification, dict) \
                    or verification.get("status") != "verified":
                raise CleanRoomError(
                    "clean-room verification receipt did not report success")
        home_inventory = _bounded_home_inventory(home)
    after = loom_release_subject._tree(cut)
    if before != after:
        raise CleanRoomError("clean-room verification changed the public cut")
    passed = operation["status"] == "passed"
    body = {"schema_version": 1, "evidence_class": "mechanical-local",
            "status": "passed" if passed else "failed", "subject_sha256": before["sha256"],
            "returncode": operation["returncode"],
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "disposable_home": home_inventory,
            "maintainer_state_loaded": False, "network_isolation_proven": False,
            "rust_toolchain": rust_metadata,
            "operation_receipt_sha256": operation["receipt_sha256"],
            "containment_provider": operation["containment_provider"],
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
            f"return code {operation['returncode']}; "
            f"failure={operation['primary_failure']}; "
            f"stdout tail={_tail(stdout_text)!r}; "
            f"stderr tail={_tail(stderr_text)!r}")
    return body


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cut")
    parser.add_argument("--timeout", type=int, default=CLEAN_ROOM_MAX_SECONDS)
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
