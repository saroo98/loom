#!/usr/bin/env python3
"""Stable user-scoped Loom launcher; pins one runtime for each invocation."""

import argparse
import json
import os
import subprocess
import sys
import hashlib
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_update
import loom_adapter_bridge
import loom_adapter_protocol
import loom_host_registry
import loom_mcp_server
import loom_codex_integration
import loom_reliability


LOCAL_SKILL_PATHS = loom_host_registry.project_skill_paths()
MAX_HOOK_EVENT_BYTES = 256 * 1024


def _reject_local_shadow(cwd):
    current = Path(cwd).resolve()
    owner_home = Path.home().resolve()
    if not current.is_dir():
        raise RuntimeError("Loom project path is unavailable")
    while True:
        # Host-global skills live directly under the owner home. They are the
        # expected route, not a project-local shadow. Never scan above that
        # boundary for projects inside the owner's profile.
        if current == owner_home:
            return
        for relative in LOCAL_SKILL_PATHS:
            candidate = current.joinpath(*Path(relative).parts)
            if candidate.exists():
                raise RuntimeError(
                    f"unowned project-local Loom skill would cause split-brain execution: {candidate}")
        if (current / ".git").exists() or current.parent == current:
            return
        current = current.parent


def _current(home):
    home = Path(home).resolve()
    pointer = home / "runtime" / "current.json"
    try:
        value = json.loads(pointer.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Loom runtime pointer is unavailable: {exc}") from exc
    if not isinstance(value, dict) or value.get("path") != value.get("version"):
        raise RuntimeError("Loom runtime pointer is invalid")
    runtime = (home / "runtime" / "versions" / value["path"]).resolve()
    if not runtime.is_dir() or not runtime.is_relative_to((home / "runtime" / "versions").resolve()):
        raise RuntimeError("Loom runtime pointer escapes the version store")
    _verify_runtime(runtime, value["version"])
    return value, runtime


def _verify_runtime(runtime, version):
    manifest_path = runtime / "RUNTIME-MANIFEST.json"
    baseline_path = runtime / ".loom-baseline-receipt.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"runtime manifest is invalid: {exc}") from exc
        if not isinstance(manifest, dict) or set(manifest) != {
                "schema_version", "version", "platform", "files"} \
                or manifest["version"] != version or not isinstance(manifest["files"], list):
            raise RuntimeError("runtime manifest contract is invalid")
        expected = set()
        for item in manifest["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} \
                    or "\\" in item["path"] or item["path"].startswith("/") \
                    or ".." in Path(item["path"]).parts:
                raise RuntimeError("runtime manifest target is invalid")
            path = runtime.joinpath(*Path(item["path"]).parts)
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("runtime manifest target is missing or redirected")
            raw = path.read_bytes()
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise RuntimeError("active runtime bytes do not match their verified manifest")
            expected.add(item["path"].replace("\\", "/"))
        try:
            observed = {
                path.relative_to(runtime).as_posix()
                for path in loom_reliability._regular_files(runtime)
                if path.name not in {
                    "RUNTIME-MANIFEST.json", ".loom-runtime-receipt.json",
                    ".loom-install-receipt.json", ".loom-health-receipt.json"}
            }
        except loom_reliability.ReliabilityError as exc:
            raise RuntimeError(f"active runtime tree is unsafe: {exc}") from exc
        if observed != expected:
            raise RuntimeError("active runtime contains unlisted or missing files")
        return
    if baseline_path.is_file():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        content = runtime / str(baseline.get("path"))
        if baseline.get("version") != version or not content.is_file() \
                or hashlib.sha256(content.read_bytes()).hexdigest() != baseline.get("sha256"):
            raise RuntimeError("baseline runtime receipt does not match active bytes")
        try:
            observed = {
                path.relative_to(runtime).as_posix()
                for path in loom_reliability._regular_files(runtime)
            }
        except loom_reliability.ReliabilityError as exc:
            raise RuntimeError(f"active runtime tree is unsafe: {exc}") from exc
        if observed != {".loom-baseline-receipt.json", str(baseline.get("path"))}:
            raise RuntimeError("baseline runtime contains unlisted or missing files")
        return
    raise RuntimeError("active runtime has no verifiable content manifest")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("adapter-probe")
    probe.add_argument("--protocol-min", type=int, default=2)
    probe.add_argument("--protocol-max", type=int, default=2)
    sub.add_parser("bridge")
    sub.add_parser("mcp")
    sub.add_parser("hook-user-prompt")
    sub.add_parser("hook-session-start")
    sub.add_parser("hook-lifecycle")
    codex_install = sub.add_parser("codex-install")
    codex_install.add_argument("--approved", action="store_true")
    codex_install.add_argument("--standard-only", action="store_true")
    codex_install.add_argument("--hooks-only", action="store_true")
    codex_install.add_argument("--codex")
    codex_uninstall = sub.add_parser("codex-uninstall")
    codex_uninstall.add_argument("--approved", action="store_true")
    codex_uninstall.add_argument("--codex")
    sub.add_parser("invoke-stdio")
    sub.add_parser("resolve-stdio")
    complete = sub.add_parser("complete")
    complete.add_argument("--action", required=True)
    complete.add_argument("--usage")
    complete.add_argument("--result")
    cancel = sub.add_parser("cancel")
    cancel.add_argument("--action", required=True)
    args = parser.parse_args(argv)
    if args.command == "bridge":
        return loom_adapter_bridge.serve(args.home, Path(__file__).resolve())
    if args.command == "mcp":
        return loom_mcp_server.serve(args.home, Path(__file__).resolve())
    if args.command in {"hook-user-prompt", "hook-session-start", "hook-lifecycle"}:
        raw = sys.stdin.buffer.read(MAX_HOOK_EVENT_BYTES + 1)
        if len(raw) > MAX_HOOK_EVENT_BYTES:
            print(json.dumps({"decision": "block", "reason": "Loom hook event is oversized"}))
            return 0
        _pointer, runtime = _current(args.home)
        relative = {
            "hook-user-prompt": "scripts/loom_codex_prompt.py",
            "hook-session-start": "scripts/loom_bootstrap.py",
            "hook-lifecycle": "tools/loom_codex_lifecycle.py",
        }[args.command]
        handler = runtime.joinpath(*relative.split("/"))
        if not handler.is_file() or handler.is_symlink():
            print(json.dumps({"decision": "block", "reason": "Loom hook handler is unavailable"}))
            return 0
        environment = {**os.environ, "PLUGIN_ROOT": str(runtime),
                       "LOOM_HOME": str(Path(args.home).resolve())}
        command = [sys.executable, "-B", str(handler)]
        if args.command == "hook-lifecycle":
            command.extend(["--home", str(Path(args.home).resolve()),
                            "--install-root", str(runtime)])
        completed = subprocess.run(
            command, input=raw,
            capture_output=True, timeout=180, check=False, env=environment)
        sys.stdout.buffer.write(completed.stdout)
        sys.stdout.buffer.flush()
        return completed.returncode
    if args.command in {"codex-install", "codex-uninstall"}:
        user_home = Path(args.home).resolve().parent
        try:
            if args.command == "codex-install":
                if args.standard_only and args.hooks_only:
                    raise loom_codex_integration.IntegrationError(
                        "standard-only and hooks-only are mutually exclusive")
                result = loom_codex_integration.install(
                    user_home, args.home, approved=args.approved,
                    codex_executable=args.codex, verified=not args.standard_only,
                    manage_mcp=not args.hooks_only)
            else:
                result = loom_codex_integration.uninstall(
                    user_home, args.home, approved=args.approved,
                    codex_executable=args.codex)
        except loom_codex_integration.IntegrationError as exc:
            print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    envelope = None
    manager = None
    lease_data = None
    runtime_healthy = False
    trust_failure = None
    try:
        if args.command in {"invoke-stdio", "resolve-stdio"}:
            envelope = loom_adapter_protocol.read_single_frame(
                sys.stdin.buffer, message_type=(
                    "request-envelope" if args.command == "invoke-stdio" else "resolve"))
        manager = loom_update.SharedRuntime(args.home)
        if args.command in {"invoke-stdio", "resolve-stdio", "complete", "cancel"}:
            if args.command == "invoke-stdio":
                _reject_local_shadow(envelope["cwd"])
            lease_data = manager.begin_session()
            current, runtime = _current(args.home)
            if current["version"] != lease_data["version"]:
                raise RuntimeError("session runtime pin does not match the active pointer")
        else:
            lease_data = None
            current, runtime = _current(args.home)
        if args.command == "adapter-probe":
            selected = loom_adapter_protocol.negotiate({
                "minimum": args.protocol_min, "maximum": args.protocol_max})
            print(json.dumps({"status": "ready", "version": current["version"],
                              "release_sequence": current["release_sequence"],
                              "protocol_version": selected}, sort_keys=True))
            return 0
        orchestrator = runtime / "tools" / "loom_orchestrator.py"
        if not orchestrator.is_file():
            raise RuntimeError("active Loom runtime has no orchestrator")
        if args.command == "invoke-stdio":
            command = [
                sys.executable, "-B", str(orchestrator), "invoke-stdio",
                "--home", str(Path(args.home).resolve()), "--install-root", str(runtime)]
        elif args.command == "resolve-stdio":
            command = [
                sys.executable, "-B", str(orchestrator), "resolve-stdio",
                "--home", str(Path(args.home).resolve()), "--install-root", str(runtime)]
        elif args.command == "complete":
            command = [sys.executable, "-B", str(orchestrator), "complete",
                       "--action", args.action,
                       "--home", str(Path(args.home).resolve()),
                       "--install-root", str(runtime)]
            if args.usage:
                command.extend(["--usage", args.usage])
            if args.result:
                command.extend(["--result", args.result])
        else:
            command = [sys.executable, "-B", str(orchestrator), "cancel",
                       "--action", args.action, "--home", str(Path(args.home).resolve()),
                       "--install-root", str(runtime)]
        run_options = {"check": False}
        if envelope is not None:
            run_options["input"] = loom_adapter_protocol.canonical_bytes(envelope) + b"\n"
        result = subprocess.run(command, **run_options)
        runtime_healthy = result.returncode in {0, 2}
        if not runtime_healthy:
            trust_failure = f"runtime-exit-{result.returncode}"
        return result.returncode
    except (RuntimeError, loom_update.UpdateError,
            loom_adapter_protocol.ProtocolError) as exc:
        if isinstance(exc, RuntimeError):
            trust_failure = str(exc)
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True))
        return 2
    finally:
        if manager is not None and lease_data is not None:
            try:
                manager.end_session(lease_data["session_id"], successful=runtime_healthy)
                manager.record_trust_health(
                    healthy=trust_failure is None, reason=trust_failure or "runtime-healthy")
                manager.prune_versions()
            except loom_update.UpdateError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
