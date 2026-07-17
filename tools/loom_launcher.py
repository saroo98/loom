#!/usr/bin/env python3
"""Stable user-scoped Loom launcher; pins one runtime for each invocation."""

import argparse
import json
import os
import subprocess
import sys
import re
import hashlib
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_update
import loom_adapter_bridge
import loom_adapter_protocol


LOCAL_SKILL_PATHS = (
    ".codex/skills/loom/SKILL.md", ".agents/skills/loom/SKILL.md",
    ".claude/skills/loom/SKILL.md", ".cursor/skills/loom/SKILL.md",
    ".gemini/skills/loom/SKILL.md", ".github/skills/loom/SKILL.md",
    ".factory/skills/loom/SKILL.md", ".opencode/skills/loom/SKILL.md",
)


def _reject_local_shadow(cwd):
    current = Path(cwd).resolve()
    if not current.is_dir():
        raise RuntimeError("Loom project path is unavailable")
    while True:
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
        observed = {path.relative_to(runtime).as_posix() for path in runtime.rglob("*")
                    if path.is_file() and path.name not in {
                        "RUNTIME-MANIFEST.json", ".loom-runtime-receipt.json",
                        ".loom-install-receipt.json", ".loom-health-receipt.json"}}
        if observed != expected:
            raise RuntimeError("active runtime contains unlisted or missing files")
        return
    if baseline_path.is_file():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        content = runtime / str(baseline.get("path"))
        if baseline.get("version") != version or not content.is_file() \
                or hashlib.sha256(content.read_bytes()).hexdigest() != baseline.get("sha256"):
            raise RuntimeError("baseline runtime receipt does not match active bytes")
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
    invoke = sub.add_parser("invoke")
    invoke.add_argument("--request", required=True)
    invoke.add_argument("--cwd", required=True)
    invoke.add_argument("--agent", required=True)
    invoke.add_argument("--agent-version", default="unknown")
    complete = sub.add_parser("complete")
    complete.add_argument("--action", required=True)
    complete.add_argument("--usage")
    complete.add_argument("--result")
    cancel = sub.add_parser("cancel")
    cancel.add_argument("--action", required=True)
    args = parser.parse_args(argv)
    if args.command == "bridge":
        return loom_adapter_bridge.serve(args.home, Path(__file__).resolve())
    manager = None
    lease_data = None
    runtime_healthy = False
    trust_failure = None
    try:
        manager = loom_update.SharedRuntime(args.home)
        if args.command in {"invoke", "complete", "cancel"}:
            if args.command == "invoke":
                _reject_local_shadow(args.cwd)
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
        environment = os.environ.copy()
        if args.command == "invoke":
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", args.agent) \
                    or not 1 <= len(args.agent_version) <= 128:
                raise RuntimeError("agent provenance is invalid")
            environment["LOOM_AGENT_HOST"] = args.agent
            environment["LOOM_AGENT_VERSION"] = args.agent_version
            command = [
                sys.executable, "-B", str(orchestrator), "invoke",
                "--request", args.request, "--cwd", str(Path(args.cwd).resolve()),
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
        result = subprocess.run(command, check=False, env=environment)
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
