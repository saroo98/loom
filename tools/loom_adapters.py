#!/usr/bin/env python3
"""Receipt-owned global adapters that route supported agents to one Loom launcher."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import loom_reliability


AGENTS = {
    "codex": ".codex/skills/loom/SKILL.md",
    "claude-code": ".claude/skills/loom/SKILL.md",
    "cursor": ".cursor/skills/loom/SKILL.md",
    "gemini-cli": ".gemini/skills/loom/SKILL.md",
    "opencode": ".config/opencode/skills/loom/SKILL.md",
    "copilot": ".copilot/skills/loom/SKILL.md",
    "factory-droid": ".factory/skills/loom/SKILL.md",
    "generic-agent-skills": ".agents/skills/loom/SKILL.md",
}


class AdapterError(RuntimeError):
    pass


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _adapter(agent):
    return ("---\nname: loom\ndescription: Route one request through the shared local Loom runtime.\n"
            "---\n\nUse one surface: `/loom <request>`. Run the stable user-scoped launcher at "
            f"`~/.loom/bin/loom --home ~/.loom invoke --agent {agent} --agent-version "
            "<current-host-version> --request <verbatim-request> --cwd <absolute-project-root>`. "
            "Never invoke a plugin-cache "
            "path or create repository-local Loom files. Return the launcher's compact receipt.\n") \
        .encode("utf-8")


def _receipt_path(loom_home, agent):
    return Path(loom_home) / "adapters" / "receipts" / f"{agent}.json"


def _preflight(target, receipt_path):
    if not target.exists():
        return
    if not target.is_file() or target.is_symlink() or not receipt_path.is_file():
        raise AdapterError(f"unowned split-brain Loom adapter exists at {target}")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"adapter ownership receipt is invalid: {exc}") from exc
    if receipt.get("path") != str(target) or receipt.get("sha256") != _sha(target.read_bytes()):
        raise AdapterError(f"owned adapter changed; refusing to overwrite {target}")


def install_launcher(loom_home, launcher_source):
    loom_home = loom_reliability._absolute(loom_home, "Loom home")
    source = loom_reliability._absolute(
        launcher_source, "launcher source", must_exist=True)
    if not source.is_file():
        raise AdapterError("launcher source is not a regular file")
    binary = loom_home / "bin"
    binary.mkdir(parents=True, exist_ok=True)
    receipt_path = binary / ".loom-launcher-receipt.json"
    python_launcher = binary / "loom.py"
    posix = binary / "loom"
    windows = binary / "loom.cmd"
    dependencies = {}
    for name in ("loom_update.py", "loom_reliability.py"):
        dependency = source.parent / name
        if not dependency.is_file() or dependency.is_symlink():
            raise AdapterError(f"launcher dependency is unavailable: {name}")
        dependencies[binary / name] = dependency.read_bytes()
    targets = {
        python_launcher: source.read_bytes(),
        posix: b'#!/bin/sh\nexec python3 "$(dirname "$0")/loom.py" "$@"\n',
        windows: b'@echo off\r\npy -3 "%~dp0loom.py" %*\r\n',
        **dependencies,
    }
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for target in targets:
            expected = receipt.get("files", {}).get(target.name)
            if target.exists() and expected != _sha(target.read_bytes()):
                raise AdapterError("owned stable launcher changed; refusing overwrite")
    elif any(target.exists() for target in targets):
        raise AdapterError("unowned stable launcher already exists")
    for target, content in targets.items():
        loom_reliability.atomic_write_bytes(target, content)
    try:
        os.chmod(posix, 0o700)
    except OSError:
        pass
    receipt = {"schema_version": 1, "files": {
        target.name: _sha(content) for target, content in targets.items()}}
    loom_reliability.atomic_write_json(receipt_path, receipt)
    return {"status": "installed", "python_launcher": str(python_launcher),
            "posix_launcher": str(posix), "windows_launcher": str(windows)}


def connect_all(user_home, loom_home, *, approved):
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home")
    detected = [agent for agent, relative in AGENTS.items()
                if (user_home / Path(relative).parts[0]).exists()
                or (user_home / Path(*Path(relative).parts[:2])).exists()]
    if not approved:
        return {"status": "approval-required", "detected": detected,
                "connected": 0, "receipts": []}
    launcher = loom_home / "bin" / "loom.py"
    launcher_receipt = loom_home / "bin" / ".loom-launcher-receipt.json"
    try:
        ownership = json.loads(launcher_receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"shared launcher is not receipt-owned: {exc}") from exc
    if not launcher.is_file() or launcher.is_symlink() \
            or ownership.get("files", {}).get("loom.py") != _sha(launcher.read_bytes()):
        raise AdapterError("shared launcher is missing, changed, or unowned")
    probe = subprocess.run(
        [sys.executable, "-B", str(launcher), "--home", str(loom_home), "adapter-probe"],
        capture_output=True, text=True, timeout=15, check=False)
    try:
        probe_value = json.loads(probe.stdout)
    except json.JSONDecodeError as exc:
        raise AdapterError("shared launcher verification returned invalid output") from exc
    if probe.returncode != 0 or probe_value.get("status") != "ready":
        raise AdapterError("shared launcher verification failed; no adapter was installed")
    plans = []
    for agent in detected:
        target = user_home.joinpath(*Path(AGENTS[agent]).parts)
        receipt = _receipt_path(loom_home, agent)
        _preflight(target, receipt)
        plans.append((agent, target, receipt, _adapter(agent)))
    receipts = []
    prior = [(target, target.read_bytes() if target.exists() else None,
              receipt_path, receipt_path.read_bytes() if receipt_path.exists() else None)
             for _agent, target, receipt_path, _content in plans]
    try:
        for agent, target, receipt_path, content in plans:
            target.parent.mkdir(parents=True, exist_ok=True)
            loom_reliability.atomic_write_bytes(target, content)
            receipt = {"schema_version": 1, "agent": agent, "path": str(target),
                       "sha256": _sha(content), "launcher": "~/.loom/bin/loom"}
            loom_reliability.atomic_write_json(receipt_path, receipt)
            if _sha(target.read_bytes()) != receipt["sha256"]:
                raise AdapterError(f"adapter verification failed for {agent}")
            receipts.append(str(receipt_path))
    except BaseException as exc:
        rollback_failed = False
        for target, old_target, receipt_path, old_receipt in reversed(prior):
            try:
                if old_target is None:
                    target.unlink(missing_ok=True)
                else:
                    loom_reliability.atomic_write_bytes(target, old_target)
                if old_receipt is None:
                    receipt_path.unlink(missing_ok=True)
                else:
                    loom_reliability.atomic_write_bytes(receipt_path, old_receipt)
            except BaseException:
                rollback_failed = True
        if rollback_failed:
            raise AdapterError("adapter connection failed and rollback was incomplete") from exc
        raise AdapterError("adapter connection failed safely; prior state was restored") from exc
    return {"status": "connected", "detected": detected,
            "connected": len(plans), "verified": len(plans), "receipts": receipts}


def disconnect_all(user_home, loom_home, *, approved):
    """Remove only unchanged adapter files proven by Loom ownership receipts."""
    user_home = loom_reliability._absolute(user_home, "user home", must_exist=True)
    loom_home = loom_reliability._absolute(loom_home, "Loom home", must_exist=True)
    receipts_root = loom_home / "adapters" / "receipts"
    planned = []
    for agent in AGENTS:
        receipt_path = _receipt_path(loom_home, agent)
        if not receipt_path.exists():
            continue
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            target = loom_reliability._absolute(receipt["path"], "adapter target", must_exist=True)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError,
                loom_reliability.ReliabilityError) as exc:
            raise AdapterError(f"adapter ownership receipt is invalid: {exc}") from exc
        expected = user_home.joinpath(*Path(AGENTS[agent]).parts)
        if target != expected or receipt.get("agent") != agent \
                or not target.is_file() or target.is_symlink() \
                or receipt.get("sha256") != _sha(target.read_bytes()):
            raise AdapterError(f"owned adapter changed; refusing to remove {target}")
        planned.append((target, receipt_path))
    if not approved:
        return {"status": "approval-required", "connected": len(planned), "removed": 0}
    for target, receipt_path in planned:
        target.unlink()
        receipt_path.unlink()
        try:
            target.parent.rmdir()
        except OSError:
            pass
    try:
        receipts_root.rmdir()
    except OSError:
        pass
    return {"status": "disconnected", "removed": len(planned)}
