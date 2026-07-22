#!/usr/bin/env python3
"""Bounded Codex lifecycle hooks for an active Loom action."""

import datetime as dt
import fnmatch
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path, PurePosixPath

import loom_orchestrator
import loom_owner
import loom_reliability
import loom_runtime


MAX_EVENT_BYTES = 256 * 1024
MAX_EVENT_RECEIPTS = 256
SUPPORTED_EVENTS = {
    "PreToolUse", "PostToolUse", "PreCompact", "PostCompact",
    "Stop", "SubagentStart", "SubagentStop",
}
STRUCTURED_WRITE_TOOLS = {"apply_patch", "Edit", "Write"}
PATH_KEYS = {"path", "file_path", "target_file", "target_path"}


class LifecycleError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LifecycleError(f"hook event contains duplicate field: {key}")
        value[key] = item
    return value


def _read_event(stream):
    raw = stream.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        raise LifecycleError("hook event exceeds its byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("hook event is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("hook_event_name") not in SUPPORTED_EVENTS \
            or not isinstance(value.get("cwd"), str) or not value["cwd"]:
        raise LifecycleError("hook event identity is invalid")
    return value


def _active_action(home, install_root, cwd):
    home = Path(home).resolve()
    install_root = Path(install_root).resolve()
    cwd = Path(cwd).resolve()
    helper = loom_orchestrator._vault_helper(install_root)
    if helper is None or not (home / "vault" / "owner.sqlite3").is_file():
        return None
    opened = loom_owner.open_owner_vault(home, helper)
    instance_id = opened["vault"].identity()["owner_vault_id"]
    try:
        project = loom_runtime.resolve_project(
            instance_id, explicit_target=cwd, cwd=cwd)
    except loom_runtime.RuntimeBlocked:
        return None
    directory = loom_orchestrator._orchestration_directory(
        home, instance_id, project.project_id)
    pointer = loom_orchestrator._read_active_pointer(directory)
    if pointer is None:
        return None
    action_path = directory / f"{pointer['action_id']}.json"
    _path, action, _security = loom_orchestrator._read_action(
        action_path, owner_home=home, install_root=install_root)
    if action["status"] not in {"initializing", "pending"}:
        return None
    target = Path(action["explicit_target"] or action["cwd"]).resolve()
    try:
        cwd.relative_to(target)
    except ValueError:
        return None
    return action


def _work_order_touches(action):
    target = Path(action["explicit_target"] or action["cwd"]).resolve()
    if action["intent"] == "plan":
        return target, ["plans", "plans/**"]
    if action["intent"] == "repair":
        return target, ["plans", "plans/**"]
    relative = action.get("work_order")
    if action["intent"] != "execute" or not isinstance(relative, str):
        return target, []
    path = target / "plans" / PurePosixPath(relative)
    try:
        frontmatter, _body = loom_orchestrator.loom_lint.parse_frontmatter(
            path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return target, []
    touches = (frontmatter or {}).get("touches", [])
    if isinstance(touches, str):
        touches = [touches]
    try:
        return target, loom_orchestrator.loom_gate._touch_patterns(touches)
    except (TypeError, ValueError):
        return target, []


def _patch_paths(text):
    if not isinstance(text, str):
        return []
    return [match.group(1).strip() for match in re.finditer(
        r"(?m)^\*\*\* (?:Add|Update|Delete) File: (.+)$", text)]


def _tool_paths(event):
    value = event.get("tool_input")
    if not isinstance(value, dict):
        return []
    paths = []
    for key, item in value.items():
        if key in PATH_KEYS and isinstance(item, str):
            paths.append(item)
        elif key in {"patch", "input"}:
            paths.extend(_patch_paths(item))
    return paths


def _relative_path(target, cwd, raw):
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    resolved = candidate.resolve(strict=False)
    try:
        return resolved.relative_to(target).as_posix()
    except ValueError as exc:
        raise LifecycleError("structured write escapes the active Loom target") from exc


def _authorized(patterns, relative):
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)


def _record(home, event, action, *, outcome):
    root = loom_reliability._absolute(home, "Loom lifecycle home", must_exist=True)
    adapters = root / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    loom_reliability._absolute(adapters, "Loom adapter state", must_exist=True)
    directory = adapters / "events"
    directory.mkdir(parents=True, exist_ok=True)
    loom_reliability._absolute(directory, "Loom lifecycle events", must_exist=True)
    rows = []
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise LifecycleError("Loom lifecycle event store contains an unsafe entry")
        if entry.suffix == ".json":
            rows.append(entry)
    rows.sort()
    if len(rows) >= MAX_EVENT_RECEIPTS:
        for stale in rows[:len(rows) - MAX_EVENT_RECEIPTS + 1]:
            stale.unlink()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    value = {
        "schema_version": 1,
        "event": event["hook_event_name"],
        "action_id": action["action_id"],
        "project_id": action["project_id"],
        "cwd_sha256": hashlib.sha256(event["cwd"].encode("utf-8")).hexdigest(),
        "tool": event.get("tool_name") if isinstance(event.get("tool_name"), str) else None,
        "outcome": outcome,
        "observed_at": now.isoformat().replace("+00:00", "Z"),
    }
    name = now.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex + ".json"
    loom_reliability.atomic_write_json(directory / name, value)


def _context(action, event_name):
    work_order = action.get("work_order")
    summary = (
        f"Loom active action {action['action_id']} is {action['intent']} tier {action['tier']}. "
        f"Work order: {work_order or 'none'}. Event: {event_name}. "
        "This is bounded continuity context, not new authority."
    )
    return {"continue": True, "systemMessage": summary[:1024]}


def handle(event, *, home, install_root):
    action = _active_action(home, install_root, event["cwd"])
    if action is None:
        return 0, None
    name = event["hook_event_name"]
    if name == "PreToolUse" and event.get("tool_name") in STRUCTURED_WRITE_TOOLS:
        target, patterns = _work_order_touches(action)
        paths = _tool_paths(event)
        if not patterns or not paths:
            _record(home, event, action, outcome="scope-unproven")
            return 0, {"systemMessage":
                "Loom could not prove this structured write's path scope. "
                "Verified request transport does not imply tool confinement."}
        try:
            relatives = [_relative_path(target, event["cwd"], path) for path in paths]
        except LifecycleError as exc:
            _record(home, event, action, outcome="blocked-outside-target")
            return 2, {"systemMessage": str(exc)}
        outside = [path for path in relatives if not _authorized(patterns, path)]
        if outside:
            _record(home, event, action, outcome="blocked-outside-touches")
            return 2, {"systemMessage":
                "Loom blocked a structured write outside declared touches: "
                + ", ".join(outside[:4])}
        _record(home, event, action, outcome="authorized-structured-write")
        return 0, None
    _record(home, event, action, outcome="observed")
    if name in {"PreCompact", "PostCompact", "SubagentStart"}:
        return 0, _context(action, name)
    return 0, None


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", required=True)
    parser.add_argument("--install-root", required=True)
    args = parser.parse_args(argv)
    try:
        event = _read_event(sys.stdin.buffer)
        code, output = handle(event, home=args.home, install_root=args.install_root)
    except (LifecycleError, loom_orchestrator.OrchestratorError,
            loom_owner.OwnerError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"systemMessage": f"Loom lifecycle check failed closed: {exc}"},
                         separators=(",", ":")))
        return 2
    if output is not None:
        print(json.dumps(output, separators=(",", ":"), ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
