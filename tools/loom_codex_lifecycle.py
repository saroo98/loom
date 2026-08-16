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
import loom_executor_guard
import loom_reliability
import loom_runtime


MAX_EVENT_BYTES = 256 * 1024
MAX_EVENT_RECEIPTS = 256
MAX_DENIAL_REASON_BYTES = 512
MAX_DENIAL_CONTEXT_BYTES = 4096
MAX_DENIAL_OUTPUT_BYTES = 8192
SUPPORTED_EVENTS = {
    "PreToolUse", "PostToolUse", "PreCompact", "PostCompact",
    "Stop", "SubagentStart", "SubagentStop",
}
STRUCTURED_WRITE_TOOLS = {"apply_patch", "Edit", "Write"}
PROCESS_TOOLS = {"Bash", "Shell", "UnifiedExec", "exec_command", "shell_command"}
READ_ONLY_TOOLS = {"Read", "Glob", "Grep", "LS"}
PATH_KEYS = {"path", "file_path", "target_file", "target_path"}


class LifecycleError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LifecycleError("hook event contains a duplicate field")
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
    if helper is None or not loom_owner.owner_vault_path(home).is_file():
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
    _path, action, security = loom_orchestrator._read_action(
        action_path, owner_home=home, install_root=install_root)
    if action["status"] not in {"initializing", "pending"}:
        return None
    target = Path(action["explicit_target"] or action["cwd"]).resolve()
    try:
        cwd.relative_to(target)
    except ValueError:
        return None
    return action, security


def _work_order_touches(action):
    target = Path(action["explicit_target"] or action["cwd"]).resolve()
    if action["intent"] == "plan":
        return target, ["plans", "plans/**"]
    if action["intent"] == "repair":
        return target, ["plans", "plans/**"]
    relative = action.get("work_order")
    if action["intent"] != "execute" or not isinstance(relative, str):
        return target, []
    try:
        pack = loom_orchestrator._action_pack_root(action)
    except loom_orchestrator.OrchestratorError:
        return target, []
    path = pack / PurePosixPath(relative)
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


def _guarded_executor(action):
    return action.get("intent") in {"execute", "repair"} \
        and isinstance(action.get("generation_id"), str)


def _guard_directory(action):
    return loom_orchestrator._orchestration_directory(
        action["owner_home"], action["instance_id"], action["project_id"])


def _lifecycle_control_operation(name):
    if not isinstance(name, str):
        return None
    match = re.fullmatch(
        r"mcp__loom__(invoke|resolve|status|complete|author|start|revise|cancel)",
        name)
    if match is None:
        match = re.fullmatch(
            r"loom[.:/](invoke|resolve|status|complete|author|start|revise|cancel)",
            name)
    return match.group(1) if match is not None else None


def _lifecycle_control_tool(name):
    return _lifecycle_control_operation(name) is not None


def _guard_is_frozen(action, security):
    directory = _guard_directory(action)
    try:
        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(directory)):
            freeze = loom_executor_guard.read(
                directory, action, security=security)["freeze"]
            return None if freeze is None else freeze["reason_code"]
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleError("executor guard lock is unavailable") from exc


def _begin_guarded_operation(
        action, event, *, operation_kind, security):
    directory = _guard_directory(action)
    try:
        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(directory)):
            return loom_executor_guard.begin_operation(
                directory, action, event, operation_kind=operation_kind,
                security=security)
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleError("executor guard lock is unavailable") from exc


def _observe_guarded_post(action, event, *, security):
    if not _guarded_executor(action):
        return
    directory = _guard_directory(action)
    path = loom_executor_guard.guard_path(directory, action)
    if not path.exists():
        return
    name = event.get("tool_name")
    try:
        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(directory)):
            loom_executor_guard.observe_post(
                directory, action, event,
                lifecycle_control=_lifecycle_control_tool(name),
                nonmutating=name in READ_ONLY_TOOLS,
                security=security)
    except loom_reliability.ReliabilityError as exc:
        raise LifecycleError("executor guard lock is unavailable") from exc


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


def _authorized_context(projection):
    projection = loom_orchestrator.validate_authorized_continuation(projection)
    touches = ", ".join(projection["allowed_touches"])
    if len(touches) > 1024:
        touches = (
            f"{len(projection['allowed_touches'])} sealed patterns; "
            "boundary_sha256="
            + hashlib.sha256(json.dumps(
                projection["allowed_touches"], sort_keys=True,
                separators=(",", ":"), ensure_ascii=True,
                allow_nan=False).encode("utf-8")).hexdigest())
    context = (
        "Loom preserved the authorized path after denying this deviation. "
        "Authorized continuation (not authority): continue current execution "
        "without reinvoking Loom, using the exact active action "
        f"{projection['active_action_id']} for work order "
        f"{projection['work_order_id']}. Allowed touches: {touches}. "
        f"Outcome digest: {projection['outcome_sha256']}. "
        f"Required evidence digest: {projection['evidence_requirements_sha256']}. "
        f"Continuation digest: {projection['continuation_sha256']}. "
        "This context cannot start work, change the plan, or grant owner authority."
    )
    if len(context.encode("utf-8")) > MAX_DENIAL_CONTEXT_BYTES:
        raise LifecycleError("authorized continuation context exceeds its bound")
    return context


def _denial_reason(code, paths):
    if code not in loom_orchestrator.AUTHORIZED_CONTINUATION_REJECTION_CODES:
        raise LifecycleError("structured-write rejection identity is invalid")
    sealed_paths = [str(item) for item in paths]
    digest = hashlib.sha256(json.dumps(
        sealed_paths, sort_keys=False, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
    boundary = {
        "OUTSIDE_PROJECT_TARGET": "outside the active target",
        "UNAUTHORIZED_PROJECT_TOUCH": "outside declared touches",
        "WRITE_SCOPE_UNPROVEN": "whose exact path scope could not be proven",
        "PROCESS_MUTATION_UNPROVEN": (
            "because raw process effects are not mechanically confined"),
        "TOOL_EFFECT_UNPROVEN": (
            "because this tool's mutation effects are not mechanically known"),
        "EXECUTION_FROZEN": "because executor cancellation is being reconciled",
        "EXECUTOR_GUARD_UNPROVEN": (
            "because exact host-operation coverage is not established"),
    }[code]
    reason = (
        f"Loom blocked an active-action operation {boundary}. code={code}; "
        f"path_count={len(sealed_paths)}; path_set_sha256={digest}")
    if len(reason.encode("utf-8")) > MAX_DENIAL_REASON_BYTES:
        raise LifecycleError("structured-write rejection exceeds its bound")
    return reason


def _denied(action, reason, rejection_code, *, home, install_root):
    specific = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }
    try:
        projection = loom_orchestrator.authorized_continuation(
            action, rejection_code=rejection_code,
            owner_home=home, install_root=install_root)
        if projection is not None:
            specific["additionalContext"] = _authorized_context(projection)
    except (LifecycleError, loom_orchestrator.OrchestratorError):
        pass
    output = {"systemMessage": reason, "hookSpecificOutput": specific}
    encoded = json.dumps(
        output, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_DENIAL_OUTPUT_BYTES and "additionalContext" in specific:
        specific.pop("additionalContext")
        encoded = json.dumps(
            output, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_DENIAL_OUTPUT_BYTES:
        raise LifecycleError("structured-write denial exceeds its output bound")
    return 0, output


def handle(event, *, home, install_root):
    active = _active_action(home, install_root, event["cwd"])
    if active is None:
        return 0, None
    # Direct unit adapters may provide a plaintext disposable action.  The
    # production resolver always returns the authenticated action and vault
    # security together.
    if isinstance(active, tuple):
        action, guard_security = active
    else:
        action, guard_security = active, None
    name = event["hook_event_name"]
    if name == "PreToolUse" and event.get("tool_name") in STRUCTURED_WRITE_TOOLS:
        target, patterns = _work_order_touches(action)
        paths = _tool_paths(event)
        if not patterns or not paths:
            _record(home, event, action, outcome="scope-unproven")
            return _denied(
                action, _denial_reason("WRITE_SCOPE_UNPROVEN", []),
                "WRITE_SCOPE_UNPROVEN", home=home,
                install_root=install_root)
        try:
            relatives = [_relative_path(target, event["cwd"], path) for path in paths]
        except LifecycleError as exc:
            _record(home, event, action, outcome="blocked-outside-target")
            return _denied(
                action, _denial_reason("OUTSIDE_PROJECT_TARGET", paths),
                "OUTSIDE_PROJECT_TARGET",
                home=home, install_root=install_root)
        outside = [path for path in relatives if not _authorized(patterns, path)]
        if outside:
            _record(home, event, action, outcome="blocked-outside-touches")
            reason = _denial_reason("UNAUTHORIZED_PROJECT_TOUCH", outside)
            return _denied(
                action, reason, "UNAUTHORIZED_PROJECT_TOUCH",
                home=home, install_root=install_root)
        if _guarded_executor(action):
            try:
                _begin_guarded_operation(
                    action, event, operation_kind="structured-write",
                    security=guard_security)
            except loom_executor_guard.GuardFrozen:
                _record(home, event, action, outcome="blocked-execution-frozen")
                return _denied(
                    action, _denial_reason("EXECUTION_FROZEN", []),
                    "EXECUTION_FROZEN", home=home,
                    install_root=install_root)
            except loom_executor_guard.GuardPending:
                _record(home, event, action, outcome="blocked-guard-unproven")
                return _denied(
                    action, _denial_reason("EXECUTOR_GUARD_UNPROVEN", []),
                    "EXECUTOR_GUARD_UNPROVEN", home=home,
                    install_root=install_root)
            except loom_executor_guard.GuardError:
                _record(home, event, action, outcome="blocked-guard-invalid")
                return _denied(
                    action, _denial_reason("EXECUTOR_GUARD_UNPROVEN", []),
                    "EXECUTOR_GUARD_UNPROVEN", home=home,
                    install_root=install_root)
        _record(home, event, action, outcome="authorized-structured-write")
        return 0, None
    if name == "PreToolUse" and _lifecycle_control_tool(event.get("tool_name")):
        operation = _lifecycle_control_operation(event.get("tool_name"))
        if _guarded_executor(action) and operation == "complete":
            try:
                frozen = _guard_is_frozen(action, guard_security)
            except loom_executor_guard.GuardError:
                _record(home, event, action, outcome="blocked-guard-invalid")
                return _denied(
                    action, _denial_reason("EXECUTOR_GUARD_UNPROVEN", []),
                    "EXECUTOR_GUARD_UNPROVEN", home=home,
                    install_root=install_root)
            if frozen is not None and frozen not in {
                    "action-completion", "action-timeout"}:
                _record(home, event, action, outcome="blocked-execution-frozen")
                return _denied(
                    action, _denial_reason("EXECUTION_FROZEN", []),
                    "EXECUTION_FROZEN", home=home,
                    install_root=install_root)
        _record(home, event, action, outcome="authorized-loom-control")
        return 0, None
    if name == "PreToolUse" and event.get("tool_name") in PROCESS_TOOLS:
        _record(home, event, action, outcome="blocked-unsupervised-process")
        return _denied(
            action, _denial_reason("PROCESS_MUTATION_UNPROVEN", []),
            "PROCESS_MUTATION_UNPROVEN", home=home,
            install_root=install_root)
    if name == "PreToolUse" and event.get("tool_name") in READ_ONLY_TOOLS:
        _record(home, event, action, outcome="authorized-read-only")
        return 0, None
    if name == "PreToolUse":
        _record(home, event, action, outcome="blocked-unproven-tool")
        return _denied(
            action, _denial_reason("TOOL_EFFECT_UNPROVEN", []),
            "TOOL_EFFECT_UNPROVEN", home=home,
            install_root=install_root)
    if name == "PostToolUse":
        _observe_guarded_post(
            action, event, security=guard_security)
    _record(home, event, action, outcome="observed")
    if name in {"PreCompact", "PostCompact", "SubagentStart"}:
        return 0, _context(action, name)
    return 0, None


def _failure_output(code):
    if code not in {"HOOK_EVENT_INVALID", "HOOK_AUTHORITY_UNAVAILABLE"}:
        raise LifecycleError("hook failure identity is invalid")
    output = {
        "systemMessage": (
            "Loom lifecycle check failed closed. "
            f"code={code}; no owner or project input was emitted."),
    }
    if len(json.dumps(
            output, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")) > MAX_DENIAL_OUTPUT_BYTES:
        raise LifecycleError("hook failure output exceeds its bound")
    return output


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", required=True)
    parser.add_argument("--install-root", required=True)
    args = parser.parse_args(argv)
    try:
        event = _read_event(sys.stdin.buffer)
    except LifecycleError:
        print(json.dumps(
            _failure_output("HOOK_EVENT_INVALID"), separators=(",", ":")))
        return 2
    try:
        code, output = handle(event, home=args.home, install_root=args.install_root)
    except (LifecycleError, loom_orchestrator.OrchestratorError,
            loom_owner.OwnerError, loom_reliability.ReliabilityError,
            loom_executor_guard.GuardError):
        print(json.dumps(
            _failure_output("HOOK_AUTHORITY_UNAVAILABLE"),
            separators=(",", ":")))
        return 2
    if output is not None:
        print(json.dumps(output, separators=(",", ":"), ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
