#!/usr/bin/env python3
"""Production bridge from one `/loom` request to gated host-agent work and a receipt."""

import sys
sys.dont_write_bytecode = True

import argparse
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import uuid
from pathlib import Path

import loom_gate
import loom_install
import loom_lint
import loom_memory
import loom_performance
import loom_runtime
import loom_session


SCHEMA_VERSION = 1
ACTION_FIELDS = {
    "schema_version", "action_id", "status", "instance_id", "project_id",
    "request", "invocation_id", "owner_home", "install_root", "cwd",
    "explicit_target", "intent", "tier", "domains", "survey_hash",
    "created_at", "expires_at", "attempts", "max_attempts", "session_id",
    "operation_id", "journal_path", "initial_pack_hash",
    "remove_pristine_pack", "result", "action_hash",
}
ACTION_STATUSES = {"pending", "completed", "cancelled", "expired", "failed"}
MAX_ACTION_BYTES = 256 * 1024


class OrchestratorError(RuntimeError):
    def __init__(self, code, message, *, status="refused"):
        self.code = str(code)
        self.message = str(message)
        self.status = str(status)
        super().__init__(f"{self.code}: {self.message}")


def _canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _stamp(value=None):
    instant = loom_runtime._parse_time(value or dt.datetime.now(dt.timezone.utc))
    return loom_runtime._format_time(instant)


def _action_hash(value):
    body = dict(value)
    body.pop("action_hash", None)
    return _hash(body)


def _absolute(value, label, *, must_exist=True):
    try:
        path = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    except (TypeError, ValueError, OSError) as exc:
        raise OrchestratorError("INVALID_PATH", f"{label} is invalid: {exc}") from exc
    if not path.is_absolute() or (must_exist and not path.exists()):
        raise OrchestratorError("INVALID_PATH", f"{label} must be an existing absolute path")
    return path


def _action_path(owner_home, instance_id, project_id, action_id):
    return (Path(owner_home) / "instances" / instance_id / "runtime" /
            "projects" / project_id / "orchestrations" / f"{action_id}.json")


def _validate_action(value, path):
    if not isinstance(value, dict) or set(value) != ACTION_FIELDS \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("status") not in ACTION_STATUSES \
            or value.get("action_hash") != _action_hash(value):
        raise OrchestratorError("ACTION_CORRUPT", "action fields or hash are invalid")
    try:
        if str(uuid.UUID(value["action_id"])) != value["action_id"] \
                or str(uuid.UUID(value["invocation_id"])) != value["invocation_id"] \
                or str(uuid.UUID(value["instance_id"])) != value["instance_id"] \
                or str(uuid.UUID(value["session_id"])) != value["session_id"]:
            raise ValueError
        created = loom_runtime._parse_time(value["created_at"])
        expires = loom_runtime._parse_time(value["expires_at"])
    except (ValueError, TypeError, loom_runtime.RuntimeError) as exc:
        raise OrchestratorError("ACTION_CORRUPT", "action identity is invalid") from exc
    if not re.fullmatch(r"p-[0-9a-f]{32}", str(value["project_id"])) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value["survey_hash"])) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(value["operation_id"])) \
            or value["intent"] not in loom_runtime.INTENTS \
            or value["tier"] not in {"S", "M", "L"} \
            or not isinstance(value["domains"], list) or not value["domains"] \
            or len(value["domains"]) > 16 \
            or len(value["domains"]) != len(set(value["domains"])) \
            or not all(isinstance(item, str) and re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", item) for item in value["domains"]) \
            or type(value["attempts"]) is not int \
            or not 0 <= value["attempts"] <= 3 \
            or value["max_attempts"] != 3 \
            or type(value["remove_pristine_pack"]) is not bool \
            or (value["initial_pack_hash"] is not None and not re.fullmatch(
                r"[0-9a-f]{64}", str(value["initial_pack_hash"]))):
        raise OrchestratorError("ACTION_CORRUPT", "action contract is invalid")
    if created >= expires \
            or any(not isinstance(value[field], str) or not Path(value[field]).is_absolute()
                   for field in ("owner_home", "install_root", "cwd", "journal_path")) \
            or (value["explicit_target"] is not None and (
                not isinstance(value["explicit_target"], str)
                or not Path(value["explicit_target"]).is_absolute())) \
            or (value["status"] == "pending" and value["result"] is not None) \
            or (value["status"] == "completed" and not isinstance(value["result"], dict)):
        raise OrchestratorError("ACTION_CORRUPT", "action state is invalid")
    expected = _action_path(
        value["owner_home"], value["instance_id"], value["project_id"],
        value["action_id"])
    if Path(path) != expected:
        raise OrchestratorError("ACTION_PATH_MISMATCH", "action path is not owner-scoped")
    expected_journal = expected.parent.parent / loom_session.JOURNAL_FILE
    if Path(value["journal_path"]) != expected_journal:
        raise OrchestratorError("ACTION_PATH_MISMATCH", "session journal is not project-scoped")
    return value


def _read_action(path):
    path = _absolute(path, "action")
    try:
        loom_memory._reject_link_ancestors(path, "orchestration action")
    except loom_memory.MemoryError as exc:
        raise OrchestratorError("ACTION_UNSAFE", str(exc)) from exc
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ACTION_BYTES:
        raise OrchestratorError("ACTION_UNSAFE", "action must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("ACTION_CORRUPT", f"action cannot be read: {exc}") from exc
    return path, _validate_action(value, path)


def _write_action(path, value):
    value = dict(value)
    value["action_hash"] = _action_hash(value)
    loom_session._atomic_json(path, value)
    return value


def _capture(function, *args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = function(*args)
    return code, (stdout.getvalue() + stderr.getvalue()).strip()


def _seed_manifest(pack, target, install_root, prepared, request):
    """Write only a valid draft shell; no semantic plan is claimed before the baseline."""
    version = (Path(install_root) / "VERSION").read_text(encoding="utf-8").strip()
    coverage = ("unknown" if prepared.route_contract["requires_domain_discovery"]
                else "adapter")
    quoted_request = "\n".join(
        "> " + line for line in request.replace("\r", "").split("\n"))
    text = f"""---
artifact: manifest
project: {json.dumps(Path(target).name)}
tier: {prepared.route_contract['tier']}
status: draft
last_verified: {dt.date.today().isoformat()}
loom_version: {json.dumps(version)}
execution_mode: planned
domain_id: {prepared.domains[0]}
domain_ids: [{', '.join(prepared.domains)}]
domain_coverage: {coverage}
freshness_window_days: 14
---

# Planning pack — {Path(target).name}

Original request (verbatim, do not paraphrase):
{quoted_request}

## Artifacts

| Artifact | Action | Consumer | Decision | Why (one line) | Status | last_verified |
|---|---|---|---|---|---|---|

## Work order frontier

| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|---|
"""
    pack.mkdir(parents=True, exist_ok=True)
    loom_gate._atomic_write_text(pack / "MANIFEST.md", text)


def _pack_hash(pack):
    return loom_runtime._hash_frontier(pack)


def _remove_pristine_pack(action):
    """Remove only an untouched pack created entirely by this action."""
    if not action.get("remove_pristine_pack"):
        return False
    pack = Path(action["explicit_target"] or action["cwd"]) / "plans"
    if not pack.is_dir() or pack.is_symlink() \
            or _pack_hash(pack) != action.get("initial_pack_hash"):
        return False
    entries = sorted(pack.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for item in entries:
        if item.is_symlink() or (not item.is_file() and not item.is_dir()):
            return False
    for item in entries:
        if item.is_file():
            item.unlink()
        else:
            item.rmdir()
    pack.rmdir()
    return True


def _handler_result(context, root, owner_home, usage):
    pack = root / "plans"
    tier = context.prepared.route_contract["tier"]
    intent = context.intent
    logs = []
    if intent == "plan":
        if tier == "S":
            record, work_order = pack / ".loom-small-lifecycle.json", pack / "WO-001.md"
            findings = []
            try:
                data = json.loads(record.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                findings = [f"Tier-S lifecycle is unreadable: {exc}"]
            if not findings and [event.get("event") for event in data.get("events", [])] \
                    == ["small-planning-started"]:
                code, output = _capture(
                    loom_gate.small_authorize, record, root, work_order)
                logs.append(output)
                if code:
                    findings = ["Tier-S authorization failed: " + output]
            findings = loom_gate.verify_small(record) if not findings else findings
        else:
            report = loom_lint.lint(
                pack, repo_path=root, enforce_lifecycle=False,
                check_repo_state=False)
            findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
            if not findings:
                lifecycle = json.loads((pack / loom_gate.LIFECYCLE_FILE).read_text(
                    encoding="utf-8"))
                events = [event["event"] for event in lifecycle["events"]]
                if events == ["planning-started"]:
                    review = pack / "reviews" / "G1-plan-review.md"
                    code, output = _capture(loom_gate.seal_g1, pack, root, review)
                    logs.append(output)
                    if not code:
                        code, output = _capture(loom_gate.authorize, pack, root)
                        logs.append(output)
                    if code:
                        findings = ["G1 sealing or authorization failed"]
                if not findings:
                    findings = loom_gate.verify(pack, root, require_authorized=True)
        if findings:
            return {
                "status": "blocked", "code": "plan-not-release-ready",
                "success": False, "metrics": {}, "evidence_ids": [],
                "reversible_action_ids": [], "usage": usage,
                "user_message": "Plan validation blocked: " + "; ".join(findings[:8]),
            }
        evidence = "pack-" + _pack_hash(pack)[:24]
        return {
            "status": "completed", "code": "plan-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [], "usage": usage,
            "user_message": (
                "Release-ready plan validated and implementation authorized. "
                f"Lifecycle evidence: {evidence}."),
        }

    if intent in {"resume", "review", "repair", "execute", "close"}:
        report = loom_lint.lint(pack, repo_path=root)
        findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
        findings.extend(loom_gate.verify(
            pack, root, require_authorized=intent in {"resume", "repair", "execute"}))
        if intent == "close" and not findings:
            lifecycle = json.loads((pack / loom_gate.LIFECYCLE_FILE).read_text(
                encoding="utf-8"))
            work_orders = list((pack / "work-orders").glob("WO-*.md"))
            if len(lifecycle.get("work_order_completions", [])) != len(work_orders):
                findings.append("not every work order has a sealed completion")
        if findings:
            return {
                "status": "blocked", "code": f"{intent}-not-ready", "success": False,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
                "usage": usage,
                "user_message": f"{intent.title()} blocked: " + "; ".join(findings[:8]),
            }
        evidence = f"{intent}-" + _pack_hash(pack)[:24]
        return {
            "status": "completed", "code": f"{intent}-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [], "usage": usage,
            "user_message": f"{intent.title()} validation completed ({evidence}).",
        }

    if intent == "remember":
        statement = re.sub(
            r"(?is)^.*?\bremember(?:\s+that)?\s+", "", context.request_text).strip()
        if not statement or len(statement) > 280:
            return {
                "status": "blocked", "code": "memory-statement-invalid",
                "success": False, "metrics": {}, "evidence_ids": [],
                "reversible_action_ids": [], "usage": usage,
                "user_message": "State one memory item of at most 280 characters.",
            }
        record = loom_memory.add_record(
            owner_home, context.prepared.instance_id, scope="project",
            category="process", statement=statement, provenance="stated",
            evidence_count=1, domain=context.prepared.domains[0],
            project_id=context.project_id, confidence=1.0)
        return {
            "status": "completed", "code": "remember-complete", "success": True,
            "metrics": {}, "evidence_ids": ["memory-" + record["id"]],
            "reversible_action_ids": [], "usage": usage,
            "user_message": f"Remembered for this project as {record['id']}.",
        }
    return {
        "status": "blocked", "code": "intent-needs-no-host-action", "success": False,
        "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
        "usage": usage, "user_message": "Use the built-in transparency handler.",
    }


def default_handlers(*, root, owner_home, usage=None):
    """Return the complete audited production handler registry."""
    root, owner_home = Path(root), Path(owner_home)
    normalized = loom_performance.normalize_usage(usage)
    usage_payload = (None if normalized["measurement_status"] == "unreported" else {
        field: normalized[field] for field in loom_performance.USAGE_FIELDS
    })
    return {
        intent: (lambda context, _intent=intent: _handler_result(
            context, root, owner_home, usage_payload))
        for intent in {
            "plan", "resume", "execute", "review", "repair", "close", "remember"
        }
    }


def _controller(action, *, usage=None):
    home = Path(action["owner_home"])
    root = Path(action["explicit_target"] or action["cwd"])
    memory = loom_session.LocalMemoryAdapter(
        owner_home=home, instance_id=action["instance_id"])
    handlers = default_handlers(root=root, owner_home=home, usage=usage)
    return loom_session.SessionController(
        owner_home=home, instance_id=action["instance_id"],
        handlers=handlers, memory=memory)


def invoke(*, request, cwd, home, install_root, explicit_target=None,
           timeout_seconds=900, now=None):
    if type(timeout_seconds) is not int or not 60 <= timeout_seconds <= 3600:
        raise OrchestratorError("INVALID_TIMEOUT", "timeout must be between 60 and 3600 seconds")
    cwd = _absolute(cwd, "cwd")
    home = _absolute(home, "owner home", must_exist=False)
    install_root = _absolute(install_root, "installation root")
    target = _absolute(explicit_target, "target") if explicit_target else cwd
    try:
        loom_install.check(install_root)
    except loom_install.InstallError as exc:
        raise OrchestratorError(
            "INSTALL_UNVERIFIED", f"installation receipt check failed: {exc}") from exc
    instance_id = loom_memory.initialize(home, install_root)
    invocation_id = str(uuid.uuid4())
    controller = loom_session.SessionController(
        owner_home=home, instance_id=instance_id, handlers={},
        memory=loom_session.LocalMemoryAdapter(
            owner_home=home, instance_id=instance_id))
    opened = controller.open(
        request, invocation_id=invocation_id, cwd=cwd,
        explicit_target=target, now=now)
    if opened.terminal_receipt is not None:
        return opened.terminal_receipt.to_dict()
    prepared = opened.prepared
    created_at = _stamp(now)
    expires_at = _stamp(
        loom_runtime._parse_time(created_at) + dt.timedelta(seconds=timeout_seconds))
    action_id = invocation_id
    path = _action_path(home, instance_id, prepared.project_id, action_id)
    action = {
        "schema_version": SCHEMA_VERSION, "action_id": action_id,
        "status": "pending", "instance_id": instance_id,
        "project_id": prepared.project_id, "request": request,
        "invocation_id": invocation_id, "owner_home": str(home),
        "install_root": str(install_root), "cwd": str(cwd),
        "explicit_target": str(target), "intent": prepared.intent,
        "tier": prepared.route_contract["tier"],
        "domains": list(prepared.domains), "survey_hash": prepared.survey_hash,
        "created_at": created_at, "expires_at": expires_at,
        "attempts": 0, "max_attempts": 3, "session_id": opened.session_id,
        "operation_id": opened.operation_id, "journal_path": opened.journal_path,
        "initial_pack_hash": None, "remove_pristine_pack": False,
        "result": None,
    }
    if prepared.route_contract["blocked"]:
        receipt = controller.run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True)
        action["status"], action["result"] = "completed", receipt.to_dict()
        _write_action(path, action)
        return receipt.to_dict()
    if prepared.intent in {"status", "why", "undo", "forget", "remember"}:
        immediate = _controller(action).run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True)
        action["status"], action["result"] = "completed", immediate.to_dict()
        _write_action(path, action)
        return immediate.to_dict()
    if prepared.intent == "plan":
        pack = target / "plans"
        pack_was_absent = not pack.exists()
        if action["tier"] == "S":
            record, work_order = pack / ".loom-small-lifecycle.json", pack / "WO-001.md"
            if not record.exists() and not work_order.exists():
                code, output = _capture(loom_gate.small_start, record, target, work_order)
                if code:
                    raise OrchestratorError("BASELINE_FAILED", output)
        else:
            lifecycle = pack / loom_gate.LIFECYCLE_FILE
            if not lifecycle.exists():
                manifest = pack / "MANIFEST.md"
                if not manifest.exists():
                    _seed_manifest(
                        pack, target, install_root, prepared, request)
                code, output = _capture(loom_gate.start, pack, target, "planned")
                if code:
                    raise OrchestratorError("BASELINE_FAILED", output)
        action["initial_pack_hash"] = _pack_hash(pack)
        action["remove_pristine_pack"] = pack_was_absent
    action = _write_action(path, action)
    return {
        "schema_version": SCHEMA_VERSION, "status": "action-required",
        "action_id": action_id, "action_path": str(path),
        "intent": action["intent"], "tier": action["tier"],
        "domains": action["domains"], "expires_at": expires_at,
        "attempts_remaining": action["max_attempts"] - action["attempts"],
        "session_environment": opened.environment(),
        "required_outcome": (
            "Author only the selected tier/domain plan or perform the routed intent; "
            "do not mutate undeclared target paths. Then call complete with all five "
            "measured token categories. The orchestrator owns validation, gates, learning, "
            "and the final receipt."),
    }


def _reopen(action):
    controller = _controller(action)
    opened = controller.open(
        action["request"], invocation_id=action["invocation_id"],
        cwd=action["cwd"], explicit_target=action["explicit_target"])
    if opened.operation_id != action["operation_id"] \
            or opened.session_id != action["session_id"]:
        raise OrchestratorError("ACTION_IDENTITY_CHANGED", "session identity no longer matches")
    return controller, opened


def complete(action_path, usage_path, *, now=None):
    path, action = _read_action(action_path)
    try:
        checked = loom_install.check(action["install_root"])
    except loom_install.InstallError as exc:
        raise OrchestratorError("INSTALL_CHANGED", str(exc)) from exc
    marker = Path(action["install_root"]) / loom_install.INSTANCE_MARKER
    if marker.read_text(encoding="utf-8").strip() != action["instance_id"] \
            or checked["status"] != "installed":
        raise OrchestratorError("INSTALL_CHANGED", "installation identity changed")
    if action["status"] != "pending":
        raise OrchestratorError(
            "ACTION_TERMINAL", f"action is already {action['status']}",
            status=action["status"])
    instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
    if instant > loom_runtime._parse_time(action["expires_at"]):
        controller, opened = _reopen(action)
        controller.interrupt(opened, code="orchestration-timeout", now=instant)
        _remove_pristine_pack(action)
        action["status"] = "expired"
        _write_action(path, action)
        raise OrchestratorError("ACTION_TIMEOUT", "action deadline expired", status="expired")
    try:
        usage = json.loads(_absolute(usage_path, "usage").read_text(encoding="utf-8"))
        normalized = loom_performance.normalize_usage(usage)
    except (OSError, UnicodeError, json.JSONDecodeError,
            loom_performance.PerformanceError) as exc:
        raise OrchestratorError("USAGE_INVALID", str(exc)) from exc
    if normalized["measurement_status"] != "measured":
        raise OrchestratorError("USAGE_REQUIRED", "production completion requires measured usage")
    prepared = loom_runtime.prepare_invocation(
        action["request"], instance_id=action["instance_id"],
        invocation_id=action["invocation_id"], cwd=action["cwd"],
        explicit_target=action["explicit_target"], owner_home=action["owner_home"],
        now=instant)
    if prepared.survey_hash != action["survey_hash"] \
            or prepared.project_id != action["project_id"] \
            or prepared.intent != action["intent"]:
        raise OrchestratorError(
            "TARGET_DRIFT", "target, project, or routed intent changed during delegated work")
    controller = _controller(action, usage=usage)
    try:
        receipt = controller.run(
            action["request"], invocation_id=action["invocation_id"],
            cwd=action["cwd"], explicit_target=action["explicit_target"],
            now=instant, continue_open=True)
    except loom_session.SessionInterrupted as exc:
        action["attempts"] += 1
        if action["attempts"] >= action["max_attempts"]:
            action["status"] = "failed"
        _write_action(path, action)
        raise OrchestratorError(
            "HANDLER_INTERRUPTED", str(exc), status=action["status"]) from exc
    action["status"], action["result"] = "completed", receipt.to_dict()
    _write_action(path, action)
    return receipt.to_dict()


def cancel(action_path, *, now=None):
    path, action = _read_action(action_path)
    try:
        loom_install.check(action["install_root"])
    except loom_install.InstallError as exc:
        raise OrchestratorError("INSTALL_CHANGED", str(exc)) from exc
    if action["status"] != "pending":
        raise OrchestratorError(
            "ACTION_TERMINAL", f"action is already {action['status']}",
            status=action["status"])
    controller, opened = _reopen(action)
    controller.interrupt(opened, code="owner-cancelled", now=now)
    _remove_pristine_pack(action)
    action["status"] = "cancelled"
    _write_action(path, action)
    return {"status": "cancelled", "action_id": action["action_id"],
            "session_id": action["session_id"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    invoke_parser = commands.add_parser("invoke")
    invoke_parser.add_argument("--request", required=True)
    invoke_parser.add_argument("--cwd", required=True)
    invoke_parser.add_argument("--home", required=True)
    invoke_parser.add_argument("--install-root", required=True)
    invoke_parser.add_argument("--target")
    invoke_parser.add_argument("--timeout-seconds", type=int, default=900)
    complete_parser = commands.add_parser("complete")
    complete_parser.add_argument("--action", required=True)
    complete_parser.add_argument("--usage", required=True)
    cancel_parser = commands.add_parser("cancel")
    cancel_parser.add_argument("--action", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "invoke":
            result = invoke(
                request=args.request, cwd=args.cwd, home=args.home,
                install_root=args.install_root, explicit_target=args.target,
                timeout_seconds=args.timeout_seconds)
        elif args.command == "complete":
            result = complete(args.action, args.usage)
        else:
            result = cancel(args.action)
    except OrchestratorError as exc:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": exc.status,
            "code": exc.code, "error": exc.message,
        }, sort_keys=True))
        return 2
    except (loom_memory.MemoryError, loom_runtime.RuntimeError,
            loom_session.SessionError, loom_install.InstallError) as exc:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION, "status": "blocked",
            "code": "RUNTIME_BLOCKED", "error": str(exc),
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
