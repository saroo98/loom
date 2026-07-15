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
import loom_lifecycle
import loom_lint
import loom_memory
import loom_performance
import loom_runtime
import loom_session


SCHEMA_VERSION = 1
ACTION_SCHEMA_VERSION = 2
ACTION_FIELDS = {
    "schema_version", "action_id", "status", "instance_id", "project_id",
    "request", "invocation_id", "owner_home", "install_root", "cwd",
    "explicit_target", "intent", "tier", "domains", "survey_hash",
    "created_at", "expires_at", "attempts", "max_attempts", "session_id",
    "operation_id", "journal_path", "initial_pack_hash",
    "remove_pristine_pack", "work_order", "prepared", "context", "result",
    "repair_plan", "host_result",
    "action_hash",
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
    if not isinstance(value, dict):
        raise OrchestratorError("ACTION_CORRUPT", "action must be an object")
    if value.get("schema_version") != ACTION_SCHEMA_VERSION:
        raise OrchestratorError(
            "ACTION_VERSION_UNSUPPORTED", "action schema version is not supported")
    if set(value) != ACTION_FIELDS \
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
            or value["tier"] not in {"S", "M", "L", "XL"} \
            or not isinstance(value["domains"], list) or not value["domains"] \
            or len(value["domains"]) > 16 \
            or len(value["domains"]) != len(set(value["domains"])) \
            or not all(isinstance(item, str) and re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", item) for item in value["domains"]) \
            or type(value["attempts"]) is not int \
            or not 0 <= value["attempts"] <= 3 \
            or value["max_attempts"] != 3 \
            or type(value["remove_pristine_pack"]) is not bool \
            or (value["work_order"] is not None and (
                not isinstance(value["work_order"], str)
                or not re.fullmatch(r"(?:work-orders/)?WO-[0-9]{3,}(?:-[A-Za-z0-9._-]+)?\.md",
                                    value["work_order"]))) \
            or not isinstance(value["prepared"], dict) \
            or not isinstance(value["context"], dict) \
            or (value["initial_pack_hash"] is not None and not re.fullmatch(
                r"[0-9a-f]{64}", str(value["initial_pack_hash"]))):
        raise OrchestratorError("ACTION_CORRUPT", "action contract is invalid")
    context = value["context"]
    if set(context) != {"memory", "preferences", "archived_count"} \
            or not isinstance(context["memory"], list) \
            or not isinstance(context["preferences"], list) \
            or len(context["memory"]) > 16 \
            or len(context["preferences"]) > 32 \
            or type(context["archived_count"]) is not int \
            or context["archived_count"] < 0 \
            or len(_canonical_bytes(context)) > 32 * 1024:
        raise OrchestratorError("ACTION_CORRUPT", "sealed context capsule is invalid")
    try:
        prepared = loom_runtime.PreparedInvocation.from_dict(value["prepared"])
    except loom_runtime.RuntimeError as exc:
        raise OrchestratorError("ACTION_CORRUPT", "sealed preparation is invalid") from exc
    if prepared.instance_id != value["instance_id"] \
            or prepared.invocation_id != value["invocation_id"] \
            or prepared.project_id != value["project_id"] \
            or prepared.survey_hash != value["survey_hash"] \
            or prepared.intent != value["intent"] \
            or prepared.route_contract["tier"] != value["tier"] \
            or list(prepared.domains) != value["domains"] \
            or not isinstance(value["request"], str) \
            or not value["request"].strip() or len(value["request"]) > 20_000 \
            or prepared.request_hash != loom_runtime._sha(
                " ".join(value["request"].split())):
        raise OrchestratorError("ACTION_CORRUPT", "sealed preparation does not match action")
    repair_plan = value["repair_plan"]
    if value["intent"] == "repair":
        if not isinstance(repair_plan, dict) or set(repair_plan) != {
                "changed_paths", "affected_plan_sections", "regate_scope",
                "prior_state_hash", "current_state_hash", "force_full"} \
                or repair_plan["regate_scope"] not in {"selective", "full"} \
                or type(repair_plan["force_full"]) is not bool \
                or not all(re.fullmatch(r"[0-9a-f]{64}", str(repair_plan[name]))
                           for name in ("prior_state_hash", "current_state_hash")) \
                or not isinstance(repair_plan["changed_paths"], list) \
                or not isinstance(repair_plan["affected_plan_sections"], list) \
                or not repair_plan["affected_plan_sections"]:
            raise OrchestratorError("ACTION_CORRUPT", "sealed repair plan is invalid")
    elif repair_plan is not None:
        raise OrchestratorError("ACTION_CORRUPT", "non-repair action carries repair scope")
    if value["host_result"] is not None and not isinstance(value["host_result"], dict):
        raise OrchestratorError("ACTION_CORRUPT", "host result is invalid")
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


def _repair_force_full(pack, instant):
    try:
        frontmatter, _ = loom_lint.parse_frontmatter(
            (Path(pack) / "MANIFEST.md").read_text(encoding="utf-8"))
        verified = dt.date.fromisoformat(str(frontmatter["last_verified"]))
        window = int(frontmatter["freshness_window_days"])
    except (OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        raise OrchestratorError(
            "REPAIR_SCOPE_INDETERMINATE", f"cannot establish freshness scope: {exc}") from exc
    return (instant.date() - verified).days > window


def _read_repair_result(result_path, action):
    if result_path is None:
        raise OrchestratorError(
            "REPAIR_EVIDENCE_REQUIRED",
            "repair completion requires content-bound real-medium evidence")
    path = _absolute(result_path, "repair result")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair result is not a bounded file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", str(exc)) from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "repair_verification"} \
            or value["schema_version"] != 1 \
            or not isinstance(value["repair_verification"], list):
        raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair result fields are invalid")
    expected = action["repair_plan"]["affected_plan_sections"]
    entries, seen = [], set()
    pack = Path(action["explicit_target"] or action["cwd"]) / "plans"
    for item in value["repair_verification"]:
        if not isinstance(item, dict) or set(item) != {
                "section", "passed", "medium", "evidence_path", "evidence_sha256"} \
                or item["section"] not in expected or item["section"] in seen \
                or item["passed"] is not True \
                or not isinstance(item["medium"], str) \
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item["medium"]) \
                or not isinstance(item["evidence_path"], str) \
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", item["evidence_path"]) \
                or ".." in item["evidence_path"].split("/") \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item["evidence_sha256"])):
            raise OrchestratorError("REPAIR_EVIDENCE_INVALID", "repair evidence entry is invalid")
        evidence = pack / Path(*item["evidence_path"].split("/"))
        try:
            loom_memory._reject_link_ancestors(evidence, "repair evidence")
            if evidence.is_symlink() or not evidence.is_file() \
                    or evidence.stat().st_size > 8 * 1024 * 1024:
                raise OrchestratorError(
                    "REPAIR_EVIDENCE_INVALID", "repair evidence is not a bounded regular file")
            raw = evidence.read_bytes()
        except (OSError, loom_memory.MemoryError) as exc:
            raise OrchestratorError("REPAIR_EVIDENCE_INVALID", str(exc)) from exc
        if hashlib.sha256(raw).hexdigest() != item["evidence_sha256"]:
            raise OrchestratorError(
                "REPAIR_EVIDENCE_INVALID", "repair evidence content does not match its digest")
        seen.add(item["section"])
        entries.append({**item, "evidence_id": "sha256-" + item["evidence_sha256"]})
    if sorted(seen) != sorted(expected):
        raise OrchestratorError(
            "REPAIR_EVIDENCE_INVALID", "repair evidence does not cover the sealed scope exactly")
    return {"schema_version": 1, "repair_verification": entries}


def _read_host_outcome(result_path, action):
    if result_path is None:
        return None
    path = _absolute(result_path, "host outcome")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise OrchestratorError("HOST_OUTCOME_INVALID", "host outcome is not a bounded file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("HOST_OUTCOME_INVALID", str(exc)) from exc
    fields = {
        "schema_version", "applied_memory_ids", "verified_memory_ids",
        "rejected_memory_ids", "metrics", "preference_observations", "artifact_usage",
    }
    if not isinstance(value, dict) or set(value) != fields or value["schema_version"] != 1:
        raise OrchestratorError("HOST_OUTCOME_INVALID", "host outcome fields are invalid")
    evidence_id = "host-outcome-" + _hash(value)
    candidate = {
        "status": "completed", "code": "host-outcome", "success": True,
        "metrics": value["metrics"], "evidence_ids": [evidence_id],
        "reversible_action_ids": [],
        "applied_memory_ids": value["applied_memory_ids"],
        "verified_memory_ids": value["verified_memory_ids"],
        "rejected_memory_ids": value["rejected_memory_ids"],
        "preference_observations": value["preference_observations"],
        "artifact_usage": value["artifact_usage"],
    }
    try:
        normalized = loom_session._validate_handler_result(candidate)
    except loom_session.SessionBlocked as exc:
        raise OrchestratorError("HOST_OUTCOME_INVALID", str(exc)) from exc
    selected = {item.get("id") for item in action["context"]["memory"]
                if isinstance(item, dict)}
    referenced = set(normalized["applied_memory_ids"]) \
        | set(normalized["verified_memory_ids"]) \
        | set(normalized["rejected_memory_ids"])
    if not referenced.issubset(selected):
        raise OrchestratorError(
            "HOST_OUTCOME_INVALID", "host outcome references memory outside sealed context")
    if not (referenced or normalized["metrics"] or normalized["preference_observations"]
            or normalized["artifact_usage"]):
        raise OrchestratorError("HOST_OUTCOME_INVALID", "empty host outcome has no learning value")
    return {"schema_version": 1, "learning": {
        key: normalized[key] for key in (
            "metrics", "evidence_ids", "applied_memory_ids", "verified_memory_ids",
            "rejected_memory_ids", "preference_observations", "artifact_usage")}}


def _merge_host_outcome(result, host_result):
    if not host_result or "learning" not in host_result or result["status"] != "completed":
        return result
    merged = dict(result)
    learning = host_result["learning"]
    merged["metrics"] = dict(learning["metrics"])
    merged["evidence_ids"] = list(dict.fromkeys(
        list(result["evidence_ids"]) + list(learning["evidence_ids"])))
    for field in (
            "applied_memory_ids", "verified_memory_ids", "rejected_memory_ids",
            "preference_observations", "artifact_usage"):
        merged[field] = list(learning[field])
    return merged


def _restamp_verified_pack(pack, repo, verified_at, *, full):
    """Update only verification stamps after a successful sealed regate."""
    pack = Path(pack)
    state = loom_gate._state(repo, pack)
    manifest, rendered = loom_gate._render_manifest(pack, state, "planned")
    stamp = loom_runtime._parse_time(verified_at).date().isoformat()
    rendered = re.sub(
        r"(?m)^last_verified\s*:.*$", f"last_verified: {stamp}", rendered, count=1)
    updates = {manifest: rendered}
    if full:
        for path in pack.rglob("*.md"):
            if path == manifest or path.is_symlink() or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            close = text.find("\n---", 4) if text.startswith("---\n") else -1
            if close < 0 or not re.search(r"(?m)^last_verified\s*:.*$", text[:close]):
                continue
            updates[path] = re.sub(
                r"(?m)^last_verified\s*:.*$", f"last_verified: {stamp}", text, count=1)
    originals = {path: path.read_text(encoding="utf-8") for path in updates}
    try:
        for path, text in updates.items():
            loom_gate._atomic_write_text(path, text)
    except BaseException:
        for path, text in originals.items():
            loom_gate._atomic_write_text(path, text)
        raise
    return originals


def _active_work_order(pack, tier):
    pack = Path(pack)
    candidates = []
    paths = [pack / "WO-001.md"] if tier == "S" \
        else sorted((pack / "work-orders").glob("WO-*.md"))
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        frontmatter, _ = loom_lint.parse_frontmatter(path.read_text(encoding="utf-8"))
        if frontmatter and frontmatter.get("status") in {"ready", "in-progress"}:
            candidates.append((str(frontmatter.get("id", "")), path))
    if len(candidates) != 1 or not re.fullmatch(r"WO-[0-9]{3,}", candidates[0][0]):
        raise OrchestratorError(
            "WORK_ORDER_AMBIGUOUS",
            "execution requires exactly one ready or in-progress work order")
    work_order, path = candidates[0]
    return work_order, path.relative_to(pack).as_posix()


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


def _handler_result(context, root, owner_home, usage, work_order=None,
                    repair_plan=None, host_result=None):
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
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": "plan-not-release-ready",
                "success": False, "metrics": {},
                "evidence_ids": [failure_evidence],
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

    if intent == "execute":
        if not work_order:
            findings = ["execution action is not bound to one work order"]
        else:
            work_order_path = pack / work_order
            if tier == "S":
                code, output = _capture(
                    loom_gate.small_close,
                    pack / ".loom-small-lifecycle.json", root, work_order_path)
            else:
                code, output = _capture(
                    loom_gate.close_wo, pack, root, work_order_path)
            logs.append(output)
            findings = (["work-order completion failed: " + output] if code else [])
        if not findings:
            findings.extend(
                loom_gate.verify_small(pack / ".loom-small-lifecycle.json")
                if tier == "S" else
                loom_gate.verify(pack, root, require_authorized=True))
        if findings:
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": "execute-not-ready", "success": False,
                "metrics": {}, "evidence_ids": [failure_evidence],
                "reversible_action_ids": [],
                "usage": usage,
                "user_message": "Execute blocked: " + "; ".join(findings[:8]),
            }
        evidence = "execute-" + _pack_hash(pack)[:24]
        return {
            "status": "completed", "code": "execute-complete", "success": True,
            "metrics": {}, "evidence_ids": [evidence],
            "reversible_action_ids": [], "usage": usage,
            "user_message": (
                "Execution completion was causally sealed against the declared "
                f"work order ({evidence})."),
        }

    if intent == "repair":
        if tier == "S":
            return {
                "status": "blocked", "code": "small-replan-required", "success": False,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
                "usage": usage,
                "user_message": "Expired Tier-S work must be re-baselined as a new compact plan.",
            }
        if repair_plan is None or host_result is None:
            raise OrchestratorError(
                "REPAIR_EVIDENCE_REQUIRED", "sealed repair evidence is missing")
        by_section = {
            item["section"]: item for item in host_result["repair_verification"]}

        def verifier(section, _changed_paths):
            item = by_section[section]
            return {"passed": True, "medium": item["medium"],
                    "evidence_id": item["evidence_id"]}

        regate = pack / loom_lifecycle.REGATE_FILE
        regate_before = regate.read_bytes() if regate.is_file() else None
        originals = {}
        try:
            outcome = loom_lifecycle.reconcile(
                pack, root, verifier,
                now=loom_runtime._parse_time(context.prepared.prepared_at),
                force_full=repair_plan["force_full"],
                expected_plan={key: repair_plan[key] for key in (
                    "changed_paths", "affected_plan_sections", "regate_scope",
                    "prior_state_hash", "current_state_hash")})
            originals = _restamp_verified_pack(
                pack, root, context.prepared.prepared_at,
                full=repair_plan["force_full"])
            report = loom_lint.lint(pack, repo_path=root, strict_staleness=True)
            findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
            findings.extend(loom_gate.verify(pack, root, require_authorized=True))
            if findings:
                raise OrchestratorError("REPAIR_POSTCHECK_FAILED", "; ".join(findings[:8]))
        except BaseException:
            for path, text in originals.items():
                loom_gate._atomic_write_text(path, text)
            if regate_before is None:
                if regate.exists() and not regate.is_symlink():
                    regate.unlink()
            else:
                loom_lifecycle._atomic_json(regate, json.loads(regate_before))
            raise
        evidence = "repair-" + outcome["receipt_hash"][:24]
        return {
            "status": "completed", "code": "repair-complete", "success": True,
            "metrics": {"drift-caught-before-execution": 1},
            "evidence_ids": [evidence], "reversible_action_ids": [], "usage": usage,
            "user_message": (
                f"Repair sealed for {outcome['regate_scope']} scope ({evidence})."),
        }

    if intent in {"resume", "review", "close"}:
        report = loom_lint.lint(
            pack, repo_path=root, strict_staleness=intent in {"resume", "repair"})
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
            failure_evidence = "gate-" + _hash(findings)[:24]
            return {
                "status": "blocked", "code": f"{intent}-not-ready", "success": False,
                "metrics": {}, "evidence_ids": [failure_evidence],
                "reversible_action_ids": [],
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


def default_handlers(*, root, owner_home, usage=None, work_order=None,
                     repair_plan=None, host_result=None):
    """Return the complete audited production handler registry."""
    root, owner_home = Path(root), Path(owner_home)
    normalized = loom_performance.normalize_usage(usage)
    usage_payload = (None if normalized["measurement_status"] == "unreported" else {
        field: normalized[field] for field in loom_performance.USAGE_FIELDS
    })
    return {
        intent: (lambda context, _intent=intent: _merge_host_outcome(
            _handler_result(context, root, owner_home, usage_payload, work_order,
                            repair_plan, host_result), host_result))
        for intent in {
            "plan", "resume", "execute", "review", "repair", "close", "remember"
        }
    }


def _controller(action, *, usage=None):
    home = Path(action["owner_home"])
    root = Path(action["explicit_target"] or action["cwd"])
    memory = loom_session.LocalMemoryAdapter(
        owner_home=home, instance_id=action["instance_id"])
    handlers = default_handlers(
        root=root, owner_home=home, usage=usage,
        work_order=action.get("work_order"),
        repair_plan=action.get("repair_plan"), host_result=action.get("host_result"))
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
    context_capsule = controller.prepare_context(opened, request)
    created_at = _stamp(now)
    expires_at = _stamp(
        loom_runtime._parse_time(created_at) + dt.timedelta(seconds=timeout_seconds))
    action_id = invocation_id
    path = _action_path(home, instance_id, prepared.project_id, action_id)
    action = {
        "schema_version": ACTION_SCHEMA_VERSION, "action_id": action_id,
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
        "work_order": None, "prepared": prepared.to_dict(),
        "context": context_capsule,
        "repair_plan": None, "host_result": None,
        "result": None,
    }
    if prepared.route_contract["blocked"]:
        receipt = controller.run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared, selected_context=context_capsule)
        action["status"], action["result"] = "completed", receipt.to_dict()
        _write_action(path, action)
        return receipt.to_dict()
    if prepared.intent in {"status", "why", "undo", "forget", "remember"}:
        immediate = _controller(action).run(
            request, invocation_id=invocation_id, cwd=cwd,
            explicit_target=target, now=now, continue_open=True,
            prepared=prepared, selected_context=context_capsule)
        action["status"], action["result"] = "completed", immediate.to_dict()
        _write_action(path, action)
        return immediate.to_dict()
    if prepared.intent == "plan":
        pack = target / "plans"
        pack_was_absent = not pack.exists()
        if action["tier"] == "S":
            record, work_order = pack / ".loom-small-lifecycle.json", pack / "WO-001.md"
            if not record.exists() and not work_order.exists():
                code, output = _capture(
                    loom_gate.small_start, record, target, work_order,
                    list(prepared.domains))
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
    elif prepared.intent == "execute":
        work_order_id, work_order_path = _active_work_order(
            target / "plans", action["tier"])
        if action["tier"] == "S":
            findings = loom_gate.verify_small(
                target / "plans" / ".loom-small-lifecycle.json")
        else:
            report = loom_lint.lint(
                target / "plans", repo_path=target, strict_staleness=True)
            findings = [f"{item['code']}: {item['msg']}" for item in report.errors]
            findings.extend(loom_gate.verify(
                target / "plans", target, require_authorized=True))
        if findings:
            raise OrchestratorError(
                "EXECUTION_NOT_READY", "; ".join(findings[:8]))
        action["work_order"] = work_order_path
    elif prepared.intent == "repair":
        if action["tier"] == "S":
            raise OrchestratorError(
                "SMALL_REPLAN_REQUIRED",
                "expired or drifted Tier-S work must be re-baselined before execution")
        force_full = _repair_force_full(target / "plans", loom_runtime._parse_time(created_at))
        preview = loom_lifecycle.preview_regate(
            target / "plans", target, force_full=force_full)
        if preview["regate_scope"] == "none":
            raise OrchestratorError(
                "REPAIR_SCOPE_INDETERMINATE", "repair route has no verifiable affected scope")
        action["repair_plan"] = {**preview, "force_full": force_full}
    action = _write_action(path, action)
    return {
        "schema_version": SCHEMA_VERSION, "status": "action-required",
        "action_id": action_id, "action_path": str(path),
        "intent": action["intent"], "tier": action["tier"],
        "domains": action["domains"], "expires_at": expires_at,
        "work_order": work_order_id if prepared.intent == "execute" else None,
        "repair_plan": action["repair_plan"],
        "context": {
            "memory": context_capsule["memory"],
            "preferences": context_capsule["preferences"],
        },
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


def complete(action_path, usage_path, *, result_path=None, now=None):
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
    if action["intent"] == "repair":
        action["host_result"] = _read_repair_result(result_path, action)
    elif result_path is not None:
        action["host_result"] = _read_host_outcome(result_path, action)
    sealed = loom_runtime.PreparedInvocation.from_dict(action["prepared"])
    if action["intent"] == "execute":
        project = loom_runtime.resolve_project(
            action["instance_id"], explicit_target=action["explicit_target"],
            cwd=action["cwd"])
        if project.project_id != action["project_id"] \
                or project.canonical_target_identity != sealed.canonical_target_identity:
            raise OrchestratorError(
                "TARGET_DRIFT", "delegated target identity changed")
    else:
        current = loom_runtime.prepare_invocation(
            action["request"], instance_id=action["instance_id"],
            invocation_id=action["invocation_id"], cwd=action["cwd"],
            explicit_target=action["explicit_target"], owner_home=action["owner_home"],
            now=instant)
        if current.survey_hash != action["survey_hash"] \
                or current.project_id != action["project_id"] \
                or current.intent != action["intent"]:
            raise OrchestratorError(
                "TARGET_DRIFT",
                "target, project, or routed intent changed during delegated work")
    controller = _controller(action, usage=usage)
    try:
        receipt = controller.run(
            action["request"], invocation_id=action["invocation_id"],
            cwd=action["cwd"], explicit_target=action["explicit_target"],
            now=instant, continue_open=True, prepared=sealed,
            selected_context=action["context"])
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
    complete_parser.add_argument("--result")
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
            result = complete(args.action, args.usage, result_path=args.result)
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
