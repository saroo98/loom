#!/usr/bin/env python3
"""Deterministic, authority-neutral presentation of one validated Loom plan."""

import hashlib
import html
import json
import os
import re
from pathlib import Path, PurePosixPath


FORMAT = "plan-presentation-v1"
SCHEMA_VERSION = 1
TIERS = {"S", "M", "L"}
PREVIEW_LIMIT = 5
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PROJECT_ID = re.compile(r"^p-[0-9a-f]{32}$|^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
UNSAFE_SCHEME = re.compile(r"(?i)\b(javascript|vbscript|data|file):")
URI_PATH_SAFE = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/:")


class PresentationError(ValueError):
    pass


def _canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def _text(value, label, maximum):
    if not isinstance(value, str) or not value or len(value) > maximum \
            or "\x00" in value:
        raise PresentationError(f"{label} is invalid")
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def _texts(value, label, *, maximum_items, maximum_characters):
    if not isinstance(value, list) or len(value) > maximum_items:
        raise PresentationError(f"{label} is invalid")
    return [
        _text(item, f"{label} item", maximum_characters)
        for item in value
    ]


def _relative_plan_path(value):
    text = _text(value, "full-plan path", 256).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or not path.parts \
            or path.parts[0] != "plans":
        raise PresentationError("full-plan path is outside the Loom plan namespace")
    return path.as_posix()


def _binding(value):
    required = {
        "action_id", "project_id", "world_fingerprint", "plan_contract_hash",
        "pack_sha256", "revision", "relative_path", "manifest_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PresentationError("plan binding fields are unknown or missing")
    action_id = _text(value["action_id"], "action ID", 128)
    project_id = _text(value["project_id"], "project ID", 128)
    if ACTION_ID.fullmatch(action_id) is None \
            or PROJECT_ID.fullmatch(project_id) is None:
        raise PresentationError("plan binding identity is invalid")
    hashes = {}
    for key in (
            "world_fingerprint", "plan_contract_hash", "pack_sha256",
            "manifest_sha256"):
        item = value[key]
        if not isinstance(item, str) or HEX64.fullmatch(item) is None:
            raise PresentationError(f"{key.replace('_', ' ')} is invalid")
        hashes[key] = item
    if type(value["revision"]) is not int or not 1 <= value["revision"] <= 1_000_000:
        raise PresentationError("plan revision is invalid")
    return {
        "action_id": action_id,
        "project_id": project_id,
        **hashes,
        "revision": value["revision"],
        "relative_path": _relative_plan_path(value["relative_path"]),
    }


def _work_order(value, index):
    required = {
        "id", "title", "outcome", "tasks", "acceptance",
        "negative_acceptance", "out_of_scope", "escalation", "touches",
        "depends_on", "routing", "size",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PresentationError(f"work order {index} fields are unknown or missing")
    identity = _text(value["id"], "work-order ID", 16)
    expected = f"WO-{index:03d}"
    if identity != expected:
        raise PresentationError("work-order order or identity is invalid")
    touches = [
        _relative_plan_path("plans/" + item)[len("plans/"):]
        for item in _texts(
            value["touches"], "touch paths", maximum_items=32,
            maximum_characters=300)
    ]
    return {
        "id": identity,
        "title": _text(value["title"], "work-order title", 100),
        "outcome": _text(value["outcome"], "work-order outcome", 500),
        "tasks": _texts(
            value["tasks"], "work-order tasks", maximum_items=16,
            maximum_characters=500),
        "acceptance": _texts(
            value["acceptance"], "acceptance", maximum_items=16,
            maximum_characters=500),
        "negative_acceptance": _texts(
            value["negative_acceptance"], "negative acceptance", maximum_items=8,
            maximum_characters=500),
        "out_of_scope": _texts(
            value["out_of_scope"], "out of scope", maximum_items=16,
            maximum_characters=500),
        "escalation": _texts(
            value["escalation"], "escalation", maximum_items=16,
            maximum_characters=500),
        "touches": touches,
        "depends_on": _texts(
            value["depends_on"], "dependencies", maximum_items=16,
            maximum_characters=16),
    }


def extract_semantics(draft):
    """Return the exact bounded fields needed to reproduce the display projection."""
    if not isinstance(draft, dict):
        raise PresentationError("semantic draft is invalid")
    work_orders = draft.get("work_orders")
    if not isinstance(work_orders, list) or not work_orders or len(work_orders) > 64:
        raise PresentationError("work orders are invalid")
    value = {
        "schema_version": 1,
        "title": _text(draft.get("title"), "plan title", 100),
        "summary": _text(draft.get("summary"), "plan summary", 1000),
        "assumptions": _texts(
            draft.get("assumptions"), "assumptions", maximum_items=16,
            maximum_characters=500),
        "decisions": _texts(
            draft.get("decisions"), "decisions", maximum_items=16,
            maximum_characters=500),
        "work_orders": [
            _work_order(item, index)
            for index, item in enumerate(work_orders, start=1)
        ],
    }
    validate_semantics(value)
    return value


def validate_semantics(value):
    required = {
        "schema_version", "title", "summary", "assumptions", "decisions",
        "work_orders",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != 1:
        raise PresentationError("presentation semantics fields are unknown or invalid")
    _text(value["title"], "plan title", 100)
    _text(value["summary"], "plan summary", 1000)
    _texts(
        value["assumptions"], "assumptions", maximum_items=16,
        maximum_characters=500)
    _texts(
        value["decisions"], "decisions", maximum_items=16,
        maximum_characters=500)
    if not isinstance(value["work_orders"], list) or not value["work_orders"] \
            or len(value["work_orders"]) > 64:
        raise PresentationError("work orders are invalid")
    for index, item in enumerate(value["work_orders"], start=1):
        _work_order({
            **item, "routing": "strong-coding", "size": "S",
        }, index)
    return value


def _inert_markdown(value):
    escaped = html.escape(value, quote=False)
    escaped = re.sub(r"([\\`*_\[\]{}#!|>])", r"\\\1", escaped)
    return UNSAFE_SCHEME.sub(
        lambda match: match.group(1) + "&#58;", escaped)


def _encoded_absolute_path(value):
    """Encode one local absolute path without importing a network-capable module."""
    output = []
    for byte in value.encode("utf-8"):
        output.append(chr(byte) if byte in URI_PATH_SAFE else f"%{byte:02X}")
    return "".join(output)


def _lines(items, *, prefix="- "):
    return [prefix + _inert_markdown(item) for item in items]


def _complete_markdown(title, summary, work_orders, assumptions, decisions):
    lines = [
        f"## {_inert_markdown(title)}",
        "",
        _inert_markdown(summary),
        "",
        "### Plan",
        "",
    ]
    for item in work_orders:
        lines.extend([
            f"#### {item['id']}: {_inert_markdown(item['title'])}",
            "",
            _inert_markdown(item["outcome"]),
            "",
        ])
        lines.extend(_lines(item["tasks"]))
        lines.extend(["", "**Expected files**", ""])
        lines.extend(_lines(item["touches"]))
        lines.extend(["", "**Completion checks**", ""])
        lines.extend(_lines(item["acceptance"]))
        lines.extend(["", "**Must still fail safely**", ""])
        lines.extend(_lines(item["negative_acceptance"]))
        lines.extend(["", "**Outside this step**", ""])
        lines.extend(_lines(item["out_of_scope"]))
        lines.extend(["", "**Stop and ask if**", ""])
        lines.extend(_lines(item["escalation"]))
        lines.append("")
    if assumptions:
        lines.extend(["### Assumptions to verify", ""])
        lines.extend(_lines(assumptions))
        lines.append("")
    if decisions:
        lines.extend(["### Decisions", ""])
        lines.extend(_lines(decisions))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def compile_presentation(draft, *, tier, binding):
    """Compile one storage-independent projection from a validated semantic draft."""
    if tier not in TIERS:
        raise PresentationError("plan tier is invalid")
    semantics = (
        draft if isinstance(draft, dict) and set(draft) == {
            "schema_version", "title", "summary", "assumptions", "decisions",
            "work_orders",
        } else extract_semantics(draft))
    validate_semantics(semantics)
    title = semantics["title"]
    summary = semantics["summary"]
    assumptions = semantics["assumptions"]
    decisions = semantics["decisions"]
    work_orders = semantics["work_orders"]
    bound = _binding(binding)
    mode = "complete" if tier == "S" else "bounded" if tier == "M" else "frontier"
    preview_steps = work_orders if tier == "S" else work_orders[:PREVIEW_LIMIT]
    touch_paths = sorted({
        path for item in work_orders for path in item["touches"]
    })
    verification = [
        item for work_order in work_orders for item in work_order["acceptance"]
    ]
    risks = [
        item for work_order in work_orders for item in work_order["escalation"]
    ]
    complete_markdown = _complete_markdown(
        title, summary, work_orders, assumptions, decisions)
    value = {
        "schema_version": SCHEMA_VERSION,
        "format": FORMAT,
        "title": title,
        "summary": summary,
        "tier": tier,
        "preview_mode": mode,
        "steps": preview_steps,
        "omitted_step_count": len(work_orders) - len(preview_steps),
        "expected_touch_paths": touch_paths,
        "assumptions": assumptions,
        "decisions": decisions,
        "risks": risks,
        "verification": verification,
        "full_plan": {
            "relative_path": bound["relative_path"],
            "sha256": bound["manifest_sha256"],
        },
        "binding": bound,
        "actions": {
            "revise": {
                "label": "Request a change",
                "instruction": "Describe what should change in this plan.",
            },
            "start": {
                "label": "Start this exact plan",
                "instruction": "Start this exact plan.",
            },
        },
        "complete_inline_markdown": complete_markdown,
    }
    digest_source = dict(value)
    value["presentation_sha256"] = hashlib.sha256(
        _canonical_bytes(digest_source)).hexdigest()
    validate(value)
    return value


def validate(value):
    required = {
        "schema_version", "format", "title", "summary", "tier", "preview_mode",
        "steps", "omitted_step_count", "expected_touch_paths", "assumptions",
        "decisions", "risks", "verification", "full_plan", "binding", "actions",
        "complete_inline_markdown", "presentation_sha256",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("format") != FORMAT \
            or value.get("tier") not in TIERS \
            or value.get("preview_mode") not in {"complete", "bounded", "frontier"}:
        raise PresentationError("plan presentation fields are unknown or invalid")
    _text(value["title"], "plan title", 100)
    _text(value["summary"], "plan summary", 1000)
    _binding(value["binding"])
    full_plan = value["full_plan"]
    if not isinstance(full_plan, dict) or set(full_plan) != {"relative_path", "sha256"} \
            or _relative_plan_path(full_plan["relative_path"]) != \
            value["binding"]["relative_path"] \
            or full_plan["sha256"] != value["binding"]["manifest_sha256"]:
        raise PresentationError("full-plan reference is not bound")
    if type(value["omitted_step_count"]) is not int \
            or value["omitted_step_count"] < 0:
        raise PresentationError("omitted step count is invalid")
    expected_mode = {
        "S": "complete", "M": "bounded", "L": "frontier",
    }[value["tier"]]
    if value["preview_mode"] != expected_mode:
        raise PresentationError("preview mode does not match the plan tier")
    _texts(
        value["expected_touch_paths"], "expected touch paths",
        maximum_items=2048, maximum_characters=300)
    _texts(value["assumptions"], "assumptions", maximum_items=16,
           maximum_characters=500)
    _texts(value["decisions"], "decisions", maximum_items=16,
           maximum_characters=500)
    _texts(value["risks"], "risks", maximum_items=1024, maximum_characters=500)
    _texts(
        value["verification"], "verification", maximum_items=1024,
        maximum_characters=500)
    if not isinstance(value["steps"], list) or len(value["steps"]) > PREVIEW_LIMIT \
            and value["tier"] != "S":
        raise PresentationError("preview steps are invalid")
    if not value["steps"] \
            or len(value["steps"]) + value["omitted_step_count"] > 64 \
            or value["tier"] == "S" and value["omitted_step_count"] != 0:
        raise PresentationError("preview inventory does not match the plan tier")
    for index, step in enumerate(value["steps"], start=1):
        _work_order({
            **step, "routing": "strong-coding", "size": "S",
        }, index)
    if not isinstance(value["actions"], dict) \
            or set(value["actions"]) != {"revise", "start"}:
        raise PresentationError("plan actions are invalid")
    for key in ("revise", "start"):
        action = value["actions"][key]
        if not isinstance(action, dict) or set(action) != {"label", "instruction"}:
            raise PresentationError("plan action fields are invalid")
        _text(action["label"], "plan action label", 64)
        _text(action["instruction"], "plan action instruction", 256)
    _text(value["complete_inline_markdown"], "complete inline Markdown", 196608)
    digest = value["presentation_sha256"]
    if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
        raise PresentationError("presentation digest is invalid")
    unsigned = dict(value)
    unsigned.pop("presentation_sha256")
    if hashlib.sha256(_canonical_bytes(unsigned)).hexdigest() != digest:
        raise PresentationError("presentation digest does not match")
    return value


def project_for_host(value, *, project_root, host_id):
    """Add one ephemeral host link after exact containment and digest checks."""
    validate(value)
    host_id = _text(host_id, "host ID", 64)
    root = Path(project_root).resolve()
    relative = PurePosixPath(value["full_plan"]["relative_path"])
    candidate = root.joinpath(*relative.parts)
    if not candidate.is_file() or candidate.is_symlink():
        raise PresentationError("the complete plan file is unavailable")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise PresentationError("the complete plan path escapes the project") from exc
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != value["full_plan"]["sha256"]:
        raise PresentationError("the complete plan changed after presentation binding")
    preview = value["complete_inline_markdown"]
    if value["preview_mode"] != "complete":
        preview = _complete_markdown(
            value["title"], value["summary"], value["steps"],
            value["assumptions"], value["decisions"])
        if value["omitted_step_count"]:
            preview += (
                f"\n_{value['omitted_step_count']} more validated step(s) are in the "
                "complete plan._\n")
    link_target = _encoded_absolute_path(resolved.as_posix())
    markdown = (
        preview.rstrip()
        + f"\n\n[Open the complete plan](<{link_target}>)\n\n"
        + "**What would you like to do?**\n\n"
        + "- **Request a change:** describe what should change in the plan.\n"
        + "- **Start this exact plan:** say `Start this exact plan.`\n")
    return {
        "schema_version": 1,
        "format": "plan-host-projection-v1",
        "host_id": host_id,
        "presentation_sha256": value["presentation_sha256"],
        "full_plan_sha256": value["full_plan"]["sha256"],
        "markdown": markdown,
        "complete_inline_markdown": value["complete_inline_markdown"],
    }
