#!/usr/bin/env python3
"""Compile closed, content-bound verification recipes without granting authority."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

import loom_lifecycle
import loom_proofline
import loom_reliability


SCHEMA_VERSION = 1
REGISTRY_ID = "loom-verification-recipes-v1"
RISKS = {"low", "medium", "high", "critical"}
SECTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PYTHON_TARGET_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
CARGO_TARGET_RE = re.compile(r"^(?:all|[A-Za-z_][A-Za-z0-9_-]{0,127})$")
NPM_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")
REASON_CODES = {
    "authority-missing", "target-invalid", "template-unsupported",
    "tool-unavailable",
}


class RecipeError(ValueError):
    pass


def _load_json(path, label):
    try:
        return json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, RecipeError) as exc:
        raise RecipeError(f"{label} is unreadable: {exc}") from exc


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RecipeError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_registry(path):
    value = _load_json(path, "verification recipe registry")
    fields = {
        "schema_version", "registry_id", "templates", "unsupported_policy",
        "host_pass_flags", "execution_isolation",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("registry_id") != REGISTRY_ID \
            or value.get("unsupported_policy") != "remain-unsupported" \
            or value.get("host_pass_flags") != "rejected" \
            or value.get("execution_isolation") != "disposable-target-snapshot" \
            or not isinstance(value.get("templates"), list):
        raise RecipeError("verification recipe registry is invalid")
    expected_fields = {
        "template_id", "outcome_class", "medium", "tool",
        "evidence_parser", "failure_meaning", "maximum_timeout_seconds",
    }
    templates = {}
    for item in value["templates"]:
        if not isinstance(item, dict) or set(item) != expected_fields \
                or not isinstance(item.get("template_id"), str) \
                or item["template_id"] in templates \
                or not all(
                    isinstance(item.get(key), str) and item[key]
                    for key in (
                        "outcome_class", "medium", "tool",
                        "failure_meaning")) \
                or item.get("evidence_parser") != "exit-code-zero-v1" \
                or type(item.get("maximum_timeout_seconds")) is not int \
                or not 1 <= item["maximum_timeout_seconds"] <= 300:
            raise RecipeError("verification recipe template is invalid")
        templates[item["template_id"]] = item
    if set(templates) != {
            "cargo-test-v1", "npm-script-v1", "pytest-node-v1",
            "python-unittest-v1"}:
        raise RecipeError("verification recipe template set is invalid")
    return value


def _tool_path(tool, available_tools):
    candidate = available_tools.get(tool)
    if candidate is None and tool == "python":
        candidate = sys.executable
    if not isinstance(candidate, str) or not candidate:
        return None
    path = Path(candidate)
    if not path.is_absolute() or not path.is_file():
        return None
    return str(path.resolve())


def _safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        return None
    return path


def _file_authority(path):
    path = Path(path)
    try:
        content = path.read_bytes()
    except OSError:
        return None
    return {
        "path": path.name,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _python_authority(root, target):
    parts = target.split("::", 1)[0].split(".")
    for stop in range(len(parts), 0, -1):
        candidate = Path(root).joinpath(*parts[:stop]).with_suffix(".py")
        authority = _file_authority(candidate)
        if authority is not None:
            authority["path"] = candidate.relative_to(root).as_posix()
            return authority
        candidate = Path(root).joinpath(*parts[:stop], "__init__.py")
        authority = _file_authority(candidate)
        if authority is not None:
            authority["path"] = candidate.relative_to(root).as_posix()
            return authority
    return None


def _compile_command(root, template_id, target, tool_path):
    root = Path(root)
    if template_id == "python-unittest-v1":
        if not PYTHON_TARGET_RE.fullmatch(target):
            return None, None, None, "target-invalid"
        source = _python_authority(root, target)
        if source is None:
            return None, None, None, "authority-missing"
        return [tool_path, "-B", "-m", "unittest", target], \
            "current-project-authority", {"files": [source]}, None
    if template_id == "pytest-node-v1":
        path_text = target.split("::", 1)[0]
        relative = _safe_relative(path_text)
        if relative is None or relative.suffix != ".py" \
                or not (root / Path(*relative.parts)).is_file():
            return None, None, None, "target-invalid"
        source = _file_authority(root / Path(*relative.parts))
        source["path"] = relative.as_posix()
        return [tool_path, "-B", "-m", "pytest", target], \
            "current-project-authority", {"files": [source]}, None
    if template_id == "cargo-test-v1":
        if not CARGO_TARGET_RE.fullmatch(target):
            return None, None, None, "target-invalid"
        files = []
        for name in ("Cargo.toml", "Cargo.lock"):
            source = _file_authority(root / name)
            if source is None:
                return None, None, None, "authority-missing"
            source["path"] = name
            files.append(source)
        command = [tool_path, "test", "--locked", "--offline"]
        if target != "all":
            command.append(target)
        return command, "current-project-authority", {"files": files}, None
    if template_id == "npm-script-v1":
        if not NPM_TARGET_RE.fullmatch(target):
            return None, None, None, "target-invalid"
        authority = root / "package.json"
        try:
            package = json.loads(
                authority.read_text(encoding="utf-8"),
                object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError, RecipeError):
            return None, None, None, "authority-missing"
        scripts = package.get("scripts") if isinstance(package, dict) else None
        if not isinstance(scripts, dict) or not isinstance(
                scripts.get(target), str):
            return None, None, None, "authority-missing"
        source = _file_authority(authority)
        source["path"] = "package.json"
        return [tool_path, "run", "--silent", target], \
            "current-project-authority", {"files": [source]}, None
    return None, None, None, "template-unsupported"


def compile_recipe(*, root, pack, requests, expected_sections, risk, registry,
                   available_tools=None):
    root, pack = Path(root).resolve(), Path(pack).resolve()
    if risk not in RISKS or not isinstance(requests, list) \
            or not 1 <= len(requests) <= 32 \
            or not isinstance(expected_sections, list) \
            or len(expected_sections) != len(set(expected_sections)) \
            or any(not isinstance(item, str) or not SECTION_RE.fullmatch(item)
                   for item in expected_sections):
        raise RecipeError("verification recipe compilation input is invalid")
    templates = {item["template_id"]: item for item in registry["templates"]}
    available_tools = dict(available_tools or {})
    by_command, unsupported, seen = {}, [], set()
    for request in requests:
        fields = {"section", "template_id", "target", "timeout_seconds"}
        if not isinstance(request, dict) or set(request) != fields \
                or request["section"] not in expected_sections \
                or request["section"] in seen \
                or not isinstance(request["template_id"], str) \
                or not isinstance(request["target"], str) \
                or type(request["timeout_seconds"]) is not int \
                or not 1 <= request["timeout_seconds"] <= 300:
            raise RecipeError("verification recipe request is invalid")
        seen.add(request["section"])
        template = templates.get(request["template_id"])
        if template is None:
            unsupported.append({
                "section": request["section"],
                "template_id": request["template_id"],
                "reason_code": "template-unsupported",
            })
            continue
        tool_path = _tool_path(template["tool"], available_tools)
        if tool_path is None:
            unsupported.append({
                "section": request["section"],
                "template_id": request["template_id"],
                "reason_code": "tool-unavailable",
            })
            continue
        command, authority, authority_source, reason = _compile_command(
            root, request["template_id"], request["target"], tool_path)
        if reason is not None:
            unsupported.append({
                "section": request["section"],
                "template_id": request["template_id"],
                "reason_code": reason,
            })
            continue
        timeout = min(
            request["timeout_seconds"], template["maximum_timeout_seconds"])
        authority_value = {
            "template": template,
            "target": request["target"],
            "command": command,
            "tool": _file_authority(tool_path),
            "source": authority_source,
        }
        key = (
            tuple(command), timeout, template["evidence_parser"],
            template["failure_meaning"], authority)
        row = by_command.setdefault(key, {
            "sections": [], "template_id": template["template_id"],
            "target": request["target"],
            "outcome_class": template["outcome_class"],
            "medium": template["medium"], "command": command,
            "timeout_seconds": timeout,
            "evidence_parser": template["evidence_parser"],
            "failure_meaning": template["failure_meaning"],
            "authority": authority,
            "authority_sha256": loom_proofline.digest(authority_value),
        })
        row["sections"].append(request["section"])
    if sorted(seen) != sorted(expected_sections):
        raise RecipeError("verification recipe does not cover the sealed scope exactly")
    rows = []
    for index, (_key, item) in enumerate(
            sorted(by_command.items(), key=lambda pair: pair[0]), start=1):
        rows.append({
            "step_id": f"VS-{index:03d}",
            **{**item, "sections": sorted(item["sections"])},
        })
    registry_sha256 = loom_proofline.digest(registry)
    body = {
        "schema_version": SCHEMA_VERSION,
        "registry_id": registry["registry_id"],
        "registry_sha256": registry_sha256,
        "subject_state_sha256": loom_lifecycle.inspect_world(
            root, pack)["state_hash"],
        "risk": risk,
        "steps": rows,
        "unsupported": sorted(
            unsupported, key=lambda item: (item["section"], item["template_id"])),
        "implementation_authorized": False,
        "execution_isolation": "disposable-target-snapshot",
    }
    value = {**body, "recipe_sha256": loom_proofline.digest(body)}
    validate_recipe(value)
    return value


def validate_recipe(value, *, root=None, registry=None):
    fields = {
        "schema_version", "registry_id", "registry_sha256",
        "subject_state_sha256", "risk", "steps", "unsupported",
        "implementation_authorized", "execution_isolation", "recipe_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("registry_id") != REGISTRY_ID \
            or value.get("risk") not in RISKS \
            or value.get("implementation_authorized") is not False \
            or value.get("execution_isolation") != "disposable-target-snapshot" \
            or not isinstance(value.get("steps"), list) \
            or not isinstance(value.get("unsupported"), list):
        raise RecipeError("compiled verification recipe is invalid")
    body = dict(value)
    observed = body.pop("recipe_sha256", None)
    if observed != loom_proofline.digest(body):
        raise RecipeError("compiled verification recipe digest changed")
    sections = []
    for index, step in enumerate(value["steps"], start=1):
        expected_fields = {
            "step_id", "sections", "template_id", "target", "outcome_class", "medium",
            "command", "timeout_seconds", "evidence_parser",
            "failure_meaning", "authority", "authority_sha256",
        }
        if not isinstance(step, dict) or set(step) != expected_fields \
                or step.get("step_id") != f"VS-{index:03d}" \
                or not isinstance(step.get("sections"), list) \
                or not step["sections"] \
                or len(step["sections"]) != len(set(step["sections"])) \
                or not isinstance(step.get("target"), str) \
                or not step["target"] \
                or step.get("evidence_parser") != "exit-code-zero-v1" \
                or step.get("authority") not in {
                    "approved-template", "current-project-authority"} \
                or not isinstance(step.get("command"), list) \
                or not 1 <= len(step["command"]) <= 32:
            raise RecipeError("compiled verification step is invalid")
        sections.extend(step["sections"])
        if root is not None and registry is not None:
            templates = {
                item["template_id"]: item for item in registry["templates"]}
            template = templates.get(step["template_id"])
            if template is None \
                    or value["registry_sha256"] != loom_proofline.digest(registry):
                raise RecipeError("compiled verification registry changed")
            command, authority, source, reason = _compile_command(
                root, step["template_id"], step["target"],
                step["command"][0])
            authority_value = {
                "template": template, "target": step["target"],
                "command": command, "tool": _file_authority(
                    step["command"][0]), "source": source,
            }
            if reason is not None or command != step["command"] \
                    or authority != step["authority"] \
                    or loom_proofline.digest(
                        authority_value) != step["authority_sha256"]:
                raise RecipeError(
                    "compiled verification authority changed")
    for item in value["unsupported"]:
        if not isinstance(item, dict) or set(item) != {
                "section", "template_id", "reason_code"} \
                or item.get("reason_code") not in REASON_CODES:
            raise RecipeError("unsupported verification entry is invalid")
        sections.append(item["section"])
    if len(sections) != len(set(sections)):
        raise RecipeError("verification section appears more than once")
    return value


def execute_recipe(*, recipe, registry, root, pack, evidence_root):
    validate_recipe(recipe, root=root, registry=registry)
    root, pack, evidence_root = (
        Path(root).resolve(), Path(pack).resolve(), Path(evidence_root).resolve())
    if recipe["unsupported"]:
        raise RecipeError(
            "verification medium remains unsupported: "
            + ", ".join(item["section"] for item in recipe["unsupported"]))
    current = loom_lifecycle.inspect_world(root, pack)["state_hash"]
    if current != recipe["subject_state_sha256"]:
        raise RecipeError("verification subject changed after recipe compilation")
    entries = []
    for step in recipe["steps"]:
        try:
            receipt = loom_lifecycle.capture_compiled_verification(
                pack, root, step["sections"], medium=step["medium"],
                command=step["command"], timeout=step["timeout_seconds"],
                evidence_parser=step["evidence_parser"],
                failure_meaning=step["failure_meaning"])
        except loom_lifecycle.LifecycleError as exc:
            raise RecipeError(
                f"{step['step_id']} {step['failure_meaning']}: {exc}") from exc
        path = evidence_root / f"{step['step_id']}.json"
        try:
            loom_reliability.atomic_write_json(path, receipt)
        except (OSError, loom_reliability.ReliabilityError) as exc:
            raise RecipeError(
                f"{step['step_id']} evidence could not be committed: {exc}") \
                from exc
        for section in step["sections"]:
            entries.append({
                "section": section, "passed": True,
                "medium": receipt["medium"],
                "evidence_id": receipt["evidence_id"],
                "evidence_hash": receipt["evidence_hash"],
                "attestation_status": "loom-compiled-executed-local",
                "receipt_path": path.relative_to(
                    evidence_root.parent).as_posix(),
                "recipe_step_id": step["step_id"],
            })
    return entries
