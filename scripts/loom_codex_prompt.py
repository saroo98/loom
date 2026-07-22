#!/usr/bin/env python3
"""Route explicit Codex Loom prompts through the sealed local stdin bridge."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path


MAX_HOOK_BYTES = 256 * 1024
MAX_BRIDGE_BYTES = 2 * 1024 * 1024
MAX_FRAME_BYTES = 65536
MAX_REQUEST_CHARACTERS = 32768
MAX_ACTION_BYTES = 384 * 1024
MAX_CONTEXT_BYTES = 128 * 1024
HOOK_PROTOCOL = "LOOM_CODEX_HOOK_RECEIPT_V2"
SKILL_PREFIX = re.compile(
    r"^\s*\[\$(?:loom(?::loom)?)\]\([^\r\n)]*SKILL\.md\)",
    re.IGNORECASE,
)
COMMAND_PREFIX = re.compile(r"^\s*/loom(?=$|[ \t\r\n])", re.IGNORECASE)


class HookError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise HookError(f"sealed Loom action has a duplicate field: {key}")
        value[key] = item
    return value


def _redirected(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise HookError(f"cannot inspect sealed Loom action path: {exc}") from exc


def _trusted_os_alias(path):
    if sys.platform != "darwin":
        return False
    expected = {Path("/var"): Path("/private/var"),
                Path("/tmp"): Path("/private/tmp")}.get(Path(path))
    return expected is not None and Path(path).resolve(strict=False) == expected


def _validated_action(path, loom_home, expected_action_id):
    try:
        action = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
        owner_root = Path(os.path.abspath(os.path.expanduser(os.fspath(loom_home))))
    except (TypeError, ValueError, OSError) as exc:
        raise HookError(f"sealed Loom action path is invalid: {exc}") from exc
    try:
        action.relative_to(owner_root)
    except ValueError as exc:
        raise HookError("sealed Loom action escapes the owner-state root") from exc
    for component in [*reversed(action.parents), action]:
        if _redirected(component) and not _trusted_os_alias(component):
            raise HookError("sealed Loom action path is redirected")
    try:
        if not action.is_file() or action.stat().st_size > MAX_ACTION_BYTES:
            raise HookError("sealed Loom action is missing or oversized")
        raw = action.read_bytes()
        if len(raw) > MAX_ACTION_BYTES:
            raise HookError("sealed Loom action changed above its size bound")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HookError(f"sealed Loom action is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "kind", "action_id", "owner_vault_id", "ciphertext"} \
            or value.get("schema_version") != 1 \
            or value.get("kind") != "loom-encrypted-action-v1" \
            or value.get("action_id") != expected_action_id \
            or not isinstance(value.get("ciphertext"), str) or not value["ciphertext"]:
        raise HookError("sealed Loom action envelope linkage is invalid")
    try:
        if str(uuid.UUID(value["action_id"])) != value["action_id"] \
                or str(uuid.UUID(value["owner_vault_id"])) != value["owner_vault_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise HookError("sealed Loom action envelope identity is invalid") from exc
    return str(action), hashlib.sha256(raw).hexdigest()


def _read_event(stream):
    raw = stream.read(MAX_HOOK_BYTES + 1)
    if len(raw) > MAX_HOOK_BYTES:
        raise HookError("Codex hook event exceeds its byte bound")
    try:
        event = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HookError("Codex hook event is not bounded UTF-8 JSON") from exc
    if not isinstance(event, dict) or event.get("hook_event_name") != "UserPromptSubmit":
        raise HookError("Codex hook event type is invalid")
    prompt = event.get("prompt")
    cwd = event.get("cwd")
    if not isinstance(prompt, str) or not isinstance(cwd, str) or not cwd:
        raise HookError("Codex hook event is missing its prompt or working directory")
    return event


def _remove_one_separator(value):
    if value.startswith("\r\n"):
        return value[2:]
    if value[:1] in {" ", "\t", "\r", "\n"}:
        return value[1:]
    return value


def extract_request(prompt):
    """Return an explicit Loom request while preserving its remaining characters."""
    for pattern in (COMMAND_PREFIX, SKILL_PREFIX):
        matched = pattern.match(prompt)
        if matched is None:
            continue
        request = _remove_one_separator(prompt[matched.end():])
        if not request:
            raise HookError("/loom requires a request")
        return request
    return None


def _json_output(additional_context):
    return json.dumps({
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": additional_context,
        },
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load_object(raw, label):
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HookError(f"{label} did not return UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise HookError(f"{label} did not return an object")
    return value


def _run_bootstrap(plugin_root, loom_home):
    bootstrap = plugin_root / "scripts" / "loom_bootstrap.py"
    if not bootstrap.is_file() or bootstrap.is_symlink():
        raise HookError("Loom bootstrap is missing or redirected")
    try:
        completed = subprocess.run([
            sys.executable, "-B", str(bootstrap), "--ensure",
            "--plugin-root", str(plugin_root), "--home", str(loom_home),
        ], capture_output=True, timeout=90, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HookError("Loom bootstrap exceeded its bounded timeout") from exc
    payload = _load_object(completed.stdout, "Loom bootstrap")
    if completed.returncode != 0 or payload.get("status") == "blocked":
        message = str(payload.get("error", "Loom bootstrap failed"))[:512]
        raise HookError(message)
    launcher = loom_home / "bin" / "loom.py"
    if not launcher.is_file() or launcher.is_symlink():
        raise HookError("receipt-owned Loom launcher is unavailable")
    return launcher, payload


def _bridge_frames(request, event):
    if not 1 <= len(request) <= MAX_REQUEST_CHARACTERS:
        raise HookError("Loom request exceeds its character bound")
    identity = hashlib.sha256(request.encode("utf-8")).hexdigest()
    operation = hashlib.sha256((
        str(event.get("session_id", "")) + "\0"
        + str(event.get("turn_id", "")) + "\0" + identity
    ).encode("utf-8")).hexdigest()[:24]
    capabilities = {
        "invoke": True, "complete": False, "cancel": False, "status": False,
        "markdown": True, "usage_receipt": False,
        "response_identity": False, "latency_events": False,
    }
    initialize = {
        "schema_version": 2, "message_type": "initialize",
        "request_id": f"hook-init-{operation}",
        "protocol": {"minimum": 2, "maximum": 2},
        "adapter": {"id": "codex-prompt-hook", "version": "1.0.0"},
        "host": {"id": "codex", "version": "user-prompt-submit-v1"},
        "capabilities": capabilities,
    }
    invoke = {
        "schema_version": 2, "message_type": "invoke",
        "request_id": f"hook-invoke-{operation}",
        "request": request, "cwd": event["cwd"],
    }
    initialize_frame = json.dumps(
        initialize, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")
    invoke_frame = json.dumps(
        invoke, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")
    if len(initialize_frame) > MAX_FRAME_BYTES or len(invoke_frame) > MAX_FRAME_BYTES:
        raise HookError("Loom request exceeds its UTF-8 frame bound")
    return initialize_frame + b"\n" + invoke_frame + b"\n", identity


def _run_bridge(launcher, loom_home, frames):
    try:
        completed = subprocess.run([
            sys.executable, "-B", str(launcher), "--home", str(loom_home), "bridge",
        ], input=frames, capture_output=True, timeout=150, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HookError("Loom sealed invocation exceeded its bounded timeout") from exc
    if len(completed.stdout) > MAX_BRIDGE_BYTES:
        raise HookError("Loom bridge response exceeds its byte bound")
    responses = []
    for raw in completed.stdout.splitlines():
        if raw:
            responses.append(_load_object(raw, "Loom bridge"))
    if len(responses) != 2:
        raise HookError("Loom bridge did not complete one initialized invocation")
    initialized, result = responses
    if initialized.get("message_type") != "initialize-result":
        raise HookError("Loom bridge did not negotiate protocol 2")
    if result.get("message_type") == "error":
        raise HookError(str(result.get("message", "Loom invocation failed"))[:512])
    if result.get("message_type") != "result" \
            or not isinstance(result.get("returncode"), int) \
            or not isinstance(result.get("payload"), dict):
        raise HookError("Loom bridge returned an unsuccessful sealed invocation")
    payload = result["payload"]
    if completed.returncode != 0 or result["returncode"] != 0:
        if payload.get("status") == "blocked":
            message = payload.get("error")
            if not isinstance(message, str) or not message:
                owner_message = payload.get("owner_message")
                message = (owner_message.get("human") if isinstance(owner_message, dict)
                           else None)
            raise HookError(str(message or "Loom sealed invocation blocked")[:512])
        raise HookError("Loom bridge returned an unsuccessful sealed invocation")
    return initialized, payload


def _bounded_context(payload, *, request_sha256, runtime_version, loom_home):
    action_path = payload.get("action_path")
    action_id = payload.get("action_id")
    action_file_sha256 = None
    owner_message = payload.get("owner_message")
    if action_path is not None:
        if not isinstance(action_path, str) or not action_path:
            raise HookError("sealed Loom action path is invalid")
        if not isinstance(action_id, str):
            raise HookError("sealed Loom action identity is invalid")
        action_path, action_file_sha256 = _validated_action(
            action_path, loom_home, action_id)
    if owner_message is not None and not isinstance(owner_message, dict):
        raise HookError("sealed Loom owner message is invalid")
    assurance = payload.get("assurance")
    if not isinstance(assurance, dict) \
            or assurance.get("mode") != "verified" \
            or assurance.get("ingress") != "codex-user-prompt-hook-v2" \
            or assurance.get("request_identity_scope") != "host-prompt" \
            or assurance.get("request_sha256") != request_sha256:
        raise HookError("sealed Loom assurance does not prove this host prompt")
    context = {
        "protocol": HOOK_PROTOCOL,
        "runtime_version": runtime_version,
        "request_sha256": request_sha256,
        "status": payload.get("status"),
        "action_id": action_id,
        "action_path": action_path,
        "action_file_sha256": action_file_sha256,
        "owner_message": owner_message,
        "assurance": assurance,
    }
    public_fields = {
        "intent": str, "tier": str, "domains": list, "expires_at": str,
        "work_order": (str, type(None)), "repair_plan": (dict, type(None)),
        "plan_contract": (dict, type(None)), "context_manifest": dict,
        "continuation_authority": dict,
        "resolved_terminal_block": (dict, type(None)), "context": dict,
        "attempts_remaining": int, "session_environment": dict,
        "required_outcome": str, "prior_recovery": dict,
    }
    for field, expected_type in public_fields.items():
        if field not in payload:
            continue
        value = payload[field]
        if (expected_type is int and type(value) is not int) \
                or (expected_type is not int and not isinstance(value, expected_type)):
            raise HookError(f"sealed Loom public frontier field is invalid: {field}")
        context[field] = value
    context["instruction"] = (
        "Loom executed this request before agent work. The allowlisted public fields in this "
        "context are the complete semantic frontier; the encrypted action file is identity and "
        "digest evidence, not readable planning input. Never invoke Loom again for this turn or "
        "invent a fallback. For a plan action, author the exact plan_contract under its declared "
        "paths before calling complete. Do not call complete until the required artifacts exist. "
        "For every other intent, perform only required_outcome, then complete through the "
        "installed Loom skill."
    )
    try:
        encoded = json.dumps(context, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise HookError("sealed Loom public frontier is not strict JSON") from exc
    if len(encoded.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise HookError("bounded Loom hook context exceeds its limit")
    return encoded


def main():
    try:
        event = _read_event(sys.stdin.buffer)
        request = extract_request(event["prompt"])
        if request is None:
            return 0
        plugin_root = Path(os.environ.get(
            "PLUGIN_ROOT", Path(__file__).resolve().parents[1])).resolve()
        loom_home = Path(os.environ.get("LOOM_HOME", Path.home() / ".loom")).resolve()
        launcher, _bootstrap = _run_bootstrap(plugin_root, loom_home)
        frames, request_sha256 = _bridge_frames(request, event)
        initialized, payload = _run_bridge(launcher, loom_home, frames)
        context = _bounded_context(
            payload, request_sha256=request_sha256,
            runtime_version=initialized["runtime_version"], loom_home=loom_home)
        print(_json_output(context))
        return 0
    except HookError as exc:
        # Explicit Loom requests fail closed. Non-Loom prompts return before this path.
        reason = str(exc)[:512]
        print(json.dumps({"decision": "block", "reason": f"Loom blocked: {reason}"},
                         sort_keys=True, separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
