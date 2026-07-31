#!/usr/bin/env python3
"""Minimal local-only MCP surface for Loom Standard mode."""

import argparse
import json
import sys
import uuid
from pathlib import Path

import loom_adapter_bridge
import loom_adapter_protocol


MCP_PROTOCOL = "2025-06-18"
MAX_FRAME_BYTES = 256 * 1024
MAX_AUTHOR_DRAFT_BYTES = 192 * 1024
_PLAN_DRAFT_SCHEMA = None


class McpError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise McpError(-32600, f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _plan_draft_schema():
    """Load the installed, integrity-covered semantic authoring contract."""
    global _PLAN_DRAFT_SCHEMA
    if _PLAN_DRAFT_SCHEMA is not None:
        return _PLAN_DRAFT_SCHEMA
    path = Path(__file__).resolve().parents[1] / "schemas" / "plan-draft.schema.json"
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, McpError) as exc:
        raise McpError(
            -32603, "installed Loom plan-draft schema is missing or invalid") from exc
    if not isinstance(value, dict) \
            or value.get("$id") != "loom/schemas/plan-draft.schema.json" \
            or value.get("type") != "object" \
            or value.get("additionalProperties") is not False:
        raise McpError(-32603, "installed Loom plan-draft schema is not authoritative")
    _PLAN_DRAFT_SCHEMA = value
    return value


def _read(stream):
    raw = stream.readline(MAX_FRAME_BYTES + 2)
    if raw == b"":
        return None
    if len(raw) > MAX_FRAME_BYTES + 1 or not raw.endswith(b"\n"):
        raise McpError(-32600, "MCP frame is incomplete or oversized")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise McpError(-32700, "MCP frame is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise McpError(-32600, "MCP request is invalid")
    return value


def _write(stream, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False) + "\n").encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES + 1:
        raise McpError(-32603, "MCP response exceeds its bound")
    stream.write(raw)
    stream.flush()


def _tools():
    path = {
        "type": "string", "minLength": 1, "maxLength": 4096,
        "description": "Existing absolute filesystem path.",
    }
    action_path = {
        **path,
        "description": "Existing absolute path returned by Loom as action_path.",
    }
    usage_path = {
        **path,
        "description": (
            "Optional existing absolute path to a private usage-receipt-v3 JSON file. "
            "Omit when the host exposes no trustworthy usage counters."),
    }
    result_path = {
        **path,
        "description": (
            "Optional existing absolute path to structured repair-result or "
            "host-outcome JSON. Omit result for ordinary plan completion. Never pass prose, "
            "a summary, JSON text, or a path that does not already exist."),
    }
    return [
        {
            "name": "invoke",
            "description": "Start one Standard-assurance Loom action for an exact request.",
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["request", "cwd"],
                "properties": {
                    "request": {"type": "string", "minLength": 1,
                                "maxLength": loom_adapter_protocol.MAX_REQUEST_CHARACTERS},
                    "cwd": path,
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "resolve",
            "description": (
                "Resolve one Verified-assurance hook action without starting another action."),
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["request", "cwd", "action", "action_sha256"],
                "properties": {
                    "request": {"type": "string", "minLength": 1,
                                "maxLength": loom_adapter_protocol.MAX_REQUEST_CHARACTERS},
                    "cwd": path,
                    "action": path,
                    "action_sha256": {
                        "type": "string", "pattern": "^[0-9a-f]{64}$"},
                },
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "status", "description": "Read the verified local Loom runtime status.",
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": {}},
            "annotations": {"readOnlyHint": True, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "complete",
            "description": (
                "Validate and complete one existing Loom action. For an ordinary plan, "
                "send only action and omit result."),
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["action"],
                "properties": {
                    "action": action_path,
                    "usage": {"anyOf": [usage_path, {"type": "null"}]},
                    "result": {"anyOf": [result_path, {"type": "null"}]},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "author",
            "description": (
                "Machine-author a sealed planning pack from one bounded semantic draft. "
                "Pass draft as strict UTF-8 JSON matching the installed plan-draft schema. "
                "Set finalize=true for an ordinary plan to run completion immediately after "
                "successful authoring and return the final sealed receipt in this same tool call."),
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["action", "draft"],
                "properties": {
                    "action": action_path,
                    "draft": {
                        "type": "string",
                        "description": (
                            "Strict JSON object conforming to "
                            "schemas/plan-draft.schema.json. Loom parses duplicate fields "
                            "strictly and validates the complete installed schema before writing."),
                    },
                    "finalize": {
                        "type": "boolean",
                        "description": (
                            "When true, complete the ordinary plan only after authoring succeeds. "
                            "False preserves the legacy separate author-then-complete flow."),
                    },
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "start",
            "description": (
                "Start only the exact completed plan presentation that the owner reviewed."),
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["action", "presentation_sha256"],
                "properties": {
                    "action": action_path,
                    "presentation_sha256": {
                        "type": "string", "pattern": "^[0-9a-f]{64}$"},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "revise",
            "description": (
                "Open a fresh planning revision bound to the exact plan presentation "
                "that the owner reviewed."),
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["action", "presentation_sha256", "request"],
                "properties": {
                    "action": action_path,
                    "presentation_sha256": {
                        "type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "request": {
                        "type": "string", "minLength": 1,
                        "maxLength": loom_adapter_protocol.MAX_REQUEST_CHARACTERS},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "cancel", "description": "Cancel one existing Loom action safely.",
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "required": ["action"],
                            "properties": {"action": action_path}},
            "annotations": {"readOnlyHint": False, "destructiveHint": True,
                            "idempotentHint": True, "openWorldHint": False},
        },
    ]


def _adapter_message(name, arguments):
    if not isinstance(arguments, dict):
        raise McpError(-32602, "Loom tool arguments must be an object")
    request_id = "mcp-" + uuid.uuid4().hex
    common = {"schema_version": 2, "request_id": request_id}
    if name == "invoke":
        expected = {"request", "cwd"}
        message = {**common, "message_type": "invoke", **arguments}
    elif name == "resolve":
        expected = {"request", "cwd", "action", "action_sha256"}
        message = {**common, "message_type": "resolve", **arguments}
    elif name == "status":
        expected = set()
        message = {**common, "message_type": "status"}
    elif name == "complete":
        expected = {"action", "usage", "result"}
        arguments = {"usage": None, "result": None, **arguments}
        message = {**common, "message_type": "complete", **arguments}
    elif name == "author":
        expected = {"action", "draft"}
        message = {**common, "message_type": "author", **arguments}
    elif name == "start":
        expected = {"action", "presentation_sha256"}
        message = {**common, "message_type": "start", **arguments}
    elif name == "revise":
        expected = {"action", "presentation_sha256", "request"}
        if set(arguments) != expected:
            raise McpError(-32602, "Loom tool arguments are unknown or missing")
        try:
            request_identity = loom_adapter_protocol.request_identity(
                arguments["request"])
        except loom_adapter_protocol.ProtocolError as exc:
            raise McpError(-32602, str(exc)) from exc
        message = {
            **common,
            "message_type": "revise",
            **arguments,
            "request_identity": request_identity,
        }
    elif name == "cancel":
        expected = {"action"}
        message = {**common, "message_type": "cancel", **arguments}
    else:
        raise McpError(-32602, "unknown Loom tool")
    if set(arguments) != expected:
        raise McpError(-32602, "Loom tool arguments are unknown or missing")
    try:
        return loom_adapter_protocol.validate_message(message)
    except loom_adapter_protocol.ProtocolError as exc:
        raise McpError(-32602, str(exc)) from exc


def _initialize_bridge(home, launcher, session):
    if session:
        return
    capabilities = {
        "invoke": True, "complete": True, "cancel": True, "status": True,
        "markdown": True, "usage_receipt": False,
        "response_identity": False, "latency_events": False,
    }
    message = {
        "schema_version": 2, "message_type": "initialize",
        "request_id": "mcp-init-" + uuid.uuid4().hex,
        "protocol": {"minimum": 2, "maximum": 2},
        "adapter": {"id": "codex-local-tool", "version": "1.0.0"},
        "host": {"id": "codex", "version": "local-mcp-v1"},
        "capabilities": capabilities,
    }
    result = loom_adapter_bridge.dispatch(
        message, home=home, launcher=launcher, session=session)
    if result.get("message_type") != "initialize-result":
        raise McpError(-32603, "Loom bridge initialization failed")


def _call_tool(
        name, arguments, *, home, launcher, bridge_session,
        integration_source, launcher_resolver=None):
    if launcher_resolver is not None:
        launcher = launcher_resolver()
    if launcher is None:
        raise McpError(-32603, "Loom stable launcher is unavailable")
    launcher = Path(launcher).resolve()
    if not launcher.is_file() or launcher.is_symlink():
        raise McpError(-32603, "Loom stable launcher is invalid")
    _initialize_bridge(home, launcher, bridge_session)
    finalize = False
    adapter_arguments = arguments
    if name == "author":
        adapter_arguments = dict(arguments)
        finalize = adapter_arguments.pop("finalize", False)
        if type(finalize) is not bool:
            raise McpError(-32602, "Loom author finalize must be a boolean")
        draft_json = adapter_arguments.get("draft")
        if not isinstance(draft_json, str):
            raise McpError(-32602, "Loom author draft must be strict JSON text")
        try:
            raw_draft = draft_json.encode("utf-8")
        except UnicodeError as exc:
            raise McpError(-32602, "Loom author draft is not valid UTF-8") from exc
        if len(raw_draft) > MAX_AUTHOR_DRAFT_BYTES:
            raise McpError(-32602, "Loom author draft exceeds its byte bound")
        try:
            parsed_draft = json.loads(
                draft_json, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, McpError) as exc:
            raise McpError(-32602, "Loom author draft is not strict JSON") from exc
        if not isinstance(parsed_draft, dict):
            raise McpError(-32602, "Loom author draft must decode to an object")
        adapter_arguments["draft"] = parsed_draft
    message = _adapter_message(name, adapter_arguments)
    response = loom_adapter_bridge.dispatch(
        message, home=home, launcher=launcher, session=bridge_session)
    if response["message_type"] == "error":
        raise McpError(-32000, response["message"])
    if name == "author" and finalize and response["returncode"] == 0:
        completion = _adapter_message(
            "complete", {"action": adapter_arguments["action"]})
        response = loom_adapter_bridge.dispatch(
            completion, home=home, launcher=launcher, session=bridge_session)
        if response["message_type"] == "error":
            raise McpError(-32000, response["message"])
    payload = response["payload"]
    if name == "status" and isinstance(payload, dict):
        payload = {
            **payload,
            "codex_integration": {
                "assurance": "standard",
                "source": integration_source,
                "user_config_registration": integration_source == "user-config",
            },
        }
    projection = (
        payload.get("plan_host_projection")
        if isinstance(payload, dict) else None)
    presentation = (
        payload.get("plan_presentation")
        if isinstance(payload, dict) else None)
    if isinstance(projection, dict) and isinstance(projection.get("markdown"), str) \
            and isinstance(presentation, dict):
        structured_presentation = {
            key: presentation[key]
            for key in (
                "schema_version", "format", "title", "summary", "tier",
                "preview_mode", "presentation_sha256", "binding", "full_plan",
                "actions")
            if key in presentation
        }
        structured = {
            key: payload[key]
            for key in ("status", "code", "owner_message")
            if key in payload
        }
        structured["plan_presentation"] = structured_presentation
        decision_action = (
            adapter_arguments.get("action")
            if isinstance(adapter_arguments, dict) else None)
        if not isinstance(decision_action, str):
            decision_action = payload.get("action_path")
        if isinstance(decision_action, str):
            structured["plan_decision_reference"] = {
                "action": decision_action,
                "presentation_sha256": presentation["presentation_sha256"],
            }
        return {
            "content": [{"type": "text", "text": projection["markdown"]}],
            "structuredContent": structured,
            "isError": response["returncode"] != 0,
        }
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    # Non-presentation results retain the universal TextContent compatibility path.
    # Successful plans use Markdown plus a deliberately small structured binding,
    # never a duplicate of the complete inline plan.
    return {"content": [{"type": "text", "text": text}],
            "isError": response["returncode"] != 0}


def _tool_call(params):
    if not isinstance(params, dict):
        raise McpError(-32602, "tool call parameters are invalid")
    if not set(params).issubset({"name", "arguments", "_meta"}) \
            or "name" not in params or not isinstance(params["name"], str):
        raise McpError(-32602, "tool call parameters are invalid")
    metadata = params.get("_meta", {})
    if not isinstance(metadata, dict):
        raise McpError(-32602, "tool call metadata is invalid")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise McpError(-32602, "tool call arguments are invalid")
    return params["name"], arguments


def serve(
        home, launcher, *, input_stream=None, output_stream=None,
        server_version="0.0.0", integration_source="user-config",
        launcher_resolver=None):
    if integration_source not in {"codex-plugin", "user-config"}:
        raise ValueError("MCP integration source is invalid")
    source = input_stream or sys.stdin.buffer
    target = output_stream or sys.stdout.buffer
    bridge_session = {}
    initialized = False
    while True:
        request = None
        try:
            request = _read(source)
            if request is None:
                return 0
            method = request.get("method")
            request_id = request.get("id")
            params = request.get("params", {})
            if request_id is None:
                if method == "notifications/initialized":
                    initialized = True
                continue
            if method == "initialize":
                if not isinstance(params, dict):
                    raise McpError(-32602, "initialize parameters are invalid")
                result = {"protocolVersion": MCP_PROTOCOL,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {
                              "name": "loom", "version": server_version},
                          "instructions": (
                              "Use resolve for a verified hook receipt; otherwise use invoke.")}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                if not initialized:
                    raise McpError(-32002, "MCP client has not initialized")
                result = {"tools": _tools()}
            elif method == "tools/call":
                if not initialized:
                    raise McpError(-32602, "tool call parameters are invalid")
                name, arguments = _tool_call(params)
                result = _call_tool(
                    name, arguments, home=Path(home).resolve(),
                    launcher=(Path(launcher).resolve()
                              if launcher is not None else None),
                    bridge_session=bridge_session,
                    integration_source=integration_source,
                    launcher_resolver=launcher_resolver)
            else:
                raise McpError(-32601, "method not found")
            _write(target, {"jsonrpc": "2.0", "id": request_id, "result": result})
        except McpError as exc:
            request_id = request.get("id") if isinstance(request, dict) else None
            _write(target, {"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": exc.code, "message": str(exc)[:512]}})
        except (OSError, ValueError, loom_adapter_protocol.ProtocolError) as exc:
            request_id = request.get("id") if isinstance(request, dict) else None
            _write(target, {"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": -32603, "message": str(exc)[:512]}})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    return serve(Path.home() / ".loom", Path(__file__).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
