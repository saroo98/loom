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
SERVER_INFO = {"name": "loom", "version": "1.0.0"}


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
    path = {"type": "string", "minLength": 1, "maxLength": 4096}
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
            "name": "complete", "description": "Complete one existing Loom action.",
            "inputSchema": {
                "type": "object", "additionalProperties": False,
                "required": ["action"],
                "properties": {"action": path, "usage": {"anyOf": [path, {"type": "null"}]},
                               "result": {"anyOf": [path, {"type": "null"}]}},
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False},
        },
        {
            "name": "cancel", "description": "Cancel one existing Loom action safely.",
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "required": ["action"], "properties": {"action": path}},
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


def _call_tool(name, arguments, *, home, launcher, bridge_session):
    _initialize_bridge(home, launcher, bridge_session)
    message = _adapter_message(name, arguments)
    response = loom_adapter_bridge.dispatch(
        message, home=home, launcher=launcher, session=bridge_session)
    if response["message_type"] == "error":
        raise McpError(-32000, response["message"])
    payload = response["payload"]
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": response["returncode"] != 0}


def serve(home, launcher, *, input_stream=None, output_stream=None):
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
                          "serverInfo": SERVER_INFO,
                          "instructions": (
                              "Use resolve for a verified hook receipt; otherwise use invoke.")}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                if not initialized:
                    raise McpError(-32002, "MCP client has not initialized")
                result = {"tools": _tools()}
            elif method == "tools/call":
                if not initialized or not isinstance(params, dict) \
                        or set(params) != {"name", "arguments"} \
                        or not isinstance(params["name"], str):
                    raise McpError(-32602, "tool call parameters are invalid")
                result = _call_tool(
                    params["name"], params["arguments"], home=Path(home).resolve(),
                    launcher=Path(launcher).resolve(), bridge_session=bridge_session)
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
