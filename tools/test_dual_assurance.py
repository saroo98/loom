"""Dual-assurance and local MCP regression tests."""

import io
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_adapter_protocol
import loom_mcp_server
import loom_orchestrator


CAPABILITIES = {
    "invoke": True, "complete": True, "cancel": True, "status": True,
    "markdown": True, "usage_receipt": False,
    "response_identity": False, "latency_events": False,
}


def invoke_message(request="Plan exactly"):
    return {"schema_version": 2, "message_type": "invoke",
            "request_id": "request-1", "request": request, "cwd": "C:/project"}


class AssuranceProtocolTests(unittest.TestCase):
    def test_local_tool_is_standard_and_prompt_hook_is_verified(self):
        host = {"id": "codex", "version": "test-host"}
        standard = loom_adapter_protocol.request_envelope(
            invoke_message(), host,
            adapter={"id": "codex-local-tool", "version": "1.0.0"},
            capabilities=CAPABILITIES)
        verified = loom_adapter_protocol.request_envelope(
            invoke_message(), host,
            adapter={"id": "codex-prompt-hook", "version": "1.0.0"},
            capabilities=CAPABILITIES)
        self.assertEqual("standard", standard["assurance"]["mode"])
        self.assertEqual("tool-argument", standard["assurance"]["request_identity_scope"])
        self.assertEqual("verified", verified["assurance"]["mode"])
        self.assertEqual("host-prompt", verified["assurance"]["request_identity_scope"])
        self.assertNotEqual(
            loom_orchestrator._transport_invocation_id(standard),
            loom_orchestrator._transport_invocation_id(verified))

    def test_tampered_assurance_fails_closed(self):
        envelope = loom_adapter_protocol.request_envelope(
            invoke_message(), {"id": "codex", "version": "test-host"},
            adapter={"id": "codex-prompt-hook", "version": "1.0.0"},
            capabilities=CAPABILITIES)
        for field, value in (
                ("mode", "standard"), ("request_sha256", "0" * 64),
                ("request_utf8_bytes", 999)):
            changed = json.loads(json.dumps(envelope))
            changed["assurance"][field] = value
            with self.subTest(field=field), self.assertRaises(
                    loom_adapter_protocol.ProtocolError):
                loom_adapter_protocol.validate_message(changed)

    def test_action_assurance_rejects_cross_mode_fields(self):
        assurance = loom_orchestrator._default_assurance("request")
        assurance["request_identity_scope"] = "host-prompt"
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "assurance identity"):
            loom_orchestrator._validate_assurance(
                assurance, "request", allow_legacy=False)


class McpServerTests(unittest.TestCase):
    def test_handshake_lists_only_the_bounded_local_tools(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        source = io.BytesIO(b"".join(
            (json.dumps(item) + "\n").encode("utf-8") for item in requests))
        target = io.BytesIO()
        self.assertEqual(0, loom_mcp_server.serve(
            Path("C:/disposable/.loom"), Path("C:/disposable/.loom/bin/loom.py"),
            input_stream=source, output_stream=target))
        responses = [json.loads(line) for line in target.getvalue().splitlines()]
        self.assertEqual(loom_mcp_server.MCP_PROTOCOL,
                         responses[0]["result"]["protocolVersion"])
        self.assertEqual(
            ["invoke", "resolve", "status", "complete", "cancel"],
            [tool["name"] for tool in responses[1]["result"]["tools"]])

    def test_invoke_remains_structured_at_the_mcp_boundary(self):
        request = "line one\nline two % ! & | < > ^ café"
        calls = []

        def call(name, arguments, **_kwargs):
            calls.append((name, arguments))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "invoke", "arguments": {"request": request, "cwd": "C:/project"}}},
        ]
        source = io.BytesIO(b"".join(
            (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
            for item in frames))
        target = io.BytesIO()
        with mock.patch.object(loom_mcp_server, "_call_tool", side_effect=call):
            loom_mcp_server.serve(Path("C:/home"), Path("C:/loom.py"),
                                  input_stream=source, output_stream=target)
        self.assertEqual([("invoke", {"request": request, "cwd": "C:/project"})], calls)

    def test_resolve_preserves_verified_identity_at_the_mcp_boundary(self):
        request = "line one\nline two % ! & | < > ^ café"
        arguments = {
            "request": request, "cwd": "C:/project",
            "action": "C:/owner/.loom/orchestration/action.json",
            "action_sha256": "a" * 64,
        }
        calls = []

        def call(name, value, **_kwargs):
            calls.append((name, value))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "resolve", "arguments": arguments}},
        ]
        source = io.BytesIO(b"".join(
            (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
            for item in frames))
        target = io.BytesIO()
        with mock.patch.object(loom_mcp_server, "_call_tool", side_effect=call):
            loom_mcp_server.serve(
                Path("C:/home"), Path("C:/loom.py"),
                input_stream=source, output_stream=target)
        self.assertEqual([("resolve", arguments)], calls)

    def test_tool_call_before_initialize_fails_closed(self):
        source = io.BytesIO((json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            + "\n").encode())
        target = io.BytesIO()
        loom_mcp_server.serve(Path("C:/home"), Path("C:/loom.py"),
                              input_stream=source, output_stream=target)
        response = json.loads(target.getvalue())
        self.assertEqual(-32002, response["error"]["code"])

    def test_non_object_tool_arguments_fail_closed(self):
        with self.assertRaisesRegex(loom_mcp_server.McpError, "must be an object"):
            loom_mcp_server._adapter_message("invoke", "not-an-object")

    def test_plugin_mcp_bootstrap_execs_only_the_stable_launcher(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "loom_codex_mcp.py"
        spec = importlib.util.spec_from_file_location("loom_codex_mcp_test", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            launcher = Path(temporary) / "loom.py"
            launcher.write_text("# stable launcher\n", encoding="utf-8")
            calls = []

            def execv(executable, arguments):
                calls.append((executable, arguments))
                raise RuntimeError("exec captured")

            with mock.patch.object(
                    module.loom_bootstrap, "reconcile",
                    return_value={"launcher": {"python_launcher": str(launcher)}}), \
                    mock.patch.object(os, "execv", side_effect=execv), \
                    self.assertRaisesRegex(RuntimeError, "exec captured"):
                module.main()
        self.assertEqual(sys.executable, calls[0][0])
        self.assertEqual("mcp", calls[0][1][-1])
        self.assertEqual(str(launcher.resolve()), calls[0][1][2])


if __name__ == "__main__":
    unittest.main()
