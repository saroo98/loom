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
    @staticmethod
    def _serve(frames, call=None):
        source = io.BytesIO(b"".join(
            (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
            for item in frames))
        target = io.BytesIO()
        context = mock.patch.object(
            loom_mcp_server, "_call_tool", side_effect=call) if call else mock.patch.object(
                loom_mcp_server, "_call_tool", wraps=loom_mcp_server._call_tool)
        with context:
            loom_mcp_server.serve(
                Path("C:/home"), Path("C:/loom.py"),
                input_stream=source, output_stream=target)
        return [json.loads(line) for line in target.getvalue().splitlines()]

    def test_handshake_lists_only_the_bounded_local_tools(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        source = io.BytesIO(b"".join(
            (json.dumps(item) + "\n").encode("utf-8") for item in requests))
        target = io.BytesIO()
        resolver = mock.Mock(
            side_effect=AssertionError("bootstrap ran before the MCP handshake"))
        self.assertEqual(0, loom_mcp_server.serve(
            Path("C:/disposable/.loom"), None,
            input_stream=source, output_stream=target,
            launcher_resolver=resolver))
        resolver.assert_not_called()
        responses = [json.loads(line) for line in target.getvalue().splitlines()]
        self.assertEqual(loom_mcp_server.MCP_PROTOCOL,
                         responses[0]["result"]["protocolVersion"])
        self.assertEqual(
            {"name": "loom", "version": "0.0.0"},
            responses[0]["result"]["serverInfo"])
        self.assertEqual(
            [
                "invoke", "resolve", "status", "complete", "author",
                "start", "revise", "cancel",
            ],
            [tool["name"] for tool in responses[1]["result"]["tools"]])
        author = next(
            tool for tool in responses[1]["result"]["tools"]
            if tool["name"] == "author")
        draft = author["inputSchema"]["properties"]["draft"]
        self.assertEqual("string", draft["type"])
        self.assertLess(
            len(json.dumps(author, separators=(",", ":"))), 4096)
        self.assertIn(
            "schemas/plan-draft.schema.json", draft["description"])
        complete = next(
            tool for tool in responses[1]["result"]["tools"]
            if tool["name"] == "complete")
        self.assertIn(
            "omit result", complete["description"])
        result_schema = complete["inputSchema"]["properties"]["result"][
            "anyOf"][0]
        self.assertIn("Never pass prose", result_schema["description"])
        self.assertIn(
            "omit result", result_schema["description"].lower())
        self.assertNotIn(
            "default", author["inputSchema"]["properties"]["finalize"])
        self.assertIn("same tool call", author["description"])

    def test_unproven_codex_ui_capability_never_mounts_a_rich_viewer(self):
        responses = self._serve([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "extensions": {
                        "io.modelcontextprotocol/ui": {
                            "mimeTypes": ["text/html;profile=mcp-app"],
                        },
                    },
                },
                "clientInfo": {"name": "codex", "version": "unverified-test"},
            }},
            {"jsonrpc": "2.0", "method": "notifications/initialized",
             "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
             "params": {}},
        ])

        initialize = responses[0]["result"]
        self.assertNotIn("resources", initialize["capabilities"])
        tools = responses[1]["result"]["tools"]
        self.assertTrue(tools)
        for tool in tools:
            self.assertNotIn("_meta", tool)
            self.assertNotIn("outputSchema", tool)

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

    def test_codex_metadata_is_protocol_envelope_not_tool_input(self):
        request = "line one\nline two % ! & | < > ^ café"
        calls = []

        def call(name, arguments, **_kwargs):
            calls.append((name, arguments))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        responses = self._serve([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "codex", "version": "test"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "invoke",
                "arguments": {"request": request, "cwd": "C:/project"},
                "_meta": {"progressToken": "codex-call-2"}}},
        ], call)

        self.assertNotIn("error", responses[-1])
        self.assertEqual(
            [("invoke", {"request": request, "cwd": "C:/project"})], calls)

    def test_zero_argument_tool_accepts_omitted_arguments_and_metadata(self):
        calls = []

        def call(name, arguments, **_kwargs):
            calls.append((name, arguments))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        responses = self._serve([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "status", "_meta": {"progressToken": 2}}},
        ], call)

        self.assertNotIn("error", responses[-1])
        self.assertEqual([("status", {})], calls)

    def test_status_reports_the_actual_codex_integration_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launcher = root / "loom.py"
            launcher.write_text("# test launcher\n", encoding="utf-8")
            with mock.patch.object(
                    loom_mcp_server.loom_adapter_bridge, "dispatch",
                    return_value={
                        "message_type": "result", "returncode": 0,
                        "payload": {"status": "ready", "version": "1.9.0"},
                    }):
                result = loom_mcp_server._call_tool(
                    "status", {}, home=root / "home",
                    launcher=launcher,
                    bridge_session={"initialized": True},
                    integration_source="codex-plugin")
        self.assertNotIn("structuredContent", result)
        integration = json.loads(
            result["content"][0]["text"])["codex_integration"]
        self.assertEqual("codex-plugin", integration["source"])
        self.assertFalse(integration["user_config_registration"])

    def test_tool_call_envelope_rejects_unknown_fields_and_invalid_metadata(self):
        invalid = (
            {"name": "status", "unexpected": True},
            {"name": "status", "_meta": "not-an-object"},
            {"name": "status", "arguments": None},
            {"arguments": {}},
        )
        for params in invalid:
            with self.subTest(params=params):
                responses = self._serve([
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized",
                     "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": params},
                ], lambda *_args, **_kwargs: self.fail("invalid call reached tool"))
                self.assertEqual(-32602, responses[-1]["error"]["code"])

    def test_mcp_metadata_cannot_relax_strict_tool_arguments(self):
        with self.assertRaisesRegex(
                loom_mcp_server.McpError, "unknown or missing"):
            loom_mcp_server._adapter_message(
                "status", {"unexpected": "not protocol metadata"})

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

    def test_author_preserves_the_bounded_semantic_draft_at_the_mcp_boundary(self):
        draft = {
            "schema_version": 1, "title": "Tiny CLI", "summary": "One outcome.",
            "assumptions": [], "decisions": [], "current_facts": [],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [], "domain_evidence": None,
        }
        arguments = {
            "action": "C:/owner/.loom/orchestration/action.json",
            "draft": json.dumps(draft, sort_keys=True, separators=(",", ":"))}
        calls = []

        def call(name, value, **_kwargs):
            calls.append((name, value))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        responses = self._serve([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "author", "arguments": arguments,
                "_meta": {"progressToken": "author-2"}}},
        ], call)

        self.assertNotIn("error", responses[-1])
        self.assertEqual([("author", arguments)], calls)

    def test_bound_start_and_revision_preserve_exact_decision_identity(self):
        action = "C:/owner/.loom/orchestration/action.json"
        digest = "a" * 64
        calls = []

        def call(name, value, **_kwargs):
            calls.append((name, value))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        responses = self._serve([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized",
             "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "start", "arguments": {
                    "action": action, "presentation_sha256": digest}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "revise", "arguments": {
                    "action": action, "presentation_sha256": digest,
                    "request": "Add one exact negative acceptance check."}}},
        ], call)

        self.assertNotIn("error", responses[-2])
        self.assertNotIn("error", responses[-1])
        self.assertEqual([
            ("start", {
                "action": action, "presentation_sha256": digest}),
            ("revise", {
                "action": action, "presentation_sha256": digest,
                "request": "Add one exact negative acceptance check."}),
        ], calls)

    def test_later_turn_start_and_revision_use_project_local_recovery(self):
        cwd = "C:/work/project"
        calls = []

        def call(name, value, **_kwargs):
            calls.append((name, value))
            return {"content": [{"type": "text", "text": "{}"}],
                    "structuredContent": {}, "isError": False}

        responses = self._serve([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized",
             "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "start", "arguments": {"cwd": cwd}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "revise", "arguments": {
                    "cwd": cwd,
                    "request": "Add one exact negative acceptance check."}}},
        ], call)

        self.assertNotIn("error", responses[-2])
        self.assertNotIn("error", responses[-1])
        self.assertEqual([
            ("start", {"cwd": cwd}),
            ("revise", {
                "cwd": cwd,
                "request": "Add one exact negative acceptance check."}),
        ], calls)

    def test_revision_tool_rejects_missing_or_non_text_request_as_invalid_params(self):
        for arguments in (
                {
                    "action": "C:/owner/.loom/orchestration/action.json",
                    "presentation_sha256": "a" * 64,
                },
                {
                    "action": "C:/owner/.loom/orchestration/action.json",
                    "presentation_sha256": "a" * 64,
                    "request": None,
                }):
            with self.subTest(arguments=arguments), self.assertRaises(
                    loom_mcp_server.McpError) as raised:
                loom_mcp_server._adapter_message("revise", arguments)
            self.assertEqual(-32602, raised.exception.code)

    def test_author_can_finalize_without_a_second_host_tool_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launcher = root / "loom.py"
            launcher.write_text("# test launcher\n", encoding="utf-8")
            action = str(root / "action.json")
            draft = {
                "schema_version": 1, "title": "Tiny CLI", "summary": "One outcome.",
                "assumptions": [], "decisions": [], "current_facts": [],
                "release_exposure": {
                    "external_users": 0, "irreversible": False,
                    "data_migration": False, "regulated": False,
                },
                "work_orders": [], "domain_evidence": None,
            }
            calls = []

            def dispatch(message, **_kwargs):
                calls.append(message)
                if message["message_type"] == "author":
                    return {
                        "schema_version": 2, "message_type": "result",
                        "request_id": message["request_id"], "returncode": 0,
                        "payload": {"status": "authored"},
                    }
                return {
                    "schema_version": 2, "message_type": "result",
                    "request_id": message["request_id"], "returncode": 0,
                    "payload": {
                        "status": "completed", "code": "plan-complete",
                        "owner_message": {"human": "Plan sealed."},
                        "plan_presentation": {
                            "schema_version": 1,
                            "format": "plan-presentation-v1",
                            "presentation_sha256": "a" * 64,
                            "binding": {"action_id": "action-1"},
                        },
                        "plan_host_projection": {
                            "schema_version": 1,
                            "format": "plan-host-projection-v1",
                            "markdown": "## Tiny CLI\n\n[Open the complete plan](C:/plan.md)\n",
                        },
                    },
                }

            with mock.patch.object(
                    loom_mcp_server, "_initialize_bridge"), mock.patch.object(
                        loom_mcp_server.loom_adapter_bridge, "dispatch",
                        side_effect=dispatch):
                result = loom_mcp_server._call_tool(
                    "author", {
                        "action": action,
                        "draft": json.dumps(
                            draft, sort_keys=True, separators=(",", ":")),
                        "finalize": True,
                    },
                    home=root / "home", launcher=launcher,
                    bridge_session={"initialized": True},
                    integration_source="codex-plugin")

        self.assertEqual(["author", "complete"], [
            item["message_type"] for item in calls])
        self.assertNotIn("finalize", calls[0])
        self.assertEqual(action, calls[1]["action"])
        self.assertEqual(
            "## Tiny CLI\n\n[Open the complete plan](C:/plan.md)\n",
            result["content"][0]["text"])
        self.assertEqual({
            "schema_version": 1,
            "format": "plan-host-projection-v1",
            "markdown": "## Tiny CLI\n\n[Open the complete plan](C:/plan.md)\n",
        }, result["structuredContent"]["plan_host_projection"])
        self.assertEqual(
            "plan-presentation-v1",
            result["structuredContent"]["plan_presentation"]["format"])
        self.assertEqual({
            "action": action,
            "presentation_sha256": "a" * 64,
        }, result["structuredContent"]["plan_decision_reference"])

    def test_codex_skill_returns_the_review_surface_instead_of_an_internal_receipt(self):
        root = Path(__file__).resolve().parents[1]
        for relative in ("skill/loom/SKILL.md", "skills/loom/SKILL.md"):
            text = (root / relative).read_text(encoding="utf-8")
            self.assertIn(
                "Return `plan_host_projection.markdown` verbatim", text)
            self.assertIn(
                "Do not replace the review surface with `owner_message.human`", text)
            self.assertIn(
                "The complete inline fallback is mandatory", text)
            self.assertIn(
                "call `loom.revise` with that exact reference", text)
            self.assertIn(
                "never guess it", text)
            self.assertIn(
                "call `loom.start` with that exact reference", text)
            self.assertIn(
                "absolute working directory if a later turn lost it", text)
            self.assertIn(
                "Never replace either bound decision with plain `loom.invoke`", text)
            self.assertIn(
                "`execution_completion_contract` exactly", text)
            self.assertIn(
                "Never claim or mark evidence that was not observed", text)

    def test_author_finalize_never_completes_after_authoring_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launcher = root / "loom.py"
            launcher.write_text("# test launcher\n", encoding="utf-8")
            calls = []

            def dispatch(message, **_kwargs):
                calls.append(message)
                return {
                    "schema_version": 2, "message_type": "result",
                    "request_id": message["request_id"], "returncode": 1,
                    "payload": {"status": "blocked", "code": "draft-invalid"},
                }

            draft = {
                "schema_version": 1, "title": "Tiny CLI", "summary": "One outcome.",
                "assumptions": [], "decisions": [], "current_facts": [],
                "release_exposure": {
                    "external_users": 0, "irreversible": False,
                    "data_migration": False, "regulated": False,
                },
                "work_orders": [], "domain_evidence": None,
            }
            with mock.patch.object(
                    loom_mcp_server, "_initialize_bridge"), mock.patch.object(
                        loom_mcp_server.loom_adapter_bridge, "dispatch",
                        side_effect=dispatch):
                result = loom_mcp_server._call_tool(
                    "author", {
                        "action": str(root / "action.json"),
                        "draft": json.dumps(
                            draft, sort_keys=True, separators=(",", ":")),
                        "finalize": True,
                    },
                    home=root / "home", launcher=launcher,
                    bridge_session={"initialized": True},
                    integration_source="codex-plugin")

        self.assertEqual(["author"], [item["message_type"] for item in calls])
        self.assertTrue(result["isError"])

    def test_author_rejects_malformed_duplicate_and_non_object_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launcher = root / "loom.py"
            launcher.write_text("# test launcher\n", encoding="utf-8")
            cases = (
                "{",
                '{"schema_version":1,"schema_version":1}',
                "[]",
            )
            for draft in cases:
                with self.subTest(draft=draft), self.assertRaises(
                        loom_mcp_server.McpError):
                    loom_mcp_server._call_tool(
                        "author", {
                            "action": str(root / "action.json"),
                            "draft": draft,
                        },
                        home=root / "home", launcher=launcher,
                        bridge_session={"initialized": True},
                        integration_source="codex-plugin")

    def test_all_mcp_tool_schemas_stay_within_host_discovery_budget(self):
        for tool in loom_mcp_server._tools():
            with self.subTest(tool=tool["name"]):
                self.assertLessEqual(
                    len(json.dumps(tool, separators=(",", ":")).encode("utf-8")),
                    4096)

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

    def test_plugin_mcp_handshake_does_not_wait_for_bootstrap(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "loom_codex_mcp.py"
        spec = importlib.util.spec_from_file_location("loom_codex_mcp_test", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module.loom_bootstrap, "reconcile") as reconcile, \
                mock.patch.object(
                    module.loom_mcp_server, "serve", return_value=0) as serve:
            self.assertEqual(0, module.main())
        reconcile.assert_not_called()
        self.assertEqual("codex-plugin", serve.call_args.kwargs["integration_source"])
        self.assertIsNone(serve.call_args.args[1])
        self.assertTrue(callable(serve.call_args.kwargs["launcher_resolver"]))

    def test_plugin_mcp_lazy_bootstrap_preserves_launcher_path_with_spaces(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "loom_codex_mcp.py"
        spec = importlib.util.spec_from_file_location("loom_codex_mcp_windows_test", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            launcher = Path(temporary) / "home with spaces" / "bin" / "loom.py"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("# stable launcher\n", encoding="utf-8")
            lazy = module._LazyLauncher(
                Path(temporary) / "plugin", Path(temporary) / "home with spaces")
            with mock.patch.object(
                    module.loom_bootstrap, "reconcile",
                    return_value={
                        "launcher": {"python_launcher": str(launcher)}}) as reconcile:
                self.assertEqual(launcher.resolve(), lazy())
                self.assertEqual(launcher.resolve(), lazy())
        reconcile.assert_called_once()

    def test_plugin_mcp_lazy_bootstrap_failure_is_a_bounded_tool_error(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "loom_codex_mcp.py"
        spec = importlib.util.spec_from_file_location(
            "loom_codex_mcp_bootstrap_error_test", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        lazy = module._LazyLauncher(Path("C:/plugin"), Path("C:/home/.loom"))
        with mock.patch.object(
                module.loom_bootstrap, "reconcile",
                side_effect=module.loom_bootstrap.BootstrapError(
                    "locked dependencies are unavailable")):
            with self.assertRaises(module.loom_mcp_server.McpError) as failure:
                lazy()
        self.assertEqual(-32000, failure.exception.code)
        self.assertIn("Loom bootstrap blocked", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
