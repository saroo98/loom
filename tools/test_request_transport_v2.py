"""End-to-end regressions for request identity across local process boundaries."""

import concurrent.futures
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import loom_adapter_bridge
import loom_adapter_protocol
import loom_execution_chain
import loom_launcher
import loom_orchestrator


TOOLS = Path(__file__).resolve().parent


def invoke_message(request, cwd, request_id="req-transport"):
    return {
        "schema_version": 2,
        "message_type": "invoke",
        "request_id": request_id,
        "request": request,
        "cwd": str(cwd),
    }


def envelope(request, cwd, request_id="req-transport"):
    return loom_adapter_protocol.request_envelope(
        invoke_message(request, cwd, request_id),
        {"id": "codex", "version": "windows-test"})


def resolve_message(request, cwd, action, request_id="req-resolve"):
    return {
        "schema_version": 2,
        "message_type": "resolve",
        "request_id": request_id,
        "request": request,
        "cwd": str(cwd),
        "action": str(action),
        "action_sha256": "a" * 64,
    }


def start_message(action, presentation_sha256, request_id="req-start"):
    return {
        "schema_version": 2,
        "message_type": "start",
        "request_id": request_id,
        "action": str(action),
        "presentation_sha256": presentation_sha256,
    }


def revision_message(
        request, action, presentation_sha256, request_id="req-revise"):
    return {
        "schema_version": 2,
        "message_type": "revise",
        "request_id": request_id,
        "action": str(action),
        "presentation_sha256": presentation_sha256,
        "request": request,
        "request_identity": loom_adapter_protocol.request_identity(request),
    }


def recovered_start_message(cwd, request_id="req-start-recovered"):
    return {
        "schema_version": 2,
        "message_type": "start",
        "request_id": request_id,
        "cwd": str(cwd),
    }


def recovered_revision_message(
        request, cwd, request_id="req-revise-recovered"):
    return {
        "schema_version": 2,
        "message_type": "revise",
        "request_id": request_id,
        "cwd": str(cwd),
        "request": request,
        "request_identity": loom_adapter_protocol.request_identity(request),
    }


class FakeManager:
    class Activations:
        @staticmethod
        def public_projection(_current):
            return {
                "activation_set_id": None,
                "runtime_version": "test-runtime",
                "release_sequence": 1,
                "state_generation": 0,
                "state_schema": 0,
                "deletion_epoch": 0,
            }

    activations = Activations()

    def begin_session(self):
        return {
            "session_id": "session-transport",
            "version": "test-runtime",
            "state_generation": 0,
            "state_schema": 0,
        }

    def end_session(self, _session_id, *, successful):
        self.successful = successful

    def record_trust_health(self, *, healthy, reason):
        self.health = (healthy, reason)

    def prune_versions(self):
        return None


class RequestTransportV2Tests(unittest.TestCase):
    def test_transport_invocation_identity_is_stable_and_operation_scoped(self):
        first = envelope("same request", "C:/disposable/project", "req-one")
        repeated = envelope("same request", "C:/disposable/project", "req-one")
        next_operation = envelope("same request", "C:/disposable/project", "req-two")
        other_target = envelope("same request", "C:/disposable/other", "req-one")

        identity = loom_orchestrator._transport_invocation_id(first)
        self.assertEqual(identity, loom_orchestrator._transport_invocation_id(repeated))
        self.assertNotEqual(
            identity, loom_orchestrator._transport_invocation_id(next_operation))
        self.assertNotEqual(
            identity, loom_orchestrator._transport_invocation_id(other_target))

    def test_launcher_forwards_only_a_bounded_frame_to_orchestrator(self):
        request = "  first\r\nsecond % ! & | < > ^ ( ) کوردی  "
        item = envelope(request, "C:/disposable/project")
        frame = loom_adapter_protocol.canonical_bytes(item) + b"\n"
        manager = FakeManager()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runtime = root / "runtime"
            orchestrator = runtime / "tools" / "loom_orchestrator.py"
            orchestrator.parent.mkdir(parents=True)
            orchestrator.write_text("# fixture\n", encoding="utf-8")
            (runtime / "RUNTIME-MANIFEST.json").write_text(
                '{"version":"test-runtime"}\n', encoding="utf-8")
            stdin = SimpleNamespace(buffer=io.BytesIO(frame))
            completed = SimpleNamespace(returncode=0)

            def run_and_seal(command, **_kwargs):
                chain_id = command[command.index("--execution-chain") + 1]
                loom_execution_chain.append(
                    root / ".loom", chain_id, "result", {
                        "status": "transport-fixture-complete",
                        "exit_code": 0,
                        "orchestrator_terminal_receipt": True,
                    })
                loom_execution_chain.seal(root / ".loom", chain_id)
                return completed

            with mock.patch.object(loom_launcher.sys, "stdin", stdin), \
                    mock.patch.object(
                        loom_launcher.loom_update, "SharedRuntime", return_value=manager), \
                    mock.patch.object(
                        loom_launcher, "_current",
                        return_value=({"version": "test-runtime", "release_sequence": 1},
                                      runtime)), \
                    mock.patch.object(loom_launcher, "_reject_local_shadow"), \
                    mock.patch.object(
                        loom_launcher.subprocess, "run", side_effect=run_and_seal) as run:
                code = loom_launcher.main([
                    "--home", str(root / ".loom"), "invoke-stdio"])
        self.assertEqual(0, code)
        command = run.call_args.args[0]
        self.assertIn("invoke-stdio", command)
        self.assertNotIn("--request", command)
        self.assertNotIn(request, command)
        self.assertNotIn("env", run.call_args.kwargs)
        self.assertEqual(frame, run.call_args.kwargs["input"])

    def test_orchestrator_rechecks_identity_before_decoding_request_into_work(self):
        request = "\nexact whitespace کوردی & % !\n"
        item = envelope(request, "C:/disposable/project")
        stdin = SimpleNamespace(buffer=io.BytesIO(
            loom_adapter_protocol.canonical_bytes(item) + b"\n"))
        output = io.StringIO()
        with mock.patch.object(loom_orchestrator.sys, "stdin", stdin), \
                mock.patch.object(
                    loom_orchestrator, "invoke", return_value={"status": "transport-ok"}) as invoke, \
                contextlib.redirect_stdout(output):
            code = loom_orchestrator.main([
                "invoke-stdio", "--home", "C:/disposable/home/.loom",
                "--install-root", "C:/disposable/runtime"])
        self.assertEqual(0, code, output.getvalue())
        self.assertEqual(request, invoke.call_args.kwargs["request"])
        self.assertEqual(item["cwd"], invoke.call_args.kwargs["cwd"])

    def test_verified_resolution_keeps_request_in_bounded_stdin_across_both_processes(self):
        request = "  verified\r\nrequest % ! & | < > ^ کوردی  "
        item = resolve_message(
            request, "C:/disposable/project",
            "C:/disposable/home/.loom/orchestration/action.json")
        frame = loom_adapter_protocol.canonical_bytes(item) + b"\n"
        manager = FakeManager()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runtime = root / "runtime"
            orchestrator = runtime / "tools" / "loom_orchestrator.py"
            orchestrator.parent.mkdir(parents=True)
            orchestrator.write_text("# fixture\n", encoding="utf-8")
            (runtime / "RUNTIME-MANIFEST.json").write_text(
                '{"version":"test-runtime"}\n', encoding="utf-8")
            stdin = SimpleNamespace(buffer=io.BytesIO(frame))
            completed = SimpleNamespace(returncode=0)
            with mock.patch.object(loom_launcher.sys, "stdin", stdin), \
                    mock.patch.object(
                        loom_launcher.loom_update, "SharedRuntime", return_value=manager), \
                    mock.patch.object(
                        loom_launcher, "_current",
                        return_value=({"version": "test-runtime", "release_sequence": 1},
                                      runtime)), \
                    mock.patch.object(
                        loom_launcher.subprocess, "run", return_value=completed) as run:
                code = loom_launcher.main([
                    "--home", str(root / ".loom"), "resolve-stdio"])
        self.assertEqual(0, code)
        command = run.call_args.args[0]
        self.assertIn("resolve-stdio", command)
        self.assertNotIn(request, command)
        self.assertEqual(frame, run.call_args.kwargs["input"])

        stdin = SimpleNamespace(buffer=io.BytesIO(frame))
        output = io.StringIO()
        with mock.patch.object(loom_orchestrator.sys, "stdin", stdin), \
                mock.patch.object(
                    loom_orchestrator, "resolve",
                    return_value={"status": "transport-ok"}) as resolve, \
                contextlib.redirect_stdout(output):
            code = loom_orchestrator.main([
                "resolve-stdio", "--home", "C:/disposable/home/.loom",
                "--install-root", "C:/disposable/runtime"])
        self.assertEqual(0, code, output.getvalue())
        self.assertEqual(request, resolve.call_args.kwargs["request"])
        self.assertEqual(item["action"], resolve.call_args.kwargs["action_path"])
        self.assertEqual(item["action_sha256"],
                         resolve.call_args.kwargs["action_sha256"])

    def test_bound_start_and_revision_preserve_identity_across_real_processes(self):
        request = "  revise\r\nquotes \" % ! & | < > ^ کوردی 🧵  "
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            launcher, _runtime = self._write_process_chain(root)
            action = root / ".loom" / "private action.json"
            presentation_sha256 = "a" * 64

            start_code, started = loom_adapter_bridge._run_request(
                launcher, root / ".loom",
                start_message(action, presentation_sha256),
                command="start-stdio", timeout=30)
            revise_code, revised = loom_adapter_bridge._run_request(
                launcher, root / ".loom",
                revision_message(request, action, presentation_sha256),
                command="revise-stdio", timeout=30)

        self.assertEqual(0, start_code, started)
        self.assertEqual(str(action), started["action"])
        self.assertEqual(presentation_sha256, started["presentation_sha256"])
        self.assertEqual(0, revise_code, revised)
        self._assert_identity(request, revised)
        self.assertEqual(str(action), revised["action"])
        self.assertEqual(presentation_sha256, revised["presentation_sha256"])
        self.assertFalse(revised["request_in_argv"])

    def test_later_turn_project_recovery_crosses_real_processes_without_request_argv(self):
        request = "  add --json\r\nquotes \" % ! & | < > ^ کوردی 🧵  "
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            launcher, _runtime = self._write_process_chain(root)
            cwd = root / "project"
            cwd.mkdir()

            start_code, started = loom_adapter_bridge._run_request(
                launcher, root / ".loom", recovered_start_message(cwd),
                command="start-stdio", timeout=30)
            revise_code, revised = loom_adapter_bridge._run_request(
                launcher, root / ".loom",
                recovered_revision_message(request, cwd),
                command="revise-stdio", timeout=30)

        self.assertEqual(0, start_code, started)
        self.assertEqual(str(cwd), started["cwd"])
        self.assertEqual(0, revise_code, revised)
        self.assertEqual(str(cwd), revised["cwd"])
        self._assert_identity(request, revised)
        self.assertFalse(revised["request_in_argv"])

    def test_legacy_request_argv_surface_is_refused_before_runtime_access(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            loom_launcher.main([
                "--home", "C:/does-not-exist", "invoke", "--request", "owner text",
                "--cwd", "C:/project", "--agent", "codex"])
        self.assertEqual(2, raised.exception.code)
        self.assertIn("invalid choice", stderr.getvalue())

    def test_real_process_chain_preserves_special_boundary_and_concurrent_requests(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            project = root / "project"
            project.mkdir()
            (project / ".git").mkdir()
            launcher, runtime = self._write_process_chain(root)
            requests = [
                "line one\r\nline two",
                "quotes: \"double\" and 'single'",
                "shell: % ! & | < > ^ ( )",
                "Unicode: کوردی 🧵 東京",
                "  leading and trailing  ",
                "x" * 32768,
            ]
            for index, request in enumerate(requests):
                with self.subTest(index=index):
                    code, payload = loom_adapter_bridge._run_request(
                        launcher, root / ".loom",
                        envelope(request, project, f"req-{index}"), timeout=30)
                    self.assertEqual(0, code, payload)
                    self._assert_identity(request, payload)

            parallel_requests = [
                f"parallel-{index}-&-%-کوردی" for index in range(8)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(
                    loom_adapter_bridge._run_request, launcher, root / ".loom",
                    envelope(request, project, f"req-parallel-{index}"), timeout=30)
                    for index, request in enumerate(parallel_requests)]
                results = [future.result(timeout=35) for future in futures]
            for request, (code, payload) in zip(parallel_requests, results):
                self.assertEqual(0, code, payload)
                self._assert_identity(request, payload)

            bad = envelope("tampered", project, "req-bad")
            bad["request_identity"]["sha256"] = "0" * 64
            result = subprocess.run(
                [sys.executable, "-B", str(launcher), "--home", str(root / ".loom"),
                 "invoke-stdio"],
                input=(json.dumps(bad, ensure_ascii=False) + "\n").encode("utf-8"),
                capture_output=True, timeout=30, check=False)
            self.assertEqual(2, result.returncode)
            self.assertIn("identity", result.stdout.decode("utf-8").lower())

    def _assert_identity(self, request, payload):
        raw = request.encode("utf-8")
        self.assertEqual(request, payload["request"])
        self.assertEqual(len(raw), payload["request_identity"]["utf8_bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         payload["request_identity"]["sha256"])

    def test_terminal_receipt_world_fingerprint_marks_project_world_observed(self):
        result = {
            "status": "blocked",
            "project_id": "p-" + "a" * 32,
            "world_fingerprint": "b" * 64,
        }
        payload, observability = loom_orchestrator._project_world_observation(result)

        self.assertEqual("observed", observability)
        self.assertTrue(payload["world_observed"])
        self.assertEqual("b" * 64, payload["world_fingerprint"])

    def test_missing_world_evidence_remains_explicitly_unavailable(self):
        payload, observability = loom_orchestrator._project_world_observation({
            "status": "blocked",
            "project_id": "p-" + "a" * 32,
        })

        self.assertEqual("unavailable", observability)
        self.assertFalse(payload["world_observed"])
        self.assertIsNone(payload["world_fingerprint"])

    def _write_process_chain(self, root):
        runtime = root / "runtime"
        runtime_tools = runtime / "tools"
        runtime_tools.mkdir(parents=True)
        orchestrator = runtime_tools / "loom_orchestrator.py"
        orchestrator.write_text(textwrap.dedent(f"""
            import sys
            sys.path.insert(0, {str(TOOLS)!r})
            import loom_adapter_protocol
            import loom_execution_chain
            import loom_orchestrator
            loom_execution_chain.verify_loaded_modules = lambda runtime: {{
                "module_count": 1, "modules_sha256": "a" * 64}}

            def transport_invoke(**kwargs):
                request = kwargs["request"]
                return {{
                    "status": "transport-ok",
                    "request": request,
                    "request_identity": loom_adapter_protocol.request_identity(request),
                }}

            def transport_start(
                    action_path, *, presentation_sha256, cwd=None,
                    owner_home, install_root):
                return {{
                    "status": "transport-ok",
                    "action": str(action_path),
                    "cwd": str(cwd) if cwd is not None else None,
                    "presentation_sha256": presentation_sha256,
                }}

            def transport_revise(
                    action_path, *, presentation_sha256, cwd=None, request,
                    owner_home, install_root):
                return {{
                    "status": "transport-ok",
                    "action": str(action_path),
                    "cwd": str(cwd) if cwd is not None else None,
                    "presentation_sha256": presentation_sha256,
                    "request": request,
                    "request_identity": loom_adapter_protocol.request_identity(request),
                    "request_in_argv": any(request in item for item in sys.argv),
                }}

            loom_orchestrator.invoke = transport_invoke
            loom_orchestrator.start = transport_start
            loom_orchestrator.revise = transport_revise
            raise SystemExit(loom_orchestrator.main())
        """).lstrip(), encoding="utf-8")
        launcher = root / "launcher_harness.py"
        launcher.write_text(textwrap.dedent(f"""
            import sys
            from pathlib import Path
            sys.path.insert(0, {str(TOOLS)!r})
            import loom_launcher

            class Manager:
                class Activations:
                    @staticmethod
                    def public_projection(current):
                        return {{
                            "activation_set_id": None,
                            "runtime_version": "test-runtime",
                            "release_sequence": 1,
                            "state_generation": 0,
                            "state_schema": 0,
                            "deletion_epoch": 0,
                        }}
                activations = Activations()
                def begin_session(self):
                    return {{
                        "session_id": "test", "version": "test-runtime",
                        "state_generation": 0, "state_schema": 0}}
                def end_session(self, session_id, *, successful):
                    pass
                def record_trust_health(self, *, healthy, reason):
                    pass
                def prune_versions(self):
                    pass

            loom_launcher.loom_update.SharedRuntime = lambda home: Manager()
            loom_launcher._current = lambda home: (
                {{"version": "test-runtime", "release_sequence": 1}},
                Path({str(runtime)!r}))
            raise SystemExit(loom_launcher.main())
        """).lstrip(), encoding="utf-8")
        (runtime / "RUNTIME-MANIFEST.json").write_text(
            '{"version":"test-runtime"}\n', encoding="utf-8")
        return launcher, runtime


if __name__ == "__main__":
    unittest.main()
