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


class FakeManager:
    def begin_session(self):
        return {"session_id": "session-transport", "version": "test-runtime"}

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
            stdin = SimpleNamespace(buffer=io.BytesIO(frame))
            completed = SimpleNamespace(returncode=0)
            with mock.patch.object(loom_launcher.sys, "stdin", stdin), \
                    mock.patch.object(
                        loom_launcher.loom_update, "SharedRuntime", return_value=manager), \
                    mock.patch.object(
                        loom_launcher, "_current",
                        return_value=({"version": "test-runtime", "release_sequence": 1},
                                      runtime)), \
                    mock.patch.object(loom_launcher, "_reject_local_shadow"), \
                    mock.patch.object(
                        loom_launcher.subprocess, "run", return_value=completed) as run:
                code = loom_launcher.main([
                    "--home", str(root / ".loom"), "invoke-stdio"])
        self.assertEqual(0, code)
        command = run.call_args.args[0]
        self.assertEqual("invoke-stdio", command[3])
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

    def _write_process_chain(self, root):
        runtime = root / "runtime"
        runtime_tools = runtime / "tools"
        runtime_tools.mkdir(parents=True)
        orchestrator = runtime_tools / "loom_orchestrator.py"
        orchestrator.write_text(textwrap.dedent(f"""
            import sys
            sys.path.insert(0, {str(TOOLS)!r})
            import loom_adapter_protocol
            import loom_orchestrator

            def transport_invoke(**kwargs):
                request = kwargs["request"]
                return {{
                    "status": "transport-ok",
                    "request": request,
                    "request_identity": loom_adapter_protocol.request_identity(request),
                }}

            loom_orchestrator.invoke = transport_invoke
            raise SystemExit(loom_orchestrator.main())
        """).lstrip(), encoding="utf-8")
        launcher = root / "launcher_harness.py"
        launcher.write_text(textwrap.dedent(f"""
            import sys
            from pathlib import Path
            sys.path.insert(0, {str(TOOLS)!r})
            import loom_launcher

            class Manager:
                def begin_session(self):
                    return {{"session_id": "test", "version": "test-runtime"}}
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
        return launcher, runtime


if __name__ == "__main__":
    unittest.main()
