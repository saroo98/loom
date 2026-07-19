"""Real Windows protocol-v2 request-transport acceptance tests."""

import concurrent.futures
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

import loom_adapter_protocol


TOOLS = Path(__file__).resolve().parent


def _capabilities():
    value = {key: False for key in loom_adapter_protocol.CAPABILITY_KEYS}
    value.update({
        "invoke": True, "complete": True, "cancel": True,
        "status": True, "markdown": True,
    })
    return value


def _initialize(request_id="req-windows-initialize"):
    return {
        "schema_version": 2,
        "message_type": "initialize",
        "request_id": request_id,
        "protocol": {"minimum": 2, "maximum": 2},
        "adapter": {"id": "codex", "version": "2.1.0"},
        "host": {"id": "codex", "version": "windows-acceptance"},
        "capabilities": _capabilities(),
    }


def _invoke(request, cwd, request_id):
    return {
        "schema_version": 2,
        "message_type": "invoke",
        "request_id": request_id,
        "request": request,
        "cwd": str(cwd),
    }


def _frames(messages):
    return b"".join(
        loom_adapter_protocol.canonical_bytes(message) + b"\n"
        for message in messages)


@unittest.skipUnless(os.name == "nt", "Windows request transport requires Windows")
class WindowsRequestTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="loom-windows-transport-")
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "owner"
        self.loom_home = self.home / ".loom"
        self.project = self.root / "project"
        self.project.mkdir(parents=True)
        (self.project / ".git").mkdir()
        self.runtime = self.root / "runtime"
        self.launcher = self._write_process_chain()
        self.environment = os.environ.copy()
        self.environment.update({
            "HOME": str(self.home),
            "USERPROFILE": str(self.home),
            "CODEX_HOME": str(self.home / ".codex"),
            "LOOM_HOME": str(self.loom_home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "TEMP": str(self.root / "tmp"),
            "TMP": str(self.root / "tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        })
        Path(self.environment["TEMP"]).mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def _write_process_chain(self):
        runtime_tools = self.runtime / "tools"
        runtime_tools.mkdir(parents=True)
        orchestrator = runtime_tools / "loom_orchestrator.py"
        orchestrator.write_text(textwrap.dedent(f"""
            import os
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
                    "request_in_argv": any(request in item for item in sys.argv),
                    "request_in_environment": any(
                        request in value for value in os.environ.values()),
                }}

            loom_orchestrator.invoke = transport_invoke
            raise SystemExit(loom_orchestrator.main())
        """).lstrip(), encoding="utf-8")
        launcher = self.root / "loom.py"
        launcher.write_text(textwrap.dedent(f"""
            import sys
            from pathlib import Path
            sys.path.insert(0, {str(TOOLS)!r})
            import loom_launcher

            class Manager:
                def begin_session(self):
                    return {{"session_id": "windows-test", "version": "1.8.3"}}
                def end_session(self, session_id, *, successful):
                    pass
                def record_trust_health(self, *, healthy, reason):
                    pass
                def prune_versions(self):
                    pass

            loom_launcher.loom_update.SharedRuntime = lambda home: Manager()
            loom_launcher._current = lambda home: (
                {{"version": "1.8.3", "release_sequence": 1}},
                Path({str(self.runtime)!r}))
            loom_launcher.__file__ = __file__
            raise SystemExit(loom_launcher.main())
        """).lstrip(), encoding="utf-8")
        return launcher

    def _bridge(self, messages, *, timeout=60):
        result = subprocess.run(
            [sys.executable, "-B", str(self.launcher),
             "--home", str(self.loom_home), "bridge"],
            input=_frames(messages), capture_output=True, timeout=timeout,
            check=False, env=self.environment)
        responses = []
        stream = io.BytesIO(result.stdout)
        while True:
            response = loom_adapter_protocol.read_frame(stream)
            if response is None:
                break
            responses.append(response)
        return result, responses

    def assertRequestIdentity(self, request, response):
        self.assertEqual("result", response["message_type"])
        self.assertEqual(0, response["returncode"], response)
        payload = response["payload"]
        raw = request.encode("utf-8")
        self.assertEqual(request, payload["request"])
        self.assertEqual(len(raw), payload["request_identity"]["utf8_bytes"])
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            payload["request_identity"]["sha256"])
        self.assertFalse(payload["request_in_argv"])
        self.assertFalse(payload["request_in_environment"])

    def test_real_windows_bridge_preserves_exact_request_bytes_across_both_processes(self):
        requests = [
            "line one\r\nline two\nline three",
            "quotes: \"double\" and 'single'",
            "shell: % ! & | < > ^ ( )",
            "Unicode: کوردی 🧵 東京",
            "  leading, repeated   spaces, and trailing  ",
            "x" * loom_adapter_protocol.MAX_REQUEST_CHARACTERS,
        ]
        messages = [_initialize()]
        messages.extend(
            _invoke(request, self.project, f"req-windows-{index}")
            for index, request in enumerate(requests))
        result, responses = self._bridge(messages)
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(1 + len(requests), len(responses))
        self.assertEqual("initialize-result", responses[0]["message_type"])
        for request, response in zip(requests, responses[1:]):
            self.assertRequestIdentity(request, response)

    def test_real_windows_bridge_isolates_concurrent_request_identities(self):
        requests = [
            f"parallel {index}: % ! & | ^ کوردی\n  exact  "
            for index in range(6)]

        def invoke_one(index_request):
            index, request = index_request
            result, responses = self._bridge([
                _initialize(f"req-init-{index}"),
                _invoke(request, self.project, f"req-parallel-{index}"),
            ])
            return request, result, responses

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(invoke_one, enumerate(requests)))
        for request, result, responses in outcomes:
            self.assertEqual(
                0, result.returncode, result.stderr.decode("utf-8", "replace"))
            self.assertEqual(2, len(responses))
            self.assertRequestIdentity(request, responses[1])

    def test_windows_process_path_rejects_tampered_and_oversized_requests(self):
        request = "tamper me"
        invoke = _invoke(request, self.project, "req-tampered")
        envelope = loom_adapter_protocol.request_envelope(
            invoke, {"id": "codex", "version": "windows-acceptance"})
        envelope["request_identity"]["sha256"] = "0" * 64
        tampered = subprocess.run(
            [sys.executable, "-B", str(self.launcher),
             "--home", str(self.loom_home), "invoke-stdio"],
            input=(json.dumps(envelope, ensure_ascii=False) + "\n").encode("utf-8"),
            capture_output=True, timeout=30, check=False, env=self.environment)
        self.assertEqual(2, tampered.returncode)
        self.assertIn("identity", tampered.stdout.decode("utf-8").casefold())

        oversized = _invoke(
            "x" * (loom_adapter_protocol.MAX_REQUEST_CHARACTERS + 1),
            self.project, "req-oversized")
        raw = (json.dumps(oversized, ensure_ascii=False) + "\n").encode("utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(self.launcher),
             "--home", str(self.loom_home), "bridge"],
            input=_frames([_initialize()]) + raw,
            capture_output=True, timeout=30, check=False, env=self.environment)
        stream = io.BytesIO(result.stdout)
        initialized = loom_adapter_protocol.read_frame(stream)
        rejected = loom_adapter_protocol.read_frame(stream)
        self.assertEqual("initialize-result", initialized["message_type"])
        self.assertEqual("error", rejected["message_type"])
        self.assertEqual("MESSAGE_INVALID", rejected["code"])


if __name__ == "__main__":
    unittest.main()
