"""Exact signed-package to stable-launcher bootstrap integration test."""

import datetime as dt
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_plugin_package
import loom_activation
import loom_adapter_protocol
import loom_install
import loom_orchestrator
import loom_release
import loom_release_sign
import loom_reliability
import loom_update
import v11_test_support
from v11_test_support import (
    RUSTC_IDENTITY_TIMEOUT_SECONDS, _build_environment_identity,
    _host_platform, _msvc_environment_from_roots, _native_build_environment,
    _rustc_identity,
    build_vault_helper, package_evidence, package_source_commit,
)


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "vault-helper"

BOOTSTRAP_SPEC = importlib.util.spec_from_file_location(
    "loom_bootstrap_under_test", ROOT / "scripts" / "loom_bootstrap.py")
loom_bootstrap = importlib.util.module_from_spec(BOOTSTRAP_SPEC)
BOOTSTRAP_SPEC.loader.exec_module(loom_bootstrap)


class NativeBuildEnvironmentTests(unittest.TestCase):
    def test_native_helper_replaces_non_msvc_linker_on_windows(self):
        selected = {"PATH": "verified-msvc"}
        with mock.patch.object(
                    v11_test_support, "_is_windows_host",
                    return_value=True), \
                mock.patch.object(
                    v11_test_support, "_windows_toolchain_roots",
                    return_value=([Path("C:/BuildTools")], Path("C:/SDK"))), \
                mock.patch.object(
                    v11_test_support, "_msvc_environment_from_roots",
                    return_value=selected) as construct:
            observed = _native_build_environment({"PATH": "C:/UnixTools"})

        self.assertIs(selected, observed)
        construct.assert_called_once()


class BootstrapIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)
        cls.direct_fixture = tempfile.TemporaryDirectory()
        cls.direct_public = Path(cls.direct_fixture.name) / "public"
        loom_release.build_public(
            ROOT, cls.direct_public,
            forbidden_tokens=["-".join(("direct", "owner", "fixture", "token"))],
            source_classification="public-release")
        platform_id = loom_update.platform_id()
        binary_name = "loom-vault.exe" if platform_id.startswith("windows-") \
            else "loom-vault"
        helper = cls.direct_public / "crypto" / platform_id / binary_name
        helper.parent.mkdir(parents=True)
        shutil.copyfile(cls.helper, helper)
        if os.name != "nt":
            os.chmod(helper, 0o755)

    @classmethod
    def tearDownClass(cls):
        cls.direct_fixture.cleanup()

    def _install_direct_fixture(self, root):
        target = Path(root) / "direct-install"
        loom_install.install(self.direct_public, target)
        return target

    def test_native_helper_cache_identity_binds_cargo_and_temp_environments(self):
        baseline = _build_environment_identity({
            "CARGO_HOME": "/one/cargo", "TMPDIR": "/one/tmp",
            "HOME": "/one/home", "USERPROFILE": "/one/profile"})
        cargo_changed = _build_environment_identity({
            "CARGO_HOME": "/two/cargo", "TMPDIR": "/one/tmp",
            "HOME": "/one/home", "USERPROFILE": "/one/profile"})
        temp_changed = _build_environment_identity({
            "CARGO_HOME": "/one/cargo", "TMPDIR": "/two/tmp",
            "HOME": "/one/home", "USERPROFILE": "/one/profile"})
        home_changed = _build_environment_identity({
            "CARGO_HOME": "/one/cargo", "TMPDIR": "/one/tmp",
            "HOME": "/two/home", "USERPROFILE": "/one/profile"})
        profile_changed = _build_environment_identity({
            "CARGO_HOME": "/one/cargo", "TMPDIR": "/one/tmp",
            "HOME": "/one/home", "USERPROFILE": "/two/profile"})
        self.assertNotEqual(baseline, cargo_changed)
        self.assertNotEqual(baseline, temp_changed)
        self.assertNotEqual(baseline, home_changed)
        self.assertNotEqual(baseline, profile_changed)

    def test_native_helper_constructs_minimal_msvc_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installation = root / "Visual Studio" / "2022" / "BuildTools"
            msvc = installation / "VC" / "Tools" / "MSVC" / "14.44.35207"
            (msvc / "bin" / "Hostx64" / "x64").mkdir(parents=True)
            (msvc / "bin" / "Hostx64" / "x64" / "link.exe").write_bytes(b"")
            (msvc / "include").mkdir()
            (msvc / "lib" / "x64").mkdir(parents=True)
            sdk = root / "Windows Kits" / "10"
            version = "10.0.26100.0"
            for relative in (
                    f"Include/{version}/ucrt", f"Include/{version}/shared",
                    f"Include/{version}/um", f"Include/{version}/winrt",
                    f"Lib/{version}/ucrt/x64", f"Lib/{version}/um/x64"):
                (sdk / relative).mkdir(parents=True)
            environment = _msvc_environment_from_roots(
                {"PATH": "fixture-path"}, installation, sdk)

        self.assertIsNotNone(environment)
        self.assertTrue(environment["PATH"].endswith("fixture-path"))
        self.assertIn(str(msvc / "bin" / "Hostx64" / "x64"),
                      environment["PATH"])
        self.assertIn(str(msvc / "lib" / "x64"), environment["LIB"])
        self.assertEqual(version + os.sep, environment["WindowsSDKVersion"])
        self.assertEqual(
            str(msvc / "bin" / "Hostx64" / "x64" / "link.exe"),
            environment["CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"])
        with mock.patch.object(loom_update, "platform_id",
                               return_value="windows-x64"):
            self.assertEqual("windows-x64", _host_platform())

    def test_plugin_session_start_canonicalizes_without_prompt_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            user = Path(temporary) / "owner"
            user.mkdir()
            launcher = user / ".loom" / "bin" / "loom.py"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("# launcher\n", encoding="utf-8")
            event = io.TextIOWrapper(
                io.BytesIO(json.dumps({
                    "hook_event_name": "SessionStart"}).encode("utf-8")))
            completed = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout=json.dumps({"status": "installed"}), stderr="")
            output = io.StringIO()
            with mock.patch.object(loom_bootstrap.sys, "stdin", event), \
                    mock.patch.dict(os.environ, {
                        "PLUGIN_ROOT": str(ROOT),
                        "USERPROFILE": str(user),
                    }, clear=False), \
                    mock.patch.object(
                        loom_bootstrap, "reconcile",
                        return_value={
                            "status": "current",
                            "launcher": {"python_launcher": str(launcher)}}), \
                    mock.patch.object(
                        loom_bootstrap.subprocess, "run",
                        return_value=completed) as run, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(0, loom_bootstrap._hook_event())
            command = run.call_args.args[0]
            self.assertIn("codex-plugin-canonicalize", command)
            self.assertIn("--approved", command)
            self.assertNotIn("UserPromptSubmit", " ".join(command))
            result = json.loads(output.getvalue())
            self.assertTrue(result["continue"])
            self.assertIn("canonical Loom route", result["systemMessage"])

    def test_plugin_session_start_reports_safe_canonicalization_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            user = Path(temporary) / "owner"
            user.mkdir()
            launcher = user / ".loom" / "bin" / "loom.py"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("# launcher\n", encoding="utf-8")
            event = io.TextIOWrapper(
                io.BytesIO(json.dumps({
                    "hook_event_name": "SessionStart"}).encode("utf-8")))
            completed = subprocess.CompletedProcess(
                args=[], returncode=2, stdout=json.dumps({
                    "status": "blocked",
                    "error": "unowned Loom route"}), stderr="")
            output = io.StringIO()
            with mock.patch.object(loom_bootstrap.sys, "stdin", event), \
                    mock.patch.dict(os.environ, {
                        "PLUGIN_ROOT": str(ROOT),
                        "USERPROFILE": str(user),
                    }, clear=False), \
                    mock.patch.object(
                        loom_bootstrap, "reconcile",
                        return_value={
                            "status": "current",
                            "launcher": {"python_launcher": str(launcher)}}), \
                    mock.patch.object(
                        loom_bootstrap.subprocess, "run",
                        return_value=completed), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(0, loom_bootstrap._hook_event())
            result = json.loads(output.getvalue())
            self.assertTrue(result["continue"])
            self.assertIn("blocked safely", result["systemMessage"])
            self.assertIn("No unowned route was changed", result["systemMessage"])

    def test_rustc_identity_probe_is_bounded_and_cached_per_process(self):
        _rustc_identity.cache_clear()
        try:
            completed = mock.Mock(stdout="rustc 1.97.1\nhost: fixture\n")
            with mock.patch("v11_test_support.subprocess.run",
                            return_value=completed) as run:
                first = _rustc_identity()
                second = _rustc_identity()
            self.assertEqual(first, second)
            run.assert_called_once()
            self.assertEqual(RUSTC_IDENTITY_TIMEOUT_SECONDS,
                             run.call_args.kwargs["timeout"])
        finally:
            _rustc_identity.cache_clear()

    def test_receipt_proven_direct_install_bootstraps_without_signed_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"

            result = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                capture_output=True, text=True, timeout=120, check=False)

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual("activated", value["status"])
            self.assertEqual(
                "direct-source-install-unattested", value["delivery_authority"])
            probe = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "adapter-probe"],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(0, probe.returncode, probe.stdout + probe.stderr)
            self.assertEqual(
                "direct-source-install-unattested",
                json.loads((home / "runtime" / "versions" / value["version"] /
                            ".loom-direct-source-receipt.json").read_text(
                                encoding="utf-8"))["delivery_authority"])

    def test_bootstrap_rejects_user_profile_root_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            profile = root / "profile"
            profile.mkdir()
            sentinel = profile / "unrelated.txt"
            sentinel.write_text("preserve", encoding="utf-8")

            environment = {
                **os.environ, "HOME": str(profile), "USERPROFILE": str(profile)}
            result = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(profile)],
                capture_output=True, text=True, timeout=30, check=False,
                env=environment)

            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn("user-profile root", json.loads(result.stdout)["error"])
            self.assertEqual("preserve", sentinel.read_text(encoding="utf-8"))
            self.assertEqual(["unrelated.txt"], sorted(
                path.name for path in profile.iterdir()))

    def test_bootstrap_rejects_filesystem_root(self):
        filesystem_root = Path(Path.cwd().anchor)
        with self.assertRaisesRegex(
                loom_bootstrap.BootstrapError, "filesystem or user-profile root"):
            loom_bootstrap._loom_home_root(filesystem_root)

    def test_concurrent_cold_direct_bootstraps_converge_on_one_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            command = [
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)]

            processes = [
                subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for _ in range(4)
            ]
            completed = [process.communicate(timeout=180) for process in processes]

            for process, (stdout, stderr) in zip(processes, completed):
                self.assertEqual(0, process.returncode, stdout + stderr)
                self.assertIn(
                    json.loads(stdout)["status"], {"activated", "current"})
            current = json.loads(
                (home / "runtime" / "current.json").read_text(encoding="utf-8"))
            runtime = home / "runtime" / "versions" / current["path"]
            helper, payload_sha256 = loom_bootstrap._verify_recoverable_direct_runtime(
                runtime, version=current["version"],
                platform_id=loom_update.platform_id(),
                binary_name="loom-vault.exe" if os.name == "nt" else "loom-vault",
                source_receipt=loom_bootstrap._direct_install_receipt(direct))
            self.assertTrue(helper.is_file())
            self.assertEqual(current["payload_sha256"], payload_sha256)
            self.assertEqual(
                [], list((home / "runtime" / "versions").glob(".*.direct-staged-*")))

    def test_concurrent_direct_activation_rejects_mismatched_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            manager = loom_update.SharedRuntime(home, plugin_roots=[direct])
            source_receipt = loom_bootstrap._direct_install_receipt(direct)
            platform_id = loom_update.platform_id()
            binary_name = "loom-vault.exe" if os.name == "nt" else "loom-vault"
            version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
            staging, final, _helper, payload_sha256 = \
                loom_bootstrap._stage_direct_runtime(
                    direct, manager, version=version, platform_id=platform_id,
                    binary_name=binary_name, source_receipt=source_receipt,
                    reliability_module=loom_reliability,
                    package_module=loom_plugin_package)
            (staging / ".loom-health-receipt.json").write_text(
                json.dumps({
                    "schema_version": 1, "version": version,
                    "delivery_authority": "direct-source-install-unattested",
                    "source_receipt_hash": source_receipt["receipt_hash"],
                    "healthy": True, "migration_complete": True,
                    "disposable_request_passed": True,
                    "before_inventory_sha256": "0" * 64,
                    "after_inventory_sha256": "0" * 64,
                }), encoding="utf-8")
            final.mkdir(parents=True)
            marker = final / "unowned-marker.txt"
            marker.write_text("preserve me", encoding="utf-8")
            pointer = {
                "version": version, "path": version,
                "payload_sha256": payload_sha256,
                "release_sequence": 1, "previous": None}

            with self.assertRaises(loom_bootstrap.BootstrapError):
                loom_bootstrap._activate_staged_direct_runtime(
                    manager, staging, final, pointer,
                    version=version, platform_id=platform_id,
                    binary_name=binary_name, source_receipt=source_receipt,
                    expected_payload_sha256=payload_sha256,
                    reliability_module=loom_reliability)

            self.assertEqual("preserve me", marker.read_text(encoding="utf-8"))
            self.assertFalse(staging.exists())
            self.assertFalse((home / "runtime" / "current.json").exists())

    def test_concurrent_direct_activation_converges_on_verified_same_source_winner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            manager = loom_update.SharedRuntime(home, plugin_roots=[direct])
            source_receipt = loom_bootstrap._direct_install_receipt(direct)
            platform_id = loom_update.platform_id()
            binary_name = "loom-vault.exe" if os.name == "nt" else "loom-vault"
            version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
            staged = [
                loom_bootstrap._stage_direct_runtime(
                    direct, manager, version=version, platform_id=platform_id,
                    binary_name=binary_name, source_receipt=source_receipt,
                    reliability_module=loom_reliability,
                    package_module=loom_plugin_package)
                for _ in range(2)
            ]
            for staging, _final, _helper, _payload in staged:
                (staging / ".loom-health-receipt.json").write_text(
                    json.dumps({
                        "schema_version": 1, "version": version,
                        "delivery_authority": "direct-source-install-unattested",
                        "source_receipt_hash": source_receipt["receipt_hash"],
                        "healthy": True, "migration_complete": True,
                        "disposable_request_passed": True,
                        "before_inventory_sha256": "0" * 64,
                        "after_inventory_sha256": "0" * 64,
                    }), encoding="utf-8")
            first_staging, final, _helper, first_payload = staged[0]
            pointer = {
                "version": version, "path": version,
                "payload_sha256": first_payload,
                "release_sequence": 1, "previous": None}
            loom_bootstrap._activate_staged_direct_runtime(
                manager, first_staging, final, pointer,
                version=version, platform_id=platform_id,
                binary_name=binary_name, source_receipt=source_receipt,
                expected_payload_sha256=first_payload,
                reliability_module=loom_reliability)

            second_staging, _final, _helper, _second_payload = staged[1]
            result = loom_bootstrap._activate_staged_direct_runtime(
                manager, second_staging, final,
                {**pointer, "payload_sha256": "f" * 64},
                version=version, platform_id=platform_id,
                binary_name=binary_name, source_receipt=source_receipt,
                expected_payload_sha256="f" * 64,
                reliability_module=loom_reliability)

            self.assertIn(result["status"], {"activated", "current"})
            self.assertEqual(first_payload, manager.current()["payload_sha256"])
            self.assertFalse(second_staging.exists())

    def test_bootstrap_accepts_and_fails_closed_on_runtime_activation_pointer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            bootstrap_command = [
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)]
            first = subprocess.run(
                bootstrap_command, capture_output=True, text=True,
                timeout=120, check=False)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)

            project = root / "project"
            project.mkdir()
            (project / "tool.py").write_text("print('tool')\n", encoding="utf-8")
            (home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
                loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
            environment = {**os.environ, "LOOM_TEST_ALLOW_LEGACY_BACKEND": "1"}
            message = {
                "schema_version": 2, "message_type": "invoke",
                "request_id": "req-activation-pointer",
                "request": "Plan a small Python command-line tool.",
                "cwd": str(project),
            }
            frame = loom_adapter_protocol.canonical_bytes(
                loom_adapter_protocol.request_envelope(
                    message, {"id": "codex", "version": "test"})) + b"\n"
            invoked = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "invoke-stdio"],
                input=frame, capture_output=True, timeout=120, check=False,
                env=environment)
            self.assertEqual(
                0, invoked.returncode,
                (invoked.stdout + invoked.stderr).decode("utf-8", errors="replace"))
            self.assertEqual(
                "action-required",
                json.loads(invoked.stdout.decode("utf-8"))["status"])

            pointer_path = home / "runtime" / "current.json"
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            self.assertEqual(
                loom_activation.POINTER_V1_FIELDS, set(pointer))
            second = subprocess.run(
                bootstrap_command, capture_output=True, text=True,
                timeout=120, check=False)
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertEqual("current", json.loads(second.stdout)["status"])

            receipt_path = (
                home / "runtime" / "activation-sets" /
                f"{pointer['activation_set_id']}.json")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            mutations = {
                "unknown pointer field": {
                    **pointer, "unexpected": "must fail closed"},
                "mismatched receipt digest": {
                    **pointer, "activation_receipt_sha256": "0" * 64},
            }
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    loom_reliability.atomic_write_json(pointer_path, mutation)
                    with self.assertRaisesRegex(
                            loom_bootstrap.BootstrapError,
                            "runtime pointer|activation pointer"):
                        loom_bootstrap._verified_current_runtime(home)
            loom_reliability.atomic_write_json(pointer_path, pointer)
            altered_receipt = {**receipt, "purpose": "reactivation"}
            loom_reliability.atomic_write_json(receipt_path, altered_receipt)
            with self.assertRaisesRegex(
                    loom_bootstrap.BootstrapError, "activation pointer"):
                loom_bootstrap._verified_current_runtime(home)
            loom_reliability.atomic_write_json(receipt_path, receipt)
            self.assertEqual(
                home / "runtime" / "versions" / pointer["version"],
                loom_bootstrap._verified_current_runtime(home))

    def test_direct_helper_build_uses_short_temporary_target_not_deep_runtime_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root.joinpath(*(["deep candidate directory"] * 12))
            crate = plugin / "vault-helper"
            crate.mkdir(parents=True)
            (crate / "Cargo.toml").write_text("[package]\nname='fixture'\n", encoding="utf-8")
            (crate / "Cargo.lock").write_text("# locked\n", encoding="utf-8")
            versions = root.joinpath(*(["deep owner home"] * 12), "versions")
            versions.mkdir(parents=True)
            manager = mock.Mock(versions=versions)
            receipt = {
                "install_id": "00000000-0000-4000-8000-000000000001",
                "receipt_hash": "a" * 64,
                "files": [
                    {"path": "vault-helper/Cargo.toml"},
                    {"path": "vault-helper/Cargo.lock"},
                ],
            }
            targets = []

            def cargo_run(command, **_kwargs):
                target = Path(command[command.index("--target-dir") + 1])
                targets.append(target)
                helper = target / "release" / "loom-vault.exe"
                helper.parent.mkdir(parents=True)
                helper.write_bytes(b"fixture")
                return subprocess.CompletedProcess(command, 0, b"", b"")

            package = mock.Mock()
            package._copy_helper_executable.side_effect = \
                lambda source, destination: shutil.copyfile(source, destination)
            with mock.patch.object(loom_bootstrap.shutil, "which", return_value="cargo"), \
                    mock.patch.object(
                        loom_bootstrap.subprocess, "run", side_effect=cargo_run):
                staging, _final, helper, _digest = loom_bootstrap._stage_direct_runtime(
                    plugin, manager, version="9.9.9", platform_id="windows-x64",
                    binary_name="loom-vault.exe", source_receipt=receipt,
                    reliability_module=loom_reliability, package_module=package)
            try:
                self.assertEqual(1, len(targets))
                self.assertFalse(targets[0].is_relative_to(plugin))
                self.assertFalse(targets[0].is_relative_to(versions))
                self.assertLess(len(str(targets[0])), len(str(plugin)))
                self.assertTrue(helper.is_file())
            finally:
                shutil.rmtree(staging, ignore_errors=True)

    def test_clean_host_plugin_mcp_bootstraps_lists_and_calls_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            user_home = root / "clean user with spaces"
            user_home.mkdir()
            frames = "".join(json.dumps(item) + "\n" for item in (
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                    "name": "status", "_meta": {"progressToken": "codex-status"}}},
            ))
            environment = {
                **os.environ,
                "HOME": str(user_home),
                "USERPROFILE": str(user_home),
                "CODEX_HOME": str(user_home / ".codex"),
            }
            result = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_codex_mcp.py")],
                input=frames, capture_output=True, text=True, timeout=120,
                check=False, env=environment)

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            responses = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(3, len(responses))
            self.assertEqual("2025-06-18", responses[0]["result"]["protocolVersion"])
            self.assertEqual(
                json.loads((direct / ".codex-plugin" / "plugin.json").read_text(
                    encoding="utf-8"))["version"],
                responses[0]["result"]["serverInfo"]["version"])
            self.assertEqual(
                ["invoke", "resolve", "status", "complete", "author", "cancel"],
                [item["name"] for item in responses[1]["result"]["tools"]])
            self.assertNotIn("error", responses[2])
            self.assertFalse(responses[2]["result"]["isError"])
            self.assertNotIn("structuredContent", responses[2]["result"])
            status = json.loads(responses[2]["result"]["content"][0]["text"])
            self.assertIsInstance(status.get("status"), str)
            self.assertTrue((user_home / ".loom" / "runtime" / "current.json").is_file())
            self.assertFalse((user_home / ".codex" / "hooks.json").exists())

    def test_changed_or_unowned_direct_install_never_creates_active_pointer(self):
        for mutation in ("changed", "missing", "unowned"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                direct = self._install_direct_fixture(root)
                if mutation == "changed":
                    (direct / "tools" / "loom_runtime.py").write_text(
                        "changed\n", encoding="utf-8")
                elif mutation == "missing":
                    (direct / "tools" / "loom_runtime.py").unlink()
                else:
                    (direct / "unowned.txt").write_text("unowned\n", encoding="utf-8")
                home = root / "home" / ".loom"

                result = subprocess.run([
                    sys.executable, "-B",
                    str(direct / "scripts" / "loom_bootstrap.py"),
                    "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                    capture_output=True, text=True, timeout=60, check=False)

                self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                self.assertEqual("blocked", json.loads(result.stdout)["status"])
                self.assertFalse((home / "runtime" / "current.json").exists())

    def test_direct_install_redirect_is_rejected_before_installed_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            direct = self._install_direct_fixture(temporary)
            redirected = direct / "tools"
            real_redirect = loom_bootstrap._redirect

            def redirect_probe(path):
                return Path(path) == redirected or real_redirect(path)

            with mock.patch.object(
                    loom_bootstrap, "_redirect", side_effect=redirect_probe):
                with self.assertRaisesRegex(loom_bootstrap.BootstrapError, "redirect"):
                    loom_bootstrap._direct_install_receipt(direct)

    def test_incomplete_signed_metadata_cannot_downgrade_to_direct_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(self.direct_public, source)
            release = source / "release"
            release.mkdir(exist_ok=True)
            (release / "metadata.json").write_text("{}\n", encoding="utf-8")
            direct = root / "direct-install"
            loom_install.install(source, direct)
            home = root / "home" / ".loom"

            result = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                capture_output=True, text=True, timeout=60, check=False)

            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn("signed delivery metadata is incomplete", result.stdout)
            self.assertFalse((home / "runtime" / "current.json").exists())

    def test_interrupted_direct_pointer_commit_recovers_verified_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            command = [
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)]
            first = subprocess.run(
                command, capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)
            version = json.loads(first.stdout)["version"]
            (home / "runtime" / "current.json").unlink()
            (home / "runtime" / "update-state.json").unlink(missing_ok=True)
            (home / "runtime" / "usage" / f"{version}.json").unlink(missing_ok=True)

            recovered = subprocess.run(
                command, capture_output=True, text=True, timeout=120, check=False)

            self.assertEqual(0, recovered.returncode, recovered.stdout + recovered.stderr)
            self.assertEqual("activated", json.loads(recovered.stdout)["status"])
            self.assertTrue((home / "runtime" / "current.json").is_file())
            self.assertTrue((home / "runtime" / "usage" / f"{version}.json").is_file())
            self.assertTrue((home / "runtime" / "update-state.json").is_file())

    def test_installed_launcher_routes_oversized_generated_project_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            bootstrap = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(0, bootstrap.returncode, bootstrap.stdout + bootstrap.stderr)

            project = root / "oversized-project"
            project.mkdir()
            (project / "Cargo.toml").write_text(
                "[package]\nname='oversized'\nversion='0.1.0'\n", encoding="utf-8")
            (project / ".gitignore").write_text("target/\n", encoding="utf-8")
            (project / "agent.py").write_text("print('agent')\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(project), "init"], check=True,
                           capture_output=True, timeout=30)
            subprocess.run(["git", "-C", str(project), "add", "."], check=True,
                           capture_output=True, timeout=30)
            subprocess.run([
                "git", "-C", str(project), "-c", "user.name=Loom Test", "-c",
                "user.email=loom@example.invalid", "commit", "-m", "fixture"],
                check=True, capture_output=True, timeout=30)
            generated = project / "target" / "debug" / "objects"
            generated.mkdir(parents=True)
            for index in range(4100):
                (generated / f"{index:04d}.o").write_bytes(b"generated")

            request = (
                "Plan recurring blocker prevention for this llm-agent runtime. "
                "The Deep Research Reports path is inert source material; do not activate "
                "website or research domains.")
            home.mkdir(parents=True, exist_ok=True)
            (home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
                loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
            environment = {**os.environ, "LOOM_TEST_ALLOW_LEGACY_BACKEND": "1"}
            message = {
                "schema_version": 2, "message_type": "invoke",
                "request_id": "req-bounded-inspection", "request": request,
                "cwd": str(project),
            }
            frame = loom_adapter_protocol.canonical_bytes(
                loom_adapter_protocol.request_envelope(
                    message, {"id": "codex", "version": "test"})) + b"\n"
            invoked = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "invoke-stdio"],
                input=frame, capture_output=True, timeout=120, check=False,
                env=environment)

            self.assertEqual(0, invoked.returncode, (invoked.stdout + invoked.stderr).decode(
                "utf-8", errors="replace"))
            result = json.loads(invoked.stdout.decode("utf-8"))
            self.assertEqual("action-required", result["status"])
            self.assertIn("llm-agent", result["domains"])
            self.assertNotIn("website", result["domains"])
            self.assertNotIn("research", result["domains"])
            inspection = result["plan_contract"]["project_inspection"]
            self.assertEqual("complete", inspection["state"])
            self.assertGreater(inspection["counts"]["entries_seen"], 4096)
            self.assertTrue(inspection["g1_eligible"])
            self.assertEqual(
                ["rust-target"],
                inspection["generated_rule_ids"])

    def test_signed_fresh_package_activates_and_stable_launcher_verifies_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, root / "evidence", loom_plugin_package.PLATFORMS,
                native_helper=self.helper)
            package = root / "plugin-cache" / "loom" / "1.1.0"
            loom_plugin_package.build(
                ROOT, package, helpers, receipts, evidence,
                version="1.1.0", release_sequence=2,
                source_commit=package_source_commit(ROOT))
            ceremony = loom_release_sign.create_root_authority(
                self.helper, root / "offline-keys",
                ["bootstrap authority one", "bootstrap authority two",
                 "bootstrap authority three"],
                expires=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
            keys = ceremony["private_key_paths"]
            finalized = loom_release_sign.finalize_package(
                self.helper, package, ceremony["root"],
                [(keys[0], "bootstrap authority one"),
                 (keys[1], "bootstrap authority two")],
                expires=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
            self.assertTrue(finalized["firewall"]["clean"])
            home = root / "home" / ".loom"
            result = subprocess.run([
                sys.executable, "-B", str(package / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(package), "--home", str(home)],
                capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("activated", json.loads(result.stdout)["status"])
            probe = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "adapter-probe"],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(0, probe.returncode, probe.stdout + probe.stderr)
            self.assertEqual("1.1.0", json.loads(probe.stdout)["version"])

    def test_post_activation_launcher_uses_candidate_runtime_not_stale_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home" / ".loom"
            home.mkdir(parents=True)
            stale = mock.Mock()
            stale.install_launcher.side_effect = AssertionError(
                "the pre-update adapter module must not install the candidate launcher")
            with mock.patch.dict(sys.modules, {"loom_adapters": stale}):
                result = loom_bootstrap._install_active_launcher(home, ROOT)
            self.assertEqual("installed", result["status"])
            receipt = json.loads(
                (home / "bin" / ".loom-launcher-receipt.json").read_text(encoding="utf-8"))
            for dependency in (
                    "loom_mcp_server.py", "loom_codex_integration.py",
                    "loom_adapters.py", "loom_install.py"):
                self.assertTrue((home / "bin" / dependency).is_file())
                self.assertIn(dependency, receipt["files"])
            probe = subprocess.run([
                sys.executable, "-B", "-c",
                "import importlib.util,sys;sys.path.insert(0,sys.argv[1]);"
                "s=importlib.util.spec_from_file_location('installed_loom',sys.argv[2]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)",
                str(home / "bin"), str(home / "bin" / "loom.py")],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(0, probe.returncode, probe.stdout + probe.stderr)

    def test_prebootstrap_runtime_scan_rejects_redirected_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            redirected = runtime / "redirected"
            redirected.mkdir(parents=True)
            (runtime / "file").write_text("bound", encoding="utf-8")
            real_redirect = loom_bootstrap._redirect

            def redirect_probe(path):
                return Path(path) == redirected or real_redirect(path)

            with mock.patch.object(
                    loom_bootstrap, "_redirect", side_effect=redirect_probe):
                with self.assertRaisesRegex(loom_bootstrap.BootstrapError, "redirected"):
                    list(loom_bootstrap._runtime_files(runtime))

    def test_failed_first_legacy_migration_never_activates_blank_vault_and_retry_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home" / ".loom"
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / ".loom-instance-id").write_text(
                "00000000-0000-4000-8000-000000000111\n", encoding="utf-8")

            class FakeVault:
                def semantic_inventory(self):
                    return {"sha256": "a" * 64}

                def online_backup(self, destination):
                    Path(destination).write_bytes(b"complete migrated vault")

            vault = FakeVault()

            class FakeOwner:
                @staticmethod
                def initialize_owner_vault(staged_home, _helper):
                    path = Path(staged_home) / "vault" / "owner.sqlite3"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"staged vault")
                    return {"vault": vault, "crypto": object()}

                @staticmethod
                def open_owner_vault(open_home, _helper):
                    if not (Path(open_home) / "vault" / "owner.sqlite3").is_file():
                        raise AssertionError("active vault is absent")
                    return vault, object()

            migrate = mock.Mock()
            migrate.migrate_v1.side_effect = [RuntimeError("injected migration failure"), None]

            with self.assertRaisesRegex(RuntimeError, "injected migration failure"):
                loom_bootstrap._migrate_legacy_staged(
                    home, "helper", runtime,
                    "00000000-0000-4000-8000-000000000111",
                    owner_module=FakeOwner, migrate_module=migrate,
                    reliability_module=loom_reliability)
            self.assertFalse((home / "vault" / "owner.sqlite3").exists())
            self.assertTrue((home / "vault" / "bootstrap-journal.json").is_file())

            migrated, _crypto = loom_bootstrap._migrate_legacy_staged(
                home, "helper", runtime,
                "00000000-0000-4000-8000-000000000111",
                owner_module=FakeOwner, migrate_module=migrate,
                reliability_module=loom_reliability)

            self.assertIs(vault, migrated)
            self.assertEqual(b"complete migrated vault", (
                home / "vault" / "owner.sqlite3").read_bytes())
            journal = json.loads((home / "vault" / "bootstrap-journal.json").read_text(
                encoding="utf-8"))
            self.assertEqual("complete", journal["state"])
            self.assertEqual(
                home.resolve(), Path(migrate.migrate_v1.call_args.args[0]).resolve())


if __name__ == "__main__":
    unittest.main()
