import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_operation_supervisor


class OperationSupervisorTests(unittest.TestCase):
    def test_minimal_environment_drops_ambient_secret_names(self):
        previous = os.environ.get("LOOM_TEST_API_KEY")
        os.environ["LOOM_TEST_API_KEY"] = "not-forwarded"
        try:
            with mock.patch.dict(os.environ, {
                    "PROCESSOR_ARCHITECTURE": "AMD64",
                    "PROCESSOR_ARCHITEW6432": "AMD64",
            }):
                environment = loom_operation_supervisor.minimal_environment()
        finally:
            if previous is None:
                os.environ.pop("LOOM_TEST_API_KEY", None)
            else:
                os.environ["LOOM_TEST_API_KEY"] = previous
        self.assertNotIn("LOOM_TEST_API_KEY", environment)
        self.assertEqual("1", environment["PYTHONNOUSERSITE"])
        self.assertEqual("AMD64", environment["PROCESSOR_ARCHITECTURE"])
        self.assertEqual("AMD64", environment["PROCESSOR_ARCHITEW6432"])

    def test_success_is_contained_and_protected_root_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            protected = root / "protected"
            protected.mkdir()
            (protected / "state.txt").write_text("unchanged", encoding="utf-8")
            receipt, stdout, stderr = loom_operation_supervisor.run(
                operation_class="verification",
                command=[sys.executable, "-c", "print('ok')"],
                cwd=root, timeout=10, allowed_roots=[root],
                protected_roots=[protected], capabilities=["local-process"],
                capture_output=True)
            self.assertEqual(["ok"], stdout.decode("utf-8").splitlines())
            self.assertEqual(b"", stderr)
            self.assertEqual("passed", receipt["status"])
            self.assertTrue(receipt["survivors_confirmed_zero"])
            self.assertTrue(receipt["protected_roots_unchanged"])
            self.assertFalse(receipt["network_isolation_proven"])
            loom_operation_supervisor.require_passed(receipt)

    def test_protected_change_fails_even_when_child_exits_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            protected = root / "protected"
            protected.mkdir()
            target = protected / "state.txt"
            target.write_text("before", encoding="utf-8")
            receipt = loom_operation_supervisor.run(
                operation_class="hostile-fixture",
                command=[
                    sys.executable, "-c",
                    "from pathlib import Path;Path(r'%s').write_text('after')"
                    % str(target).replace("\\", "\\\\"),
                ],
                cwd=root, timeout=10, allowed_roots=[root],
                protected_roots=[protected])
            self.assertEqual("failed", receipt["status"])
            self.assertEqual("protected-root-changed", receipt["primary_failure"])
            with self.assertRaises(loom_operation_supervisor.SupervisorError):
                loom_operation_supervisor.require_passed(receipt)

    def test_timeout_preserves_primary_failure_and_reconciles_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipt = loom_operation_supervisor.run(
                operation_class="timeout-fixture",
                command=[
                    sys.executable, "-c",
                    "import subprocess,sys,time;"
                    "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                    "time.sleep(60)",
                ],
                cwd=root, timeout=0.2, allowed_roots=[root])
            self.assertEqual("failed", receipt["status"])
            self.assertEqual("timed-out", receipt["primary_failure"])
            self.assertTrue(receipt["survivors_confirmed_zero"])
        with mock.patch.object(
                loom_operation_supervisor.shutil, "which", return_value="/bin/ps"), \
                mock.patch.object(
                    loom_operation_supervisor.subprocess, "run",
                    return_value=subprocess.CompletedProcess(
                        args=[], returncode=0,
                        stdout=" 10 42 Z\n 11 42 S\n", stderr="")):
            self.assertTrue(
                loom_operation_supervisor._ps_group_live_state(42))
        with mock.patch.object(
                loom_operation_supervisor.shutil, "which", return_value="/bin/ps"), \
                mock.patch.object(
                    loom_operation_supervisor.subprocess, "run",
                    return_value=subprocess.CompletedProcess(
                        args=[], returncode=0,
                        stdout=" 10 42 Z\n 12 99 S\n", stderr="")):
            self.assertFalse(
                loom_operation_supervisor._ps_group_live_state(42))

    def test_posix_cleanup_retries_one_transient_census_uncertainty(self):
        process = mock.Mock(pid=4242)
        process.wait.return_value = 0
        with mock.patch.object(
                loom_operation_supervisor.os, "name", "posix"), \
                mock.patch.object(
                    loom_operation_supervisor.os, "killpg", create=True), \
                mock.patch.object(
                    loom_operation_supervisor.signal, "SIGKILL", 9,
                    create=True), \
                mock.patch.object(
                    loom_operation_supervisor.time, "monotonic",
                    side_effect=[0.0, 0.0, 0.1]), \
                mock.patch.object(
                    loom_operation_supervisor.time, "sleep"), \
                mock.patch.object(
                    loom_operation_supervisor, "_posix_group_live_state",
                    side_effect=[None, False]):
            survivors_zero, secondary = loom_operation_supervisor._terminate(
                process, None)

        self.assertTrue(survivors_zero)
        self.assertEqual([], secondary)

    def test_posix_cleanup_fails_closed_if_census_stays_uncertain(self):
        process = mock.Mock(pid=4242)
        process.wait.return_value = 0
        with mock.patch.object(
                loom_operation_supervisor.os, "name", "posix"), \
                mock.patch.object(
                    loom_operation_supervisor.os, "killpg", create=True), \
                mock.patch.object(
                    loom_operation_supervisor.signal, "SIGKILL", 9,
                    create=True), \
                mock.patch.object(
                    loom_operation_supervisor.time, "monotonic",
                    side_effect=[0.0, 0.0, 6.0]), \
                mock.patch.object(
                    loom_operation_supervisor.time, "sleep"), \
                mock.patch.object(
                    loom_operation_supervisor, "_posix_group_live_state",
                    return_value=None):
            survivors_zero, secondary = loom_operation_supervisor._terminate(
                process, None)

        self.assertFalse(survivors_zero)
        self.assertEqual(["process-group-census:unavailable"], secondary)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object release contract")
    def test_windows_timeout_releases_cwd_before_returning_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            for index in range(12):
                operation_root = parent / f"operation-{index}"
                operation_root.mkdir()
                receipt = loom_operation_supervisor.run(
                    operation_class="timeout-fixture",
                    command=[
                        sys.executable, "-c",
                        "import subprocess,sys,time;"
                        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                        "time.sleep(60)",
                    ],
                    cwd=operation_root, timeout=0.2,
                    allowed_roots=[operation_root])
                self.assertTrue(receipt["survivors_confirmed_zero"])
                operation_root.rmdir()

    def test_cancellation_is_distinct_and_reconciles_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipt = loom_operation_supervisor.run(
                operation_class="cancellation-fixture",
                command=[sys.executable, "-c", "import time;time.sleep(60)"],
                cwd=root, timeout=10, allowed_roots=[root],
                cancel_requested=lambda: True)
            self.assertEqual("failed", receipt["status"])
            self.assertEqual("cancelled", receipt["primary_failure"])
            self.assertTrue(receipt["survivors_confirmed_zero"])

    def test_cwd_outside_allowed_root_fails_before_process_start(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            with self.assertRaises(loom_operation_supervisor.SupervisorError):
                loom_operation_supervisor.run(
                    operation_class="verification",
                    command=[sys.executable, "-c", "pass"],
                    cwd=Path(first).resolve(), timeout=5,
                    allowed_roots=[Path(second).resolve()])


if __name__ == "__main__":
    unittest.main()
