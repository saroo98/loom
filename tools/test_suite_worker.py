"""Isolated release-suite worker execution contracts."""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_release_subject
import loom_release
import loom_suite_plan
import loom_suite_worker
import loom_lint


ENVIRONMENT = {
    "requested_label": "local",
    "image_os": "windows" if os.name == "nt" else "posix",
    "image_version": "fixture",
    "os": os.name,
    "os_release": "fixture", "os_version": "fixture",
    "architecture": "fixture-arch",
    "python_implementation": "CPython",
    "python_version": __import__("platform").python_version(),
    "workflow_path": ".github/workflows/quality.yml",
    "workflow_digest": "a" * 64, "action_manifest_digest": "b" * 64,
    "event_name": "push", "run_id": "1", "run_attempt": "1",
}


class SuiteWorkerTests(unittest.TestCase):
    def fixture(self, root, source):
        cut = root / "cut"
        tools = cut / "tools"
        tools.mkdir(parents=True)
        source_tools = Path(loom_suite_worker.__file__).resolve().parent
        (tools / "loom_suite_worker.py").write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(source_tools)!r})\n"
            "import loom_suite_worker as implementation\n"
            "raise SystemExit(implementation.main())\n",
            encoding="utf-8")
        (tools / "test_worker_fixture.py").write_text(source, encoding="utf-8")
        files = []
        for item in sorted(tools.iterdir(), key=lambda path: path.name):
            raw = item.read_bytes()
            files.append({
                "path": f"tools/{item.name}", "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        body = {"schema_version": 1, "files": files}
        manifest = {**body, "root_sha256": loom_release._canonical_hash(body)}
        manifest_path = cut / loom_release.MANIFEST
        manifest_path.write_text(
            __import__("json").dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        public_root = manifest["root_sha256"]
        subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": "1" * 40,
            "source_tree_sha256": "2" * 64,
            "public_root_sha256": public_root,
            "public_manifest_sha256": hashlib.sha256(
                manifest_path.read_bytes()).hexdigest(),
            "public_file_count": len(files) + 1,
        }
        harness = hashlib.sha256(
            (tools / "loom_suite_worker.py").read_bytes()).hexdigest()
        inventory = loom_suite_plan.inventory(
            tools, subject=subject, environment=ENVIRONMENT,
            harness_sha256=harness)
        profile = loom_suite_plan.seal_timing_profile({
            "schema_version": 1, "default_p75_microseconds": 100,
            "module_microseconds": {},
        })
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": [],
        })
        plan = loom_suite_plan.plan(
            inventory, timing_profile=profile, policy=policy,
            logical_cpus=2)
        output = root / "workers"
        output.mkdir()
        return cut, inventory, plan, output

    def test_worker_runs_real_tests_in_an_isolated_copy_and_drops_secrets(self):
        source = (
            "import os,sys,unittest\n"
            "from pathlib import Path\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_isolated(self):\n"
            "        keys=('HOME','USERPROFILE','APPDATA','LOCALAPPDATA','CODEX_HOME',"
            "'TMP','TEMP','TMPDIR','XDG_CACHE_HOME','XDG_CONFIG_HOME',"
            "'XDG_DATA_HOME','XDG_STATE_HOME','LOOM_TEST_CACHE_ROOT','CARGO_HOME',"
            "'CARGO_TARGET_DIR')\n"
            "        self.assertTrue(all(os.environ.get(key) for key in keys))\n"
            "        self.assertNotIn('LOOM_TEST_API_KEY', os.environ)\n"
            "        self.assertEqual('candidate', Path(__file__).resolve().parents[1].name)\n"
            "        self.assertEqual('candidate', Path(sys.argv[0]).resolve().parents[1].name)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            old = os.environ.get("LOOM_TEST_API_KEY")
            os.environ["LOOM_TEST_API_KEY"] = "must-not-cross-boundary"
            try:
                receipt = loom_suite_worker.execute_shard(
                    cut, inventory, plan, "general-000", output,
                    timeout=10)
            finally:
                if old is None:
                    os.environ.pop("LOOM_TEST_API_KEY", None)
                else:
                    os.environ["LOOM_TEST_API_KEY"] = old
            self.assertFalse((output / "general-000" / "home").exists())
            self.assertFalse((output / "general-000" / "temp").exists())
        self.assertEqual("passed", receipt["status"])
        self.assertEqual(1, receipt["test_count"])
        self.assertTrue(receipt["mutation_clean"])
        self.assertTrue(receipt["privacy_clean"])
        self.assertTrue(receipt["runtime_roots_clean"])
        self.assertTrue(receipt["operation"]["survivors_confirmed_zero"])
        self.assertEqual(
            inventory["subject"]["public_manifest_sha256"],
            receipt["subject"]["public_manifest_sha256"])
        self.assertNotIn("C:\\", str(receipt))
        self.assertNotIn("/home/", str(receipt))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "worker-receipt", receipt,
            "suite-worker-receipt-v1.schema.json")
        self.assertEqual([], report.errors)

    def test_worker_fails_closed_when_the_candidate_copy_changes(self):
        source = (
            "import unittest\n"
            "from pathlib import Path\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_mutates(self):\n"
            "        (Path(__file__).parent/'mutation.txt').write_text('changed')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
        self.assertEqual("failed", receipt["status"])
        self.assertEqual("CANDIDATE_MUTATION", receipt["primary_reason"])
        self.assertFalse(receipt["mutation_clean"])

    def test_platform_skip_is_terminal_worker_evidence(self):
        source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    @unittest.skip('fixture platform boundary')\n"
            "    def test_skipped(self): pass\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
        self.assertEqual("passed", receipt["status"])
        self.assertEqual(1, receipt["skip_count"])
        self.assertEqual(
            "platform-boundary",
            receipt["observed_tests"][0]["skip_reason_code"])
        self.assertEqual("passed", receipt["operation"]["status"])

    def test_unclassified_skip_fails_closed_with_a_terminal_receipt(self):
        source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    @unittest.skip('because the fixture said so')\n"
            "    def test_skipped(self): pass\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
        self.assertEqual("failed", receipt["status"])
        self.assertEqual("UNAUTHORIZED_SKIP", receipt["primary_reason"])
        self.assertEqual(
            "unclassified", receipt["observed_tests"][0]["skip_reason_code"])
        subtest_source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_subtest_failure(self):\n"
            "        with self.subTest(case='fixture'): self.fail('fixture')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, subtest_source)
            failed = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
        self.assertEqual("failed", failed["status"])
        self.assertEqual("TEST_FAILURE", failed["primary_reason"])
        self.assertEqual(1, failed["failure_count"])
        self.assertTrue(failed["operation"]["survivors_confirmed_zero"])

    def test_worker_timeout_is_terminal_and_confirms_no_survivors(self):
        source = (
            "import time,unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_waits(self): time.sleep(60)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=0.2)
        self.assertEqual("failed", receipt["status"])
        self.assertEqual("WORKER_NOT_TERMINAL", receipt["primary_reason"])
        self.assertEqual("timed-out", receipt["operation"]["primary_failure"])
        self.assertTrue(receipt["operation"]["survivors_confirmed_zero"])

    @unittest.skipUnless(os.name == "nt", "Windows runtime-root contract")
    def test_windows_external_runtime_root_is_cleaned_if_supervisor_raises(self):
        source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_ok(self): pass\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            external = root / "short-runtime"

            def make_runtime_root(**_kwargs):
                external.mkdir()
                return str(external)

            with mock.patch.object(
                    loom_suite_worker.tempfile, "mkdtemp",
                    side_effect=make_runtime_root), mock.patch.object(
                        loom_suite_worker.loom_operation_supervisor, "run",
                        side_effect=RuntimeError("supervisor unavailable")):
                with self.assertRaisesRegex(RuntimeError, "supervisor unavailable"):
                    loom_suite_worker.execute_shard(
                        cut, inventory, plan, "general-000", output, timeout=10)
            self.assertFalse(external.exists())

    def test_run_plan_counts_exclusive_lane_inside_parallel_budget(self):
        plan = {
            "max_parallel_workers": 4,
            "shards": [
                {"shard_id": "exclusive", "exclusive": True},
                {"shard_id": "general-000", "exclusive": False},
                {"shard_id": "general-001", "exclusive": False},
            ],
        }
        order = []
        release = __import__("threading").Event()

        def execute(_cut, _inventory, _plan, shard_id, _root, **_kwargs):
            if shard_id == "exclusive" and _plan["max_parallel_workers"] > 2:
                release.wait(timeout=1)
            else:
                release.set()
            order.append(shard_id)
            return {"shard_id": shard_id}

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                loom_suite_worker, "execute_shard", side_effect=execute):
            receipts = loom_suite_worker.run_plan(
                Path(temporary) / "cut", {}, plan, Path(temporary), timeout=1)
        self.assertNotEqual("exclusive", order[0])
        self.assertEqual(
            ["exclusive", "general-000", "general-001"],
            [row["shard_id"] for row in receipts])
        constrained = {
            **plan, "max_parallel_workers": 2,
            "shards": plan["shards"][:2],
        }
        order.clear()
        release.clear()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                loom_suite_worker, "execute_shard", side_effect=execute):
            receipts = loom_suite_worker.run_plan(
                Path(temporary) / "cut", {}, constrained, Path(temporary),
                timeout=1)
        self.assertEqual(["exclusive", "general-000"], order)
        self.assertEqual(
            ["exclusive", "general-000"],
            [row["shard_id"] for row in receipts])


if __name__ == "__main__":
    unittest.main()
