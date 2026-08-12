"""Isolated release-suite worker execution contracts."""

import hashlib
import json
import os
import shutil
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
    def test_worker_import_boundary_excludes_broad_product_modules(self):
        source = Path(loom_suite_worker.__file__).read_text(encoding="utf-8")
        tree = __import__("ast").parse(source)
        imports = {
            alias.name
            for node in __import__("ast").walk(tree)
            if isinstance(node, __import__("ast").Import)
            for alias in node.names
        }
        self.assertTrue({
            "loom_lifecycle", "loom_memory", "loom_owner",
            "loom_orchestrator", "loom_release", "loom_release_subject",
            "loom_runtime", "loom_test", "loom_update", "loom_vault",
            "v11_test_support",
        }.isdisjoint(imports))

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
        # This fixture is already executing inside a supervised release worker.
        # Discover its synthetic one-module suite directly so worker tests do not
        # create a nested supervisor whose transient host failure can obscure the
        # behavior the test is meant to exercise. Supervised inventory has its
        # own integration coverage in test_suite_plan.py.
        inventory = loom_suite_plan._discover_inventory(
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

    def test_worker_fixture_does_not_nest_supervised_inventory(self):
        source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_passes(self): pass\n"
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                loom_suite_plan, "inventory",
                side_effect=AssertionError("nested inventory is forbidden")):
            _, inventory, plan, _ = self.fixture(
                Path(temporary).resolve(), source)

        self.assertEqual(1, inventory["test_count"])
        self.assertEqual(
            1, sum(len(shard["modules"]) for shard in plan["shards"]))

    def assert_setup_failure_worker(self, source, expected_test,
                                    private_message):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
            diagnostic_path = (
                output / "general-000" / "failure-diagnostic.json")
            self.assertTrue(diagnostic_path.is_file())
            diagnostic = json.loads(
                diagnostic_path.read_text(encoding="utf-8"))

        self.assertEqual(1, receipt["error_count"])
        self.assertEqual(0, receipt["failure_count"])
        self.assertEqual([{
            "test": expected_test, "status": "error",
        }], receipt["observed_tests"])
        self.assertIn("INVENTORY_MISMATCH", receipt["findings"])
        self.assertIn("TEST_FAILURE", receipt["findings"])
        self.assertEqual([{
            "test": expected_test, "status": "error",
            "exception_type": "RuntimeError",
        }], diagnostic["failures"])
        loom_suite_worker.validate_failure_diagnostic(diagnostic, receipt)
        public = json.dumps({"receipt": receipt, "diagnostic": diagnostic},
                            sort_keys=True)
        self.assertNotIn(private_message, public)
        self.assertNotIn(hashlib.sha256(private_message.encode()).hexdigest(),
                         public)
        self.assertNotIn("setUpClass (", public)
        self.assertNotIn("setUpModule (", public)

    def test_class_setup_error_emits_bound_failure_diagnostic(self):
        self.assert_setup_failure_worker(
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls):\n"
            "        raise RuntimeError('private class setup')\n"
            "    def test_never_runs(self): pass\n",
            "fixture.class.test_worker_fixture.WorkerFixture",
            "private class setup")

    def test_module_setup_error_emits_bound_failure_diagnostic(self):
        self.assert_setup_failure_worker(
            "import unittest\n"
            "def setUpModule():\n"
            "    raise RuntimeError('private module setup')\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_never_runs(self): pass\n",
            "fixture.module.test_worker_fixture", "private module setup")

    def test_worker_runs_real_tests_in_an_isolated_copy_and_drops_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "temp-base"
            base.mkdir()
            real_mkdtemp = tempfile.mkdtemp

            def create(*, prefix, dir):
                self.assertEqual(base.resolve(), Path(dir))
                return real_mkdtemp(prefix=prefix, dir=dir)

            with mock.patch.object(
                    loom_suite_worker.tempfile, "gettempdir",
                    return_value=str(base)), mock.patch.object(
                    loom_suite_worker.tempfile, "mkdtemp", side_effect=create):
                environment, runtime_root = \
                    loom_suite_worker._isolated_environment(
                        Path(temporary) / "worker", "general-000")
            try:
                self.assertEqual(runtime_root, runtime_root.resolve())
                self.assertTrue(all(Path(value).is_absolute()
                                    for value in environment.values()
                                    if value != "general-000"))
            finally:
                shutil.rmtree(runtime_root)

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

    def test_failed_worker_writes_a_closed_privacy_safe_diagnostic_sidecar(self):
        source = (
            "import os,unittest\n"
            "class HostFailure(AssertionError):\n"
            "    code = 'HOST_UNVERIFIED'\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_failed(self):\n"
            "        print('private stdout')\n"
            "        raise HostFailure('private message secret-value')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
            worker_root = output / "general-000"
            diagnostic_path = worker_root / "failure-diagnostic.json"
            self.assertTrue((worker_root / "worker-receipt.json").is_file())
            self.assertTrue(diagnostic_path.is_file())
            diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))

        test_id = "test_worker_fixture.WorkerFixture.test_failed"
        self.assertEqual(receipt["worker_receipt_sha256"],
                         diagnostic["worker_receipt_sha256"])
        self.assertEqual("general-000", diagnostic["shard_id"])
        self.assertEqual([{
            "error_code": "HOST_UNVERIFIED",
            "exception_type": "HostFailure",
            "status": "failed", "test": test_id,
        }], diagnostic["failures"])
        loom_suite_worker.validate_failure_diagnostic(diagnostic, receipt)
        serialized = json.dumps(diagnostic, sort_keys=True)
        for private in (
                "private message", "private stdout", "secret-value",
                str(root), str(Path.home()), "traceback", "stdout", "stderr"):
            self.assertNotIn(private, serialized)
        self.assertNotIn(
            hashlib.sha256(b"private message secret-value").hexdigest(),
            serialized)

        for field in diagnostic:
            tampered = dict(diagnostic)
            if field == "schema_version":
                tampered[field] = 2
            elif field == "failures":
                tampered[field] = [dict(diagnostic[field][0], status="error")]
            else:
                tampered[field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(
                    loom_suite_worker.SuiteWorkerError):
                loom_suite_worker.validate_failure_diagnostic(tampered, receipt)

    def test_passing_worker_does_not_write_a_failure_diagnostic(self):
        source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_ok(self): pass\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
            self.assertEqual("passed", receipt["status"])
            self.assertFalse(
                (output / "general-000" / "failure-diagnostic.json").exists())

    def test_secret_shaped_error_code_is_redacted_through_worker_sidecar(self):
        source = (
            "import unittest\n"
            "class SecretFailure(AssertionError):\n"
            "    code = 'AKIA' + 'ABCDEFGHIJKLMNOP'\n"
            "class UnhashableFailure(AssertionError):\n"
            "    code = []\n"
            "class OddCode(str):\n"
            "    __hash__ = None\n"
            "class HostileStringFailure(AssertionError):\n"
            "    code = OddCode('HOST_UNVERIFIED')\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_failed(self): raise SecretFailure('private')\n"
            "    def test_unhashable(self): raise UnhashableFailure('private')\n"
            "    def test_hostile_string(self): "
            "raise HostileStringFailure('private')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
            diagnostic = json.loads((
                output / "general-000" / "failure-diagnostic.json").read_text(
                    encoding="utf-8"))

        self.assertEqual("failed", receipt["status"])
        self.assertEqual(
            {"PUBLIC_ERROR_CODE_REDACTED"},
            {row["error_code"] for row in diagnostic["failures"]})
        self.assertEqual(3, len(diagnostic["failures"]))
        serialized = json.dumps(diagnostic, sort_keys=True)
        self.assertNotIn("AKIA" + "ABCDEFGHIJKLMNOP", serialized)
        self.assertTrue(loom_suite_worker._privacy_clean(diagnostic))
        loom_suite_worker.validate_failure_diagnostic(diagnostic, receipt)
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "failure-diagnostic", diagnostic,
            "suite-failure-diagnostic-v1.schema.json")
        self.assertEqual([], report.errors)

    def test_mixed_subtest_severity_seals_one_terminal_error_receipt(self):
        source = (
            "import unittest\n"
            "class WorkerFixture(unittest.TestCase):\n"
            "    def test_mixed(self):\n"
            "        with self.subTest(case='failed'):\n"
            "            self.fail('private failure')\n"
            "        with self.subTest(case='error'):\n"
            "            raise RuntimeError('private error')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cut, inventory, plan, output = self.fixture(root, source)
            receipt = loom_suite_worker.execute_shard(
                cut, inventory, plan, "general-000", output, timeout=10)
            worker_root = output / "general-000"
            diagnostic = json.loads((worker_root / "failure-diagnostic.json").read_text(
                encoding="utf-8"))
            self.assertTrue((worker_root / "worker-receipt.json").is_file())

        self.assertEqual("failed", receipt["status"])
        self.assertEqual("TEST_FAILURE", receipt["primary_reason"])
        self.assertEqual(0, receipt["failure_count"])
        self.assertEqual(1, receipt["error_count"])
        self.assertTrue(receipt["privacy_clean"])
        self.assertTrue(receipt["mutation_clean"])
        self.assertTrue(receipt["runtime_roots_clean"])
        self.assertTrue(receipt["operation"]["survivors_confirmed_zero"])
        self.assertEqual(1, len(diagnostic["failures"]))
        self.assertEqual("error", diagnostic["failures"][0]["status"])
        loom_suite_worker.validate_failure_diagnostic(diagnostic, receipt)

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

    def test_run_plan_uses_two_available_slots_for_exclusive_and_general(self):
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
            if shard_id == "exclusive" and _plan["max_parallel_workers"] > 1:
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
        self.assertNotEqual("exclusive", order[0])
        self.assertEqual(
            ["exclusive", "general-000"],
            [row["shard_id"] for row in receipts])


if __name__ == "__main__":
    unittest.main()
