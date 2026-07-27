"""Adversarial tests for the private end-to-end execution chain."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

import loom_execution_chain


class ExecutionChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve() / ".loom"
        self.runtime = self.home / "runtime" / "versions" / "1.8.15"
        self.runtime.mkdir(parents=True)
        self.launcher = self.runtime / "loom_launcher.py"
        self.launcher.write_text("print('launcher')\n", encoding="utf-8")
        (self.runtime / "RUNTIME-MANIFEST.json").write_text(
            '{"version":"1.8.15"}\n', encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_chain_preserves_exact_utf8_request_identity_and_seals_bounded_projection(self):
        request = "Plan café.\r\nKeep 100% of ! & | < > ^ (spacing)."
        raw = request.encode("utf-8")
        chain = loom_execution_chain.create(
            self.home, launcher_path=self.launcher)
        loom_execution_chain.append(
            self.home, chain["chain_id"], "request",
            loom_execution_chain.request_identity(request))
        loom_execution_chain.append(
            self.home, chain["chain_id"], "host-adapter",
            {"host": "codex", "identity": None}, observability="unavailable")
        projection = loom_execution_chain.seal(self.home, chain["chain_id"])

        private = loom_execution_chain.read(self.home, chain["chain_id"])
        request_stage = next(
            item for item in private["stages"] if item["name"] == "request")
        self.assertEqual(len(raw), request_stage["payload"]["utf8_bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         request_stage["payload"]["sha256"])
        self.assertEqual(
            {"chain_id", "status", "stages", "chain_sha256"}, set(projection))
        self.assertNotIn(str(self.home), json.dumps(projection))

    def test_tampered_stage_and_prior_digest_fail_closed(self):
        chain = loom_execution_chain.create(
            self.home, launcher_path=self.launcher)
        path = Path(chain["path"])
        value = json.loads(path.read_text(encoding="utf-8"))
        value["stages"][0]["payload"]["bytes"] += 1
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_execution_chain.ExecutionChainError, "digest"):
            loom_execution_chain.read(self.home, chain["chain_id"])

    def test_loaded_loom_module_outside_runtime_is_refused(self):
        inside_path = self.runtime / "loom_inside.py"
        outside_path = self.home / "loom_shadow.py"
        inside_path.write_text("VALUE = 1\n", encoding="utf-8")
        outside_path.write_text("VALUE = 2\n", encoding="utf-8")
        inside = types.SimpleNamespace(__file__=str(inside_path))
        outside = types.SimpleNamespace(__file__=str(outside_path))
        observed = loom_execution_chain.verify_loaded_modules(
            self.runtime, modules={"loom_inside": inside})
        self.assertEqual(1, observed["module_count"])
        with self.assertRaisesRegex(
                loom_execution_chain.ExecutionChainError, "outside"):
            loom_execution_chain.verify_loaded_modules(
                self.runtime, modules={
                    "loom_inside": inside, "loom_shadow": outside})

    def test_isolated_process_ignores_pythonpath_user_site_and_startup(self):
        shadow = self.home / "shadow"
        shadow.mkdir(parents=True)
        (shadow / "loom_poison.py").write_text(
            "raise RuntimeError('loaded poison')\n", encoding="utf-8")
        startup = self.home / "startup.py"
        marker = self.home / "startup-ran"
        startup.write_text(
            f"open({str(marker)!r}, 'w').write('bad')\n", encoding="utf-8")
        script = self.runtime / "probe.py"
        script.write_text(
            "import json,sys\n"
            "print(json.dumps({'isolated':bool(sys.flags.isolated),"
            "'no_user_site':bool(sys.flags.no_user_site),"
            "'safe_path':bool(getattr(sys.flags,'safe_path',False))}))\n",
            encoding="utf-8")
        environment = dict(os.environ)
        environment.update({
            "PYTHONPATH": str(shadow),
            "PYTHONSTARTUP": str(startup),
            "PYTHONUSERBASE": str(shadow),
        })
        completed = subprocess.run(
            loom_execution_chain.isolated_python(script),
            env=environment, text=True, capture_output=True, check=True)
        flags = json.loads(completed.stdout)
        self.assertEqual(
            {"isolated": True, "no_user_site": True, "safe_path": True}, flags)
        self.assertFalse(marker.exists())

    def test_python310_isolated_flag_proves_safe_path_without_newer_flag(self):
        flags = types.SimpleNamespace(isolated=1)
        self.assertTrue(loom_execution_chain._safe_path_proven(flags))
        flags = types.SimpleNamespace(isolated=0)
        self.assertFalse(loom_execution_chain._safe_path_proven(flags))


if __name__ == "__main__":
    unittest.main()
