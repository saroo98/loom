"""Closed transitive dependency manifest for repeated qualification."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

import loom_qualification_manifest


class QualificationManifestTests(unittest.TestCase):
    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def fixture(self, root):
        sha = "1" * 40
        self.write(root, "tools/mechanism.py", """
import helper
import subprocess
import sys

subprocess.run([sys.executable, "-B", "tools/child.py"], check=False)
""")
        self.write(root, "tools/helper.py", "VALUE = 1\n")
        self.write(root, "tools/child.py", "VALUE = 2\n")
        self.write(root, "contracts/policy.json", "{\"schema_version\":1}\n")
        self.write(root, "schemas/a.schema.json", json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "b.schema.json",
        }))
        self.write(root, "schemas/b.schema.json", json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
        }))
        self.write(root, ".github/workflows/main.yml", f"""
name: qualification
on: workflow_dispatch
jobs:
  run:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{sha}
      - uses: ./.github/workflows/reusable.yml
      - run: python -B tools/child.py
""")
        self.write(root, ".github/workflows/reusable.yml", """
name: reusable
on:
  workflow_call:
jobs:
  noop:
    runs-on: ubuntu-24.04
    steps:
      - run: python -B tools/helper.py
""")
        boundary = loom_qualification_manifest.seal_boundary({
            "schema_version": 2,
            "python_entrypoints": ["tools/mechanism.py"],
            "workflow_entrypoints": [".github/workflows/main.yml"],
            "roles": [
                {"path": ".github/workflows/main.yml",
                 "role": "mechanism-repeat"},
                {"path": ".github/workflows/reusable.yml",
                 "role": "mechanism-repeat"},
                {"path": "contracts/policy.json", "role": "shared-interface"},
                {"path": "schemas/a.schema.json", "role": "shared-interface"},
                {"path": "schemas/b.schema.json", "role": "shared-interface"},
                {"path": "tools/child.py", "role": "mechanism-repeat"},
                {"path": "tools/helper.py", "role": "mechanism-repeat"},
                {"path": "tools/mechanism.py", "role": "mechanism-repeat"},
            ],
            "declared_data_edges": [
                {"source": "tools/mechanism.py",
                 "target": "contracts/policy.json",
                 "kind": "declared-data"},
                {"source": "tools/mechanism.py",
                 "target": "schemas/a.schema.json",
                 "kind": "declared-data"},
            ],
            "data_sets": [],
            "runtime_process_sources": [],
        })
        return boundary

    def test_derives_literal_transitive_graph_and_explains_dependency_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boundary = self.fixture(root)
            first = loom_qualification_manifest.derive(root, boundary)
            second = loom_qualification_manifest.derive(root, boundary)

            self.assertEqual(first, second)
            self.assertEqual(first, loom_qualification_manifest.verify(
                root, boundary, first))
            nodes = {row["path"]: row for row in first["nodes"]}
            self.assertEqual({
                ".github/workflows/main.yml",
                ".github/workflows/reusable.yml",
                "contracts/policy.json",
                "schemas/a.schema.json",
                "schemas/b.schema.json",
                "tools/child.py", "tools/helper.py", "tools/mechanism.py",
            }, set(nodes))
            self.assertIn(
                {"kind": "python-import", "target": "tools/helper.py"},
                nodes["tools/mechanism.py"]["dependencies"])
            self.assertIn(
                {"kind": "process-invocation", "target": "tools/child.py"},
                nodes["tools/mechanism.py"]["dependencies"])
            self.assertIn(
                {"kind": "schema-ref", "target": "schemas/b.schema.json"},
                nodes["schemas/a.schema.json"]["dependencies"])
            self.assertIn({
                "kind": "external-action",
                "target": "actions/checkout@" + "1" * 40,
            }, nodes[".github/workflows/main.yml"]["dependencies"])
            chain = loom_qualification_manifest.explain(
                first, "schemas/b.schema.json")
            self.assertEqual("tools/mechanism.py", chain[0])
            self.assertEqual("schemas/b.schema.json", chain[-1])

    def test_rejects_dynamic_import_laundering_floating_action_and_stale_graph(self):
        cases = {
            "dynamic-import": lambda root, boundary: self.write(
                root, "tools/mechanism.py",
                "import importlib\nname='helper'\nimportlib.import_module(name)\n"),
            "candidate-import": lambda root, boundary: next(
                row.update(role="candidate-exact") for row in boundary["roles"]
                if row["path"] == "tools/helper.py"),
            "floating-action": lambda root, boundary: self.write(
                root, ".github/workflows/main.yml", """
name: qualification
on: workflow_dispatch
jobs:
  run:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
"""),
            "unclassified": lambda root, boundary: boundary["roles"].remove(
                next(row for row in boundary["roles"]
                     if row["path"] == "tools/child.py")),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                boundary = self.fixture(root)
                mutate(root, boundary)
                boundary.pop("boundary_sha256", None)
                boundary = loom_qualification_manifest.seal_boundary(boundary)
                with self.assertRaises(
                        loom_qualification_manifest.ManifestError):
                    loom_qualification_manifest.derive(root, boundary)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boundary = self.fixture(root)
            manifest = loom_qualification_manifest.derive(root, boundary)
            self.write(root, "tools/helper.py", "VALUE = 3\n")
            with self.assertRaises(loom_qualification_manifest.ManifestError):
                loom_qualification_manifest.verify(root, boundary, manifest)

    def test_rejects_unknown_fields_duplicate_roles_path_escape_and_redirects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boundary = self.fixture(root)
            duplicate = copy.deepcopy(boundary)
            duplicate["roles"].append(copy.deepcopy(duplicate["roles"][0]))
            duplicate.pop("boundary_sha256")
            with self.assertRaises(loom_qualification_manifest.ManifestError):
                loom_qualification_manifest.seal_boundary(duplicate)

            escaped = copy.deepcopy(boundary)
            escaped["python_entrypoints"] = ["../outside.py"]
            escaped.pop("boundary_sha256")
            with self.assertRaises(loom_qualification_manifest.ManifestError):
                loom_qualification_manifest.seal_boundary(escaped)

            unknown = copy.deepcopy(boundary)
            unknown["private"] = "field"
            with self.assertRaises(loom_qualification_manifest.ManifestError):
                loom_qualification_manifest.derive(root, unknown)

            target = root / "tools" / "helper.py"
            target.unlink()
            try:
                target.symlink_to(root / "tools" / "child.py")
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(loom_qualification_manifest.ManifestError):
                loom_qualification_manifest.derive(root, boundary)

    def test_checked_in_manifest_is_current_and_excludes_product_implementation(self):
        root = Path(__file__).resolve().parents[1]
        boundary = json.loads((
            root / "contracts" / "release-qualification-boundary-v2.json"
        ).read_text(encoding="utf-8"))
        manifest = json.loads((
            root / "contracts" / "release-qualification-manifest-v2.json"
        ).read_text(encoding="utf-8"))

        self.assertEqual(
            manifest,
            loom_qualification_manifest.verify(root, boundary, manifest))
        paths = {row["path"] for row in manifest["nodes"]}
        self.assertTrue({
            "tools/loom_suite_harness.py",
            "tools/loom_suite_plan.py",
            "tools/loom_suite_worker.py",
            "tools/loom_suite_certificate_core.py",
            "tools/loom_operation_supervisor.py",
            "tools/loom_release_authority.py",
            "schemas/release-authority-v2.schema.json",
            "schemas/release-candidate-suite-v2.schema.json",
        }.issubset(paths))
        self.assertTrue({
            "tools/loom_memory.py", "tools/loom_owner.py",
            "tools/loom_orchestrator.py", "tools/loom_runtime.py",
            "tools/loom_update.py", "tools/loom_vault.py",
            "tools/loom_release.py", "tools/loom_release_suite.py",
        }.isdisjoint(paths))
        self.assertEqual(
            "tools/loom_qualification_manifest.py",
            loom_qualification_manifest.explain(
                manifest,
                "contracts/release-qualification-boundary-v2.json")[0])


if __name__ == "__main__":
    unittest.main()
