import hashlib
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import jsonschema

import loom_plugin_package
import loom_release_candidate


class ReleaseCandidateTests(unittest.TestCase):
    @staticmethod
    def _native_subjects(package):
        return [{
            "platform": platform_id,
            "binary_sha256": hashlib.sha256((package / "crypto" / platform_id /
                                               binary_name).read_bytes()).hexdigest(),
            "sbom_sha256": hashlib.sha256(
                ("sbom:" + platform_id).encode("ascii")).hexdigest(),
            "provenance_sha256": hashlib.sha256(
                ("provenance:" + platform_id).encode("ascii")).hexdigest(),
        } for platform_id, binary_name in loom_release_candidate.NATIVE_PLATFORMS.items()]

    def _package(self, root):
        package = root / "plugin"
        (package / "release").mkdir(parents=True)
        signed_manifest = {"package": "loom", "version": "1.9.0",
                           "release_sequence": 19, "targets": []}
        (package / "release" / "metadata.json").write_text(json.dumps({
            "root": {"signed": {}},
            "targets": {"signed": {"manifest": signed_manifest}},
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        (package / "release" / "trusted-root.json").write_text("{}", encoding="utf-8")
        manifest_body = {
            "schema_version": 1,
            "files": [{"path": "skills/SKILL.md", "bytes": 7,
                       "sha256": hashlib.sha256(b"public\n").hexdigest()}],
        }
        manifest = {**manifest_body, "root_sha256": hashlib.sha256(json.dumps(
            manifest_body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()}
        (package / "BUILD-MANIFEST.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        (package / "skills").mkdir()
        (package / "skills" / "SKILL.md").write_bytes(b"public\n")
        for platform_id, binary_name in loom_release_candidate.NATIVE_PLATFORMS.items():
            binary = package / "crypto" / platform_id / binary_name
            binary.parent.mkdir(parents=True)
            binary.write_bytes(("native:" + platform_id).encode("ascii"))
            runtime = package / "runtime-payload" / platform_id / "loom-runtime.zip"
            runtime.parent.mkdir(parents=True)
            with zipfile.ZipFile(runtime, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(f"bin/{binary_name}", binary.read_bytes())
        files = []
        for path in sorted(item for item in package.rglob("*") if item.is_file()):
            raw = path.read_bytes()
            files.append({"path": path.relative_to(package).as_posix(),
                          "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        (package / "FINAL-PACKAGE-RECEIPT.json").write_text(json.dumps({
            "schema_version": 1, "version": "1.9.0", "release_sequence": 19,
            "files": files,
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return package

    def test_reconstruction_rebuilds_unsigned_bytes_and_reuses_only_authority_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self._package(root)
            authority = root / "authority.zip"
            loom_plugin_package.archive_finalized(package, authority)
            native_root = root / "native"
            for platform_id, binary_name in loom_release_candidate.NATIVE_PLATFORMS.items():
                directory = native_root / platform_id
                directory.mkdir(parents=True)
                environment = {
                    "evidence_class": "ci-reproduced",
                    "requested_label": "fixture", "image_os": "fixture",
                    "image_version": "fixture", "os": "fixture",
                    "os_release": "fixture", "os_version": "fixture",
                    "architecture": "fixture",
                    "python_implementation": "CPython",
                    "python_version": "3.11.1",
                    "workflow_path": ".github/workflows/build-helper.yml",
                    "workflow_digest": "a" * 64,
                    "action_manifest_digest": "b" * 64,
                    "event_name": "workflow_call", "run_id": "1",
                    "run_attempt": "1",
                }
                environment = {**environment, "environment_sha256": hashlib.sha256(
                    json.dumps(environment, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")).hexdigest()}
                (directory / "environment.json").write_text(
                    json.dumps(environment), encoding="utf-8")
                receipt = {
                    "schema_version": 2, "platform": platform_id,
                    "source_commit": "1" * 40,
                    "environment_sha256": environment["environment_sha256"],
                    "workflow_digest": environment["workflow_digest"],
                    "action_manifest_digest": environment[
                        "action_manifest_digest"],
                }
                receipt = {**receipt, "receipt_sha256": hashlib.sha256(json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False).encode("utf-8")).hexdigest()}
                (directory / "receipt.json").write_text(
                    json.dumps(receipt), encoding="utf-8")
                (directory / binary_name).write_bytes(b"fixture")
                (directory / (binary_name + ".rebuild")).write_bytes(b"fixture")
                (directory / "loom-vault.spdx.json").write_text("{}", encoding="utf-8")
                (directory / "provenance.json").write_text("{}", encoding="utf-8")
            source = root / "source"
            source.mkdir()
            signed_manifest = json.loads((package / "release" / "metadata.json").read_text(
                encoding="utf-8"))["targets"]["signed"]["manifest"]

            def build(_source, output, _helpers, _receipts, _evidence, **_kwargs):
                output.mkdir()
                for path in sorted(item for item in package.rglob("*") if item.is_file()):
                    relative = path.relative_to(package)
                    if relative.as_posix() in {
                            "release/metadata.json", "release/trusted-root.json",
                            "FINAL-PACKAGE-RECEIPT.json"}:
                        continue
                    target = output / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
                unsigned = output / "release" / "unsigned-manifest.json"
                unsigned.parent.mkdir(parents=True, exist_ok=True)
                unsigned.write_text(json.dumps(signed_manifest), encoding="utf-8")
                return {"manifest": signed_manifest}

            rebuilt = root / "rebuilt.zip"
            with mock.patch.object(
                    loom_release_candidate.loom_plugin_package, "build",
                    side_effect=build):
                result = loom_release_candidate.reconstruct(
                    source, authority, native_root, rebuilt,
                    source_commit="1" * 40)
            self.assertEqual(authority.read_bytes(), rebuilt.read_bytes())
            self.assertEqual(hashlib.sha256(authority.read_bytes()).hexdigest(),
                             result["sha256"])

    def test_independent_archives_compare_and_bind_embedded_public_cut(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self._package(root)
            first = root / "a.zip"
            second = root / "b.zip"
            loom_plugin_package.archive_finalized(package, first)
            loom_plugin_package.archive_finalized(package, second)
            expected = json.loads((package / "BUILD-MANIFEST.json").read_text(
                encoding="utf-8"))["root_sha256"]
            result = loom_release_candidate.compare(
                first, second, expected_public_root_sha256=expected,
                native_subjects=self._native_subjects(package))
            self.assertEqual("reproduced", result["status"])
            self.assertEqual(result["candidate_a"]["sha256"],
                             result["candidate_b"]["sha256"])
            self.assertEqual(expected, result["public_cut"]["root_sha256"])
            self.assertRegex(result["receipt_sha256"], r"^[0-9a-f]{64}$")
            schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" /
                                 "release-reproducibility-receipt-v1.schema.json").read_text(
                                     encoding="utf-8"))
            jsonschema.Draft202012Validator(schema).validate(result)

    def test_mismatched_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self._package(root)
            first = root / "a.zip"
            second = root / "b.zip"
            loom_plugin_package.archive_finalized(package, first)
            second.write_bytes(first.read_bytes() + b"mutation")
            with self.assertRaisesRegex(
                    loom_release_candidate.CandidateError, "candidate bytes"):
                loom_release_candidate.compare(
                    first, second, expected_public_root_sha256="a" * 64,
                    native_subjects=self._native_subjects(package))

    def test_immutable_staging_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "candidate.zip"
            source.write_bytes(b"same bytes")
            destination = root / "draft" / "loom.zip"
            first = loom_release_candidate.stage_immutable(source, destination)
            second = loom_release_candidate.stage_immutable(source, destination)
            self.assertEqual("created", first["disposition"])
            self.assertEqual("already-identical", second["disposition"])
            changed = root / "changed.zip"
            changed.write_bytes(b"different")
            with self.assertRaisesRegex(
                    loom_release_candidate.CandidateError, "already exists"):
                loom_release_candidate.stage_immutable(changed, destination)
            self.assertEqual(b"same bytes", destination.read_bytes())

    def test_public_json_inputs_reject_duplicate_keys_and_non_finite_numbers(self):
        for raw in (b'{"platform":"linux-x64","platform":"windows-x64"}',
                    b'{"value":NaN}'):
            with self.subTest(raw=raw):
                with self.assertRaises(loom_release_candidate.CandidateError):
                    loom_release_candidate._json_bytes(raw, "fixture")


if __name__ == "__main__":
    unittest.main()
