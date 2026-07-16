"""Exact release-evidence and checksum generation tests."""

import tempfile
import unittest
from pathlib import Path

import loom_release_evidence


class ReleaseEvidenceTests(unittest.TestCase):
    def test_checksums_bind_plugin_sbom_and_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "loom-plugin-v1.2.0.zip"
            sbom = root / "loom-v1.2.0.spdx.json"
            helper = root / "loom-vault.exe"
            for path, raw in ((plugin, b"plugin"), (sbom, b"{}"), (helper, b"helper")):
                path.write_bytes(raw)
            output = root / "release"
            result = loom_release_evidence.create(
                output, repository="https://github.com/saroo98/loom",
                commit="a" * 40, version="1.2.0", release_sequence=3,
                source_tree_sha256="b" * 64, public_cut_sha256="c" * 64,
                plugin=plugin, sbom=sbom, helpers={"windows-x64": helper},
                test_matrix={"passed": 6}, capability_coverage={"status": "certified"},
                firewall={"clean": True}, signer_key_ids=["key-one-1", "key-two-2"])
            self.assertEqual("created", result["status"])
            lines = (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            self.assertEqual(3, len(lines))
            self.assertTrue(any("loom-plugin-v1.2.0.zip" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
