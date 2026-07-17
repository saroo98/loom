"""Python 3.10-safe Cargo metadata contract tests."""

import tempfile
import unittest
from pathlib import Path

import loom_cargo


class CargoMetadataTests(unittest.TestCase):
    def test_reads_only_the_package_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.toml"
            path.write_text('[package]\nname = "loom-vault"\nversion = "1.6.0"\n'
                            '[dependencies]\nversion = "9.9.9"\n', encoding="utf-8")
            self.assertEqual("1.6.0", loom_cargo.package_version(path))

    def test_reads_lock_package_identities_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.lock"
            path.write_text('version = 4\n\n[[package]]\nname = "alpha"\n'
                            'version = "1.2.3"\nchecksum = "' + "a" * 64 + '"\n'
                            'dependencies = [\n "beta",\n]\n\n[[package]]\n'
                            'name = "beta"\nversion = "2.0.0"\n', encoding="utf-8")
            self.assertEqual([("alpha", "1.2.3", "a" * 64),
                              ("beta", "2.0.0", None)],
                             loom_cargo.lock_packages(path))

    def test_rejects_ambiguous_or_invalid_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            manifest.write_text('[package]\nversion = "1.0.0"\nversion = "2.0.0"\n',
                                encoding="utf-8")
            with self.assertRaises(loom_cargo.CargoMetadataError):
                loom_cargo.package_version(manifest)
            lock = root / "Cargo.lock"
            lock.write_text('[[package]]\nname = "alpha"\nversion = "1.0.0"\n'
                            'checksum = "not-a-digest"\n', encoding="utf-8")
            with self.assertRaises(loom_cargo.CargoMetadataError):
                loom_cargo.lock_packages(lock)


if __name__ == "__main__":
    unittest.main()
