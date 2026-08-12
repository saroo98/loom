"""Fixed general-lane isolated writable-root workload."""

from pathlib import Path
import tempfile
import unittest


class QualificationGeneralBTests(unittest.TestCase):
    def test_disposable_writable_root(self):
        with tempfile.TemporaryDirectory(prefix="loom-qual-workload-") as temporary:
            path = Path(temporary) / "value.txt"
            path.write_bytes(b"bounded\n")
            self.assertEqual(b"bounded\n", path.read_bytes())
