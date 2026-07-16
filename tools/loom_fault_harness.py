#!/usr/bin/env python3
"""Subprocess crash probes for Loom's durable atomic-write boundary."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class FaultError(RuntimeError):
    pass


def atomic_pointer_probe(root):
    root = Path(root).resolve()
    tools = root / "tools"
    with tempfile.TemporaryDirectory(prefix="loom-fault-") as temporary:
        target = Path(temporary) / "pointer.json"
        target.write_text('{"generation":"old"}\n', encoding="utf-8")
        script = (
            "import os,sys; from pathlib import Path; import loom_reliability; "
            "target=Path(sys.argv[1]); original=os.replace; "
            "os.replace=lambda a,b: os._exit(91); "
            "loom_reliability.atomic_write_json(target, {'generation':'new'})")
        crashed = subprocess.run(
            [sys.executable, "-B", "-c", script, str(target)], cwd=tools,
            capture_output=True, timeout=10, check=False)
        if crashed.returncode != 91 \
                or json.loads(target.read_text(encoding="utf-8"))["generation"] != "old":
            raise FaultError("pre-replace process death damaged the old pointer")
        completed = subprocess.run(
            [sys.executable, "-B", "-c",
             "import os,sys; from pathlib import Path; import loom_reliability; "
             "loom_reliability.atomic_write_json(Path(sys.argv[1]), {'generation':'new'}); "
             "os._exit(92)", str(target)], cwd=tools,
            capture_output=True, timeout=10, check=False)
        if completed.returncode != 92 \
                or json.loads(target.read_text(encoding="utf-8"))["generation"] != "new":
            raise FaultError("post-replace process death did not preserve the new pointer")
    return {"status": "passed", "boundaries": ["before-replace", "after-replace"],
            "process_exit_codes": [91, 92]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        result = atomic_pointer_probe(Path(__file__).resolve().parents[1])
    except (FaultError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
