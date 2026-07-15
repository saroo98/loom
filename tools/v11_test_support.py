"""Shared external build cache for the exact Loom vault-helper test source."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


def build_vault_helper(root):
    root = Path(root).resolve()
    crate = root / "vault-helper"
    source_files = [crate / "Cargo.toml", crate / "Cargo.lock", *sorted(
        (crate / "src").rglob("*.rs"))]
    if any(not path.is_file() for path in source_files):
        raise RuntimeError("vault-helper test source is incomplete")
    rustc = subprocess.run(
        ["rustc", "--version", "--verbose"], capture_output=True, text=True,
        timeout=15, check=True).stdout.encode("utf-8")
    digest = hashlib.sha256(rustc)
    for path in source_files:
        relative = path.relative_to(crate).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big") + relative)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    source_key = digest.hexdigest()
    target = Path(tempfile.gettempdir()) / "loom-cargo-test-cache" / source_key
    binary = target / "debug" / ("loom-vault.exe" if os.name == "nt" else "loom-vault")
    receipt = target / "loom-test-helper-receipt.json"
    valid = False
    if binary.is_file() and receipt.is_file():
        try:
            value = json.loads(receipt.read_text(encoding="utf-8"))
            valid = value == {
                "source_key": source_key,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
        except (OSError, UnicodeError, json.JSONDecodeError):
            valid = False
    if not valid:
        binary.unlink(missing_ok=True)
        subprocess.run(
            ["cargo", "build", "--quiet", "--locked", "--manifest-path",
             str(crate / "Cargo.toml")], cwd=root,
            env={**os.environ, "CARGO_TARGET_DIR": str(target)},
            check=True, timeout=180)
        if not binary.is_file():
            raise RuntimeError("vault-helper build produced no executable")
        target.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({
            "source_key": source_key,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return binary
