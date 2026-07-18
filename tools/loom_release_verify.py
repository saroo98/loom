#!/usr/bin/env python3
"""Independent standard-library verifier for Loom's canonical plugin ZIP."""

import argparse
import hashlib
import io
import json
import os
import stat
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath


FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
MAX_FILES = 4096
MAX_TOTAL_BYTES = 512 * 1024 * 1024
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
TOKEN_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")


class VerifyError(RuntimeError):
    pass


def _redirect(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise VerifyError(f"cannot inspect canonical plugin path: {path}: {exc}") from exc


def _safe_archive(path):
    try:
        path = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise VerifyError(f"canonical plugin ZIP path is invalid: {exc}") from exc
    for component in [*reversed(path.parents), path]:
        if _redirect(component):
            raise VerifyError("canonical plugin ZIP is missing or redirected")
    if not path.is_file():
        raise VerifyError("canonical plugin ZIP is missing or redirected")
    return path


def _name(value, seen):
    if not isinstance(value, str) or "\\" in value:
        raise VerifyError("archive entry path is ambiguous")
    path = PurePosixPath(value)
    parts = path.parts
    if path.is_absolute() or not parts or any(
            part in {"", ".", ".."} or part.endswith((" ", "."))
            or part.split(".", 1)[0].upper() in WINDOWS_RESERVED for part in parts):
        raise VerifyError("archive entry path is unsafe")
    canonical = unicodedata.normalize("NFC", value).casefold()
    if canonical in seen:
        raise VerifyError("archive contains duplicate, case-fold, or Unicode aliases")
    seen.add(canonical)
    return parts


def _forbidden_in_archive(raw, display_name, tokens, *, depth=0):
    if depth > 3:
        raise VerifyError("nested archive depth exceeds the release firewall bound")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise VerifyError("nested archive inventory exceeds its bound")
            seen = set()
            total = 0
            for entry in entries:
                _name(entry.filename, seen)
                if entry.is_dir() or entry.file_size < 0:
                    raise VerifyError("nested archive contains a non-regular entry")
                total += entry.file_size
                if total > MAX_TOTAL_BYTES:
                    raise VerifyError("nested archive expands beyond its bound")
                content = archive.read(entry)
                names = (display_name + "!" + entry.filename).casefold()
                for token in tokens:
                    forms = {token.encode(encoding) for encoding in TOKEN_ENCODINGS}
                    forms |= {item.lower() for item in forms}
                    if token.casefold() in names or any(
                            form in content or form in content.lower() for form in forms):
                        raise VerifyError(
                            "forbidden owner token is present in nested release bytes")
                if entry.filename.casefold().endswith(".zip"):
                    _forbidden_in_archive(
                        content, display_name + "!" + entry.filename, tokens, depth=depth + 1)
    except zipfile.BadZipFile as exc:
        raise VerifyError(f"nested release archive is invalid: {exc}") from exc


def verify(path, *, forbidden_tokens=()):
    path = _safe_archive(path)
    total = 0
    observed = {}
    seen = set()
    with tempfile.TemporaryDirectory(prefix="loom-release-verify-") as temporary:
        root = Path(temporary)
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if not 1 <= len(entries) <= MAX_FILES:
                    raise VerifyError("archive inventory is empty or oversized")
                for entry in entries:
                    parts = _name(entry.filename, seen)
                    mode = (entry.external_attr >> 16) & 0o170000
                    if entry.is_dir() or mode not in {0, stat.S_IFREG} \
                            or entry.date_time != FIXED_ZIP_TIME or entry.file_size < 0:
                        raise VerifyError("archive entry is not a canonical regular file")
                    total += entry.file_size
                    if total > MAX_TOTAL_BYTES:
                        raise VerifyError("archive expands beyond its bound")
                    raw = archive.read(entry)
                    if len(raw) != entry.file_size:
                        raise VerifyError("archive entry size changed while reading")
                    relative = "/".join(parts)
                    observed[relative] = {
                        "path": relative, "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                    destination = root.joinpath(*parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(raw)
                if [item.filename for item in entries] != sorted(
                        item.filename for item in entries):
                    raise VerifyError("archive inventory order is not canonical")
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            if isinstance(exc, VerifyError):
                raise
            raise VerifyError(f"canonical plugin ZIP is invalid: {exc}") from exc

        try:
            receipt = json.loads((root / "FINAL-PACKAGE-RECEIPT.json").read_text(
                encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise VerifyError(f"final package receipt is invalid: {exc}") from exc
        if not isinstance(receipt, dict) or set(receipt) != {
                "schema_version", "version", "release_sequence", "files"} \
                or receipt["schema_version"] != 1 or not isinstance(receipt["files"], list):
            raise VerifyError("final package receipt contract is invalid")
        expected = {item.get("path"): item for item in receipt["files"]
                    if isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}}
        receipted_observed = dict(observed)
        receipted_observed.pop("FINAL-PACKAGE-RECEIPT.json", None)
        if len(expected) != len(receipt["files"]) or expected != receipted_observed:
            raise VerifyError("archive bytes do not exactly match the final package receipt")
        if "release/metadata.json" not in expected or "release/trusted-root.json" not in expected \
                or "release/unsigned-manifest.json" in expected:
            raise VerifyError("archive is unsigned, incomplete, or contains draft metadata")
        tokens = [item for item in forbidden_tokens if item]
        folded_tokens = [item.casefold().encode("utf-8") for item in tokens]
        for name, item in observed.items():
            raw = root.joinpath(*PurePosixPath(name).parts).read_bytes()
            haystacks = (name.casefold().encode("utf-8"), raw.lower())
            if any(token in haystack for token in folded_tokens for haystack in haystacks):
                raise VerifyError("forbidden owner token is present in canonical release bytes")
            if name.casefold().endswith(".zip"):
                _forbidden_in_archive(raw, name, tokens)
    return {
        "status": "verified", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size, "files": len(observed),
        "version": receipt["version"], "release_sequence": receipt["release_sequence"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--forbid", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        result = verify(args.archive, forbidden_tokens=args.forbid)
    except VerifyError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
