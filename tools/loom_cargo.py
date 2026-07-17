"""Strict, standard-library readers for Loom's Cargo metadata surfaces.

This is deliberately not a general TOML parser.  Loom only needs the package
version from Cargo.toml and package identities from Cargo.lock.  Keeping that
contract narrow preserves Python 3.10 support without adding an installation
dependency or accepting ambiguous TOML.
"""

import re
from pathlib import Path


class CargoMetadataError(ValueError):
    pass


_QUOTED = re.compile(r'^"([^"\\\r\n]*)"$')
_PACKAGE_FIELD = re.compile(r"^(name|version|checksum)\s*=\s*(.+?)\s*$")


def _quoted(value, label):
    match = _QUOTED.fullmatch(value)
    if not match:
        raise CargoMetadataError(f"{label} must be a plain quoted string")
    return match.group(1)


def package_version(path):
    """Read the exact package version from Cargo.toml's [package] section."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise CargoMetadataError(f"Cargo.toml cannot be read: {exc}") from exc
    in_package = False
    versions = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_package = line == "[package]"
            continue
        if in_package:
            match = re.fullmatch(r"version\s*=\s*(.+?)\s*", line)
            if match:
                versions.append(_quoted(match.group(1), "package version"))
    if len(versions) != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", versions[0]):
        raise CargoMetadataError("Cargo.toml must contain one stable package version")
    return versions[0]


def lock_packages(path):
    """Read package name, version, and optional checksum from Cargo.lock."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise CargoMetadataError(f"Cargo.lock cannot be read: {exc}") from exc
    packages = []
    current = None
    for raw in lines:
        line = raw.strip()
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
            continue
        if current is None or not line or line.startswith("#"):
            continue
        match = _PACKAGE_FIELD.fullmatch(line)
        if match:
            key, value = match.groups()
            if key in current:
                raise CargoMetadataError(f"Cargo.lock package repeats {key}")
            current[key] = _quoted(value, f"package {key}")
    if current is not None:
        packages.append(current)
    result = []
    for item in packages:
        if set(item) - {"name", "version", "checksum"} \
                or not isinstance(item.get("name"), str) \
                or not isinstance(item.get("version"), str) \
                or not re.fullmatch(r"[A-Za-z0-9_.+-]+", item["name"]) \
                or not re.fullmatch(r"[0-9A-Za-z_.+-]+", item["version"]):
            raise CargoMetadataError("Cargo.lock package identity is invalid")
        checksum = item.get("checksum")
        if checksum is not None and not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise CargoMetadataError("Cargo.lock package checksum is invalid")
        result.append((item["name"], item["version"], checksum))
    if not result:
        raise CargoMetadataError("Cargo.lock contains no packages")
    return result
