#!/usr/bin/env python3
"""Install, check, or safely remove Loom agent entry points.

The two platform launchers delegate here so ownership, hashing, refusal rules, and
rollback behavior have one implementation. Only intact files bearing this Loom
instance's marker may be replaced or removed. No directory is ever removed.
"""

import argparse
import hashlib
import os
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import loom_memory  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OWNER_RE = re.compile(
    r"(?s)<!-- loom-install-owner:([0-9a-f-]{36}) "
    r"body-sha256:([0-9a-f]{64}) -->\n?$")
LEGACY_RE = re.compile(
    r"(?m)^(?:name:\s*loom\s*$|# Loom\b|description:\s*Loom planning OS\b)")


class InstallError(RuntimeError):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Target:
    source: Path
    destination: Path
    label: str


@dataclass(frozen=True)
class Inspection:
    state: str
    normalized: str = ""
    original: bytes | None = None


def _normalize(text):
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _owner_id(home, root, may_create):
    marker = root / loom_memory.INSTANCE_MARKER
    if not marker.is_file():
        if not may_create:
            return None
        try:
            return loom_memory.initialize(home / ".loom", root)
        except (OSError, UnicodeError, loom_memory.MemoryError) as exc:
            raise InstallError(f"could not initialize Loom installation identity: {exc}") from exc
    try:
        value = marker.read_text(encoding="utf-8").strip()
        parsed = str(uuid.UUID(value))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InstallError("invalid .loom-instance-id; refusing installation mutation") from exc
    if parsed != value:
        raise InstallError("non-canonical .loom-instance-id; refusing installation mutation")
    return value


def _targets(root, home):
    skill = root / "skill" / "loom" / "SKILL.md"
    prompt = root / "skill" / "codex-prompt" / "loom.md"
    for source in (skill, prompt):
        if source.is_symlink() or not source.is_file():
            raise InstallError(f"not a safe Loom source (missing or symlinked): {source}")
        try:
            source.resolve().relative_to(root)
        except ValueError as exc:
            raise InstallError(f"installer source escapes Loom root: {source}") from exc
    return (
        Target(skill, home / ".claude" / "skills" / "loom" / "SKILL.md",
               "Claude Code skill"),
        Target(skill, home / ".codex" / "skills" / "loom" / "SKILL.md",
               "Codex skill"),
        Target(prompt, home / ".codex" / "prompts" / "loom.md", "Codex /loom prompt"),
    )


def _render(source, root, owner):
    try:
        body = _normalize(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise InstallError(f"cannot read installer source {source}: {exc}") from exc
    body = body.replace("{{LOOM_PATH}}", root.as_posix())
    if not body.endswith("\n"):
        body += "\n"
    marker = f"<!-- loom-install-owner:{owner} body-sha256:{_sha256(body)} -->\n"
    return (body + marker).encode("utf-8")


def _safe_destination(path, home):
    if path.is_symlink():
        raise InstallError(f"refusing symlink destination: {path}", 1)
    try:
        path.relative_to(home)
        path.parent.resolve(strict=False).relative_to(home)
    except ValueError as exc:
        raise InstallError(f"destination escapes the selected user home: {path}", 1) from exc
    current = path.parent
    while current != home:
        if current.exists() and (current.is_symlink() or not current.is_dir()):
            raise InstallError(f"unsafe destination parent: {current}", 1)
        current = current.parent


def _inspect(path, owner):
    if path.is_symlink():
        return Inspection("symlink")
    if not path.exists():
        return Inspection("missing")
    if not path.is_file():
        return Inspection("foreign-type")
    try:
        original = path.read_bytes()
        text = _normalize(original.decode("utf-8"))
    except (OSError, UnicodeError):
        return Inspection("unreadable")
    match = OWNER_RE.search(text)
    if not match:
        return Inspection("unowned", text, original)
    try:
        marker_owner = str(uuid.UUID(match.group(1)))
    except ValueError:
        return Inspection("invalid-owner", text, original)
    if marker_owner != match.group(1):
        return Inspection("invalid-owner", text, original)
    if marker_owner != owner:
        return Inspection("foreign-owner", text, original)
    body = text[:match.start()]
    if _sha256(body) != match.group(2):
        return Inspection("modified-owned", text, original)
    return Inspection("owned", text, original)


def _atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_tmp = tempfile.mkstemp(prefix=".loom-install-", suffix=".tmp",
                                           dir=str(path.parent))
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _restore_install(changed):
    failures = []
    for path, previous, installed in reversed(changed):
        try:
            if not path.is_file() or path.read_bytes() != installed:
                failures.append(f"{path}: current file changed during rollback; preserved")
            elif previous is None:
                path.unlink()
            else:
                _atomic_write(path, previous)
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    return failures


def _install(targets, expected, inspections, root, adopt_legacy):
    refusals = []
    for target, inspection in zip(targets, inspections):
        legacy = (inspection.state == "unowned" and adopt_legacy
                  and root.as_posix() in inspection.normalized
                  and LEGACY_RE.search(inspection.normalized))
        if inspection.state not in {"owned", "missing"} and not legacy:
            refusals.append(f"{target.destination} [{inspection.state}]")
    if refusals:
        raise InstallError(
            "preflight refused; no entry-point files changed: " + "; ".join(refusals), 1)

    changed = []
    messages = []
    try:
        for target, content, inspection in zip(targets, expected, inspections):
            if inspection.state == "owned" and inspection.normalized.encode("utf-8") == content:
                messages.append(f"CURRENT: {target.label} -> {target.destination}")
                continue
            _atomic_write(target.destination, content)
            changed.append((target.destination, inspection.original, content))
            messages.append(f"INSTALLED: {target.label} -> {target.destination}")
    except OSError as exc:
        failures = _restore_install(changed)
        detail = f"; rollback failures: {'; '.join(failures)}" if failures else ""
        raise InstallError(f"installation I/O failed and prior files were restored: {exc}{detail}") \
            from exc
    for message in messages:
        print(message)


def _uninstall(targets, inspections):
    refusals = [f"{target.destination} [{inspection.state}]"
                for target, inspection in zip(targets, inspections)
                if inspection.state not in {"owned", "missing"}]
    if refusals:
        raise InstallError(
            "uninstall preflight refused; no files removed: " + "; ".join(refusals), 1)
    removed = []
    messages = []
    try:
        for target, inspection in zip(targets, inspections):
            if inspection.state == "missing":
                messages.append(f"ABSENT: {target.label} -> {target.destination}")
                continue
            target.destination.unlink()
            removed.append((target.destination, inspection.original))
            messages.append(f"REMOVED: {target.label} -> {target.destination}")
    except OSError as exc:
        failures = []
        for path, previous in reversed(removed):
            try:
                if path.exists():
                    failures.append(f"{path}: recreated during rollback; preserved")
                else:
                    _atomic_write(path, previous)
            except OSError as rollback_error:
                failures.append(f"{path}: {rollback_error}")
        detail = f"; rollback failures: {'; '.join(failures)}" if failures else ""
        raise InstallError(f"uninstall I/O failed and removed files were restored: {exc}{detail}") \
            from exc
    for message in messages:
        print(message)


def run(home, *, mode="install", adopt_legacy=False, loom_root=ROOT):
    root = Path(loom_root).expanduser().resolve()
    home = Path(home).expanduser().resolve()
    if mode not in {"install", "check", "uninstall"}:
        raise InstallError(f"invalid installer mode: {mode}")
    if adopt_legacy and mode != "install":
        raise InstallError("--adopt-legacy is valid only for installation")
    owner = _owner_id(home, root, may_create=mode == "install")
    if owner is None:
        print("STALE: Loom installation identity is missing; run the installer.")
        return 1
    targets = _targets(root, home)
    for target in targets:
        _safe_destination(target.destination, home)
    expected = tuple(_render(target.source, root, owner) for target in targets)
    inspections = tuple(_inspect(target.destination, owner) for target in targets)

    if mode == "check":
        bad = 0
        for target, content, inspection in zip(targets, expected, inspections):
            current = inspection.state == "owned" \
                and inspection.normalized.encode("utf-8") == content
            print(f"{'CURRENT' if current else 'STALE'}: {target.label} -> "
                  f"{target.destination}" + ("" if current else f" [{inspection.state}]"))
            bad += 0 if current else 1
        if bad:
            return 1
        print("Loom install check: current")
        return 0
    if mode == "uninstall":
        _uninstall(targets, inspections)
        print("Loom uninstall: intact owned files removed; directories and foreign files preserved")
        return 0

    _install(targets, expected, inspections, root, adopt_legacy)
    print(f"Loom repo path stamped: {root.as_posix()}")
    print("Run the platform installer with --check/-Check to verify freshness; "
          "--uninstall/-Uninstall removes only intact owned files.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Safely install Loom agent entry points")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--uninstall", action="store_true")
    parser.add_argument("--adopt-legacy", action="store_true")
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--loom-root", default=str(ROOT),
                        help="Loom source root (normally inferred; useful for isolated verification)")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        print("loom_install: Python 3.11 or newer is required", file=sys.stderr)
        return 2
    mode = "check" if args.check else "uninstall" if args.uninstall else "install"
    try:
        return run(args.home, mode=mode, adopt_legacy=args.adopt_legacy,
                   loom_root=args.loom_root)
    except InstallError as exc:
        print(f"loom_install: REFUSED - {exc}", file=sys.stderr)
        return exc.code
    except (OSError, UnicodeError) as exc:
        print(f"loom_install: REFUSED - I/O is indeterminate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
