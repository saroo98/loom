#!/usr/bin/env python3
"""loom_survey — mechanical half of a Loom repo survey.

Gathers the facts a survey needs (ecosystems, dependencies, CI, tests, git state,
danger-zone candidates) and emits a survey skeleton with [FACT] labels, leaving the
judgment sections (architecture-as-found, conventions, health verdicts) as explicit TODOs
for the agent. With --since, emits the staleness-recheck delta instead
(loom/execution/staleness.md, full recheck step 1). Stdlib only.

Usage:
    python loom_survey.py <repo_root> [--out <file>]           # survey skeleton
    python loom_survey.py <repo_root> --since <commit> [--out <file>]   # drift delta

Exit codes: 0 ok, 2 usage/IO problem.
"""

import argparse
import datetime as dt
import hashlib
import os
import re
import stat
import subprocess
import sys

import loom_reliability
import time
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
             "target", ".idea", ".vscode", "vendor", ".next", "out", "bin", "obj"}
FILE_CAP = 20000
STATE_FILE_CAP = 100000
MAX_STATE_FILE_BYTES = 64 * 1024 * 1024 * 1024
MAX_STATE_TOTAL_BYTES = 512 * 1024 * 1024 * 1024
STATE_HASH_DEADLINE_SECONDS = 60.0
GIT_CONFIG_CAP = 256 * 1024
FILTER_DRIVER_RE = re.compile(r"^filter\.([A-Za-z0-9._-]{1,128})\."
                              r"(?:clean|smudge|process)$", re.I)

ECOSYSTEM_MARKERS = [
    ("package.json", "Node.js / JavaScript"),
    ("pyproject.toml", "Python (pyproject)"),
    ("requirements.txt", "Python (requirements)"),
    ("setup.py", "Python (setup.py)"),
    ("go.mod", "Go"),
    ("Cargo.toml", "Rust"),
    ("pom.xml", "Java (Maven)"),
    ("build.gradle", "Java/Kotlin (Gradle)"),
    ("build.gradle.kts", "Kotlin (Gradle)"),
    ("composer.json", "PHP"),
    ("Gemfile", "Ruby"),
    ("mix.exs", "Elixir"),
    ("CMakeLists.txt", "C/C++ (CMake)"),
    ("*.sln", "C#/.NET (solution)"),
    ("*.csproj", "C#/.NET (project)"),
    ("*.mq5", "MQL5 (MetaTrader EA/indicator)"),
    ("*.mq4", "MQL4"),
]

LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
             "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock"]

CI_MARKERS = [".github/workflows", ".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile",
              ".circleci"]

DOC_MARKERS = ["README.md", "README.rst", "README.txt", "CONTRIBUTING.md", "AGENTS.md",
               "CLAUDE.md", "GEMINI.md", "LICENSE", "LICENSE.md", "LICENSE.txt"]

DANGER_RE = re.compile(r"(auth|login|password|passwd|payment|billing|checkout|migrat"
                       r"|trade|trading|broker|secret|token|crypt|credential)", re.I)
TEST_FILE_RE = re.compile(r"(^test_.*\.py$|_test\.(py|go|rb)$|\.(test|spec)\.[jt]sx?$"
                          r"|Tests?\.cs$)")


class SurveyError(RuntimeError):
    """Repository state could not be established safely."""


@dataclass(frozen=True)
class RepoState:
    is_git: bool
    mode: str = "git"
    head: str = ""
    branch: str = ""
    staged: tuple = ()
    unstaged: tuple = ()
    untracked: tuple = ()
    state_hash: str = ""
    excluded: tuple = ()

    @property
    def dirty(self):
        return bool(self.staged or self.unstaged or self.untracked)


@dataclass(frozen=True)
class _WorkspaceEntry:
    rel: str
    path: Path
    kind: str
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    uid: int
    gid: int
    flags: int
    attributes: int


def _git_environment():
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update({
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return environment


def _configured_filter_drivers(repo, timeout=20):
    """Return bounded configured content-filter names without executing them."""
    command = [
        "git", "--no-pager", "-c", "core.fsmonitor=false", "-C", str(repo),
        "config", "--null", "--name-only", "--get-regexp",
        r"^filter\..*\.(clean|smudge|process)$",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, timeout=timeout, env=_git_environment())
    except OSError as exc:
        raise SurveyError(f"git unavailable: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SurveyError("git timed out while inspecting content-filter configuration") \
            from exc
    if result.returncode not in (0, 1):
        detail = result.stderr.decode("utf-8", errors="replace").strip() or "no diagnostic"
        raise SurveyError(
            f"git filter-configuration query failed ({result.returncode}): {detail}")
    if len(result.stdout) > GIT_CONFIG_CAP:
        raise SurveyError("Git content-filter configuration exceeds its safety bound")
    drivers = set()
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            key = raw.decode("utf-8")
        except UnicodeError as exc:
            raise SurveyError("Git content-filter configuration is not UTF-8") from exc
        match = FILTER_DRIVER_RE.fullmatch(key)
        if not match:
            raise SurveyError(f"unsafe Git content-filter key cannot be neutralized: {key!r}")
        drivers.add(match.group(1))
        if len(drivers) > 1024:
            raise SurveyError("Git content-filter driver count exceeds its safety bound")
    return tuple(sorted(drivers, key=str.casefold))


def run_git(repo, *args, allowed=(0,), timeout=20, filter_drivers=None,
            binary=False):
    """Run a read-only Git query without inheriting effectful Git controls.

    Repository inspection is a trust boundary.  Ambient ``GIT_*`` variables can
    redirect the repository or make an otherwise read-only command write trace
    files, while diff drivers/textconv and fsmonitor can execute arbitrary local
    programs.  Loom therefore supplies the repository explicitly, strips every
    ambient Git control, disables the effectful extension points used by its
    query set, and asks Git not to take optional locks.
    """
    git_args = list(args)
    if git_args and git_args[0] == "diff":
        git_args[1:1] = ["--no-ext-diff", "--no-textconv"]
        if filter_drivers is None:
            filter_drivers = _configured_filter_drivers(repo, timeout=timeout)
    else:
        filter_drivers = filter_drivers or ()
    filter_overrides = []
    for driver in filter_drivers:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", driver):
            raise SurveyError("invalid prevalidated Git content-filter driver")
        for endpoint in ("clean", "smudge", "process"):
            filter_overrides.extend(["-c", f"filter.{driver}.{endpoint}="])
        filter_overrides.extend(["-c", f"filter.{driver}.required=false"])
    command = [
        "git", "--no-pager", "-c", "core.fsmonitor=false",
        *filter_overrides, "-C", str(repo), *git_args,
    ]
    try:
        options = {
            "capture_output": True,
            "timeout": timeout,
            "env": _git_environment(),
        }
        if not binary:
            options.update({
                "text": True, "encoding": "utf-8", "errors": "replace",
            })
        result = subprocess.run(command, **options)
    except OSError as exc:
        raise SurveyError(f"git unavailable: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SurveyError(f"git timed out while running {' '.join(git_args)}") from exc
    if result.returncode not in allowed:
        stderr = result.stderr.decode("utf-8", errors="backslashreplace") \
            if isinstance(result.stderr, bytes) else result.stderr
        stdout = result.stdout.decode("utf-8", errors="backslashreplace") \
            if isinstance(result.stdout, bytes) else result.stdout
        detail = stderr.strip() or stdout.strip() or "no diagnostic"
        raise SurveyError(
            f"git {' '.join(git_args)} failed ({result.returncode}): {detail}")
    return result


def _nul_paths(text):
    return tuple(sorted(path for path in text.split("\0") if path))


def _nul_path_bytes(content):
    if not isinstance(content, bytes):
        raise SurveyError("binary Git path query did not return bytes")
    return tuple(sorted(path for path in content.split(b"\0") if path))


def _display_git_path(path):
    return path.decode("utf-8", errors="backslashreplace")


def _is_excluded(rel, excluded):
    candidate = os.path.normcase(rel) if os.name == "nt" else rel
    return any(
        candidate == (os.path.normcase(prefix) if os.name == "nt" else prefix)
        or candidate.startswith(
            (os.path.normcase(prefix) if os.name == "nt" else prefix) + "/")
        for prefix in excluded)


def _windows_named_stream_count(path):
    """Count non-default NTFS streams without reading or exposing their names."""
    if os.name != "nt":
        return 0
    import ctypes
    from ctypes import wintypes

    class StreamData(ctypes.Structure):
        _fields_ = [
            ("size", ctypes.c_longlong),
            ("name", wintypes.WCHAR * 296),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    first_stream = kernel.FindFirstStreamW
    first_stream.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(StreamData), wintypes.DWORD,
    ]
    first_stream.restype = wintypes.HANDLE
    next_stream = kernel.FindNextStreamW
    next_stream.argtypes = [wintypes.HANDLE, ctypes.POINTER(StreamData)]
    next_stream.restype = wintypes.BOOL
    close = kernel.FindClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    data = StreamData()
    handle = first_stream(str(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = ctypes.get_last_error()
        if error in {1, 2, 3, 38}:  # unsupported/no streams/path disappeared
            if error in {2, 3} and Path(path).exists():
                raise SurveyError("cannot enumerate Windows alternate data streams")
            return 0
        raise SurveyError(
            f"cannot enumerate Windows alternate data streams (error {error})")
    count = 0
    try:
        while True:
            if data.name != "::$DATA":
                count += 1
            if not next_stream(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 38:
                    raise SurveyError(
                        "Windows alternate data stream enumeration changed or failed "
                        f"(error {error})")
                break
    finally:
        close(handle)
    return count


def _workspace_census(root, excluded):
    """Enumerate every target entry without following links; reject unknown types."""
    entries, stack = [], [Path(root)]
    while stack:
        directory = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise SurveyError(f"cannot enumerate workspace state: {exc}") from exc
        for child in children:
            path = Path(child.path)
            try:
                rel_path = path.relative_to(root)
            except ValueError as exc:
                raise SurveyError("workspace enumeration escaped its root") from exc
            if ".git" in rel_path.parts:
                continue
            rel = rel_path.as_posix()
            if _is_excluded(rel, excluded):
                continue
            try:
                # pathlib.lstat supplies the stable volume/file identity that
                # DirEntry.stat reports as (0, 0) on supported Windows Python.
                info = path.lstat()
                is_link = child.is_symlink()
            except OSError as exc:
                raise SurveyError(f"cannot inspect workspace entry {rel}: {exc}") from exc
            attributes = getattr(info, "st_file_attributes", 0)
            reparse = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
            if reparse and not is_link:
                raise SurveyError(
                    f"workspace contains unsupported junction/reparse entry: {rel}")
            if is_link or stat.S_ISLNK(info.st_mode):
                kind = "symlink"
            elif stat.S_ISDIR(info.st_mode):
                kind = "directory"
                stack.append(path)
            elif stat.S_ISREG(info.st_mode):
                kind = "file"
            else:
                raise SurveyError(f"workspace contains unsupported special entry: {rel}")
            if kind in {"file", "directory"}:
                stream_count = _windows_named_stream_count(path)
                if stream_count:
                    raise SurveyError(
                        "workspace contains an unsupported alternate data stream "
                        f"on {rel}; complete state is indeterminate")
            entries.append(_WorkspaceEntry(
                rel, path, kind, info.st_dev, info.st_ino,
                stat.S_IMODE(info.st_mode), info.st_size,
                getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
                getattr(info, "st_uid", 0), getattr(info, "st_gid", 0),
                getattr(info, "st_flags", 0), attributes))
            if len(entries) > STATE_FILE_CAP:
                raise SurveyError(
                    f"workspace state contains more than {STATE_FILE_CAP} visible entries; "
                    "no partial state hash was produced")
    total_bytes = 0
    for entry in entries:
        if entry.kind != "file":
            continue
        if entry.size > MAX_STATE_FILE_BYTES:
            raise SurveyError(
                f"workspace file {entry.rel} exceeds the complete-snapshot per-file bound "
                f"of {MAX_STATE_FILE_BYTES} bytes")
        total_bytes += entry.size
        if total_bytes > MAX_STATE_TOTAL_BYTES:
            raise SurveyError(
                "workspace file bytes exceed the complete-snapshot aggregate bound of "
                f"{MAX_STATE_TOTAL_BYTES}; no partial state hash was produced")
    return tuple(sorted(entries, key=lambda item: os.fsencode(item.rel)))


def _hash_field(digest, label, value):
    """Add one unambiguous binary field to a digest."""
    label = bytes(label)
    value = bytes(value)
    digest.update(len(label).to_bytes(2, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _hash_stream_header(digest, label, size):
    label = bytes(label)
    digest.update(len(label).to_bytes(2, "big"))
    digest.update(label)
    digest.update(int(size).to_bytes(8, "big"))


def _hash_workspace(entries):
    """Hash semantic project state while using volatile metadata only for race detection."""
    digest = hashlib.sha256(b"complete-workspace-v4\0")
    digest.update(len(entries).to_bytes(8, "big"))
    deadline = time.monotonic() + STATE_HASH_DEADLINE_SECONDS
    total_read = 0
    for entry in entries:
        if time.monotonic() > deadline:
            raise SurveyError(
                "complete workspace hash exceeded its time bound; no partial state hash "
                "was produced")
        entry_digest = hashlib.sha256(b"workspace-entry-v2\0")
        _hash_field(entry_digest, b"path", os.fsencode(entry.rel))
        _hash_field(entry_digest, b"kind", entry.kind.encode("ascii"))
        _hash_field(entry_digest, b"mode", f"{entry.mode:o}".encode("ascii"))
        # Ownership IDs, archive/indexing flags, platform attributes, mtimes, and xattrs
        # vary across checkout filesystems without changing a project's executable source.
        # They remain census/stability inputs where applicable, not freshness semantics.
        if entry.kind == "directory":
            digest.update(entry_digest.digest())
            continue
        if entry.kind == "symlink":
            try:
                target = os.readlink(entry.path)
                after = entry.path.lstat()
            except OSError as exc:
                raise SurveyError(f"cannot hash workspace symlink {entry.rel}: {exc}") from exc
            if (after.st_dev, after.st_ino) != (entry.device, entry.inode) \
                    or not stat.S_ISLNK(after.st_mode):
                raise SurveyError(f"workspace symlink changed during survey: {entry.rel}")
            _hash_field(entry_digest, b"target", os.fsencode(target))
            digest.update(entry_digest.digest())
            continue
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(entry.path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) \
                        or (before.st_dev, before.st_ino) != (entry.device, entry.inode):
                    raise SurveyError(
                        f"workspace file identity changed during survey: {entry.rel}")
                entry_read = 0
                _hash_stream_header(entry_digest, b"content", entry.size)
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    entry_read += len(chunk)
                    total_read += len(chunk)
                    if entry_read > entry.size or entry_read > MAX_STATE_FILE_BYTES \
                            or total_read > MAX_STATE_TOTAL_BYTES:
                        raise SurveyError(
                            f"workspace file grew or exceeded a hash bound: {entry.rel}")
                    if time.monotonic() > deadline:
                        raise SurveyError(
                            "complete workspace hash exceeded its time bound; no partial "
                            "state hash was produced")
                    entry_digest.update(chunk)
                after = os.fstat(stream.fileno())
        except SurveyError:
            raise
        except OSError as exc:
            raise SurveyError(f"cannot hash workspace file {entry.rel}: {exc}") from exc
        after_mtime = getattr(
            after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000))
        if (after.st_dev, after.st_ino, after.st_size, after_mtime,
                stat.S_IMODE(after.st_mode), getattr(after, "st_uid", 0),
                getattr(after, "st_gid", 0), getattr(after, "st_flags", 0),
                getattr(after, "st_file_attributes", 0)) != (
                    entry.device, entry.inode, entry.size, entry.mtime_ns, entry.mode,
                    entry.uid, entry.gid, entry.flags, entry.attributes):
            raise SurveyError(f"workspace file changed during survey: {entry.rel}")
        if entry_read != entry.size:
            raise SurveyError(f"workspace file size changed during survey: {entry.rel}")
        digest.update(entry_digest.digest())
    return digest.hexdigest()


def _enforce_state_file_cap(*path_sets):
    count = len({path for paths in path_sets for path in paths})
    if count > STATE_FILE_CAP:
        raise SurveyError(
            f"workspace state contains {count} visible files, above the complete-snapshot "
            f"safety limit of {STATE_FILE_CAP}; no partial state hash was produced")


def _filesystem_state(root, excluded, entries=None, workspace_hash=None):
    entries = entries if entries is not None else _workspace_census(root, excluded)
    files = tuple(item.rel for item in entries if item.kind != "directory")
    digest = hashlib.sha256(b"filesystem-v2\0")
    digest.update(bytes.fromhex(workspace_hash or _hash_workspace(entries)))
    return RepoState(
        is_git=False, mode="filesystem", untracked=files,
        state_hash=digest.hexdigest(), excluded=excluded)


def _state_pathspec(excluded):
    magic = "exclude,icase" if os.name == "nt" else "exclude"
    return ("--", ".", *(f":({magic}){path.rstrip('/')}/**" for path in excluded))


def repo_state(root_path, exclude_prefixes=None):
    """Return a content-sensitive snapshot of committed and local Git state."""
    root = Path(root_path)
    # Runtime callers have already supplied and validated an absolute root.
    # Do not call resolve() on that path: on Windows it can consult ambient cwd.
    if not root.is_absolute():
        root = Path(os.path.abspath(root))
    if exclude_prefixes is None:
        exclude_prefixes = ("plans",) if (root / "plans" / "MANIFEST.md").is_file() else ()
    excluded = tuple(sorted(str(path).replace("\\", "/").strip("/")
                            for path in exclude_prefixes if str(path).strip("/\\")))
    entries = _workspace_census(root, excluded)
    workspace_hash = _hash_workspace(entries)
    pathspec = _state_pathspec(excluded)
    try:
        probe = run_git(root, "rev-parse", "--is-inside-work-tree", allowed=(0, 128))
    except SurveyError:
        if (root / ".git").exists():
            raise
        return _filesystem_state(root, excluded, entries, workspace_hash)
    if probe.returncode != 0:
        diagnostic = (probe.stderr or probe.stdout).lower()
        if "not a git repository" in diagnostic or "not a git directory" in diagnostic:
            return _filesystem_state(root, excluded, entries, workspace_hash)
        raise SurveyError(
            "cannot determine Git state: " + (probe.stderr.strip() or "unknown error"))
    if probe.stdout.strip() != "true":
        return _filesystem_state(root, excluded, entries, workspace_hash)
    head_result = run_git(
        root, "rev-parse", "--verify", "HEAD", allowed=(0, 1, 128))
    if head_result.returncode == 0:
        head = head_result.stdout.strip()
        branch_raw = run_git(
            root, "branch", "--show-current", binary=True).stdout.strip() or b"(detached)"
        branch = _display_git_path(branch_raw)
    else:
        symbolic = run_git(
            root, "symbolic-ref", "-q", "HEAD", allowed=(0, 1), binary=True)
        symbolic_raw = symbolic.stdout.strip()
        if symbolic.returncode != 0 or not symbolic_raw.startswith(b"refs/heads/"):
            detail = head_result.stderr.strip() or head_result.stdout.strip() or "invalid HEAD"
            raise SurveyError(f"Git HEAD is indeterminate: {detail}")
        head = ""
        branch_raw = symbolic_raw[len(b"refs/heads/"):]
        branch = _display_git_path(branch_raw)
    filter_drivers = _configured_filter_drivers(root)
    staged_raw = _nul_path_bytes(run_git(
        root, "diff", "--cached", "--name-only", "-z", *pathspec,
        filter_drivers=filter_drivers, binary=True).stdout)
    unstaged_raw = _nul_path_bytes(run_git(
        root, "diff", "--name-only", "-z", *pathspec,
        filter_drivers=filter_drivers, binary=True).stdout)
    staged = tuple(_display_git_path(path) for path in staged_raw)
    unstaged = tuple(_display_git_path(path) for path in unstaged_raw)
    untracked_raw = _nul_path_bytes(run_git(
        root, "ls-files", "--others", "--exclude-standard", "-z",
        *pathspec, binary=True).stdout)
    untracked = tuple(_display_git_path(path) for path in untracked_raw)
    index_state = run_git(
        root, "ls-files", "--stage", "-v", "-z", *pathspec, binary=True).stdout
    unsafe_index = []
    for record in (item for item in index_state.split(b"\0") if item):
        tag = record[0]
        if chr(tag).islower() or tag == ord("S"):
            unsafe_index.append(_display_git_path(record.split(b"\t", 1)[-1]))
    if unsafe_index:
        raise SurveyError(
            "Git index contains assume-unchanged/skip-worktree paths; complete "
            f"freshness is indeterminate: {unsafe_index[:10]}")
    _enforce_state_file_cap(staged, unstaged, untracked)
    digest = hashlib.sha256()
    digest.update(b"head\0" + head.encode("ascii") + b"\0")
    digest.update(b"branch\0" + branch_raw + b"\0")
    digest.update(b"index\0" + index_state + b"\0")
    digest.update(b"workspace\0" + bytes.fromhex(workspace_hash) + b"\0")
    for label, paths in ((b"staged", staged_raw), (b"unstaged", unstaged_raw),
                         (b"untracked", untracked_raw)):
        digest.update(label + b"\0")
        for path in paths:
            digest.update(path + b"\0")
    return RepoState(
        is_git=True, mode="git", head=head, branch=branch, staged=staged,
        unstaged=unstaged, untracked=untracked, state_hash=digest.hexdigest(),
        excluded=excluded)


def walk_files(root):
    """Bounded file walk skipping vendored/dot dirs. Returns relative Paths."""
    files, stack = [], [Path(root)]
    while stack and len(files) < FILE_CAP:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name not in SKIP_DIRS and not e.name.startswith("."):
                    stack.append(e)
            elif e.is_file():
                files.append(e.relative_to(root))
                if len(files) >= FILE_CAP:
                    break
    return files


def detect_ecosystems(root, files):
    found = []
    names = {f.name for f in files}
    suffixes = {f.suffix for f in files}
    for marker, label in ECOSYSTEM_MARKERS:
        if marker.startswith("*."):
            if marker[1:] in suffixes:
                found.append(label)
        elif marker in names:
            found.append(label)
    return found


def dep_count(root):
    counts = []
    pj = root / "package.json"
    if pj.is_file():
        try:
            import json
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            n = len(data.get("dependencies", {})) + len(data.get("devDependencies", {}))
            counts.append(f"package.json: {n} declared (deps+dev)")
        except Exception:
            counts.append("package.json: present, unparseable")
    req = root / "requirements.txt"
    if req.is_file():
        lines = [l for l in req.read_text(encoding="utf-8", errors="replace").splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        counts.append(f"requirements.txt: {len(lines)} entries")
    py = root / "pyproject.toml"
    if py.is_file():
        text = py.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M)
        if m:
            n = len([x for x in m.group(1).split(",") if x.strip().strip("'\"")])
            counts.append(f"pyproject.toml: {n} project dependencies")
    cargo = root / "Cargo.toml"
    if cargo.is_file():
        text = cargo.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"\[dependencies\](.*?)(\n\[|\Z)", text, re.S)
        if m:
            n = len([l for l in m.group(1).splitlines() if "=" in l])
            counts.append(f"Cargo.toml: {n} dependencies")
    return counts


def top_structure(root, files, depth=1):
    from collections import Counter
    c = Counter()
    for f in files:
        parts = f.parts
        key = parts[0] if len(parts) > 1 else "(root files)"
        c[key] += 1
    return sorted(c.items(), key=lambda kv: -kv[1])


def survey(root_path):
    root = Path(root_path).resolve()
    today = dt.date.today().isoformat()
    files = walk_files(root)
    state = repo_state(root)
    log = (run_git(root, "log", "--oneline", "-15").stdout.strip()
           if state.is_git and state.head else "")
    names = {f.name for f in files}
    fact = f"[FACT — loom_survey {today}]"

    L = []
    L.append("---")
    L.append("artifact: survey")
    L.append(f'project: "{root.name}"')
    L.append("status: draft")
    L.append(f"last_verified: {today}")
    if state.is_git:
        L.append(f'repo_head: "{state.head}"' if state.head else "repo_head: null")
    L.append(f'repo_state_hash: "{state.state_hash}"')
    L.append(f'repo_state_mode: "{state.mode}"')
    L.append("generated_by: loom_survey (facts) + agent judgment (TODO sections)")
    L.append("---")
    L.append(f"\n# Repo survey — {root.name}\n")

    L.append("## Git state")
    if state.is_git:
        local_count = len(set(state.staged + state.unstaged + state.untracked))
        display_head = state.head or "(unborn — no commit)"
        L.append(f"- HEAD: `{display_head}` on branch `{state.branch}` {fact}")
        L.append(f"- Working tree: {'DIRTY - ' + str(local_count) + ' path(s)' if state.dirty else 'clean'} {fact}")
        L.append(f"- Repository state hash: `{state.state_hash}` {fact}")
        if state.excluded:
            L.append(f"- State-hash exclusions (private pack only): "
                     f"{list(state.excluded)} {fact}")
        L.append(f"- Staged: {list(state.staged) or 'none'} {fact}")
        L.append(f"- Unstaged: {list(state.unstaged) or 'none'} {fact}")
        L.append(f"- Untracked: {list(state.untracked) or 'none'} {fact}")
        L.append(f"- Recent commits {fact}:\n```\n{log or '(none)'}\n```")
    else:
        L.append(f"- Not a Git repository; filesystem state is still hashed {fact}")
        L.append(f"- Filesystem state hash: `{state.state_hash}` across "
                 f"{len(state.untracked)} file(s) {fact}")

    L.append(f"\n## Ecosystems detected {fact}")
    ecos = detect_ecosystems(root, files)
    L.extend([f"- {e}" for e in ecos] or ["- none recognized — inspect manually"])

    deps = dep_count(root)
    if deps:
        L.append(f"\n## Dependencies {fact}")
        L.extend(f"- {d}" for d in deps)
    locks = [lf for lf in LOCKFILES if lf in names]
    L.append(f"- Lockfiles: {', '.join(locks) if locks else 'NONE FOUND — reproducibility risk'} {fact}")

    L.append(f"\n## CI / docs / instructions {fact}")
    for m in CI_MARKERS:
        if (root / m).exists():
            L.append(f"- CI config: `{m}`")
    for m in DOC_MARKERS:
        if m in names or (root / m).exists():
            L.append(f"- `{m}` present")

    L.append(f"\n## Tests {fact}")
    test_files = [f for f in files if TEST_FILE_RE.search(f.name)]
    test_dirs = sorted({f.parts[0] for f in files
                        if f.parts[0].lower() in ("test", "tests", "__tests__", "spec")})
    L.append(f"- Test-looking files: {len(test_files)}; test dirs at root: {test_dirs or 'none'}")
    L.append("- Do they RUN and PASS? -> judgment TODO below (run them; record command + output)")

    L.append(f"\n## Structure (files per top-level dir) {fact}")
    for name, n in top_structure(root, files)[:15]:
        L.append(f"- `{name}/`: {n}")
    if len(files) >= FILE_CAP:
        L.append(f"- NOTE: walk capped at {FILE_CAP} files; counts are lower bounds")

    L.append(f"\n## Danger-zone candidates (path-name heuristic) {fact}")
    danger = [str(f) for f in files if DANGER_RE.search(str(f))][:30]
    L.extend([f"- `{d}`" for d in danger] or ["- none matched — still confirm by reading entry points"])
    envs = [str(f) for f in files if f.name.startswith(".env")]
    if envs:
        L.append(f"- SECRETS RISK: env file(s) present: {', '.join('`'+e+'`' for e in envs)} "
                 "— path only, never read values into the pack (privacy rule 2)")

    L.append("""
## Judgment TODO (agent work — the tool cannot do these)
- [ ] Architecture-as-found: components and boundaries as they ARE (entry points, wiring)
- [ ] Conventions list: naming, formatting, error handling, commit style (WOs inherit these)
- [ ] Deliberate vs generated vs abandoned classification for anything odd (partial repos)
- [ ] Health verdict: build/test commands RUN, with output recorded as [FACT]
- [ ] Confirm/extend danger zones by reading, not just path names
- [ ] Label everything above you modify: tool facts stay [FACT — loom_survey], your
      inferences get their own labels (loom/core/epistemics.md)
""")
    return "\n".join(L)


def delta(root_path, since):
    root = Path(root_path).resolve()
    today = dt.date.today().isoformat()
    state = repo_state(root)
    if not state.is_git:
        raise SurveyError("--since requires a git repository")
    if not state.head:
        raise SurveyError(
            "--since requires a committed HEAD; this Git repository is valid but unborn")
    verify = run_git(root, "rev-parse", "--verify", f"{since}^{{commit}}",
                     allowed=(0, 128))
    if verify.returncode != 0:
        raise SurveyError(f"invalid base commit: {since}")
    base = verify.stdout.strip()
    ancestor = run_git(root, "merge-base", "--is-ancestor", base, state.head,
                       allowed=(0, 1))
    if ancestor.returncode != 0:
        raise SurveyError(
            f"base commit {since} is not an ancestor of HEAD {state.head}")
    rng = f"{base}..{state.head}"
    commits = run_git(root, "log", "--oneline", rng).stdout.strip()
    committed = _nul_paths(run_git(
        root, "diff", "--name-only", "-z", rng).stdout)
    all_changed = tuple(sorted(set(
        committed + state.staged + state.unstaged + state.untracked)))
    manifests = [c for c in all_changed if Path(c).name in
                 {m for m, _ in ECOSYSTEM_MARKERS if not m.startswith('*')} | set(LOCKFILES)]
    ci = [c for c in all_changed if ".github/workflows" in c or Path(c).name in
          {"Jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml"}]
    danger = [c for c in all_changed if DANGER_RE.search(c)]

    L = [f"# Staleness delta — {root.name} — {today}",
         f"- Range: `{base}` -> `{state.head}`",
         f"- Commits in range: {len(commits.splitlines()) if commits else 0}",
         f"- Repository state hash: `{state.state_hash}`",
         "\n## Commits\n```", commits or "(none — repo_head current)", "```",
         "\n## Committed changes"]
    L.extend([f"- `{path}`" for path in committed] or ["- none"])
    L.append("\n## Staged changes")
    L.extend([f"- `{path}`" for path in state.staged] or ["- none"])
    L.append("\n## Unstaged changes")
    L.extend([f"- `{path}`" for path in state.unstaged] or ["- none"])
    L.append("\n## Untracked files")
    L.extend([f"- `{path}`" for path in state.untracked] or ["- none"])
    if manifests:
        L += ["\n## Dependency/manifest changes — re-verify version facts"] + \
             [f"- `{m}`" for m in manifests]
    if ci:
        L += ["\n## CI changes — verification commands may have moved"] + [f"- `{c}`" for c in ci]
    if danger:
        L += ["\n## Danger-zone paths touched — review before any dependent WO runs"] + \
             [f"- `{d}`" for d in danger]
    L += ["\n## Next steps (loom/execution/staleness.md, full recheck)",
          "- Walk the assumption ledger against the changes above",
          "- Mark contradicted artifacts stale / affected WOs blocked",
          "- Restamp only what you actually rechecked"]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mechanical half of a Loom repo survey")
    ap.add_argument("repo", help="target repo root")
    ap.add_argument("--since", help="emit drift delta since this commit instead of a survey")
    ap.add_argument("--out", help="write to file instead of stdout")
    args = ap.parse_args(argv)
    if not Path(args.repo).is_dir():
        print(f"loom_survey: not a directory: {args.repo}", file=sys.stderr)
        return 2
    try:
        text = delta(args.repo, args.since) if args.since else survey(args.repo)
    except SurveyError as exc:
        print(f"loom_survey: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    if args.out:
        loom_reliability.atomic_write_text(Path(args.out), text)
        print(f"written: {args.out}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
