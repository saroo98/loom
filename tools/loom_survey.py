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
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
             "target", ".idea", ".vscode", "vendor", ".next", "out", "bin", "obj"}
FILE_CAP = 20000
STATE_FILE_CAP = 100000

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


def run_git(repo, *args, allowed=(0,), timeout=20):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo)] + list(args), capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except OSError as exc:
        raise SurveyError(f"git unavailable: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SurveyError(f"git timed out while running {' '.join(args)}") from exc
    if result.returncode not in allowed:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise SurveyError(
            f"git {' '.join(args)} failed ({result.returncode}): {detail}")
    return result


def _nul_paths(text):
    return tuple(sorted(path for path in text.split("\0") if path))


def _hash_untracked(root, paths, digest):
    for rel in paths:
        path = root / rel
        digest.update(b"untracked\0" + rel.encode("utf-8") + b"\0")
        try:
            if path.is_symlink():
                digest.update(str(path.readlink()).encode("utf-8"))
            else:
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
        except OSError as exc:
            raise SurveyError(f"cannot hash untracked file {rel}: {exc}") from exc


def _enforce_state_file_cap(*path_sets):
    count = len({path for paths in path_sets for path in paths})
    if count > STATE_FILE_CAP:
        raise SurveyError(
            f"workspace state contains {count} visible files, above the complete-snapshot "
            f"safety limit of {STATE_FILE_CAP}; no partial state hash was produced")


def _filesystem_state(root, excluded):
    files = []
    try:
        for path in root.rglob("*"):
            if not path.is_file() or ".git" in path.relative_to(root).parts:
                continue
            rel = path.relative_to(root).as_posix()
            if any(rel == prefix or rel.startswith(prefix + "/")
                   for prefix in excluded):
                continue
            files.append(rel)
            if len(files) > STATE_FILE_CAP:
                _enforce_state_file_cap(files)
    except OSError as exc:
        raise SurveyError(f"cannot enumerate workspace state: {exc}") from exc
    digest = hashlib.sha256(b"filesystem\0")
    _hash_untracked(root, tuple(sorted(files)), digest)
    return RepoState(
        is_git=False, mode="filesystem", untracked=tuple(sorted(files)),
        state_hash=digest.hexdigest(), excluded=excluded)


def _state_pathspec(excluded):
    return ("--", ".", *(f":(exclude){path.rstrip('/')}/**" for path in excluded))


def repo_state(root_path, exclude_prefixes=None):
    """Return a content-sensitive snapshot of committed and local Git state."""
    root = Path(root_path).resolve()
    if exclude_prefixes is None:
        exclude_prefixes = ("plans",) if (root / "plans" / "MANIFEST.md").is_file() else ()
    excluded = tuple(sorted(str(path).replace("\\", "/").strip("/")
                            for path in exclude_prefixes if str(path).strip("/\\")))
    pathspec = _state_pathspec(excluded)
    try:
        probe = run_git(root, "rev-parse", "--is-inside-work-tree", allowed=(0, 128))
    except SurveyError:
        if (root / ".git").exists():
            raise
        return _filesystem_state(root, excluded)
    if probe.returncode != 0:
        diagnostic = (probe.stderr or probe.stdout).lower()
        if "not a git repository" in diagnostic or "not a git directory" in diagnostic:
            return _filesystem_state(root, excluded)
        raise SurveyError(
            "cannot determine Git state: " + (probe.stderr.strip() or "unknown error"))
    if probe.stdout.strip() != "true":
        return _filesystem_state(root, excluded)
    head_result = run_git(
        root, "rev-parse", "--verify", "HEAD", allowed=(0, 1, 128))
    if head_result.returncode == 0:
        head = head_result.stdout.strip()
        branch = run_git(root, "branch", "--show-current").stdout.strip() or "(detached)"
    else:
        symbolic = run_git(root, "symbolic-ref", "-q", "HEAD", allowed=(0, 1))
        if symbolic.returncode != 0 or not symbolic.stdout.strip().startswith("refs/heads/"):
            detail = head_result.stderr.strip() or head_result.stdout.strip() or "invalid HEAD"
            raise SurveyError(f"Git HEAD is indeterminate: {detail}")
        head = ""
        branch = symbolic.stdout.strip()[len("refs/heads/"):]
    staged = _nul_paths(run_git(
        root, "diff", "--cached", "--name-only", "-z", *pathspec).stdout)
    unstaged = _nul_paths(run_git(
        root, "diff", "--name-only", "-z", *pathspec).stdout)
    untracked = _nul_paths(run_git(
        root, "ls-files", "--others", "--exclude-standard", "-z", *pathspec).stdout)
    _enforce_state_file_cap(staged, unstaged, untracked)
    digest = hashlib.sha256()
    digest.update(b"head\0" + head.encode("ascii") + b"\0")
    for label, args in (
        (b"staged", ("diff", "--cached", "--binary")),
        (b"unstaged", ("diff", "--binary")),
    ):
        digest.update(label + b"\0")
        digest.update(run_git(root, *args, *pathspec).stdout.encode("utf-8"))
    _hash_untracked(root, untracked, digest)
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
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"written: {args.out}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
