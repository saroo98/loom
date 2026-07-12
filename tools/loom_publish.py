#!/usr/bin/env python3
"""loom_publish — build the public cut of a Loom repo (core only, leak-firewalled).

A Loom repo = core (the generic method) + owner-layer (everything the owner's loop
grew: self-pack, evidence, plan docs, domain deep-dives, FEEDBACK/CHANGELOG contents).
This tool builds `dist/public-<VERSION>/` containing core only:

  1. ALLOWLIST copy — only listed paths go out; a forgotten file stays private by
     construction (never use a blocklist for privacy).
  2. OVERLAY — public-only sources win: for each overlay-managed path, `public/<rel>`
     is used if present, else the repo-root `<rel>` (so a published cut, which has no
     `public/` dir, can itself be re-published by its owner).
  3. FIREWALL — the whole output is scanned for forbidden tokens
     (tools/publish-tokens.txt: owner names, machine paths, domain words) plus the
     secret patterns from loom_lint. One hit = the build FAILS and the tree is removed.
  4. LINK CHECK — relative markdown links must resolve inside the output.
  5. `--check` additionally runs the full test suite inside the output tree.

Building is not publishing: pushing the result anywhere stays a human decision.

Usage:
    python loom_publish.py [--out <dir>] [--check] [--json]

Exit codes: 0 = built clean, 1 = firewall/link/suite failure, 2 = usage/IO problem.
"""

import argparse
import contextlib
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from loom_lint import PLACEHOLDER_RE, SECRET_PATTERNS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SOURCE_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
DEFAULT_OUT = (ROOT / "dist" / f"public-{SOURCE_VERSION}").resolve()
OUTPUT_MARKER = ".loom-public-output.json"
MARKER_FORMAT = "loom-public-output"
MARKER_VERSION = 2

# Only these leave the repo. Directories are copied recursively.
ALLOWLIST = [
    "VERSION",
    "START-HERE.md",
    "LICENSE",
    ".gitignore",
    "loom/core",
    "loom/intake",
    "loom/planning",
    "loom/execution",
    "loom/verification",
    "loom/review",
    "loom/prompts",
    "loom/examples",
    "loom/adaptation/project-types.md",
    "loom/adaptation/using-loom-well.md",
    "loom/adaptation/localization-playbook.md",
    "loom/meta/evolving-loom.md",
    "loom/meta/v1-scorecard.md",
    "templates",
    "schemas",
    "skill",
    "tools/install.ps1",
    "tools/install.sh",
    "tools/loom_install.py",
    "tools/loom_audit.py",
    "tools/loom_lint.py",
    "tools/loom_survey.py",
    "tools/loom_kickoff.py",
    "tools/loom_gate.py",
    "tools/loom_memory.py",
    "tools/loom_domain.py",
    "tools/loom_release_check.py",
    "tools/loom_benchmark.py",
    "tools/loom_context.py",
    "tools/loom_tier.py",
    "tools/loom_migrate.py",
    "tools/loom_report.py",
    "tools/loom_publish.py",
    "tools/gen_assets.py",
    "tools/test_loom_audit.py",
    "tools/test_loom_lint.py",
    "tools/test_loom_tools.py",
    "tools/test_loom_migrate.py",
    "tools/test_loom_pipeline.py",
    "tools/test_loom_privacy.py",
    "tools/test_loom_report.py",
    "tools/test_loom_guard.py",
    "tools/test_loom_gate.py",
    "tools/test_loom_memory.py",
    "tools/test_loom_domain.py",
    "tools/test_loom_install.py",
    "tools/test_loom_release_check.py",
    "tools/test_loom_benchmark.py",
    "tools/test_loom_tier.py",
    "tools/test_loom_context_budget.py",
    "tools/test_loom_publish.py",
]

# Overlay-managed paths: public/<rel> wins; falls back to root <rel> when absent
# (that fallback is what makes a published cut re-publishable by its owner).
OVERLAY = [
    "README.md",
    "PRIVACY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "BENCHMARK.md",
    "FEEDBACK.md",
    "assets",
    "docs",
    ".github",
    "tools/publish-tokens.txt",
]

MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)")
MD_REF_RE = re.compile(r"(?m)^\s*\[[^\]]+\]:\s*(\S+)")
CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^)'\"\s]+)", re.IGNORECASE)


class _HTMLReferences(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.anchors = set()

    def handle_starttag(self, tag, attrs):
        line, _ = self.getpos()
        for key, value in attrs:
            if not value:
                continue
            low = key.lower()
            if low in {"id", "name"}:
                self.anchors.add(value)
            if low in {"href", "src", "poster", "xlink:href"}:
                self.references.append((line, value))


def _markdown_anchors(text):
    anchors = set()
    counts = {}
    for raw in text.splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", raw)
        if not match:
            continue
        label = re.sub(r"<[^>]+>", "", match.group(1)).strip().lower()
        slug = re.sub(r"[^\w\- ]", "", label, flags=re.UNICODE)
        slug = re.sub(r"[\s-]+", "-", slug).strip("-")
        index = counts.get(slug, 0)
        counts[slug] = index + 1
        anchors.add(slug if index == 0 else f"{slug}-{index}")
    return anchors


def _is_external_reference(ref):
    low = ref.lower()
    return low.startswith(("http://", "https://", "mailto:", "data:",
                           "javascript:", "tel:", "//"))


def _target_anchors(path):
    text = path.read_text(encoding="utf-8", errors="strict")
    if path.suffix.lower() == ".md":
        return _markdown_anchors(text)
    if path.suffix.lower() in {".html", ".htm", ".svg"}:
        parser = _HTMLReferences()
        parser.feed(text)
        return parser.anchors
    return set()


def _check_reference(out, source, rel, line, raw):
    ref = raw.strip().strip("<>")
    if not ref or _is_external_reference(ref):
        return None
    path_part, _, anchor = ref.partition("#")
    path_part = path_part.split("?", 1)[0]
    if not path_part:
        target = source
    elif path_part.startswith("/"):
        target = out / path_part.lstrip("/")
    else:
        target = source.parent / path_part
    target = target.resolve()
    try:
        target.relative_to(out.resolve())
    except ValueError:
        return f"LINK     {rel}:{line} -> {raw} escapes the output tree"
    if target.is_dir():
        target = target / "index.html"
    if not target.is_file():
        return f"LINK     {rel}:{line} -> {raw} does not resolve in the output tree"
    if anchor and anchor not in _target_anchors(target):
        return f"LINK     {rel}:{line} -> {raw} has no matching anchor"
    return None


def _is_same_or_parent(candidate, protected):
    """True when candidate is protected itself or one of its ancestors."""
    return candidate == protected or candidate in protected.parents


def _marker_is_valid(out):
    marker = out / OUTPUT_MARKER
    if not marker.is_file():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if data.get("format") != MARKER_FORMAT or data.get("version") != MARKER_VERSION:
        return False
    if data.get("source_version") != SOURCE_VERSION:
        return False
    expected = data.get("files")
    try:
        actual = _tree_hashes(out)
    except (OSError, UnicodeError, ValueError):
        return False
    return isinstance(expected, dict) and expected == actual


def _tree_hashes(out):
    hashes = {}
    for path in sorted(out.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"output contains a symlink: {path}")
        if not path.is_file() or path.name == OUTPUT_MARKER:
            continue
        rel = path.relative_to(out).as_posix()
        hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def _write_marker(out):
    data = {
        "format": MARKER_FORMAT,
        "version": MARKER_VERSION,
        "source_version": SOURCE_VERSION,
        "files": _tree_hashes(out),
    }
    (out / OUTPUT_MARKER).write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")


def _is_macos_system_var_alias(path):
    """Recognize the fixed macOS /var compatibility alias, never arbitrary symlinks."""
    return sys.platform == "darwin" \
        and path == Path("/var") \
        and path.resolve() == Path("/private/var")


def validate_output_path(out_dir, *, allow_outside=False,
                         replace_existing=False):
    """Return a safe resolved output path or raise ValueError.

    Only the versioned canonical dist/public-<VERSION> path is implicit. A custom path requires an
    explicit opt-in, and an existing directory is replaceable only when it carries
    Loom's ownership marker. No flag can authorize replacing an unmarked directory.
    """
    raw = Path(out_dir).expanduser().absolute()
    for component in (raw, *raw.parents):
        if component.exists() and component.is_symlink() \
                and not _is_macos_system_var_alias(component):
            raise ValueError(f"output path contains a symlink component: {component}")
    out = raw.resolve()
    root = ROOT.resolve()
    protected = {root, Path.cwd().resolve(), Path.home().resolve(),
                 Path(out.anchor).resolve()}
    for path in protected:
        if _is_same_or_parent(out, path):
            raise ValueError(f"dangerous output path: {out}")

    canonical = out == DEFAULT_OUT
    if not canonical:
        if root == out or root in out.parents:
            raise ValueError("custom output paths inside the Loom source tree are forbidden")
        if not allow_outside:
            raise ValueError("custom output requires --allow-outside-dist")
        if not out.parent.is_dir():
            raise ValueError("custom output parent must already exist and be a directory")

    if out.exists():
        if not out.is_dir():
            raise ValueError("output exists and is not a directory")
        if not _marker_is_valid(out):
            raise ValueError(
                f"existing output is not Loom-owned (missing valid {OUTPUT_MARKER})")
        if not canonical and not replace_existing:
            raise ValueError("replacing custom output requires --replace-existing-output")
    return out


def _activate_staged_output(stage, out):
    """Swap a verified stage into place; roll back if activation fails."""
    if not out.exists():
        stage.rename(out)
        return None
    backup = out.parent / f".{out.name}.loom-backup-{uuid.uuid4().hex}"
    out.rename(backup)
    try:
        stage.rename(out)
    except OSError as activation_error:
        try:
            backup.rename(out)
        except OSError as rollback_error:
            raise OSError(
                f"activation failed ({activation_error}); automatic rollback also failed "
                f"({rollback_error}); verified prior output is preserved at {backup}") \
                from rollback_error
        raise OSError(
            f"activation failed and the prior output was restored: {activation_error}") \
            from activation_error
    try:
        shutil.rmtree(backup)
    except OSError as exc:
        return f"verified prior output retained as backup {backup}: {exc}"
    return None


def _assert_source_tree_safe(src):
    """Refuse source symlinks so an allowlisted path cannot escape the source tree."""
    root = ROOT.resolve()
    try:
        src.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise OSError(f"allowlisted source escapes or cannot be resolved: {src}") from exc
    if src.is_symlink():
        raise OSError(f"allowlisted source is a symlink: {src}")
    if src.is_dir():
        for path in src.rglob("*"):
            if path.is_symlink():
                raise OSError(f"allowlisted source contains a symlink: {path}")


def _cleanup_stage(stage, expected_parent, expected_prefix):
    """Remove only the exact temporary directory created by this process."""
    if not stage or not stage.exists():
        return None
    try:
        if stage.is_symlink() or stage.parent.resolve() != expected_parent.resolve() \
                or not stage.name.startswith(expected_prefix):
            return f"refused to clean ambiguous staging path {stage}"
        shutil.rmtree(stage)
    except OSError as exc:
        return f"could not remove tool-owned staging directory {stage}: {exc}"
    return None


def _cleanup_test_artifacts(root):
    """Remove only interpreter/report cache artifacts from the tool-owned stage."""
    for directory in sorted(root.rglob("__pycache__"), reverse=True):
        if directory.is_symlink():
            raise OSError(f"test suite created a symlinked cache directory: {directory}")
        if directory.is_dir():
            shutil.rmtree(directory)
    for pattern in ("*.pyc", "report.html"):
        for path in root.rglob(pattern):
            if path.is_symlink():
                raise OSError(f"test suite created a symlinked artifact: {path}")
            if path.is_file():
                path.unlink()


def _tree_delta(before, after):
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = sorted(path for path in before.keys() & after.keys()
                     if before[path] != after[path])
    return added, removed, changed


def load_tokens(path):
    """Returns (patterns, allowed). `allow:` lines name exact substrings that are
    deliberately public (the artifact's own URLs); they are removed from each line
    before token matching, so raw identity tokens still trip everywhere else."""
    pats, allowed = [], []
    if not path.is_file():
        return pats, allowed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("allow:"):
            allowed.append(line[6:].strip())
        elif line.startswith("re:"):
            pats.append((line, re.compile(line[3:])))
        else:
            pats.append((line, re.compile(re.escape(line), re.IGNORECASE)))
    return pats, allowed


def copy_path(rel, out):
    src = ROOT / rel
    dst = out / rel
    if src.exists() or src.is_symlink():
        _assert_source_tree_safe(src)
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc",
                                                      "report.html"))
        return True
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    return False


def overlay_path(rel, out):
    for base in (ROOT / "public", ROOT):
        src = base / rel
        if src.exists():
            _assert_source_tree_safe(src)
            dst = out / rel
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            return str(src.relative_to(ROOT))
    return None


def scan(out, tokens, allowed=()):
    """Firewall + secret scan + md link check over every shipped file.

    Public output is deliberately UTF-8 text-only. An opaque or differently encoded
    file blocks publication instead of receiving an unearned clean result.
    """
    findings = []
    files = [f for f in sorted(out.rglob("*")) if f.is_file()]
    for f in files:
        rel = f.relative_to(out).as_posix()
        path_scan = rel
        for a in allowed:
            path_scan = path_scan.replace(a, "")
        for label, pat in tokens:
            if pat.search(path_scan):
                findings.append(
                    f"FIREWALL-PATH {rel} matches forbidden token '{label}'")
        try:
            text = f.read_text(encoding="utf-8", errors="strict")
        except (UnicodeError, OSError) as exc:
            findings.append(f"ENCODING {rel} is not readable UTF-8 text: {exc}")
            continue
        for n, line in enumerate(text.splitlines(), start=1):
            scanline = line
            for a in allowed:
                scanline = scanline.replace(a, "")
            for label, pat in tokens:
                if pat.search(scanline):
                    findings.append(f"FIREWALL {rel}:{n} matches forbidden token "
                                    f"'{label}'")
            candidate = PLACEHOLDER_RE.sub("<SAFE_PLACEHOLDER>", line)
            for spat in SECRET_PATTERNS:
                if spat.search(candidate):
                    findings.append(f"SECRET   {rel}:{n} secret-shaped content")
        references = []
        suffix = f.suffix.lower()
        if suffix == ".md":
            for regex in (MD_LINK_RE, MD_REF_RE):
                for match in regex.finditer(text):
                    references.append(
                        (text.count("\n", 0, match.start()) + 1, match.group(1)))
        if suffix in {".html", ".htm", ".svg"}:
            parser = _HTMLReferences()
            parser.feed(text)
            references.extend(parser.references)
        if suffix in {".css", ".html", ".htm", ".svg"}:
            for match in CSS_URL_RE.finditer(text):
                references.append(
                    (text.count("\n", 0, match.start()) + 1, match.group(1)))
        for line, reference in references:
            finding = _check_reference(out, f, rel, line, reference)
            if finding:
                findings.append(finding)
    return findings


def build(out_dir, check=False, *, allow_outside=False,
          replace_existing=False):
    import loom_release_check
    try:
        coherence = loom_release_check.source_findings(ROOT)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"loom_publish: source coherence is indeterminate: {exc}", file=sys.stderr)
        return 2
    if coherence:
        for finding in coherence:
            print(f"VERSION  {finding}", file=sys.stderr)
        print("loom_publish: source coherence failed; output untouched", file=sys.stderr)
        return 1
    try:
        out = validate_output_path(out_dir, allow_outside=allow_outside,
                                   replace_existing=replace_existing)
    except ValueError as exc:
        print(f"loom_publish: REFUSED — {exc}", file=sys.stderr)
        return 2
    stage = None
    prefix = f".{out.name}.loom-stage-"
    try:
        if out == DEFAULT_OUT:
            out.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=prefix, dir=str(out.parent)))

        copied, missing = [], []
        for rel in ALLOWLIST:
            (copied if copy_path(rel, stage) else missing).append(rel)
        overlays = []
        for rel in OVERLAY:
            src = overlay_path(rel, stage)
            if src:
                overlays.append(f"{rel} <- {src}")
            else:
                missing.append(rel)
        if missing:
            print("loom_publish: allowlist/overlay entries not found:", file=sys.stderr)
            for item in missing:
                print(f"  {item}", file=sys.stderr)
            return 2

        stage_coherence = loom_release_check.source_findings(stage)
        if stage_coherence:
            for finding in stage_coherence:
                print(f"VERSION  {finding}")
            print("loom_publish: staged public version coherence failed; previous output untouched")
            return 1

        _write_marker(stage)

        tokens, allowed = load_tokens(ROOT / "tools" / "publish-tokens.txt")
        if not tokens:
            if (ROOT / "plans" / "MANIFEST.md").is_file():
                print("CONFIG   owner-layer source has 0 forbidden tokens; refusing "
                      "an unprotected public build")
                return 1
            print("loom_publish: public-template mode — 0 owner tokens expected; "
                  "generic secret and content checks remain active")

        findings = scan(stage, tokens, allowed)
        # the no-network audit must also pass on the output tree
        import loom_audit
        _, audit_findings = loom_audit.audit(stage)
        findings += [f"AUDIT    {item}" for item in audit_findings]
        if findings:
            for item in findings:
                print(item)
            print(f"\nloom_publish: {len(findings)} finding(s) — staged build rejected, "
                  f"nothing activated")
            return 1

        if check:
            before_suite = _tree_hashes(stage)
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "unittest", "discover", "-s", "tools",
                     "-p", "test_*.py"], cwd=str(stage), capture_output=True,
                    text=True, timeout=600)
            except subprocess.TimeoutExpired:
                print("loom_publish: suite timed out inside staging — previous output untouched")
                return 1
            tail = (result.stderr or result.stdout).strip().splitlines()[-1:]
            print(f"suite in output tree: {' '.join(tail)}")
            if result.returncode != 0:
                print("loom_publish: suite FAILED inside staging — previous output untouched")
                return 1
            _cleanup_test_artifacts(stage)
            after_suite = _tree_hashes(stage)
            added, removed, changed = _tree_delta(before_suite, after_suite)
            if added or removed or changed:
                print("loom_publish: suite mutated the staged public tree; refusing activation")
                for label, paths in (("added", added), ("removed", removed),
                                     ("changed", changed)):
                    if paths:
                        shown = ", ".join(paths[:20])
                        suffix = f" (+{len(paths) - 20} more)" if len(paths) > 20 else ""
                        print(f"SUITE-{label.upper()} {shown}{suffix}")
                return 1

            post_coherence = loom_release_check.source_findings(stage)
            if post_coherence:
                for finding in post_coherence:
                    print(f"VERSION  {finding}")
                print("loom_publish: suite left staged version coherence invalid")
                return 1
            post_findings = scan(stage, tokens, allowed)
            _, post_audit_findings = loom_audit.audit(stage)
            post_findings += [f"AUDIT    {item}" for item in post_audit_findings]
            if post_findings:
                for item in post_findings:
                    print(item)
                print("loom_publish: post-suite firewall/audit failed; refusing activation")
                return 1

        _write_marker(stage)
        warning = _activate_staged_output(stage, out)
        if warning:
            print(f"loom_publish: WARNING — {warning}", file=sys.stderr)
        n_files = sum(1 for path in out.rglob("*") if path.is_file())
        print(f"loom_publish: built {out} — {n_files} files; every shipped file and "
              "filename passed the UTF-8 firewall; local Markdown/HTML/SVG/CSS "
              "references valid" + (", suite green and stage unchanged" if check else ""))
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"loom_publish: REFUSED — staging/activation I/O failed: {exc}; "
              "previous verified output was not intentionally removed", file=sys.stderr)
        return 2
    finally:
        warning = _cleanup_stage(stage, out.parent, prefix)
        if warning:
            print(f"loom_publish: WARNING — {warning}", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the public cut (core only)")
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help=f"output directory (default: dist/public-{SOURCE_VERSION})")
    ap.add_argument("--check", action="store_true",
                    help="also run the test suite inside the output tree")
    ap.add_argument("--allow-outside-dist", action="store_true",
                    help="allow a custom output outside this Loom source tree")
    ap.add_argument("--replace-existing-output", action="store_true",
                    help="replace a verified Loom-owned custom output")
    ap.add_argument("--json", action="store_true",
                    help="emit one machine-readable result object")
    args = ap.parse_args(argv)
    kwargs = {
        "check": args.check,
        "allow_outside": args.allow_outside_dist,
        "replace_existing": args.replace_existing_output,
    }
    if not args.json:
        return build(args.out, **kwargs)

    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = build(args.out, **kwargs)
    out = Path(args.out).expanduser().resolve()
    payload = {
        "schema_version": 1,
        "status": {0: "built", 1: "blocked", 2: "refused"}.get(code, "failed"),
        "exit_code": code,
        "output": str(out),
        "output_exists": out.is_dir(),
        "shipped_file_count": (
            sum(1 for path in out.rglob("*") if path.is_file())
            if out.is_dir() else 0),
        "check_requested": bool(args.check),
        "messages": [
            *({"stream": "stdout", "text": line}
              for line in stdout.getvalue().splitlines() if line),
            *({"stream": "stderr", "text": line}
              for line in stderr.getvalue().splitlines() if line),
        ],
    }
    print(json.dumps(payload, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
