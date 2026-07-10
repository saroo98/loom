#!/usr/bin/env python3
"""loom_publish — build the public cut of a Loom repo (core only, leak-firewalled).

A Loom repo = core (the generic method) + owner-layer (everything the owner's loop
grew: self-pack, evidence, plan docs, domain deep-dives, FEEDBACK/CHANGELOG contents).
This tool builds `dist/public/` containing core only:

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
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from loom_lint import SECRET_PATTERNS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# Only these leave the repo. Directories are copied recursively.
ALLOWLIST = [
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
    "tools/loom_audit.py",
    "tools/loom_lint.py",
    "tools/loom_survey.py",
    "tools/loom_kickoff.py",
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
    "tools/test_loom_publish.py",
]

# Overlay-managed paths: public/<rel> wins; falls back to root <rel> when absent
# (that fallback is what makes a published cut re-publishable by its owner).
OVERLAY = [
    "README.md",
    "PRIVACY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "FEEDBACK.md",
    "assets",
    "docs",
    ".github",
    "tools/publish-tokens.txt",
]

MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)#\s]+)")
TEXT_EXT = {".md", ".py", ".json", ".txt", ".ps1", ".sh", ""}


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
            dst = out / rel
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            return str(src.relative_to(ROOT))
    return None


def scan(out, tokens, allowed=()):
    """Firewall + secret scan + md link check. Returns list of findings."""
    findings = []
    files = [f for f in sorted(out.rglob("*"))
             if f.is_file() and f.suffix.lower() in TEXT_EXT]
    for f in files:
        rel = f.relative_to(out).as_posix()
        if rel == "tools/publish-tokens.txt":
            continue  # the template's own examples are not leaks
        text = f.read_text(encoding="utf-8", errors="replace")
        is_test = rel.startswith("tools/test_")
        for n, line in enumerate(text.splitlines(), start=1):
            scanline = line
            for a in allowed:
                scanline = scanline.replace(a, "")
            for label, pat in tokens:
                if pat.search(scanline):
                    findings.append(f"FIREWALL {rel}:{n} matches forbidden token "
                                    f"'{label}'")
            if is_test:
                continue  # test files legitimately contain secret-SHAPED fixtures;
                          # the token firewall above still applies to them
            for spat in SECRET_PATTERNS:
                if spat.search(line) and not re.search(
                        r"<[A-Z_ ]+>|\{\{.*\}\}|\$\{.*\}|xxx+|<value>", line):
                    findings.append(f"SECRET   {rel}:{n} secret-shaped content")
        if f.suffix.lower() == ".md":
            for m in MD_LINK_RE.finditer(text):
                target = m.group(1)
                if "://" in target or target.startswith("mailto:"):
                    continue
                if not (f.parent / target).exists():
                    findings.append(f"LINK     {rel} -> {target} does not resolve "
                                    f"in the output tree")
    return findings


def build(out_dir, check=False):
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    copied, missing = [], []
    for rel in ALLOWLIST:
        (copied if copy_path(rel, out) else missing).append(rel)
    overlays = []
    for rel in OVERLAY:
        src = overlay_path(rel, out)
        if src:
            overlays.append(f"{rel} <- {src}")
        else:
            missing.append(rel)
    if missing:
        print("loom_publish: allowlist/overlay entries not found:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)
        shutil.rmtree(out)
        return 2

    tokens, allowed = load_tokens(ROOT / "tools" / "publish-tokens.txt")
    if not tokens:
        print("loom_publish: WARNING — 0 firewall tokens loaded "
              "(tools/publish-tokens.txt); add your own before publishing")

    findings = scan(out, tokens, allowed)
    # the no-network audit must also pass on the output tree
    import loom_audit
    _, audit_findings = loom_audit.audit(out)
    findings += [f"AUDIT    {x}" for x in audit_findings]
    if findings:
        for x in findings:
            print(x)
        print(f"\nloom_publish: {len(findings)} finding(s) — build REMOVED, "
              f"nothing to publish")
        shutil.rmtree(out)
        return 1

    if check:
        r = subprocess.run([sys.executable, "-m", "unittest", "discover",
                            "-s", "tools", "-p", "test_*.py"],
                           cwd=str(out), capture_output=True, text=True, timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()[-1:]
        print(f"suite in output tree: {' '.join(tail)}")
        if r.returncode != 0:
            print("loom_publish: suite FAILED inside the output tree — build kept "
                  "for debugging, do not publish")
            return 1

    n_files = sum(1 for f in out.rglob("*") if f.is_file())
    print(f"loom_publish: built {out} — {n_files} files, firewall clean, links ok"
          + (", suite green" if check else ""))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the public cut (core only)")
    ap.add_argument("--out", default=str(ROOT / "dist" / "public"),
                    help="output directory (default: dist/public)")
    ap.add_argument("--check", action="store_true",
                    help="also run the test suite inside the output tree")
    args = ap.parse_args(argv)
    return build(args.out, check=args.check)


if __name__ == "__main__":
    sys.exit(main())
