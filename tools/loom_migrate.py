#!/usr/bin/env python3
"""loom_migrate — carry a planning pack forward between Loom versions.

Packs record the Loom version that produced them (MANIFEST frontmatter `loom_version`).
This tool applies the known migrations from that version to the current one, so old packs
keep working instead of silently drifting from the guidance. Dry-run by default; `--apply`
edits. Idempotent: re-running an applied migration changes nothing.

Usage:
    python loom_migrate.py <pack_path> [--apply] [--target <version>]

Exit codes: 0 up-to-date or migrated, 1 actions pending (dry-run found work), 2 usage/IO.
"""

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from loom_lint import parse_frontmatter, current_version, vtuple as vt  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent


# --- migrations ----------------------------------------------------------------

def mig_020(pack, apply, log):
    """0.1.0 -> 0.2.0: autonomy/config era. Advisory only — no pack-file shape changed."""
    log("note", "0.2.0: consider creating loom.config.json at the target repo root "
                "(templates/loom.config.json) — autonomy level, decision budget, routing map")
    return False  # nothing file-changing


def mig_030(pack, apply, log):
    """0.2.0 -> 0.3.0: add `touches: []` to work orders that lack it."""
    changed = False
    wo_dir = pack / "work-orders"
    for f in sorted(wo_dir.glob("*.md")) if wo_dir.is_dir() else []:
        text = f.read_text(encoding="utf-8", errors="replace")
        fm, _ = parse_frontmatter(text)
        if fm is None or "touches" in fm:
            continue
        changed = True
        if apply:
            new = re.sub(r"(?m)^(last_verified\s*:)", "touches: []\n\\1", text, count=1)
            if new == text:  # no last_verified line — insert before closing ---
                new = re.sub(r"(?ms)\A(---\n.*?)(^---$)", "\\1touches: []\n\\2", text, count=1)
            f.write_text(new, encoding="utf-8")
            log("applied", f"{f.name}: added `touches: []` (declare real globs — parallel-work.md)")
        else:
            log("pending", f"{f.name}: would add `touches: []`")
    log("note", "0.3.0: MANIFEST frontier now carries claim columns "
                "(WO/Status/Routing/Claimed by/Claimed at/Heartbeat) — adopt on next edit")
    return changed


def mig_040(pack, apply, log):
    """0.3.0 -> 0.4.0: outcome ledger skeleton."""
    out = pack / "outcomes.md"
    if out.exists():
        return False
    if apply:
        tpl = LOOM_ROOT / "templates" / "pack" / "outcomes.md"
        text = tpl.read_text(encoding="utf-8", errors="replace")
        mfm, _ = parse_frontmatter((pack / "MANIFEST.md").read_text(encoding="utf-8", errors="replace")) \
            if (pack / "MANIFEST.md").is_file() else ({}, 0)
        text = text.replace("<name>", (mfm or {}).get("project", pack.parent.name))
        text = text.replace("<YYYY-MM-DD>", dt.date.today().isoformat())
        out.write_text(text, encoding="utf-8")
        log("applied", "created outcomes.md skeleton (fill at G4/G5 — loom/execution/outcomes.md)")
    else:
        log("pending", "would create outcomes.md skeleton")
    return True


def mig_062(pack, apply, log):
    """0.6.1 -> 0.6.2: sharpened-shuttle era. Advisory only — no pack shape changed."""
    intake = pack / "intake.md"
    if intake.is_file() and "## Silence sweep" not in intake.read_text(encoding="utf-8",
                                                                       errors="replace"):
        log("note", "0.6.2: intake now carries a '## Silence sweep' section for tier M+ "
                    "(loom/intake/intake.md §4) — add hits, or 'swept — no material "
                    "silences'; lint W12 reminds until it exists")
    log("note", "0.6.2: new tools — loom_report.py renders the pack as one HTML page "
                "(/loom report; git-ignore report.html); templates/hooks/pre-commit is "
                "the pack guard (lint at commit time); lint W13 now measures WO heft")
    return False


def mig_070(pack, apply, log):
    """0.6.2 -> 0.7.0: sovereignty era. Advisory only — no pack shape changed."""
    log("note", "0.7.0: contribute now targets YOUR Loom repo's FEEDBACK (sovereign "
                "instances, D-012); lint W14 flags criteria hedged in the same WO's "
                "epistemic notes; tools/loom_publish.py builds a public cut of a Loom "
                "repo (allowlist + firewall) if you ever want one")
    return False


def mig_071(pack, apply, log):
    """0.7.0 -> 0.7.1: real-medium UI design-floor advisory."""
    log("note", "0.7.1: any human-facing UI work order must cite the design floor and "
                "include a real rendered-medium observation; source inspection is not proof")
    return False


def _frontmatter_set(text, key, value):
    pattern = rf"(?m)^{re.escape(key)}\s*:.*$"
    line = f"{key}: {value}"
    if re.search(pattern, text):
        return re.sub(pattern, line, text, count=1)
    close = text.find("\n---", 4)
    if close < 0:
        return text
    return text[:close] + "\n" + line + text[close:]


def mig_080(pack, apply, log):
    """0.7.1 -> 0.8.0: fail-closed lifecycle v2, domain scope, and full WO contract."""
    changed = False
    manifest = pack / "MANIFEST.md"
    text = manifest.read_text(encoding="utf-8", errors="replace")
    fm, _ = parse_frontmatter(text)
    lifecycle = pack / "lifecycle.json"
    lifecycle_v2 = False
    if lifecycle.is_file():
        try:
            import json
            lifecycle_v2 = json.loads(lifecycle.read_text(encoding="utf-8")) \
                .get("schema_version") == 2
        except (OSError, UnicodeError, ValueError):
            lifecycle_v2 = False
    mode = str((fm or {}).get("execution_mode", ""))
    if not mode or (mode == "planned" and not lifecycle_v2):
        text = _frontmatter_set(text, "execution_mode", "build-first")
        changed = True
        log("applied" if apply else "pending",
            "MANIFEST execution_mode -> build-first because pre-0.8 causal chronology "
            "cannot be proven; start a fresh lifecycle v2 plan to regain planned credit")
    if not (fm or {}).get("domain_id"):
        text = _frontmatter_set(text, "domain_id", "unclassified")
        changed = True
        log("applied" if apply else "pending", "MANIFEST domain_id -> unclassified")
    if not (fm or {}).get("domain_ids"):
        primary_domain = str((fm or {}).get("domain_id") or "unclassified")
        text = _frontmatter_set(text, "domain_ids", f"[{primary_domain}]")
        changed = True
        log("applied" if apply else "pending",
            f"MANIFEST domain_ids -> [{primary_domain}]")
    if not (fm or {}).get("domain_coverage"):
        text = _frontmatter_set(text, "domain_coverage", "unknown")
        changed = True
        log("applied" if apply else "pending",
            "MANIFEST domain_coverage -> unknown (blocks execution until discovery)")
    if "| domain-discovery.md |" not in text:
        row = ("| domain-discovery.md | produce | 0.8 migration requires domain "
               f"classification | draft | {dt.date.today().isoformat()} |\n")
        match = re.search(r"(?m)^\| work orders \|", text)
        if match:
            text = text[:match.start()] + row + text[match.start():]
        else:
            text += "\n## Migration-required artifact\n\n" + row
        changed = True
        log("applied" if apply else "pending",
            "MANIFEST: add produced domain-discovery.md row")
    if apply:
        manifest.write_text(text, encoding="utf-8")

    discovery = pack / "domain-discovery.md"
    if not discovery.is_file():
        changed = True
        log("applied" if apply else "pending", "create domain-discovery.md in blocked draft state")
        if apply:
            template = (LOOM_ROOT / "templates" / "domain-discovery.md") \
                .read_text(encoding="utf-8")
            template = template.replace("<safe-domain-id>", "unclassified") \
                .replace("<domain>", "unclassified") \
                .replace("<YYYY-MM-DD>", dt.date.today().isoformat()) \
                .replace("<current>", current_version())
            discovery.write_text(template, encoding="utf-8")

    for wo in sorted((pack / "work-orders").glob("*.md")) \
            if (pack / "work-orders").is_dir() else []:
        wo_text = wo.read_text(encoding="utf-8", errors="replace")
        wo_fm, _ = parse_frontmatter(wo_text)
        for key in ("depends_on", "blocks", "touches"):
            if key not in (wo_fm or {}):
                wo_text = _frontmatter_set(wo_text, key, "[]")
                changed = True
                log("applied" if apply else "pending", f"{wo.name}: add required {key}: []")
        if apply:
            wo.write_text(wo_text, encoding="utf-8")
    log("note", "0.8.0: empty touches and unknown domain coverage deliberately block "
                "execution; classify them from current repo/domain evidence, then run strict lint")
    return changed


MIGRATIONS = [
    ("0.2.0", mig_020),
    ("0.3.0", mig_030),
    ("0.4.0", mig_040),
    ("0.6.2", mig_062),
    ("0.7.0", mig_070),
    ("0.7.1", mig_071),
    ("0.8.0", mig_080),
]

# --------------------------------------------------------------------------------


def bump_stamps(pack, target, apply, log):
    """Rewrite loom_version in every pack frontmatter to the target."""
    n = 0
    for f in sorted(pack.rglob("*.md")):
        text = f.read_text(encoding="utf-8", errors="replace")
        new = re.sub(r'(?m)^(loom_version\s*:\s*)["\']?[\d.]+["\']?\s*$',
                     f'\\1"{target}"', text)
        if new != text:
            n += 1
            if apply:
                f.write_text(new, encoding="utf-8")
    if n:
        log("applied" if apply else "pending",
            f"loom_version stamp -> {target} in {n} file(s)")
    return n > 0


def migrate(pack_path, apply=False, target=None):
    pack = Path(pack_path)
    manifest = pack / "MANIFEST.md"
    if not manifest.is_file():
        print(f"loom_migrate: no MANIFEST.md at {pack} — not a pack", file=sys.stderr)
        sys.exit(2)
    mfm, _ = parse_frontmatter(manifest.read_text(encoding="utf-8", errors="replace"))
    pack_v = (mfm or {}).get("loom_version", "0.1.0")
    target = target or current_version()

    entries = []

    def log(kind, msg):
        entries.append((kind, msg))
        print(f"{kind.upper():8} {msg}")

    print(f"loom_migrate: pack at {pack_v}, target {target} "
          f"({'apply' if apply else 'dry-run'})")
    if vt(pack_v) >= vt(target):
        print("up to date — nothing to do")
        return 0

    work = False
    for ver, fn in MIGRATIONS:
        if vt(pack_v) < vt(ver) <= vt(target):
            print(f"-- migration to {ver}: {fn.__doc__.strip().splitlines()[0]}")
            work = fn(pack, apply, log) or work
    work = bump_stamps(pack, target, apply, log) or work

    pending = any(k == "pending" for k, _ in entries)
    if apply:
        print(f"done — pack migrated to {target}. Run loom_lint next; review 'note' items manually.")
        return 0
    if pending or work:
        print("dry-run complete — re-run with --apply to perform the changes above")
        return 1
    print("only advisory notes — nothing file-changing pending")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Migrate a Loom pack between Loom versions")
    ap.add_argument("pack", help="path to the plans/ directory")
    ap.add_argument("--apply", action="store_true", help="perform changes (default: dry-run)")
    ap.add_argument("--target", help="target version (default: current Loom version)")
    args = ap.parse_args(argv)
    return migrate(args.pack, args.apply, args.target)


if __name__ == "__main__":
    sys.exit(main())
