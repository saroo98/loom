#!/usr/bin/env python3
"""loom_report — render a Loom planning pack as one self-contained HTML page.

The pack view: header stamps with live drift status, frontier chips, work-order DAG,
ledger and decision tables, outcomes summary, and the live lint findings embedded —
this tool imports loom_lint rather than reimplementing it, so the page always tells
the truth the gate would see. Stdlib only; zero network; light/dark via
prefers-color-scheme.

The output is DISPOSABLE by design: git-ignore it, regenerate any time
(`/loom report`). A committed report is a stale generated artifact — a lie in a
system about staleness.

Usage:
    python loom_report.py <pack_path> [--repo <target_repo_root>] [--out <file>]

Exit codes: 0 = report written (pack may still have lint findings — they are IN the
report), 2 = usage/IO problem.
"""

import argparse
import datetime as dt
import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from loom_lint import (Report, parse_frontmatter, parse_ledger, lint,  # noqa: E402
                       git_head, heads_match, pack_only_drift, current_version)

MAX_DAG_NODES = 30  # beyond this the SVG is spaghetti; the table below it remains

CSS = """
:root { --bg:#ffffff; --fg:#1a1a1a; --mut:#6b7280; --line:#e5e7eb; --card:#f9fafb;
  --ok:#15803d; --okbg:#dcfce7; --warn:#b45309; --warnbg:#fef3c7; --err:#b91c1c;
  --errbg:#fee2e2; --info:#1d4ed8; --infobg:#dbeafe; --gray:#4b5563; --graybg:#f3f4f6; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#111418; --fg:#e5e7eb; --mut:#9ca3af; --line:#2d333b; --card:#1a1f26;
  --ok:#4ade80; --okbg:#14321f; --warn:#fbbf24; --warnbg:#3a2c10; --err:#f87171;
  --errbg:#3b1516; --info:#93c5fd; --infobg:#172a46; --gray:#9ca3af; --graybg:#22272e; } }
* { box-sizing: border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
  font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
h1 { font-size:20px; margin:0 0 4px; } h2 { font-size:15px; margin:28px 0 8px; }
.sub { color:var(--mut); margin:0 0 16px; }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }
.chip { padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; }
table { border-collapse:collapse; width:100%; margin:8px 0; }
th,td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line);
  vertical-align:top; }
th { color:var(--mut); font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
.wrap { overflow-x:auto; border:1px solid var(--line); border-radius:8px;
  background:var(--card); padding:8px; }
.s { padding:1px 8px; border-radius:999px; font-size:11px; font-weight:600;
  white-space:nowrap; }
.s-done,.s-verified,.s-gated { background:var(--okbg); color:var(--ok); }
.s-ready,.s-active { background:var(--infobg); color:var(--info); }
.s-in-progress,.s-open,.s-draft { background:var(--warnbg); color:var(--warn); }
.s-blocked,.s-broken,.s-stale { background:var(--errbg); color:var(--err); }
.s-cancelled,.s-retired,.s-superseded { background:var(--graybg); color:var(--gray); }
.sev-ERROR { color:var(--err); font-weight:700; } .sev-WARN { color:var(--warn); }
.mono { font-family:ui-monospace,Consolas,monospace; font-size:12px; }
.clean { color:var(--ok); font-weight:600; }
svg text { font:11px system-ui,sans-serif; fill:var(--fg); }
svg .edge { stroke:var(--mut); stroke-width:1.2; fill:none; }
footer { margin-top:32px; color:var(--mut); font-size:12px;
  border-top:1px solid var(--line); padding-top:10px; }
"""

NODE_FILL = {"done": "var(--okbg)", "ready": "var(--infobg)",
             "in-progress": "var(--warnbg)", "blocked": "var(--errbg)",
             "draft": "var(--graybg)", "cancelled": "var(--graybg)"}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def chip(label, cls):
    return f'<span class="chip s-{cls}" style="font-size:12px">{esc(label)}</span>'


def status_cell(st):
    return f'<span class="s s-{esc(st)}">{esc(st)}</span>'


def read_wos(pack):
    wos = {}
    wo_dir = pack / "work-orders"
    for f in sorted(wo_dir.glob("*.md")) if wo_dir.is_dir() else []:
        fm, _ = parse_frontmatter(f.read_text(encoding="utf-8", errors="replace"))
        if not fm or not fm.get("id"):
            continue
        deps = fm.get("depends_on", [])
        if isinstance(deps, str):
            deps = [deps] if deps else []
        touches = fm.get("touches", [])
        if isinstance(touches, str):
            touches = [touches] if touches else []
        wos[fm["id"]] = {"title": fm.get("title", ""), "status": fm.get("status", ""),
                         "routing": fm.get("routing", ""), "size": fm.get("size", ""),
                         "deps": [d for d in deps if str(d).startswith("WO-")],
                         "touches": touches, "file": f.name}
    return wos


def topo_depth(wos):
    depth = {}

    def d(w, seen):
        if w in depth:
            return depth[w]
        if w in seen:
            return 0  # cycle — lint E09's problem, not the renderer's
        seen.add(w)
        ds = [d(x, seen) + 1 for x in wos[w]["deps"] if x in wos]
        depth[w] = max(ds) if ds else 0
        return depth[w]

    for w in wos:
        d(w, set())
    return depth


def dag_svg(wos):
    if not wos or len(wos) > MAX_DAG_NODES:
        return ""
    depth = topo_depth(wos)
    cols = {}
    for w in sorted(wos):
        cols.setdefault(depth[w], []).append(w)
    BW, BH, XG, YG, PAD = 176, 42, 60, 18, 12
    pos = {}
    for c, members in cols.items():
        for r, w in enumerate(members):
            pos[w] = (PAD + c * (BW + XG), PAD + r * (BH + YG))
    width = PAD * 2 + (max(cols) + 1) * (BW + XG) - XG
    height = PAD * 2 + max(len(m) for m in cols.values()) * (BH + YG) - YG
    parts = [f'<svg viewBox="0 0 {width} {height}" width="{width}" '
             f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="work-order DAG">']
    parts.append('<defs><marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" '
                 'markerWidth="6" markerHeight="6" orient="auto">'
                 '<path d="M0,0 L8,4 L0,8 z" fill="var(--mut)"/></marker></defs>')
    for w, meta in wos.items():
        x2, y2 = pos[w]
        for dep in meta["deps"]:
            if dep in pos:
                x1, y1 = pos[dep]
                parts.append(f'<path class="edge" marker-end="url(#arr)" '
                             f'd="M{x1 + BW},{y1 + BH // 2} C{x1 + BW + XG // 2},'
                             f'{y1 + BH // 2} {x2 - XG // 2},{y2 + BH // 2} '
                             f'{x2},{y2 + BH // 2}"/>')
    for w, (x, y) in pos.items():
        st = wos[w]["status"]
        fill = NODE_FILL.get(st, "var(--graybg)")
        title = wos[w]["title"]
        title = title if len(title) <= 24 else title[:23] + "…"
        parts.append(f'<g><rect x="{x}" y="{y}" width="{BW}" height="{BH}" rx="7" '
                     f'fill="{fill}" stroke="var(--line)"/>'
                     f'<text x="{x + 9}" y="{y + 17}" font-weight="700">{esc(w)}'
                     f' <tspan font-weight="400" fill="var(--mut)">{esc(st)}</tspan></text>'
                     f'<text x="{x + 9}" y="{y + 33}">{esc(title)}</text></g>')
    parts.append("</svg>")
    return "".join(parts)


def read_decisions(pack):
    f = pack / "decisions.md"
    if not f.is_file():
        return []
    out = []
    for m in re.finditer(r"^##\s+(D-\d{3,})\s*:\s*(.+)$",
                         f.read_text(encoding="utf-8", errors="replace"), re.M):
        out.append((m.group(1), m.group(2).strip()))
    return out


def outcomes_summary(pack):
    f = pack / "outcomes.md"
    if not f.is_file():
        return None
    rows = 0
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("|") and not re.match(r"^\|[\s\-|]+\|?$", s) \
                and "Prediction" not in s and not s.lower().startswith("| #"):
            rows += 1
    return rows


def build(pack_path, repo_path=None):
    pack = Path(pack_path)
    manifest = pack / "MANIFEST.md"
    mfm = {}
    if manifest.is_file():
        mfm, _ = parse_frontmatter(manifest.read_text(encoding="utf-8", errors="replace"))
        mfm = mfm or {}
    project = mfm.get("project", pack.parent.name)
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    # drift status (same logic the gate sees)
    drift = None
    if repo_path:
        head = git_head(repo_path)
        rh = str(mfm.get("repo_head", "") or "")
        if head and rh:
            if heads_match(head, rh):
                drift = ("clean", f"repo_head {rh} = repo HEAD")
            else:
                try:
                    rel = pack.resolve().relative_to(Path(repo_path).resolve()).as_posix()
                except ValueError:
                    rel = None
                if pack_only_drift(repo_path, rh, rel):
                    drift = ("clean", f"only the pack moved since {rh} (restamp noise)")
                else:
                    drift = ("stale", f"repo_head {rh} behind HEAD {head} — run the recheck")

    wos = read_wos(pack)
    rep = Report()
    ledger = {}
    lf = pack / "assumptions.md"
    if lf.is_file():
        ledger = parse_ledger(rep, lf, lf.read_text(encoding="utf-8", errors="replace"))
    decisions = read_decisions(pack)
    out_rows = outcomes_summary(pack)
    reviews = sorted(f.name for f in (pack / "reviews").glob("*.md")) \
        if (pack / "reviews").is_dir() else []
    findings = lint(pack, repo_path).findings

    # ---- assemble ----
    H = [f"<title>{esc(project)} — Loom pack</title><style>{CSS}</style>"]
    H.append(f"<h1>{esc(project)}</h1>")
    H.append(f'<p class="sub">tier {esc(mfm.get("tier", "?"))} · '
             f'pack status {status_cell(mfm.get("status", "?"))} · '
             f'loom {esc(mfm.get("loom_version", "?"))} · '
             f'last_verified {esc(mfm.get("last_verified", "?"))}</p>')
    if drift:
        cls, msg = ("gated", drift[1]) if drift[0] == "clean" else ("stale", drift[1])
        H.append(f'<div class="chips">{chip("freshness: " + drift[0], cls)}'
                 f'<span class="mono" style="color:var(--mut)">{esc(msg)}</span></div>')

    # frontier chips
    counts = {}
    for w in wos.values():
        counts[w["status"]] = counts.get(w["status"], 0) + 1
    H.append('<div class="chips">'
             + "".join(chip(f"{st}: {n}", st) for st, n in sorted(counts.items()))
             + (chip("no work orders", "draft") if not wos else "") + "</div>")

    if wos:
        H.append("<h2>Work orders</h2>")
        svg = dag_svg(wos)
        if svg:
            H.append(f'<div class="wrap">{svg}</div>')
        elif len(wos) > MAX_DAG_NODES:
            H.append(f'<p class="sub">{len(wos)} work orders — DAG drawing capped at '
                     f'{MAX_DAG_NODES}; table below is complete.</p>')
        H.append('<div class="wrap"><table><tr><th>ID</th><th>Title</th><th>Status</th>'
                 '<th>Routing</th><th>Size</th><th>Depends on</th><th>Touches</th></tr>')
        for wid, w in sorted(wos.items()):
            H.append(f"<tr><td class='mono'>{esc(wid)}</td><td>{esc(w['title'])}</td>"
                     f"<td>{status_cell(w['status'])}</td><td>{esc(w['routing'])}</td>"
                     f"<td>{esc(w['size'])}</td>"
                     f"<td class='mono'>{esc(', '.join(w['deps']) or '—')}</td>"
                     f"<td class='mono'>{esc(', '.join(w['touches']) or '—')}</td></tr>")
        H.append("</table></div>")

    if ledger:
        H.append("<h2>Assumption ledger</h2>")
        H.append('<div class="wrap"><table><tr><th>ID</th><th>Status</th><th>Risk</th>'
                 '<th>Verify by</th><th>Used in</th></tr>')
        for aid, e in sorted(ledger.items()):
            st = (e.get("status", "") or "").split()[0]
            H.append(f"<tr><td class='mono'>{esc(aid)}</td><td>{status_cell(st)}</td>"
                     f"<td>{esc(e.get('risk_if_wrong', ''))}</td>"
                     f"<td>{esc(e.get('verify_by', ''))}</td>"
                     f"<td class='mono'>{esc(e.get('used_in', ''))}</td></tr>")
        H.append("</table></div>")

    if decisions:
        H.append("<h2>Decisions</h2><div class='wrap'><table>")
        for did, title in decisions:
            H.append(f"<tr><td class='mono'>{esc(did)}</td><td>{esc(title)}</td></tr>")
        H.append("</table></div>")

    extra = []
    if out_rows is not None:
        extra.append(f"outcomes.md: {out_rows} recorded row(s)")
    if reviews:
        extra.append("reviews: " + ", ".join(reviews))
    if extra:
        H.append(f'<p class="sub">{esc(" · ".join(extra))}</p>')

    H.append("<h2>Lint (live)</h2>")
    if not findings:
        H.append('<p class="clean">mechanically clean — 0 errors, 0 warnings</p>')
    else:
        errs = sum(1 for f in findings if f["sev"] == "ERROR")
        H.append(f'<p class="sub">{errs} error(s), {len(findings) - errs} warning(s)'
                 + (" — gates blocked" if errs else "") + "</p>")
        H.append('<div class="wrap"><table><tr><th>Sev</th><th>Code</th><th>Where</th>'
                 '<th>Finding</th></tr>')
        for f in sorted(findings, key=lambda x: (x["sev"] != "ERROR", x["path"])):
            where = f"{Path(f['path']).name}:{f['line']}"
            H.append(f"<tr><td class='sev-{f['sev']}'>{esc(f['sev'])}</td>"
                     f"<td class='mono'>{esc(f['code'])}</td>"
                     f"<td class='mono'>{esc(where)}</td><td>{esc(f['msg'])}</td></tr>")
        H.append("</table></div>")

    H.append(f"<footer>Generated {now} by loom_report (Loom {current_version()}). "
             f"Disposable — regenerate with <span class='mono'>/loom report</span>; "
             f"do not commit.</footer>")
    return "<!doctype html>\n<meta charset='utf-8'>\n" \
           "<meta name='viewport' content='width=device-width, initial-scale=1'>\n" \
           + "\n".join(H)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a Loom pack as one HTML page")
    ap.add_argument("pack", help="path to the plans/ directory")
    ap.add_argument("--repo", help="target repo root (enables freshness/drift status)")
    ap.add_argument("--out", help="output file (default: <pack>/report.html)")
    args = ap.parse_args(argv)
    pack = Path(args.pack)
    if not pack.is_dir():
        print(f"loom_report: pack path not found: {pack}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else pack / "report.html"
    out.write_text(build(pack, args.repo), encoding="utf-8")
    print(f"loom_report: wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
