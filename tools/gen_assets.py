#!/usr/bin/env python3
"""gen_assets — generate Loom's visual identity (public/assets/*.svg).

One geometry, two palettes: light/dark pairs are guaranteed to match because they
come from the same template. Hand-authored shapes, no external assets, no fonts
beyond the system sans stack. Re-run any time; output is committed (the assets ARE
source — this script is just how they stay consistent).
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
# upstream tree keeps assets in the public/ overlay; a published cut keeps them at root
OUT = _ROOT / "public" / "assets" if (_ROOT / "public").is_dir() else _ROOT / "assets"

LIGHT = dict(fg="#1f2328", mut="#57606a", line="#d0d7de", card="#f6f8fa",
             a="#4f46e5", b="#0d9488", c="#d97706", warp="#9da7b3",
             fact="#1a7f37", assum="#9a6700", spec="#8250df", unk="#57606a",
             dec="#cf222e", factbg="#dafbe1", assumbg="#fff8c5", specbg="#fbefff",
             unkbg="#f6f8fa", decbg="#ffebe9")
DARK = dict(fg="#e6edf3", mut="#9ca3af", line="#30363d", card="#161b22",
            a="#818cf8", b="#2dd4bf", c="#fbbf24", warp="#484f58",
            fact="#3fb950", assum="#d29922", spec="#a371f7", unk="#8b949e",
            dec="#f85149", factbg="#12261e", assumbg="#272115", specbg="#221a2e",
            unkbg="#1c2128", decbg="#2d1518")

FONT = "font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif'"


def weave(x0, y0, w, h, p, rows=7, cols=13, unfinished=2):
    """A woven-cloth motif: warp verticals + dashed weft rows; the last rows stop
    short (the cloth is still being woven) and a shuttle sits on the working row."""
    e = []
    colw = w / (cols - 1)
    rowh = h / (rows + 1)
    for i in range(cols):
        x = x0 + i * colw
        e.append(f"<line x1='{x:.0f}' y1='{y0}' x2='{x:.0f}' y2='{y0 + h}' "
                 f"stroke='{p['warp']}' stroke-width='1.6'/>")
    yarn = [p["a"], p["b"], p["c"]]
    for r in range(rows):
        y = y0 + (r + 1) * rowh
        col = yarn[r % 3]
        full = r < rows - unfinished
        x2 = x0 + w if full else x0 + w * 0.55
        off = 0 if r % 2 == 0 else 12
        e.append(f"<line x1='{x0}' y1='{y:.0f}' x2='{x2:.0f}' y2='{y:.0f}' "
                 f"stroke='{col}' stroke-width='5' stroke-linecap='round' "
                 f"stroke-dasharray='13 9' stroke-dashoffset='{off}'/>")
        if r == rows - unfinished:  # the working row gets the shuttle
            sx, sy = x2 + 10, y
            e.append(f"<path d='M{sx} {sy} q14 -9 28 0 q-14 9 -28 0 z' "
                     f"fill='{col}' opacity='0.95'/>")
            e.append(f"<path d='M{sx + 28} {sy} q26 4 44 -6' stroke='{col}' "
                     f"stroke-width='1.6' fill='none' stroke-dasharray='3 4'/>")
    return "".join(e)


def banner(p):
    return f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 880 230' role='img' aria-label='Loom — the planning OS that shows its work'>
<rect x='0.5' y='0.5' width='879' height='229' rx='14' fill='{p["card"]}' stroke='{p["line"]}'/>
{weave(36, 30, 250, 170, p)}
<text x='340' y='118' {FONT} font-size='82' font-weight='800' letter-spacing='8' fill='{p["fg"]}'>LOOM</text>
<text x='344' y='156' {FONT} font-size='21' fill='{p["mut"]}'>the planning OS that shows its work</text>
<text x='344' y='188' {FONT} font-size='14' fill='{p["mut"]}'>truth-labeled plans &#183; gates &#183; drift detection &#183; a loop that learns you &#8212; locally</text>
</svg>"""


NODES = [
    ("Intake", "goals + the silence sweep"),
    ("Plan", "artifacts + assumption ledger"),
    ("Gate G1", "lint + verification battery"),
    ("Work orders", "atomic, verifiable, routed"),
    ("Verify", "criteria + negative checks"),
    ("Outcomes", "predictions vs reality"),
    ("Learn", "~/.loom + FEEDBACK — yours"),
    ("Resume", "staleness recheck; repo wins"),
]


def lifecycle(p):
    W, H, NW, NH = 940, 400, 190, 58
    # 8 node positions around a loop: 3 top, 1 right, 3 bottom (reversed), 1 left
    pos = [(60, 40), (375, 40), (690, 40), (690, 171),
           (690, 302), (375, 302), (60, 302), (60, 171)]
    e = [f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {H}' role='img' "
         f"aria-label='the Loom lifecycle loop'>"]
    e.append(f"<rect x='0.5' y='0.5' width='{W - 1}' height='{H - 1}' rx='14' "
             f"fill='{p['card']}' stroke='{p['line']}'/>")
    e.append(f"<defs><marker id='ar' viewBox='0 0 8 8' refX='7' refY='4' "
             f"markerWidth='7' markerHeight='7' orient='auto'>"
             f"<path d='M0,0 L8,4 L0,8 z' fill='{p['mut']}'/></marker></defs>")
    yarn = [p["a"], p["b"], p["c"]]
    for i, (x, y) in enumerate(pos):
        nx, ny = pos[(i + 1) % 8]
        cx1, cy1 = x + NW / 2, y + NH / 2
        cx2, cy2 = nx + NW / 2, ny + NH / 2
        # trim the connector to the node edges (horizontal or vertical hops only)
        if abs(cy1 - cy2) < 1:  # horizontal
            sgn = 1 if cx2 > cx1 else -1
            e.append(f"<line x1='{cx1 + sgn * NW / 2}' y1='{cy1}' "
                     f"x2='{cx2 - sgn * (NW / 2 + 6)}' y2='{cy2}' "
                     f"stroke='{p['mut']}' stroke-width='1.6' marker-end='url(#ar)'/>")
        else:  # vertical
            sgn = 1 if cy2 > cy1 else -1
            e.append(f"<line x1='{cx1}' y1='{cy1 + sgn * NH / 2}' "
                     f"x2='{cx2}' y2='{cy2 - sgn * (NH / 2 + 6)}' "
                     f"stroke='{p['mut']}' stroke-width='1.6' marker-end='url(#ar)'/>")
    for i, ((x, y), (title, sub)) in enumerate(zip(pos, NODES)):
        col = yarn[i % 3]
        e.append(f"<g><rect x='{x}' y='{y}' width='{NW}' height='{NH}' rx='9' "
                 f"fill='{p['card']}' stroke='{col}' stroke-width='1.8'/>"
                 f"<text x='{x + 14}' y='{y + 24}' {FONT} font-size='15' "
                 f"font-weight='700' fill='{p['fg']}'>{title}</text>"
                 f"<text x='{x + 14}' y='{y + 43}' {FONT} font-size='11.5' "
                 f"fill='{p['mut']}'>{sub}</text></g>")
    e.append(f"<text x='{W / 2}' y='{H / 2 - 6}' {FONT} font-size='15' text-anchor='middle' "
             f"font-weight='600' fill='{p['fg']}'>every pass tightens the weave</text>")
    e.append(f"<text x='{W / 2}' y='{H / 2 + 16}' {FONT} font-size='12' text-anchor='middle' "
             f"fill='{p['mut']}'>the repo is the truth &#8212; the plan adapts to it, never the reverse</text>")
    e.append("</svg>")
    return "".join(e)


def growth(p):
    """Three panels: day one (a few threads) -> every run (the loop feeds back) ->
    a year in (dense cloth). The compounding story, drawn instead of claimed."""
    W, H, PW, PH, G = 940, 300, 284, 216, 24
    yarn = [p["a"], p["b"], p["c"]]
    e = [f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {H}' role='img' "
         f"aria-label='a Loom compounds: day one, every run, a year in'>"]
    e.append(f"<rect x='0.5' y='0.5' width='{W - 1}' height='{H - 1}' rx='14' "
             f"fill='{p['card']}' stroke='{p['line']}'/>")
    e.append(f"<defs><marker id='gr' viewBox='0 0 8 8' refX='7' refY='4' "
             f"markerWidth='8' markerHeight='8' orient='auto'>"
             f"<path d='M0,0 L8,4 L0,8 z' fill='{p['mut']}'/></marker></defs>")
    xs = [20, 20 + PW + G, 20 + 2 * (PW + G)]  # 20..304, 328..612, 636..920 (< 940)
    titles = [("day one", "clone · install · /loom — the whole setup"),
              ("every run", "outcomes + calibration flow back in"),
              ("a year in", "fitted to you — no shelf ships this")]
    for i, x in enumerate(xs):
        e.append(f"<rect x='{x}' y='22' width='{PW}' height='{PH}' rx='10' "
                 f"fill='{p['card']}' stroke='{p['line']}'/>")
        title, sub = titles[i]
        e.append(f"<text x='{x + 16}' y='{PH + 52}' {FONT} font-size='15' "
                 f"font-weight='700' fill='{p['fg']}'>{title}</text>")
        e.append(f"<text x='{x + 16}' y='{PH + 72}' {FONT} font-size='11.5' "
                 f"fill='{p['mut']}'>{sub}</text>")
        if i < 2:
            e.append(f"<line x1='{x + PW + 3}' y1='{22 + PH / 2}' "
                     f"x2='{xs[i + 1] - 7}' y2='{22 + PH / 2}' stroke='{p['mut']}' "
                     f"stroke-width='2' marker-end='url(#gr)'/>")
    # panel 1: sparse weave — three weft threads on a small frame
    e.append(weave(xs[0] + 30, 52, PW - 60, PH - 60, p, rows=3, cols=7, unfinished=1))
    # panel 2: the loop — weave feeding a circular arrow back into itself
    cx, cy, r = xs[1] + PW / 2, 22 + PH / 2, 56
    e.append(weave(xs[1] + 30, 52, PW - 60, 60, p, rows=2, cols=7, unfinished=0))
    e.append(f"<path d='M {cx + r} {cy + 26} A {r} {r} 0 1 1 {cx + r * 0.5} "
             f"{cy - 20}' fill='none' stroke='{p['b']}' stroke-width='3.5' "
             f"marker-end='url(#gr)'/>")
    for j, word in enumerate(["outcomes", "feedback", "calibration"]):
        e.append(f"<text x='{cx}' y='{cy + 14 + j * 16}' {FONT} font-size='11' "
                 f"text-anchor='middle' fill='{p['mut']}'>{word}</text>")
    # panel 3: dense cloth — full rows, all colors, plus accretion tags
    e.append(weave(xs[2] + 30, 46, PW - 60, PH - 90, p, rows=8, cols=13, unfinished=1))
    tags = ["your stacks", "your languages", "your failures"]
    for j, tag in enumerate(tags):
        tx = xs[2] + 12 + j * 89  # 3 chips of 84 + 5px gaps = 262, inside the 284 panel
        e.append(f"<rect x='{tx}' y='{PH - 16}' width='84' height='20' rx='10' "
                 f"fill='{p['card']}' stroke='{yarn[j]}' stroke-width='1.2'/>"
                 f"<text x='{tx + 42}' y='{PH - 2}' {FONT} font-size='9.5' "
                 f"text-anchor='middle' fill='{p['fg']}'>{tag}</text>")
    e.append("</svg>")
    return "".join(e)


LABELS = [
    ("[FACT]", "cite the source", "fact", "factbg"),
    ("[ASSUMPTION]", "ledger: risk + verify_by", "assum", "assumbg"),
    ("[SPECULATION]", "never load-bearing", "spec", "specbg"),
    ("[UNKNOWN]", "attach a resolution path", "unk", "unkbg"),
    ("[HUMAN-DECISION]", "batch it, recommend one", "dec", "decbg"),
]


def labels(p):
    # 5 chips of 176 + 4 gaps of 9 = 916, centered in 940 -> 12px side margins
    W, H, CW, G, M = 940, 74, 176, 9, 12
    e = [f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {H}' role='img' "
         f"aria-label='the five epistemic labels'>"]
    for i, (name, oblig, fgk, bgk) in enumerate(LABELS):
        x = M + i * (CW + G)
        e.append(f"<g><rect x='{x + 0.5}' y='0.5' width='{CW}' height='{H - 1}' rx='10' "
                 f"fill='{p[bgk]}' stroke='{p[fgk]}' stroke-width='1.4'/>"
                 f"<text x='{x + 13}' y='30' font-family='ui-monospace,Consolas,monospace' "
                 f"font-size='14' font-weight='700' fill='{p[fgk]}'>{name}</text>"
                 f"<text x='{x + 13}' y='52' {FONT} font-size='11.5' "
                 f"fill='{p['fg']}'>{oblig}</text></g>")
    e.append("</svg>")
    return "".join(e)


def mark(text, icon, w=190):
    """Theme-neutral little marks (mid-gray reads on both GitHub themes)."""
    g, acc = "#8b949e", "#6e7681"
    return (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {w} 30' role='img' "
            f"aria-label='{text}'>"
            f"<rect x='0.5' y='0.5' width='{w - 1}' height='29' rx='15' fill='none' "
            f"stroke='{g}'/>{icon}"
            f"<text x='40' y='20' {FONT} font-size='13' font-weight='600' "
            f"fill='{g}'>{text}</text></svg>")


ICON_SHUTTLE = ("<path d='M12 15 q10 -7 20 0 q-10 7 -20 0 z' fill='none' "
                "stroke='#8b949e' stroke-width='1.6'/>"
                "<circle cx='22' cy='15' r='2' fill='#8b949e'/>")
ICON_OFFLINE = ("<circle cx='22' cy='15' r='9' fill='none' stroke='#8b949e' "
                "stroke-width='1.6'/><line x1='15' y1='22' x2='29' y2='8' "
                "stroke='#8b949e' stroke-width='1.6'/>")
ICON_GAUGE = ("<path d='M13 20 a9 9 0 1 1 18 0' fill='none' stroke='#8b949e' "
              "stroke-width='1.6'/><line x1='22' y1='20' x2='17' y2='13' "
              "stroke='#8b949e' stroke-width='1.8'/>")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, pal in (("light", LIGHT), ("dark", DARK)):
        (OUT / f"banner-{name}.svg").write_text(banner(pal), encoding="utf-8")
        (OUT / f"lifecycle-{name}.svg").write_text(lifecycle(pal), encoding="utf-8")
        (OUT / f"labels-{name}.svg").write_text(labels(pal), encoding="utf-8")
        (OUT / f"growth-{name}.svg").write_text(growth(pal), encoding="utf-8")
    (OUT / "mark-stdlib.svg").write_text(
        mark("stdlib-only tools", ICON_SHUTTLE, 170), encoding="utf-8")
    (OUT / "mark-notelemetry.svg").write_text(
        mark("zero telemetry, provable", ICON_OFFLINE, 210), encoding="utf-8")
    (OUT / "mark-selfscoring.svg").write_text(
        mark("scores itself, honestly", ICON_GAUGE, 200), encoding="utf-8")
    n = len(list(OUT.glob("*.svg")))
    print(f"wrote {n} assets to {OUT}")


if __name__ == "__main__":
    main()
