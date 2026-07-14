#!/usr/bin/env python3
"""loom_kickoff — generate an implementer kickoff prompt from a work-order file.

Emits the need-to-know prompt for routing a WO to any implementing agent (privacy rule 5:
the implementer gets the work order, not the pack). Mirrors the kickoff template in
loom/prompts/prompt-library.md — this tool exists so every kickoff is complete and
identical instead of hand-assembled.

Usage:
    python loom_kickoff.py <path/to/WO-xxx-*.md> [--loom-path <p>] [--project <name>] [--out <file>]

Exit codes: 0 ok, 1 WO not executable (missing/invalid), 2 usage/IO problem.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_lint  # noqa: E402
import loom_reliability  # noqa: E402

TEMPLATE = """Execute work order {wid} for project {project}. The work order text follows at the end of
this prompt; it is your contract.

Rules:
1. Run the pre-WO staleness check first ({loom}/loom/execution/staleness.md, "pre-WO"
   section) — unless this kickoff states the planner already ran it, in which case verify
   the WO's stated facts still hold and proceed. If facts no longer hold, STOP and report
   the drift — do not improvise around a stale work order.
2. Respect the escalation triggers listed in the WO. Escalating is success, not failure.
3. Follow the target repo's conventions named in the WO's Context section.
4. Modify only paths matching the WO's declared touches: {touches}. Needing more is an
   escalation, not a judgment call ({loom}/loom/execution/parallel-work.md).
5. Done = every acceptance criterion demonstrated with command output or a reproducible
   observation, recorded in the WO's close-out block, including the negative checks.
6. Out-of-scope items are out of scope even when tempting and adjacent.
7. If you stop before done, leave the 4-line handoff brief (done / in flight / surprises /
   repo state) in the close-out section.

--- WORK ORDER ---
{body}
"""


def _render(text, fm, loom_path=None, project=None):
    touches = fm.get("touches", [])
    if isinstance(touches, str):
        touches = [touches] if touches else []
    loom = (loom_path or str(Path(__file__).resolve().parent.parent)) \
        .replace("\\", "/").rstrip("/")
    return TEMPLATE.format(
        wid=fm["id"],
        project=project or fm.get("project", "(see MANIFEST)"),
        loom=loom,
        touches=", ".join(touches) if touches else
        "(none declared — treat any shared-path edit as escalation)",
        body=text.strip(),
    )


def build(wo_path, loom_path=None, project=None, repo_path=None):
    p = Path(wo_path)
    if not p.is_file():
        print(f"loom_kickoff: work order not found: {p}", file=sys.stderr)
        return None, 1
    text = p.read_text(encoding="utf-8", errors="replace")
    fm, _ = loom_lint.parse_frontmatter(text)
    if fm is None or not fm.get("id"):
        print(f"loom_kickoff: {p} has no valid frontmatter/id — lint it first", file=sys.stderr)
        return None, 1
    status = fm.get("status", "")
    if status not in ("ready", "in-progress"):
        print(f"loom_kickoff: BLOCKED — {fm['id']} status is '{status}', "
              "not ready/in-progress", file=sys.stderr)
        return None, 1
    if p.parent.name != "work-orders" or not (p.parent.parent / "MANIFEST.md").is_file():
        print("loom_kickoff: BLOCKED — WO is not inside a Loom pack", file=sys.stderr)
        return None, 1
    pack = p.parent.parent
    repo = Path(repo_path).resolve() if repo_path else pack.parent.resolve()
    report = loom_lint.lint(pack, repo_path=repo, strict_staleness=True)
    if report.errors:
        for finding in report.errors:
            print(f"loom_kickoff: BLOCKED — {finding['code']} {finding['msg']}",
                  file=sys.stderr)
        return None, 1
    return _render(text, fm, loom_path, project), 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate implementer kickoff prompt from a work order")
    ap.add_argument("wo", help="path to the work-order .md file")
    ap.add_argument("--loom-path", help="Loom repo root (default: this tool's repo)")
    ap.add_argument("--project", help="project name for the prompt header")
    ap.add_argument("--repo", help="target repo root (default: parent of pack)")
    ap.add_argument("--out", help="write to file instead of stdout")
    args = ap.parse_args(argv)
    prompt, code = build(args.wo, args.loom_path, args.project, args.repo)
    if prompt is None:
        return code
    if args.out:
        loom_reliability.atomic_write_text(Path(args.out), prompt)
        print(f"written: {args.out}")
    else:
        print(prompt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
