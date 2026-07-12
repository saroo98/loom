#!/usr/bin/env python3
"""Measure the exact static Loom files named by each context route.

This is a source-text inventory, not a token counter. Tokenizer totals, cache reads,
project context, system prompts, tool transcripts, and model output are outside its
scope and are reported as unknown rather than estimated.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ROUTES = {
    "skill-dispatch": ("skill/loom/SKILL.md",),
    "tier-s-core": ("loom/core/small-kernel.md",),
    "tier-s-ui": (
        "loom/core/small-kernel.md",
        "loom/execution/design-floor-small.md",
    ),
    "tier-mplus-kernel": ("START-HERE.md",),
    "session-tier-s-core": (
        "skill/loom/SKILL.md",
        "loom/core/small-kernel.md",
    ),
    "session-tier-s-ui": (
        "skill/loom/SKILL.md",
        "loom/core/small-kernel.md",
        "loom/execution/design-floor-small.md",
    ),
    # Fixed M+ repo-planning load before route-dependent artifact/domain guides. This is the
    # maximum fixed base (repo-survey is skipped only when no target repo exists).
    "session-tier-mplus": (
        "skill/loom/SKILL.md",
        "START-HERE.md",
        "loom/core/principles.md",
        "loom/core/epistemics.md",
        "loom/core/privacy.md",
        "loom/core/autonomy.md",
        "loom/core/user-memory.md",
        "loom/core/lifecycle.md",
        "loom/intake/intake.md",
        "loom/intake/repo-survey.md",
        "loom/intake/artifact-matrix.md",
        "loom/planning/plan-authoring.md",
        "loom/execution/work-orders.md",
        "loom/review/gates.md",
        "loom/review/rubric.md",
        "loom/verification/overview.md",
        "loom/verification/task-fit.md",
        "loom/verification/contradiction-detection.md",
        "loom/verification/weak-assumptions.md",
        "loom/verification/hallucination-check.md",
        "loom/verification/uncertainty-calibration.md",
        "loom/verification/fact-vs-speculation.md",
        "loom/verification/long-context-consistency.md",
        "loom/verification/self-verification.md",
    ),
}


class ContextError(RuntimeError):
    pass


def measure(route, root=ROOT):
    root = Path(root).resolve()
    if route not in ROUTES:
        raise ContextError(f"unknown route: {route}")
    files = []
    for relative in ROUTES[route]:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ContextError(f"route source missing or symlinked: {relative}")
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ContextError(f"cannot measure {relative}: {exc}") from exc
        files.append({
            "path": relative,
            "utf8_bytes": len(raw),
            "unicode_characters": len(text),
            "lines": len(text.splitlines()),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return {
        "schema_version": 1,
        "route": route,
        "scope": "fixed static Loom source files explicitly named by this route",
        "files": files,
        "file_count": len(files),
        "utf8_bytes": sum(item["utf8_bytes"] for item in files),
        "unicode_characters": sum(item["unicode_characters"] for item in files),
        "lines": sum(item["lines"] for item in files),
        "tokenizer_tokens": None,
        "cache_read_tokens": None,
        "excluded": [
            "system/developer prompts", "project files", "selected owner memory",
            "tool input/output", "model output", "provider cache accounting",
            "route-dependent artifact/domain guides and templates",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("route", choices=sorted(ROUTES))
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = measure(args.route, args.root)
    except ContextError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"loom_context: REFUSED - {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"status": "ok", "result": result}, sort_keys=True))
    else:
        print(f"loom_context: {result['route']} - {result['file_count']} file(s), "
              f"{result['unicode_characters']} Unicode characters, "
              f"{result['utf8_bytes']} UTF-8 bytes, {result['lines']} lines")
        print("loom_context: tokenizer/cache token totals are unknown; no character-based "
              "estimate is reported")
    return 0


if __name__ == "__main__":
    sys.exit(main())
