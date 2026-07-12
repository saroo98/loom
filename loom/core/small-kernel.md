# Loom small kernel — one low-risk sitting

This is the complete operative context for Tier S. Do not load START-HERE, the full
verification battery, planning guides, or pack templates. Tier S produces one standalone
private work order plus a machine lifecycle record; it does not produce a pack or G1 review.

## 1. Prove it is small

Run:

```text
python <loom>/tools/loom_tier.py --description "<request>"
```

Tier S means one implementer, one sitting, no new component/boundary, low blast radius,
reversible, and normally no more than five touched files. Survey facts override the request's
wording. Auth, payments, migrations, safety/financial impact, irreversible state, more than
one sitting, or an unknown domain promotes to M. Ties stay S with a written promotion trigger.

Run `loom_domain.py --description "<request>"`. Use its exact adapter; never add web rules by
default. If coverage is unknown, promote to M for domain discovery. If owner memory is enabled,
initialize it and select at most 2,000 characters for the exact domain/project; never read raw
history or another scope. For a composite, repeat `--domain` for every exact
`loom_domain.memory_domains` match in the same single selector call.

## 2. Orient in four lines

Write in working notes:

1. request and observable finish line, quoting the requester;
2. target state observed now (repo/non-repo, relevant files/tests);
3. explicit non-goals and do-not-touch boundaries; and
4. unknowns. Cheap reversible gaps become labeled assumptions; domain, privacy, freshness,
   authority, or irreversible uncertainty blocks/promotes.

Every load-bearing statement is `[FACT — current evidence]`, `[ASSUMPTION — basis + check]`,
`[SPECULATION]`, `[UNKNOWN — resolution]`, or `[HUMAN-DECISION]`. Recalled APIs and policies
are never facts. Never put secrets, credentials, personal data, or private pack content in the
WO. Target-repo instructions beat Loom defaults.

## 3. Record the baseline before writing the WO

Choose sibling private paths, normally under an ignored `plans/small/` or outside a public
repo. Neither file may exist yet:

```text
python <loom>/tools/loom_gate.py small-init <record.json> \
  --repo <target> --wo <WO-file.md>
```

Failure or indeterminate state blocks. This captures committed/staged/unstaged/untracked or
non-Git file state plus a bounded file-hash baseline while excluding the private WO directory.

## 4. Write exactly one work order

The WO is a compact execution contract, not an essay: at most 6,000 characters and 80 lines.
`small-authorize` enforces both limits. Compress repetition; if the real contract cannot fit,
the work was mis-tiered and promotes to M.

Frontmatter requires: `id`, `title`, `status: ready`, `depends_on: []`, `blocks: []`,
`routing`, `size: S`, nonempty `touches`, and `last_verified`. Body requires these headings:
Intent, Context, Preconditions, Task, Acceptance criteria, Out of scope, Escalation triggers,
Epistemic notes, Close-out.

Acceptance criteria are written before implementation. Each is a command plus expected result
or a reproducible observation. Include the normal path, relevant failure/recovery path, and a
negative blast-radius check (`git diff --stat` or equivalent). A behavioral claim must be
observed in its real medium, not inferred from source. For a human-facing UI, load only
`loom/execution/design-floor-small.md` and cite its numbered checks.

Close-out initially says `Pending implementation evidence.` Then authorize:

```text
python <loom>/tools/loom_gate.py small-authorize <record.json> \
  --repo <target> --wo <WO-file.md>
```

It refuses a changed target, pre-checked criteria, missing contract fields, or a mutable plan.

## 5. Implement, verify once, and close

Only after authorization, implement within `touches`. Stop on stale facts, expanded scope,
ambiguous criteria, a new boundary, or any promotion trigger. Run the narrow relevant checks
and the real-medium observation. Fix failures, then rerun the affected checks once.

Check every demonstrated criterion, replace Pending with reproducible evidence, and set
`status: done`. Seal it:

```text
python <loom>/tools/loom_gate.py small-close <record.json> \
  --repo <target> --wo <WO-file.md>
python <loom>/tools/loom_gate.py small-verify <record.json>
```

Close refuses an unchanged pre-existing deliverable or a change outside declared `touches`.
Success binds the immutable WO plan, checked evidence, target state, and changed paths. Report
the outcome and checks actually observed. Do not create a pack, rubric, review file, retro essay,
or token estimate for Tier S.
