# Benchmark — observed quality, corrected cost and chronology

This page preserves Loom's first isolated landing-page experiment without granting it evidence
the run did not produce. One brief was run once in three agent configurations and graded blind
against prewritten acceptance tests. It is directional evidence for this task family, not proof
of general superiority.

## Configurations and task

| # | Model / effort | Loom invoked |
|---|---|---|
| A2 | Claude Opus 4.8 / low | no |
| B2 | Claude Opus 4.8 / low | yes |
| C | Claude Fable 5 / maximum | no |

> Build a landing page for a small neighborhood coffee shop called “Driftwood Coffee”.
> Static files only, served as-is.

The A2 and B2 prompts were byte-identical except for `/loom` invocation and the skill pointer.
Ten sealed pass/fail checks were fixed before the runs. A separate isolated evaluator graded the
live deliverables under anonymous labels and cited file/line or computed evidence.

## Deliverable results

| Metric | A2 naked | B2 Loom-invoked | C naked/max |
|---|---:|---:|---:|
| Sealed tests | 8 / 10 | **10 / 10** | **10 / 10** |
| 12-category mean | 76.8 | **90.1** | 89.8 |
| Adversarial defects | 9 | **5** | 16 † |
| Observed wall time | 127.6 s | 253.6 s | 1,240.9 s |

† C used a different grading pass/severity threshold; its defect count is not comparable to
the A2/B2 pair. Category means across different graders also carry grader drift.

Within the same-model/same-grader A2/B2 pair, the Loom-invoked artifact scored 13.3 points
higher and passed two more sealed checks. With one stochastic run per arm, this is an observed
association, not an estimated average effect.

## Token accounting correction

The earlier page called 74,363 B2's “token total.” That was false. It is a harness field named
`subagent_tokens`; the harness definition was not preserved, so it is a subset of unknown
meaning `[UNVERIFIED]`. The same limitation applies to the displayed A2/C harness values.

An independent reconstruction of B2's preserved response-usage records found:

| B2 usage field | Count |
|---|---:|
| Non-cache input | 19,222 |
| Cache-creation input | 54,035 |
| Cache-read input | 1,189,952 |
| Output | 14,917 |
| **Processed token events (sum of the four fields)** | **1,278,126** |

“Processed token events” is deliberately not called provider-billed tokens or cost. Cache
pricing/weights were not captured, so a billing-equivalent value is `[UNVERIFIED]`. The old
74,363 figure understated this complete four-field sum by about 17.2×.

`tools/loom_benchmark.py` now rejects any run record missing one of the four fields, reports
them separately, and leaves provider-billed equivalent `null` unless the caller supplies all
four explicit weights. No subset may be labeled total.

## Chronology correction

The preserved B2 transcript writes the three deliverable files before it writes MANIFEST, the
work order, and G1. The pack/G1 phase did not change a deliverable file. Therefore:

- B2 is evidence that an agent exposed to Loom produced a strong artifact in this run;
- B2 is **not** evidence that a pre-implementation G1 gate caused that artifact;
- the retrospective pack receives no causal planning credit; and
- the 846,456 processed token events spent after the deliverable on pack/G1 work were overhead
  for this task, not release-gating value.

Lifecycle v2 now prevents recurrence: the target file-hash baseline must exist before planning,
the unchanged state must reach authorization, and a done WO must bind post-authorization changes
inside declared `touches`. Tier S uses the same proof through the compact standalone lifecycle.

## What the artifacts actually show

- A2 shipped dead social links, an invented press endorsement presented as real, a realistic
  address presented as fact, two computed contrast failures, and an unused third-party font
  preconnect.
- B2 had no broken anchors or external requests, declared placeholders, passed the measured
  contrast checks, and included keyboard/focus affordances.
- C led several craft categories but shipped a newsletter interaction that claimed success
  without storing anything and contradictory hours copy.

Truthfulness failures dominated the material defects. That observation supports preserving
Loom's evidence/placeholder discipline; it does not establish cross-domain performance.

## Limits and the next valid experiment

- n=1 per arm; no confidence interval.
- One static website family; CLI, mobile, ETL/ML, accounting, real-time 3D, firmware, and
  research remain untested by this benchmark.
- A2/B2 is the controlled comparison; C is cross-model and cross-grader context only.
- Model grading is not a substitute for human or domain-expert review.
- The B2 lifecycle chronology was retrospective.

A valid follow-up must pre-register acceptance tests and usage schema, run repeated seeds, use
the same grader protocol, record all four token fields and wall time, exercise multiple domains,
and require lifecycle authorization before any deliverable change. Until then, no “world-best,”
cost-saving, or generalization claim is supported.

Artifacts as originally published:

- A2: https://saroo98.github.io/bench-lp-a2/
- B2: https://saroo98.github.io/bench-lp-b2/
- C: https://saroo98.github.io/bench-fable-max/
