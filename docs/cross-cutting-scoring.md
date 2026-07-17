# Evidence-bound scoring

Loom does not award itself a number because a feature exists in source or because a document says it
works. The scorecard asks a narrower question: which requirements are proven for these exact bytes,
by which kind of evidence, and which points must still be withheld?

## The fixed rubric

The v1 rubric has 17 categories and exactly 100 total weight. Each category has named requirements
whose points total 100 within that category. A requirement lists the evidence classes that can
satisfy it. Neither an evidence file nor a command-line flag contains an editable score.

The classes are deliberately separate:

- `mechanical-local`: deterministic implementation plus exact-revision local tests;
- `matrix-reproduced`: every required platform or capability cell reproduced;
- `real-host`: a disposable invocation through the named host and version;
- `provider-attested`: a content-bound response from the actual provider;
- `longitudinal-local`: repeated owner outcomes under a valid comparison design;
- `independent-external`: an independent audit, reproduction, or usability study;
- `public-adoption`: current facts from an authoritative public source;
- `claimed-only`: a statement without sufficient behavior evidence, worth zero points.

Every non-local class also needs an independently provisioned trust policy whose RSA key is
authorized for that exact subject, evidence class, and requirement. A class label and a digest are
not external proof. Without a valid signature, the scorer refuses the record.

## What the scorer rejects

The scorer refuses altered digests, changed source artifacts, duplicate evidence or coverage,
multiple records for one requirement, another subject tree, an unknown requirement, an ineligible
evidence class, future timestamps, expired supplied evidence, inconsistent rubric versions, and
stale competitive snapshots. Missing evidence is different: the scorer completes, lists the
withheld requirement, and assigns no points for it.

## Reproducible local use

Run the collector with an output path outside the tree being measured, then score the result at a
fixed evaluation time:

```text
python tools/loom_scorecard.py collect-local . --suite full --output ../loom-evidence.json
python tools/loom_scorecard.py score --evidence ../loom-evidence.json --as-of 2026-07-17T12:00:00Z --output ../loom-scorecard.json
```

For a release candidate, build the public cut and use `collect-release` instead. It independently
verifies the manifest, firewall, documentation, offline boundary, and complete suite for the exact
exported bytes, then reuses that bound suite receipt instead of running the same full suite twice.

The collector hashes the public allowlisted source tree before and after running the suite, fast
gate, documentation audit, offline audit, mutation gate, domain corpus, performance corpus,
adaptation scenarios, adapter conformance, version check, and disposable public build. A mid-run
source change blocks the receipt. The output is private by default; publish only a sanitized receipt
for an immutable public cut.

A scorecard can be compared with an earlier scorecard through the `regression` operation. Any
decrease is reported. Decreases in correctness, lifecycle, learning isolation, robustness, privacy,
release engineering, or claim honesty block the regression gate; adoption and other non-trust
decreases remain visible but informational. A changed rubric cannot be compared as if it were the
same scale.

## Competitive comparison

Every project snapshot names its canonical GitHub repository, exact revision, access and expiry
times, rubric version, category applicability, sources, and unknowns. Known score is the weighted
result across verified cells only. Lower and upper bounds treat unknown applicable cells as zero and
100 respectively. Evidence coverage states how much of the applicable rubric is actually known.

This prevents a popular project from receiving unearned engineering points, prevents Loom-specific
features from being silently imposed on a differently scoped project, and prevents an old comparison
from being presented as current.
