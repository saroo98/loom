# Planning quality rubric

Scores a planning pack (or a single plan) on ten dimensions, 0–4 each. Used at G1 and G4,
and for reviewing plans produced by other agents. Threshold to pass: **average ≥ 3.0 and no
dimension < 2**, computed over the dimensions applicable to the tier (mark n/a honestly —
a tier-M pack without a maintenance plan isn't scored on operability readiness it never
claimed).

## Scoring anchors

Each dimension: 0 = absent · 1 = token effort · 2 = present with real gaps · 3 = solid,
would trust it · 4 = exemplary, teachable. Anchors below define 2 and 4; interpolate.

### 1. Goal fidelity
Does the pack serve the requester's actual request?
- **2:** goals restated with mild drift; one inferred requirement unlabeled.
- **4:** goals quoted; every requirement traced to words or ledger; scope ladder complete
  including NEVER; a cold reader maps pack → request without help.

### 2. Epistemic hygiene
Are the five labels applied per `loom/core/epistemics.md`?
- **2:** labels used in obvious places; ledger exists but `used_in`/`verify_by` spotty;
  some hedge-verbs hiding claims.
- **4:** load-bearing claims labeled with sources; ledger bidirectionally linked; verify_by
  events real and ordered before first irreversible use; zero confident paraphrase promotions.

### 3. Right-sizing
Is planning effort proportional to tier and blast radius?
- **2:** one artifact over- or under-built; some sections exist because the template had them.
- **4:** matrix selection justified both ways; every section passes "what would an
  implementer do differently"; budgets respected without cramming.

### 4. Decision quality
Are the expensive choices made explicitly and well?
- **2:** major decisions stated but rationale thin; some silent defaults on non-obvious calls.
- **4:** decision records with options, evidence-based why, reversibility, revisit triggers;
  silent defaults only where genuinely obvious; `[HUMAN-DECISION]` used exactly where the
  epistemics triggers say, each with a recommendation.

### 5. Boundary clarity (architecture & contracts)
Could two agents build opposite sides of any boundary without talking?
- **2:** components named with responsibilities; data ownership fuzzy in places; error shapes
  partial.
- **4:** ownership unambiguous; contracts frozen where parallel work needs them; error cases,
  units, timezones explicit; one normative home per contract.

### 6. Work-order executability
Could a context-free implementer execute the frontier WOs tonight?
- **2:** WOs exist and are roughly atomic; some criteria subjective; context sometimes
  assumes session knowledge.
- **4:** four atomicity properties hold; criteria are commands/observations incl. negative
  checks; escalation triggers per WO; DAG valid with real parallel width.

### 7. Verifiability
Does the pack define what "correct" means and how to check it?
- **2:** verification commands catalog exists; some plans have no verification hooks.
- **4:** every artifact has hooks; testing plan allocates by risk; gates' evidence
  requirements satisfiable from the pack alone.

### 8. Failure preparedness
Rollback, escalation, staleness — is being wrong survivable?
- **2:** rollback exists but untested claims; staleness stamps present, triggers unnamed.
- **4:** rollback triggers pre-agreed with data reversibility addressed; escalation triggers
  on WOs; freshness window set; divergence rulings anticipated (repo-is-truth honored).

### 9. Adaptation fit
Does the pack fit *this* project — its repo, type, audience, conventions?
- **2:** survey done; conventions mostly respected; project-type peculiarities partially
  reflected; localization/RTL considered late or shallowly where relevant.
- **4:** plans build on architecture-as-found; type-specific emphasis correct (store
  release, signing, RTL, device matrix — whatever applies); Loom defaults visibly yielded
  to repo conventions where they met.

### 10. Clarity & navigability
Can a reader find and trust what they need under context pressure?
- **2:** structure per templates; some repetition drifting; MANIFEST index present but stale
  in places.
- **4:** decisions front-loaded; single-statement-single-home with references; glossary
  stable; MANIFEST accurate including skip-justifications and frontier.

## Procedure

1. Score each applicable dimension against the anchors — **cite evidence for every score**
   (a score without a pack location is a vibe).
2. Compute average; check the no-dimension-below-2 rule.
3. Findings from scores < 3 become standard-format findings (fix or accept-with-record).
4. Record the scorecard in the gate review file.

## Worked micro-example

> Tier M pack, feature slice. Scores: fidelity 4 (goals quoted, trace table), hygiene 3
> (ledger solid; two hedge-verbs found in uiux), sizing 4 (product plan skipped w/
> justification), decisions 3 (D-002 lacks revisit trigger), boundaries 4, WOs 3 (WO-006
> criterion "UI feels responsive" — subjective, rewrite), verifiability 3, failure prep 2
> (rollback untested claim → finding F-09), adaptation 4, clarity 4.
> Avg 3.4, min 2 → **pass-with-fixes**: F-09 + WO-006 criterion + hedge-verbs before G1 exit.

## Anti-gaming

The rubric is a proxy. Signs it's being gamed rather than served: scores justified by
artifact *existence* rather than content; evidence citations that don't actually support the
number; a 3.0-exactly average with no dimension examined hard. If the pack scores well and
still feels wrong, **trust the wrongness**: run the adversarial pass
(`loom/verification/self-verification.md` method §3) and find what the rubric missed — then
file the gap against the rubric itself in `FEEDBACK.md`.
