# Intake — analyzing a project description

Purpose: turn a request of any quality — one vague sentence or a ten-page spec — into an
Intake Note that the rest of Loom can build on. Intake is where most planning failures are
born: solving the wrong problem, at the wrong size, with invented requirements.

## 1. Extract what was actually said

Work from the requester's words, not your paraphrase. Build four lists:

- **Stated goals** — quote them. Quoting prevents drift; your summary is already an
  interpretation.
- **Stated constraints** — platform, budget, deadline, "don't touch X", privacy, tech
  preferences.
- **Stated non-goals** — anything explicitly excluded.
- **Everything else you *think* is required** — this list is your inference, and every entry
  is `[ASSUMPTION]` or `[SPECULATION]`, never silently promoted to requirement. The classic
  intake failure is inventing requirements that sound professional ("needs SSO", "needs 99.9%
  uptime") that the requester never asked for and would not pay for.

## 2. Identify the finish line

What observable state means "done"? A URL serving traffic, an installer that runs, a passing
test suite, a store listing? If the description doesn't say, write
`[UNKNOWN] finish line — assuming: <X>` and put the assumption in the ledger with
`verify_by: G1 exit`. Products additionally get success metrics in the product plan; intake
only needs the finish line.

## 3. Classify

- **Project type** — consult `loom/adaptation/project-types.md` for what each type changes.
  Multi-type is normal (web app + API).
- **Repo state** — none / empty / partial / active / legacy-unknown. Survey per
  `repo-survey.md` before finishing intake if any repo exists.
- **Tier** — S/M/L/XL per `artifact-matrix.md`. When torn between tiers, pick the lower one
  and note the promotion trigger ("promote to L if the plugin system is confirmed in scope").
  Under-planning is recoverable at the first gate; over-planning wastes the budget invisibly.

## 4. The silence sweep — interrogate what was NOT said

§1 catches the inferences you already made; this pass finds the ones you never thought to
make. Every planning description is mostly silence, and the expensive failures live there.
Probe eight categories — each earned by a real observed miss, not invented:

| Category | Probe | The miss it prevents |
|---|---|---|
| **Scope edges** | Where exactly does "done" stop? What adjacent thing will the requester assume is included? | Building the thing next to the thing (a "test run" mistaken for the project itself) |
| **Actors & access** | Who/what calls this? Who must NOT be able to? | Auth designed for one audience, used by three |
| **Data shape & lifecycle** | Where does state live, what migrates, what may be deleted? | Schema decisions discovered during implementation |
| **Failure & recovery** | What happens when it breaks? What must survive a crash? | Happy-path plans; rollback invented under fire |
| **Quality bar** | What perf/a11y/security level is implied but unstated? | Gold-plating — or shipping embarrassment |
| **Integration surface** | What existing systems touch this? What breaks downstream? | The change that was "local" until deploy day |
| **Operational reality** | How does it deploy, on what triggers, with what credentials handled how? | Criteria that name an action but not its trigger topology (CI filters, webhooks) |
| **Language/locale/time** | Which languages, scripts, timezones, calendars are actually in the audience? | Rendering/RTL surprises that turn effort-1 into effort-4 |

**Record hits only.** A category that yields no assumption, no decision, and no question
produces no row — "swept — no material silences" is a legitimate one-line result. Each hit
routes through machinery that already exists: resolved from repo evidence → `[FACT]`;
assumed → ledger entry; irreversible fork → `[HUMAN-DECISION]`; plan-forking → one batched
question (per §5). The sweep finds gaps; it never adds a new way of asking.

Tier S skips the sweep (the work order's own criteria surface gaps at that size). Tier
L/XL repeat it per subsystem at plan time. The Intake Note carries the results under
`## Silence sweep` — lint (W12) notices when an M+ pack lacks the section.

## 5. The question policy

You may ask the requester questions at intake — but every question has a cost (latency, and
requesters often aren't available). Decide per gap:

| Gap is… | Action |
|---|---|
| Cheap to assume, easy to reverse | Assume, label, ledger, continue |
| Expensive/irreversible, but options are clear | `[HUMAN-DECISION]` with recommendation; continue on non-dependent work |
| So fundamental the plan forks entirely (e.g., "is this a product or a script?") | Ask now — one batched, concrete set of questions, each with your default stated ("If no answer: I'll assume X") |

Never send a drip of single questions. Never ask what you can verify yourself from the repo
or the description.

## 6. Write the Intake Note

Template (also `templates/pack/` — lives at `plans/intake.md` in the pack):

```markdown
---
artifact: intake
project: "<name>"
tier: M            # with one-line justification below
status: draft
last_verified: <today>
loom_version: "0.8.0"
---

# Intake Note — <project>

## Goal (requester's words)
> "<quote>"

## Finish line
<observable done-state>  [FACT|ASSUMPTION]

## Non-goals
- ...

## Constraints
- ...  (label each: stated [FACT] vs inferred [ASSUMPTION])

## Project type & repo state
<type(s)>; repo: <none|empty|partial|active|legacy> (survey: see below / plans/survey.md)

## Tier: <S|M|L|XL>
Justification: <one line>. Promotion trigger: <condition or "none">.

## Silence sweep
<hits only — category: what was unsaid → how resolved (FACT source / A-xxx / D-xxx /
batched question). Or: "swept — no material silences.">

## Known facts
- ... [FACT — source]

## Initial assumptions
- A-001 ... (full entries in assumptions.md)

## Unknowns
- ... [UNKNOWN — resolution path]

## Human decisions needed
- D-001 ... (full records in decisions.md)

## Proposed artifacts
Produce: <list, one-line consumer each>
Skip: <list, one-line reason each>
```

## 7. Gate G0 (self-administered)

- Re-read the **original request**, then the Note. Does the Note answer it, all of it, and
  only it? (`loom/verification/task-fit.md`)
- Is every inferred requirement labeled?
- Is the tier the smallest that fits?
- Would the requester recognize their project in this Note?

Fail → fix the Note, not the request.
