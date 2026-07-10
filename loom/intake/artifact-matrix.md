# Artifact matrix — what to produce, by tier and type

The matrix answers one question: **which artifacts earn their existence for this project?**
Deviating from it is allowed and normal — the rule is that every produce/skip decision gets
one honest line in the MANIFEST.

## Tier definitions

| Tier | Criteria (any strong signal decides) | Typical planning budget |
|---|---|---|
| **S** | One sitting, one implementer, blast radius ≤ a module, no new architecture | One work order; minutes |
| **M** | One feature/slice; touches several modules or introduces one new component; days of agent work | Slim pack: intake + 1–3 plans + work orders |
| **L** | New product to release, or subsystem with its own architecture; weeks of agent work | Full pack |
| **XL** | Multiple subsystems/milestones; months; several implementing agents in parallel | Full pack + per-milestone slices |

Tie-break rule: choose the **lower** tier and record the promotion trigger. Gates catch
under-planning cheaply; over-planning is never caught because unused documents don't complain.

**Where the saved budget goes.** Tiering down is not doing less — it is spending the
same attention where it converts: on the deliverable's craft (composition passes, copy
specificity) and on *proof* (the smoke battery, the restated-fact sweep, behavior probed
in the artifact's real medium). A slim pack plus a hard verification loop beats a rich
pack plus an admired-from-a-distance deliverable, at every tier where both fit the
budget. Planning documents never impressed a user; the artifact did.

## The matrix

●&nbsp;required ◐ produce if the modifier column applies ○ skip by default

| Artifact | S | M | L | XL | Modifier that flips ◐→● |
|---|---|---|---|---|---|
| Intake Note | ○¹ | ● | ● | ● | — |
| Repo survey | ○¹ | ◐ | ● | ● | any existing repo |
| Product plan | ○ | ◐ | ● | ● | product ambiguity: users/scope unclear |
| Architecture plan | ○ | ◐ | ● | ● | new component, new integration, or data-model change |
| UI/UX plan (incl. responsive) | ○ | ◐ | ◐ | ● | any human-facing UI |
| Contracts (data/API/runtime) | ○ | ◐ | ● | ● | any boundary another agent/service consumes |
| Testing plan | ○² | ◐ | ● | ● | legacy repo, or risk concentrated in behavior |
| Release & rollback plan | ○ | ◐ | ● | ● | anything user-visible ships |
| Security plan | ○ | ◐ | ◐ | ● | auth, payments, personal data, or public network exposure |
| Maintenance plan | ○ | ○ | ◐ | ● | someone operates this after delivery |
| Scaffold plan | ○ | ◐ | ◐ | ◐ | repo none/empty/partial AND structure precedes features |
| Work orders | ●³ | ● | ● | ● | — |
| Routing assignments | ○ | ◐ | ● | ● | more than one implementer/model in play |
| Project instructions draft (AGENTS.md/CLAUDE.md) | ○ | ◐ | ◐ | ● | repo will be worked by agents beyond this pack |

¹ Tier S: intake and survey happen in your head; their conclusions land in the single work order's Context section.
² Tier S: acceptance criteria in the work order carry the testing burden.
³ Tier S: exactly one.

## Applying modifiers by project type

`loom/adaptation/project-types.md` adjusts emphasis, not existence — e.g., an Android app at
tier L makes the release plan heavier (store review, signing) but the matrix row is already ●.
The two common existence-level overrides:

- **Websites/marketing sites:** UI/UX plan is usually the *center of gravity*; architecture
  plan often collapses into a section of it. Collapsing two artifacts into one document is
  fine — the MANIFEST says so, and the rubric scores substance, not file count.
- **Libraries/CLIs:** UI/UX plan → skip; its budget moves to contracts (the API *is* the UI).

## Declaring the selection

In `plans/MANIFEST.md`:

```markdown
## Artifacts
| Artifact | Decision | Why (one line) |
|---|---|---|
| architecture.md | produce | two new services + a queue; boundaries need deciding |
| uiux.md | produce | user-facing dashboard |
| product.md | skip | scope fully specified by requester; nothing to decide |
| maintenance.md | skip | requester operates it; handoff doc covered by release plan |
```

A skip line that says "not needed" is not a reason. Say *why* it's not needed.
