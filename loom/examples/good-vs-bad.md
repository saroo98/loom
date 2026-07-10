# Good vs bad — planning output, side by side

Short paired excerpts. The commentary explains *why* — the pattern is what transfers, not
the text.

---

## 1. Work order task

**Bad**
> Improve the authentication system. Make sure sessions are handled properly and fix any
> issues you find. Also update the docs if needed.

**Good**
> Add session refresh to auth middleware. When a request arrives with an expired session
> and a valid refresh token, issue a new session transparently. Use the existing
> `SessionStore` (`auth/session.py`) — do not add a cache (that's WO-012). Out of scope:
> refresh-token rotation, docs (WO-015).

*Why:* "properly", "any issues", "if needed" delegate the actual decisions to whoever has
the least context. The good version has one outcome, names its boundary, and pushes
temptations to their own WOs. Conjunction "also" in the bad one = splitting instruction.

## 2. Acceptance criterion

**Bad**
> - [ ] Authentication works correctly and is well tested.

**Good**
> - [ ] `pytest tests/auth -q` green, including a new test for refresh-at-expiry boundary
> - [ ] Manual: expired session + valid refresh → 200 + new token (curl transcript in close-out)
> - [ ] `git diff --stat` touches only `auth/` and `tests/auth/`

*Why:* the bad one is a mood. Each good criterion is a command someone else can run, plus a
negative check guarding blast radius.

## 3. Architecture decision

**Bad**
> We will use a modern, scalable microservices architecture with industry best practices to
> ensure robustness and future growth.

**Good**
> D-002: Single process, modular monolith. Three modules behind interfaces (catalog, orders,
> notify). Why: one developer-agent team, ~200 users year one [ASSUMPTION A-006], zero ops
> budget [FACT — requester: "I don't want to maintain servers"]. Reversibility: module
> boundaries are the future service seams — extraction ≈ 1 WO per module. Revisit trigger:
> A-006 breaks upward by 10x, or a second team forms.

*Why:* the bad one contains zero decisions — every buzzword defers the choice. The good one
commits, shows its evidence with labels, prices the exit, and names what would reopen it.

## 4. Handling a gap in the description

**Bad**
> The requester didn't specify a database, so PostgreSQL was selected as the industry
> standard.

**Good**
> Storage: requester silent. [ASSUMPTION A-004] single-user desktop usage (from "my
> brother's shop PC") → SQLite; zero-install beats server features here. risk_if_wrong:
> MED — if multi-terminal turns out real, migration WO ≈ 1 day. verify_by: G1 exit
> question to requester (batched with A-002, A-007).

**Also bad (opposite failure)**
> Cannot proceed until the requester specifies: database, hosting, auth provider, CSS
> framework, logging library… (12 blocking questions)

*Why:* the first bad silently converts a default into a fact. The second bad stalls on
questions an agent is paid to have defaults for. The good one assumes, prices the risk,
schedules the check, keeps moving — Loom's core move.

## 5. Uncertainty in a plan

**Bad**
> The API should be able to handle the expected load without problems.

**Good**
> Load: unknown; no traffic history exists [UNKNOWN — resolved by WO-003's counter after
> week 1]. Design for the assumption of ~10 req/min [ASSUMPTION A-009]: no queue, no cache,
> synchronous handlers. Trigger to revisit: p95 > 500ms or A-009 measured >5x wrong.

*Why:* "should… without problems" is confidence theater over an unmeasured quantity. The
good version puts a number on the assumption, builds the *simpler* thing, and makes
revisiting mechanical (default + trigger), not anxious.

## 6. Repo survey claim

**Bad**
> This is a standard Django project, so the usual structure applies.

**Good**
> Django 4.2 confirmed [FACT — manage.py + `django==4.2.11` in requirements.txt:3]. Layout
> is NOT default: apps live under `src/services/` [FACT — ls output], and settings are
> split per-env in `config/settings/*.py` [FACT — config/settings/]. Tests: pytest-django,
> last green in CI 4 days ago [FACT — .github/workflows/ci.yml + actions run].

*Why:* "standard, so the usual applies" is convention projection — the hallucination-check
failure for repos. Every good claim carries its evidence, and the survey caught exactly the
nonstandard thing that would have broken every path-assuming WO.

## 7. Scope ladder entry

**Bad**
> Nice to have: dark mode, offline support, multi-language, admin panel, analytics.

**Good**
> SHOULD: Persian UI (requester's audience is Shiraz shop owners [FACT — quote]; ship
> English first only if translation review isn't done by G4).
> LATER: dark mode (no user signal; cheap to add post-v1 given tokens in uiux §4).
> NEVER (v1): offline mode — sync conflict design would dominate the whole architecture;
> requester confirmed shop has stable internet [FACT — quote, 2026-07-08].

*Why:* an undifferentiated "nice to have" pile makes every scope fight a fresh debate. Rungs
with reasons make cuts pre-negotiated — and NEVER entries stop idea necromancy.

## 8. Rollback section

**Bad**
> In case of problems, the deployment can be rolled back to the previous version.

**Good**
> Rollback target: tag v1.3.2 (image `app:1.3.2`, verified runnable on staging 2026-07-06).
> Triggers: checkout error rate >2% over 10 min, or any failed payment capture. Procedure:
> steps 1–4 below (≈6 min, rehearsed on staging — transcript in reviews/G4). Data: this
> release's migration is expand-only (new nullable column); old code runs against new schema
> [FACT — tested], so rollback loses nothing. Window: 48h, then contract phase (column made
> NOT NULL) via WO-021.

*Why:* the bad one asserts possibility; the good one names the target, pre-agrees triggers,
prices the time, and answers the only hard question (data) with evidence. "Can be rolled
back" without a rehearsal transcript is a hope.
