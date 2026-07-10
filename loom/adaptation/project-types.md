# Project-type adaptation

The lifecycle, gates, and epistemics never change. What changes per project type: **planning
emphasis, testing peculiarities, release mechanics, and the characteristic pitfalls.** This
file is a modifier catalog — apply the section(s) that match; multi-type projects apply
several.

Everything here about specific platforms is knowledge that decays — treat concrete platform
requirements (store policies, signing procedures, API levels) as `[SPECULATION]` to verify
in-session per `loom/verification/hallucination-check.md` before load-bearing use.

## Web application (SPA/SSR, dashboards, tools)

- **Emphasis:** contracts (client/server boundary is the coordination point), UI/UX with
  full state coverage, auth model as an early decision record.
- **Testing:** contract tests both directions; e2e over MUST flows; cross-browser scope as
  an explicit decision (which browsers, which not — NEVER rung).
- **Release:** staged deploys natural — use them; rollback usually cheap (previous build)
  *except migrations* — the expand-contract question is mandatory.
- **Pitfalls:** auth/session edge cases planned last; "works on my viewport" (responsive
  plan §3 exists for this); API error shapes improvised per endpoint.

## Website (marketing, content, portfolio)

- **Emphasis:** UI/UX is the center of gravity (may absorb architecture); content plan and
  real copy early — layout with fictional copy is fictional layout; SEO/performance as
  explicit scope rungs.
- **Performance defaults (deviating is a decision, not a habit):** system font stacks
  first — a webfont is a chosen dependency, never a reflex; inline vector art over image
  files at small scale; zero third-party requests as the baseline; script deferred and
  optional (the page works with it off); animations on compositor properties only. One
  trap worth naming: styling that hides content until a script reveals it must be gated
  on a class the SAME script sets — split the gate from the enhancer and a failed load
  strands the content invisible.
- **Testing:** the deliverable smoke battery (`loom/planning/testing-plan.md` §6) —
  scripted static checks, measured per-breakpoint probes, event-dispatch behavior
  checks; plus the restated-fact sweep for anything the page says twice; Lighthouse-class
  budget if performance is a stated goal.
- **Release:** DNS/hosting steps are release-plan steps (and rollback = keep old hosting
  live until verified).
- **Pitfalls:** treating it as an app (over-scaffolding a static site); no content-ready
  date so "done" never arrives; localized/RTL variants discovered post-layout.

## Windows desktop app

- **Emphasis:** framework decision record is heavy (WinUI/WPF/Tauri/Electron/.NET MAUI —
  tradeoffs: footprint, native feel, web-skill reuse); update strategy decided at
  architecture time (installer-only vs auto-update); filesystem/registry contracts
  (`contracts.md` §3).
- **Testing:** clean-machine test is non-negotiable (dev machines hide dependencies);
  per-OS-version matrix as explicit scope.
- **Release:** build → sign (signing is a `[HUMAN-DECISION]` — cert costs money) →
  installer → clean-VM verify. Unsigned = SmartScreen friction: plan for it explicitly
  either way.
- **Pitfalls:** DPI scaling and multi-monitor as afterthoughts; admin-rights assumptions;
  auto-update designed after v1 ships (retrofit is painful).

## Android app

- **Emphasis:** minSdk / device-floor decision record (audience fact, not developer
  preference — see weak-assumptions escapee type 2); permissions model planned with the
  features that need them; offline/sync behavior as an early architecture decision.
- **Testing:** device matrix (cheap real device + emulator floor/ceiling); process-death
  and rotation state tests; store pre-launch report.
- **Release:** signed bundle, store listing assets, review lead time in the schedule,
  staged rollout percentages with widen-criteria; rollback = staged-rollout halt + expedited
  fix (full rollback isn't really available — plan accordingly: **the store makes releases
  semi-irreversible, so G4 is stricter here**).
- **Pitfalls:** store policy surprises (verify current policies in-session at planning
  time); background-work restrictions varying by OS version; APK-size creep unbudgeted.

## CLI tool

- **Emphasis:** the interface contract IS the product: commands, flags, exit codes, stdout
  vs stderr, machine-readable output mode — all contracts.md material. UI/UX plan → skip;
  its budget goes to interface ergonomics + help text.
- **Testing:** golden-file tests over output; exit-code assertions; cross-platform path/
  encoding checks if claimed.
- **Release:** distribution decision record (registry, binary releases, package managers);
  breaking-flag changes follow the compatibility rules.
- **Pitfalls:** breaking scripted consumers with "improved" output (machine-mode is the
  hedge); interactive prompts that break automation (always plan a non-interactive path).

## Library / SDK

- **Emphasis:** public API surface = the contract, designed first, frozen hardest;
  versioning + deprecation policy is a decision record; docs-and-examples are MUST-rung
  product scope, not garnish.
- **Testing:** the examples in docs run in CI (rot-proofing); semver discipline tests
  (public-surface diff check) if tooling allows.
- **Release:** publish + install-from-registry verification on a clean project.
- **Pitfalls:** leaking internals into the public surface (boundary clarity dimension);
  breaking changes disguised as fixes; README examples that stopped compiling months ago.

## Data / ML project

- **Emphasis:** data contracts (schemas, provenance, refresh cadence) dominate; evaluation
  criteria defined *before* modeling (else "looks good" ships); reproducibility decisions
  (seeds, versions, environment) up front.
- **Testing:** data validation gates in the pipeline; eval sets held out and versioned;
  regression on metrics, not just code.
- **Release:** model/artifact versioning; rollback = previous model kept warm; monitoring
  for drift is maintenance-plan material with real thresholds.
- **Pitfalls:** leakage between train/eval discovered late; pipeline works-once (no rerun
  from scratch verification); metrics without a decision rule attached.

## Automation / scripts (including trading/EA work, e.g. MQL5)

- **Emphasis:** blast-radius analysis first — what can this touch, what must it never touch
  (danger zones are the plan's spine); dry-run/simulation mode as a MUST rung; idempotency
  and re-run safety as explicit decisions.
- **Testing:** simulation/backtest verification before anything touches real systems;
  compile/lint gates (e.g., MQL5: compile log parsed to 0 errors / 0 warnings as the
  mechanical gate); characterization of existing behavior before modifying.
- **Release:** staged exposure = demo/paper environment first, always; live activation is a
  `[HUMAN-DECISION]` **every time** — never auto-promoted, regardless of green checks.
- **Pitfalls:** the script that "can't affect anything" affecting things (file writes,
  orders, API side effects — enumerate them); safety rules relaxed during debugging and
  never restored; time/timezone bugs in anything scheduled.

## iOS / macOS app

- **Emphasis:** minimum OS version decision record (audience devices, not developer's);
  App Store review constraints shape scope *early* (IAP rules, entitlement needs, privacy
  disclosure labels); offline/sync and notification behavior as architecture decisions.
- **Testing:** real-device pass beyond the simulator (sensors, performance, notch/Dynamic
  Island layout); privacy manifest / permission-prompt flows exercised, not assumed.
- **Release:** signing + provisioning is its own precondition checklist (certs, profiles,
  team roles — a `[HUMAN-DECISION]`: paid developer account); TestFlight as the staged
  stage; App Review lead time in the schedule; like Android, **store distribution makes
  releases semi-irreversible → stricter G4**, expedited-review path noted in rollback.
- **Pitfalls:** entitlement discovered missing at submission; iPad/macOS layout treated as
  scaled iPhone; review rejection for a scope rung nobody checked against store policy
  (verify current policy in-session — it moves).

## Linux desktop app

- **Emphasis:** distribution decision record dominates (Flatpak / AppImage / Snap / native
  packages / tarball — tradeoffs: sandboxing, update path, distro coverage); desktop-
  environment matrix as explicit scope (GNOME/KDE at minimum, Wayland vs X11 stated);
  filesystem/config contracts follow XDG conventions.
- **Testing:** clean-VM pass per packaging format; Wayland *and* X11 smoke if GUI;
  theme/scaling variance (fractional scaling is the DPI bug farm here).
- **Release:** per-format publishing steps (Flathub review has lead time too); rollback =
  previous package version kept installable, stated by name.
- **Pitfalls:** hard dependency on a distro-specific path/library; tray/notification APIs
  differing per DE; assuming systemd everywhere the moment a daemon appears.

## Browser extension

- **Emphasis:** permission budget is the product decision — every permission requested
  costs installs and review time; manifest version + store policies verified in-session
  (this surface changes yearly); cross-browser scope rung (Chrome/Firefox/Edge/Safari are
  four different stores and two-plus API dialects).
- **Testing:** the permission-prompt path and the update path (extensions update in place —
  state migrations run unsupervised on users' machines); content-script interaction with
  hostile/unknown pages (the input boundary is the entire web).
- **Release:** store review lead time; staged rollout where the store supports it;
  rollback = pushing a previous version *through review again* — plan the expedited path
  before shipping, not during the incident.
- **Pitfalls:** scope creep into "just one more permission"; breaking on the store's
  manifest-policy migration; storing sensitive data in extension storage without the
  security plan noticing it's synced.

## Bots & LLM apps (chatbots, agents, LLM-backed features)

- **Emphasis:** the *eval set is the spec* — define graded example interactions (the
  MUST flows) before building, or "works" stays vibes; prompt/model version pinning as
  contracts (`contracts.md`: prompts are runtime contracts — versioned, diffable, owned);
  cost budget as a first-class constraint (per-interaction token math in the architecture
  plan, labeled); safety/abuse posture is a mandatory security-plan section (prompt
  injection, data exfiltration via tool use, unsafe output handling).
- **Testing:** eval harness over the graded set on every prompt/model change (regression
  on *behavior*, not just code); adversarial inputs from the abuse cases; non-determinism
  handled by scoring thresholds, not exact-match assertions.
- **Release:** model/prompt changes ship like code — staged, with the eval delta attached;
  rollback = previous prompt+model pair kept addressable; monitor cost per interaction and
  refusal/failure rates as release metrics.
- **Pitfalls:** "improving" a prompt with no eval set (every change is a coin flip);
  model-version drift silently changing behavior (pin, and record the pin as a decision);
  tool-using agents with no `touches`-equivalent blast-radius limit; costs discovered in
  the first invoice instead of the architecture plan.

## Choosing when the requester didn't say

Platform choice open → it's a `[HUMAN-DECISION]` with a recommendation derived from audience
facts (their devices, their distribution reality), not from what's pleasant to build. The
recommendation states what evidence would flip it.
