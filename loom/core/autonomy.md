# Autonomy — how much the agent decides alone

Loom's epistemics say *what* needs a human (`[HUMAN-DECISION]` triggers); this file says
*when and how* the human is actually involved. The goal is minimum human interruption at
equal safety: humans state preferences once, agents batch what remains, and a short
never-delegable list stays human forever.

## The levels

| Level | Name | Agent behavior | Human touchpoints (typical tier M) |
|---|---|---|---|
| **A0** | Advisory | Plan only. Nothing executes; every gate presents and waits. | Every gate |
| **A1** | Checkpointed | Agent executes; pauses for approval at G1 and G4. | 2–3 |
| **A2** | Batched *(default)* | Agent runs the full lifecycle. `[HUMAN-DECISION]` items are collected and presented **once per gate** as a batch; work not dependent on them continues while waiting. Reversible choices within the decision budget are made by the agent and recorded. | ~1 batch reply + release go |
| **A3** | Autopilot | As A2, but on batch items the agent applies its **recorded recommendation** after logging it, instead of waiting — except hard stops. Human gets the close-out report. | Release go only (if user-visible) |

Level comes from, in precedence order: the human's words this session > `loom.config.json`
(`autonomy` field) > default **A2**. The skill flags `--advise`, `--careful`, `--auto` map to
A0, A1, A3. Record the operative level in MANIFEST — reviewers judge conduct against it.

## The decision budget (what A2/A3 agents decide alone)

An agent may decide and record — no human — when **all** hold:

1. Reversibility MED or HIGH (per the decision-record field; pricing the exit is part of
   deciding).
2. No spend beyond `auto_decide.spend_limit` in config (default **0** — any real money is a
   human matter).
3. Not on the hard-stop list below, and not on the project's `hard_stops_extra` config list.
4. The decision doesn't contradict anything the requester said this session or in config.

Everything decided this way still gets a decision record with `type: agent-decided`. Silent
is never an option; *solo* often is. A human can veto any agent decision later — that's what
reversibility bought.

## Hard stops (never delegable, at any level — including A3)

- Privacy boundaries: publishing or externally sharing anything derived from a pack
  (`loom/core/privacy.md` outranks autonomy).
- Real money: purchases, subscriptions, paid tiers, ads — anything beyond the configured
  limit (default: anything at all).
- Destructive-irreversible: deleting user data, dropping columns/tables with data, force
  pushes to shared branches, production migrations without verified backups.
- Live systems with real-world stakes: activating live trading, sending real user
  communications at scale, anything the project type marks as `[HUMAN-DECISION] every time`
  (`loom/adaptation/project-types.md`, automation/EA section).
- Credentials and access: creating, rotating, or granting access to secrets and accounts.
- Anything the requester marked "ask me first" — verbatim or in config.

When a hard stop blocks the critical path, the agent parks the dependent work orders
(`blocked`), continues everything else, and surfaces the item in the next batch — a hard
stop pauses a *branch*, never the project.

## The batched checkpoint (how to ask well)

One message per gate, not a drip. Each item:

```
D-007 (blocks WO-009, WO-011): Payment provider
  Options: Stripe / local PSP / cash-on-delivery only for v1
  Recommendation: cash-on-delivery v1 — audience fact A-003 (most customers pay cash),
  integration cost pushes release out ~2 weeks, reversibility HIGH.
  If you answer nothing: A2 = these WOs stay blocked; A3 = recommendation applies at G1 exit.
```

Rules: always a recommendation (menus without one are outsourced thinking); always the
blocked-work consequence; always the no-answer behavior, stated per the operative level.
This format is what makes A3 safe — the human saw exactly what would happen by default.

## Interaction economics (why this file exists)

Every human round-trip costs hours of latency against minutes of agent time. But a wrong
irreversible guess costs more than all the round-trips it saved. Hence the design: spend
human attention **only** where reversibility can't buy it back, batch it where it must be
spent, and make the default path (A2) the one that respects both.

## Reporting

Close-out reports state: operative level, count of agent-decided records, batch items and
their resolutions (or applied defaults), and any hard stops hit. An A3 run that produced
zero agent-decided records is suspicious (probably over-asking); one with zero recorded
decisions is worse (deciding silently).
