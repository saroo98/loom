# Intake contract

Intake turns the owner's words into a decision boundary. It does not embellish the request.

## Required record

1. Preserve the original request verbatim.
2. Identify the target and evidence used to resolve it. Ambiguity blocks target mutation.
3. State the desired outcome, exclusions, irreversible effects, external users, regulated data,
   spend, credentials, and release authority.
4. Classify tier from actual size and consequence, then select artifacts from
   `loom/intake/artifact-matrix.md`.
5. Identify domains. If no shipped adapter covers the work, require domain discovery before G1.
6. Record assumptions and unknowns using `loom/core/epistemics.md`.

## Question policy

Ask only when the answer changes safety, scope, architecture, or acceptance. Batch related
questions into one checkpoint. Prefer reversible defaults for routine choices and record them.

## Silence sweep

For Tier M and above, add `## Silence sweep` to `intake.md`. Record material signals the request
did **not** mention, including authentication, payments, personal data, migration, accessibility,
localization, offline operation, destructive actions, compliance, observability, rollback, and
multi-user behavior. Each item is either applicable, explicitly out of scope, or `[UNKNOWN]` with
a verification step. Absence of a word is not consent to ignore its risk.
