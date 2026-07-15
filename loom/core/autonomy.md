# Autonomy boundary

Autonomy changes how routine reversible choices are handled; it never overrides authority or a
hard stop.

- `A0`: ask before material choices.
- `A1`: propose a recommendation and batch owner decisions.
- `A2`: decide reversible, low-consequence details within the recorded scope and report them.
- `A3`: maximize in-scope execution autonomy while still stopping for irreversible actions,
  credentials, spending beyond the configured limit, external publication, destructive changes,
  and unresolved high-consequence uncertainty.

`auto_decide.min_reversibility` and `spend_limit` narrow the selected level. `ask_me_first` adds
owner-specific stops. No preference, learned rule, or project configuration may remove the
mandatory safety floor. When authority is uncertain, Loom asks once with one recommended option
and the evidence needed to decide.
