# Contributing — to *your* Loom

Loom inverts the usual open-source loop: **improvements flow to your instance, not to
this repository.** Every install is sovereign; each one evolves for its owner.

## Make it yours (the intended flow)

1. **Clone, then re-home.** Clone this repo, then point `origin` at a remote you own
   (private is a fine default) — or keep it purely local. Loom never fetches/pulls on load;
   synchronize only when you explicitly choose. Learning state stays local to this install.
2. **Install once.** `tools/install.sh` / `tools\install.ps1` stamps your clone's
   location into the `/loom` skill.
3. **Close the loop deliberately.** Retros record bounded numeric outcomes and may queue a
   controlled generic pattern locally. Only explicit `/loom contribute` merges that queue
   into this install's `FEEDBACK.md`. Triage with the playbook in
   [`loom/meta/evolving-loom.md`](loom/meta/evolving-loom.md) — fix guidance that misled
   you, delete guidance nobody uses, grow deep-dives for your domains. That ritual *is*
   contribution here.
4. **Diverge deliberately.** Domain/project memory stays in scoped local state; core guidance
   changes only through reviewed authored edits. Upstream releases are optional imports—check
   and cherry-pick what serves you, skip the rest.

## About changes to this repository

This repo is a released cut of a living upstream. Its improvement channel is its owner's
own loop — the same one you get. Issues that report real defects (broken links, install
failures, lint bugs with a reproduction) are welcome; feature requests will most likely
be answered with "your Loom can grow that — here's the ritual", because that's the
design working as intended.

## The one rule that binds every Loom

No instance sends data to any other instance. If you fork this and add a collection
channel, what you've built may be useful — but it isn't Loom.
