# Contributing — to *your* Loom

Loom inverts the usual open-source loop: **improvements flow to your instance, not to
this repository.** Every install is sovereign; each one evolves for its owner.

## Make it yours (the intended flow)

1. **Clone, then re-home.** Clone this repo, then point `origin` at a remote you own
   (private is a fine default) — or keep it purely local. Your Loom's freshness pulse
   syncs against *your* remote, and everything the learning loop writes stays in *your*
   tree.
2. **Install once.** `tools/install.sh` / `tools\install.ps1` stamps your clone's
   location into the `/loom` skill.
3. **Let the loop run.** Every real project run appends honest entries to your
   `FEEDBACK.md` and teaches your `~/.loom/`. Triage the queue with the playbook in
   [`loom/meta/evolving-loom.md`](loom/meta/evolving-loom.md) — fix guidance that misled
   you, delete guidance nobody uses, grow deep-dives for your domains. That ritual *is*
   contribution here.
4. **Diverge proudly.** A year in, your Loom should look different from this snapshot:
   your language deep-dives under `loom/adaptation/`, your calibration data, your
   triage judgments. Upstream releases are optional imports — cherry-pick what serves
   you, skip the rest. Divergence from upstream is success, not drift.

## About changes to this repository

This repo is a released cut of a living upstream. Its improvement channel is its owner's
own loop — the same one you get. Issues that report real defects (broken links, install
failures, lint bugs with a reproduction) are welcome; feature requests will most likely
be answered with "your Loom can grow that — here's the ritual", because that's the
design working as intended.

## The one rule that binds every Loom

No instance sends data to any other instance. If you fork this and add a collection
channel, what you've built may be useful — but it isn't Loom.
