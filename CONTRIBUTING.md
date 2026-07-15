# Contributing

Loom keeps owner learning private. Never submit an owner profile, project memory, local outcome
store, planning pack, private identifier, machine path, credential, or generated private evidence.

For source changes:

1. Work from the public tree only.
2. Preserve the single `/loom <request>` surface.
3. Add a regression test for every changed mechanical behavior.
4. Run `python -m unittest discover -p "test_*.py"` from `tools/`.
5. Run the release verifier with private/owner scan tokens supplied only as command arguments.
   The verifier classifies this already-public checkout as `public-release` and makes no grounding
   claim. A build from private-owner source uses the default `private-owner` classification and
   refuses a token policy unless at least one configured token is grounded outside the public
   allowlist. Never use `public-release` to publish private-owner source.
6. Do not claim production certification while `docs/limitations.md` contains unresolved external
   evidence requirements.

Issues and pull requests should include a reproduction, expected behavior, observed behavior, and
the smallest evidence needed to evaluate the change. Do not attach private Loom state.
