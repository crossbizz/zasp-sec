# Precise session search driver

SessionIndex.ApplyPrecise now accepts committed V3 receipts and exact V2
archives only on the sandbox-capable V2 target. Historical Apply remains
separate. Both paths share bounded immutable creates, exact document readback
and refresh-before-success.

Superpowers evidence:

- The added precise profile failed with the rejecting method before implementation.
- The actual driver and document builder run against declared HTTP responses.
  Tests verify separate schema/marker setup, sandbox identity, lost acknowledgement
  recovery, exact readback, two identical writes and two successful refreshes.
- V1 target and legacy Apply reject precise receipts before network access.
- Expanded driver/search/worker races exited0:1.774s/1.275s/14.816s.
- Independent review found no issues. A fresh UI build exited0.

This is local driver behavior, not live OpenSearch visibility or deployed
search. Search-worker dispatch, queue routing, database finalization and
production activation remain open. No push or original task credit.
