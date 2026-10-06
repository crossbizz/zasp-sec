## Fresh full verification at 6af016b4: worker passes; API refusal remains

The actual faithful full `npm run verify` at unchanged before/after
`6af016b47c13980465aa4598c193b0693e1a2233` ran from 02:37:29 to 02:45:27 UTC
and FAILED after 478 seconds. Pinned Node 22.23.1 / npm 10.9.8 / Go 1.25.13 / Tini 0.19.0,
workspace-owned 0700 TMPDIR and umask 0077 were recorded. Dependencies and shared
health/healthserver packages passed. The full worker race package passed in
439.046 seconds after the independently reviewed two worker test-fixture repairs.
The sole failure is API `TestP7OrderedReadinessRoutingCharacterization/current_
typed_release_without_actor_proof`: missing/expired/excessive deadline and typed
release refusal. API package took 9.050 seconds. Original 1s caller and 5s production
bounds remain unchanged; the full run does not instrument or prove the expiry cause.

UI, release, build and all later phases were unreached. Earlier full 512 FAIL302s
with three failures remains unchanged; its separate private diagnostics did not
reproduce API expiry in five focused/three package runs and selected no API fix.
The earlier 246-file/2535-test UI pass belongs to 3ccc, not this current run.

Root's separate faithful full-history scan at the exact same 6af commit passed
0 findings in 92.417 seconds. The separate ledger consistency proof retains 728 rows,
523/144/61 categories, zero missing/duplicates and full ownercoverage. These
checks do not clear failed full verification, the approved-advisory-unavailable
production release gate, native acceptance or deployed authority. Bounded task
links use only existing M1-28/M1-28b health-command gate rows, without additional
inferred IDs or original acceptance/category promotion.

The private packet retains exact commands/tools/source and result hashes,
scanned sanitized compressed output and explicit sanitization match counts.
No raw secret matches, provider/native actions, shared source/guard edits or
online audit/disclosure were added by this verification recorder. Independent
packet/publication review remains required before repository adoption.
