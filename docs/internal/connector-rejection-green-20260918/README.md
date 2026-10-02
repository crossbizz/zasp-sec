# Connector rejection audit: local integration evidence

This directory retains the final connected integration result for M8-41 and
the exact ten-file BEFORE/AFTER manifest and scoped patch. Root independently
verified all ten current AFTER hashes and byte-equal copies of the five
retained evidence files. The implementation has no migration or privilege change.

`green-combined.log` proves mounted registered-role HTTP rejection auditing,
authorization races, group writer contention, rollback/fault handling and the
actual production PostgreSQL driver/decorator path in isolated cached Docker.
`affected-race.log` covers 48 affected top-level Go tests. These are local
integration results, not live-provider, production-deployment or live-egress
proof. Fault injection does not prove every network-failure mode.

The supported Node 22.23.1/npm 10.9.8 full UI boundary passed: 224 files,
2136 tests, typecheck, lint and build. `ui-pinned22.log` is authoritative for
that runtime; the Node 26 logs are retained diagnostics. Root verified all nine
retained evidence texts are byte-equal to their SDD originals.

Independent spec/quality review passed with no actionable scoped findings;
see `independent-review.md`. No production classification promotion,
staging, commit or push is
authorized by these results alone. External scanner and deployment gates remain
open. The earlier missing-audit RED is retained separately in
`../connector-rejection-20260918/`; failed setup diagnostics remain in the SDD
working evidence directory and are not counted as final passing evidence.
