## Detached full verification at 9970bcbd failed on runtime-readiness callback

The actual fresh full `npm run verify` ran from 02:55:12 to 03:03:42 UTC and
FAILED after 510 seconds in a new owned detached worktree. Before/after commits
are exactly `9970bcbd04227e32d3161e921838371a3c14642c`, with clean tracked
source after completion. Pinned Node 22.23.1 / npm 10.9.8 / Go 1.25.13 / Tini 0.19.0,
umask 0077 and workspace-owned 0700 TMPDIR were recorded; no package install or
guard skip occurred. Dependencies and shared health/healthserver checks passed.
Worker full race package passed 451.861 seconds. The sole failure is
`TestP7GuardedRuntimeReadinessCallback/healthy` at 1.01 seconds: callback runtime
unavailable, with services 1 / core 1 / agent 0 / previous 0. API package took 11.042 seconds.
The earlier routing characterization failure was absent; the callback expiry
stage and production cause are not established by this full log. Separate
private diagnosis/any future repair requires its own reviewed evidence.

The worktree's node_modules symlink resolves to the existing shared root
node_modules. Exact997 package.json/lock bytes and observed shared module-lock
identity match before/after; runtime paths and this sharing are disclosed.
These observations do not prove a complete immutable dependency-file closure.
Root checkout changes cannot change this detached tracked source; no future
HEAD verification or new deployed/native acceptance follows from this run.

UI, release, build and later phases were unreached. Earlier 512 302s FAIL,
6af 478s FAIL and native 205/224s failures remain preserved. Historical 3ccc 2535 UI
passes belong to that separate 733s failure, not current 997. Root's separate
faithful full-history scan at exact 997 passed 0 findings in 96.673 seconds; it is
not full verification or approved-advisory production-release clearance.

The sealed private packet binds exact commands/tools/source/runtime identities,
actual summary, scanned sanitized gzip with raw hash/transform counts, observed
dependency limits, separate scanner proof and bounded existing M1-28/M1-28b
health-command task links. No all 728/category or original acceptance promotion,
provider mutations, online audit/disclosure or root shared edits by this recorder.
Receipt/status are private drafts requiring independent review before adoption.
