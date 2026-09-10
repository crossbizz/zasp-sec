# Reconciliation lane plan, September 10, 2026

Status: locally verified bounded candidate-plan correction on
`codex/reconciliation-lane-plan`. Not shipped. No original task credit changes:
535 production-available / 132 component-only / 61 external gates, all 728 rows.

The pre-existing query-plan defect reproduced on unchanged main and then under
controlled cardinality estimates. Schema 46 moves the provider/operation-wide
live-lease exclusion into a materialized eligible-lane CTE before each ordered
per-scope candidate lookup. This prevents the candidate-level selectivity estimate
from defeating the LIMIT-one index lookup. The original schema-11 SQL is unchanged.

The replacement verifies the exact prior claim body digest, preserves ownership,
SECURITY DEFINER, fixed search path and API/worker grants. A new fingerprint binds
its body and ACLs to current schema-45 readiness. Down checks drift and restores
the exact prior body, readiness and compatibility caps. There is no executable
legacy bypass. The historical schema-11 security predicate is false at the
current predecessor, so the new readiness uses current schema-45 security and
explicit checks on the changed function. Independent review accepted this.

Global lock 742516322, the 100-active cap, global provider/operation exclusion,
scope fairness, age/attempt eligibility, PKCE-consuming exclusion and SKIP LOCKED
are retained. Transaction-start timestamps after lock waits are existing semantics
and have not been silently changed by this plan-only correction.

## Evidence so far

- `/tmp/zasp-reconciliation46-diagnostic.log`: controlled old/new query comparison
  at provider cardinalities 25 and 101. Fixed statistics are test-only.
- `/tmp/zasp-reconciliation46-bounded-red.log`: the original bounded-plan test
  fails deterministically against the installed schema-11 function at cardinality
  25. The test reads installed candidate CTEs instead of a copied query.
- `/tmp/zasp-reconciliation46-bounded-green.log`: actual schema-46 function passed
  the original index, row-work, read-block and spill bounds, then the 100,000-row
  history retirement checks. Test 45.32 seconds, race command 47.397 seconds.
  Later normal-planner candidate checks passed at both 25 and 101. Expanded
  repetitions failed a separate historical-retirement I/O check; see below.
- `/tmp/zasp-reconciliation46-migration-green.log`: upgrade, exact rollback and
  re-upgrade passed. The final fingerprint is
  `1ea4724c2dc08814f8f46cbc34c5f0613ffc9b21a28dd1384e9d3e26dcbeb5b6`.
- `/tmp/zasp-reconciliation46-authority-green.log`: actual registered API and
  discovery-worker readiness passed, as did future-version, search-path and ACL
  drift rejection through readiness, API startup and Down. Race command 6.251s.
- `/tmp/zasp-reconciliation46-cli-red.log`: the new command test failed at schema
  45 before wiring 46. Focused GREEN passed. Full CLI/catalog verification first
  exposed old manual rollback expectations, which now include Down46. Retry
  `/tmp/zasp-reconciliation46-cli-full-green.log` passed (64.761s / 1.863s).
- `/tmp/zasp-reconciliation46-claims.log`: real registered-worker SQL/repository
  claims passed scope fairness, a live lease in another tenant, PKCE-consuming
  exclusion with a later eligible candidate, capacity 100 and concurrent claims.
  The concurrency case observes a real database lock wait before committing the
  first lease and verifies the waiting worker cannot duplicate it. These are
  explicit database fixtures, not live provider composition. Extra attempt/time/
  row-lock cases passed in the final focused authority run, along with predecessor
  body drift, actual-role startup and future/body/ACL/path rejection:
  `/tmp/zasp-reconciliation46-final-authority.log`, race command 9.718 seconds.
- `/tmp/zasp-reconciliation46-verify.log`: full Node verification passed, 196
  files / 1179 tests, types, lint, API checks, production build and ledger.
- `/tmp/zasp-reconciliation46-api-full.log`: full API race suite passed in
  346.830 seconds. Later expanded repetitions still failed on retirement I/O;
  this earlier full-suite pass does not establish that defect is fixed.
- `/tmp/zasp-reconciliation46-contracts.log`: 61 passed, 2 explicitly gated
  skips. `/tmp/zasp-reconciliation46-release.log`: source release gate passed.
- `/tmp/zasp-reconciliation46-chrome.log`: actual full browser composition
  passed with exit 0, schema 46, owned runtime pipeline, pairing, discovery,
  security workflows and complete cleanup. Provider and graph fixture limits
  remain as declared by the composed harness; this is not a live deployment.
- `/tmp/zasp-reconciliation46-ci-contract.log`: all 15 workflow contract tests
  passed. Initial staged secret scan passed; privacy review found 9 medium and
  zero high findings, all fixed fixture IDs, example AWS accounts or CI run IDs.
- `/tmp/zasp-reconciliation46-final-focused.log`: three complete focused race
  repetitions passed in 167.484 seconds. Each includes normal-planner candidate
  checks at 25 and 101, the original retirement phase with its original planner
  setting, all claim conditions and migration/readiness/drift checks. This does
  not fix or invalidate the separate default-planner retirement failure.
- Independent read-only review found no intermediate migration blocker. Final
  approval is conditional on the remaining evidence; it did not run heavy suites.
- Final read-only review approved bounded M46 shipping after the local evidence
  completed, conditional on required push/PR/main CI. It explicitly retains the
  separate retirement defect and awards no original task credit.

## Still required

Commit-history secret scan, push/PR checks, merge and main CI. Each pending gate
is pending, not a pass. The broad file count includes required schema catalog,
release CLI, deployment identities, startup caps and their regression contracts.

## Separate retirement exception

`2026-09-10-reconciliation-retired-lane-io.md` records a second, unresolved
default-planner physical-scan defect. It reproduced three times against exact
schema 45. Expanded M46 repetitions failed that phase despite bounded candidate
plans. Review accepted this predecessor-causality evidence and permits bounded
M46 shipping only after Chrome and required CI pass unchanged. The new normal
candidate checks restore the prior `enable_seqscan=off` setting before the old
retirement phase; review explicitly accepted this as test isolation. All original
workloads and bounds remain. No VACUUM or extra cache warming was added.

Retirement remediation is next, before frozen candidate work. This migration
fixes candidate planning, not empty-catalog physical I/O or general launch readiness.

This fix does not finish frozen runtime candidate snapshots, actual collector
lineage emission, Strong/Probable cross-batch attribution or mixed-evidence E2E.
Those original criteria remain on the critical path. No live deployment or
external production acceptance is claimed.
