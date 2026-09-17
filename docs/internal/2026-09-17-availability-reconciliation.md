# Availability reconciliation against original criteria

This is a six-row evidence correction, not new implementation or live production
acceptance. Original task scope and historical ledger_status values are unchanged.
The current availability table becomes 534 production-available, 133 component-only
and 61 blocked/external, with all 728 original IDs present.

Production-available uses the ledger's existing meaning: shipped, reachable
production composition meeting the stated original task criterion. It does not
mean deployed cloud/customer acceptance. An original criterion that explicitly
requires controlled fixtures can be met by those fixtures; a live requirement
cannot. All product-wide provider, deployment, load and release gates remain open.

| Original task | Current class | Evidence and limit |
| --- | --- | --- |
| M1-33 | component-only | Original agentsec-tests queue/schema acceptance is not satisfied by main's current queue definitions. Local queue repair and disposable LocalStack evidence do not establish verified publication or live queues. |
| M3-46 | production-available | Original Strong-correlation criterion uses controlled fixtures. PR49 fda8ae99 is an ancestor of main; registered51 provider/browser evidence proves a semantic-ID-absent Strong match with source-qualified process/sandbox identity. See 2026-09-11-precision-provider-evidence.md and 2026-09-11-file-cgroup-lineage.md. No live sensor/attestation claim. |
| M3-47 | production-available | The same shipped composition admits competing candidates and proves unassigned Probable, plus frozen Strong replay. This is positive ambiguity evidence, not an absent-candidate-only result. Precise correlator tests are unchanged from main. No live deployment claim. |
| M7-36 | component-only | The shipped Audit Log UI does not establish every original filter/export and SSO/config/policy/test-event browser criterion. New local audit UI/export work is not included in this increment. |
| M7A-49 | component-only | Existing budget fields and earlier component tests do not prove all original limits through wait/reclaim and actual-worker accounting paths. Candidate repairs are unshipped; remaining action/accounting verification is open. |
| M8-47 | component-only | Main's offline npm audit returns without advisory lookup. Zero counters are insufficient security clearance. Local fail-closed containment is not a fresh candidate-bound scanner or completed original acceptance. |

Owner routing changes only for M7-36 (T11-identity-admin) and M8-47 (T15-deployment).
The demotions were checked against the original implementation plan's M1-33
(line 1114), M7-36 (line 3438), M7A-49 (line 3872), and M8-47 (line 4768).
Their shipped-source anchors are respectively
`services/platform/queuedefinition/definitions.go`,
`app/features/administration/AdminOperationsView.tsx`,
`services/platform/securityagent/planner.go`, and
`scripts/production-release-gate.mjs`. These anchors identify the inspected
composition; they do not establish that the missing original acceptance passed.
No original task is dropped or redefined. Independent Superpowers review inspected
the original task criteria, category definitions, source/evidence references and
main ancestry; it accepted all six category decisions and required stale evidence
prose to be refreshed. This note supplies that refresh without importing unrelated
unpublished implementation or its full investigation history.

Verification: run the authoritative status checker against these exact tables and
review the six-row/two-owner diff before commit. Historical count statements in
the status document remain historical; its current table and top checkpoint are
authoritative. This document is not proof of an entire 728-row re-audit.

## Candidate verification

The test-first candidate initially failed against the old checker. Updating the
checker and milestone rows exposed one remaining stale total in the documentation
matrix (33 passing tests, one failure). Correcting that total produced 34 passing
tests, zero failures and zero skips in `implementation-status-check.test.mjs`.
The standalone checker then reported all 728 rows valid at 534/133/61/0.
`git diff --check` also passed. These are ledger-consistency checks, not new
product acceptance evidence. Final independent review found no Critical or
Important issues. Its minor request for durable demotion-source references is
addressed above. Fresh candidate UI build and compiled imports passed with seven
client and eight server chunks. A standalone loopback smoke returned the root and
all seven referenced JS/CSS assets with HTTP 200 and nonempty bodies; the owned
server joined on SIGTERM. No product-source or lockfile changes are in this batch.
Publication identity is recorded by git; this note alone does not prove a push.
