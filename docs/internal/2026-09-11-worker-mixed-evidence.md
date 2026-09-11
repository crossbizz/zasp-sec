# M7-07 worker-backed browser acceptance

Original criterion: compose session timeline rows with confidence/source and
pagination; render mixed evidence without false Exact attribution.

Status: local verification and independent review passed. Publication and hosted
checks are pending. No original task credit before verified main.

The recovery fixture's tenant owns the events throughout this proof. The new
browser context has a separately declared identity/session fixture. It uses the
normal scoped API, PostgreSQL authorization and mounted UI. This is not an OIDC
login proof, live source attestation or deployed production evidence.

The test first reached the actual API and failed because the mixed session had
2 events instead of the 27 required to cross a 25-row page boundary. Evidence:
`/tmp/zasp-mixed-browser-count-red.log`. Earlier attempts stopped for synthetic
identity/session reference errors; those are setup failures, not product REDs.

The added 25 events go through authenticated OTLP ingestion and normal archive,
index, correlation, projection and completion workers. Their timestamps descend
in ingress order. A versioned S3 correlation receipt must contain exactly 25
Exact decisions with the original explicit agent/session identity. Existing
Strong recovery and unassigned Probable ambiguity fixtures are unchanged.

The first enlarged runtime fixture passed its receipt/projection checks, but the
browser found no indexed session and correctly displayed five pending batches.
Evidence: `/tmp/zasp-mixed-browser-green.log` (failed despite the filename).
The fixture now invokes the existing composed session-search worker and requires
all five batches indexed. The browser independently requires current search
status, zero pending batches and the canonical mixed session in search results.

The browser checks 25-plus-2 paging, exact event identities, canonical ordering
against the input fixture, visible confidence labels, source and scoped API
agreement. Strong runtime evidence must not display Exact. Probable evidence
stays in the unassigned collection and cannot be fetched through the known
session. A different authenticated tenant must get 404. Role revocation must
produce API 403; this assertion does not claim removal of already-rendered UI
data. Browser cleanup must leave worker events, summaries and frozen snapshots
byte-for-byte unchanged.

Independent review required visible label checks as well as data attributes and
nontrivial event-time ordering. Both are now in the test. The current-source full
combined proof passed with exit0 and completed cleanup:
`/tmp/zasp-mixed-browser-indexed.log`. Worker races passed in 9.246s; runner contracts
passed with two explicit opt-in interruption probes skipped. The source release
gate passed. Full verification passed all 1,188 UI tests, typecheck/lint/build,
compiled imports and all 728 ledger rows. Logs:
`/tmp/zasp-mixed-browser-verify.log`,
`/tmp/zasp-mixed-browser-worker-races.log`,
`/tmp/zasp-mixed-browser-final-contracts.log` and
`/tmp/zasp-mixed-browser-source-gate.log`.

Final independent review found no blocking issue and accepted this evidence for
M7-07's original criterion, conditional on final verification and merge/main CI.
M3-46/M3-47 lineage acceptance, login verification, live source attestation and all
live deployment gates are separate and remain open.
