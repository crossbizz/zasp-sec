# Independent decoder and process review

Reviewer: evidence_export_worker_review, 2026-09-19. Read-only review verified
the three frozen hashes in progress.md and unchanged HEAD. No production-code
defect was found. Bounded verdict: continue integration, with planned test
coverage still incomplete. This is not production acceptance.

P3: the wrong-version test returned a provider error from its fake reader before
the decoder saw the wrong locator. Separate expected request locator from
returned artifact and assert integrity plus repository-unavailable classification.

P3: add two-record reversed grant selection, malformed package schema and
package/per-format size bounds with valid outer hashes. Current tests couldn't
detect missing ordering validation or several package checks.

Process fixture starts two real registered OS processes with an interrupt and
restart. Before/after byte equality alone doesn't independently exclude
deterministic rerendering. Retain worker native no-render replay evidence with
the process result; don't claim the process fixture alone proves that branch.

Open integration: registered permission revocation, real parent cancellation,
foreign scope, browser coexistence, grant issue/read/final consume, public
routes, planner/settlement/UI and live-provider acceptance. No original task
is newly marked production-available.

Scoped follow-up: both P3 findings ADDRESSED. Reviewer verified test hash
81f967ccbbb24e287d16f8d3ccbb3b723dfd304bc87b3163d6a848031d19db86,
unchanged decoder/process hashes and retained seven-test race output. No new
actionable issue. No reviewer rerun or mutation. Decoder component review is
accepted; the process-proof limitation and connected integration gates remain.
