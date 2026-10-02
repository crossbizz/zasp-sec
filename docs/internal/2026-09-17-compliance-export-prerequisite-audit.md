# Compliance export batch: prerequisite correction

## Current local implementation checkpoint

The missing-source and missing-UI observations below are historical pre-fix
evidence, not descriptions of the current shipping worktree. Tasks1–5, both API
final fixes and CI wiring are now locally implemented and independently reviewed
at task boundaries. Configured release56 routes use scoped current sources;
durable jobs and typed evidence/filter/export UI are mounted in the local
assembled runtime. A fresh controlled-storage browser run passed on the final
API/worker revision. See compliance-ci-20260918 and its review receipt.

The original M7-08 through M7-15 evidence rows now point to these local results.
Their classes, owners and historical Complete fields are unchanged, including
the historical M7-15c production class. Connected final review is still active;
hosted Linux, advisory/publication, deployed provider/operator and live acceptance
remain open. Counts stay527/140/61 across728rows. Local remediation does not
retroactively validate the old production claims or establish a new deployment.

## September18 both-framework correction

Original M7-08 and M7-15a require both SOC 2 Security and HIPAA safeguard
mappings/control lists. Migration0007 at170-172 inserts only the SOC 2
access-control seed. A current non-test Go/SQL writer search finds no other
legacy control writer. Mounted administration_repository.go still reads those
legacy controls; SessionsComplianceView renders their framework without adding
missing mappings. Its current list fixture verifies SOC 2 only. The both-
framework mapping in release56 is locally reviewed but still unmounted.

Correct M7-08/M7-15a to component-only/T14-data-workflows, retaining historical
Complete. This is a missing production source, not a new live runtime test.
Current totals527/140/61/0 retain all728 IDs. Counts in older sections below
are checkpoint history. M7-15c freshness labeling is not changed by this audit;
its original UI-state requirement differs from the both-framework mapping.

New ledger regression first failed on M7-08's old production classification.
Then node --test scripts/implementation-status-check.test.mjs passed36/36 and
node scripts/implementation-status-check.mjs confirmed527/140/61/0 across728
rows. Independent read-only review approved the semantic/mechanical correction,
independently counted728 unique IDs and527/140/61 plus M7's30/32 split, and
confirmed original both-framework requirements. No product-suite rerun or
production promotion follows from this edit.

## September18 mounted-source correction

M7-09 requires current audit/finding/policy/test/config evidence assembly.
Mounted listComplianceControls/listComplianceEvidence still dispatch through
administration_repository.go:127-130 to queries at32-33 that constrain only
organization_id. Migration0007 at149-176 defines organization-only tables and
seeds membership evidence once. A fresh non-test service-source search found
only those migration inserts as writers to the legacy tables. The new release56
source authority is locally verified and reviewed, but not yet mounted by the
production routes. It cannot supply production credit to the existing endpoints.

M7-09/M7-10/M7-11 are corrected to component-only under T14-data-workflows,
preserving historical Complete. This is an unfulfilled current-source dependency
and selected-scope contract, not a newly reproduced live disclosure. Counts are
529 production-available,138 component-only,61 blocked/external,0 missing.
Earlier counts below describe the earlier two-row correction only. The original
728 tasks remain in scope; no other row gained or lost credit in this correction.

Verification for the September18 correction: new seed-backed regression failed
on the old production classification, then all35 ledger-validator tests passed.
Independent read-only review confirmed the original dependencies, three-row
classification/owner edits,529/138/61 totals and M7 split32/30 with no semantic
or mechanical findings. No broad product suite or live environment check ran.

September 17, 2026. Source audit, not implementation or runtime acceptance.
Original scope remains all 728 tasks. No deployment, new production proof,
commit or push is claimed.

## Evidence that changes the next action

The original plan requires M7-15b evidence rows with asset/source/timestamp links
that open a product evidence target. The current production
`app/features/sessions/SessionsComplianceView.tsx` compliance branch renders
asset ID, source and evidence ID as plain paragraphs. It omits the timestamp and
clickable target. M7-15 requires composed filtering/export acceptance; the same
branch has no filter or export interaction and explicitly displays exports as
unavailable. Both rows were incorrectly production-available. They are now
component-only, owned by T14-data-workflows. Historical Complete is retained as
the historical ledger field, not a current completion claim.

Current totals after these two corrections: 532 production-available,
135 component-only, 61 blocked/external, zero missing. The counts are ledger
classifications, not a new live verification of the other 726 tasks.

## Dependencies to include in the feature batch

The production compliance read queries in
`services/platform/apiserver/administration_repository.go` select by
organization only. Migration 0007 defines no workspace/environment on either
compliance table and seeds membership-derived evidence once. Searching current
non-test Go sources found the read queries and migration locking, not a ongoing
evidence projector. Do not assume these rows are current, environment-authorized
inventory evidence.

This is a source-scope concern, not a reproduced unauthorized disclosure.
Before selecting the export source, trace the actual permission authority and
decide how organization evidence and environment evidence are separately
authorized. Do not silently assign legacy organization rows to an environment.

The only current create/get export implementation in
`services/platform/sessioncontrol/http.go` is an in-memory map, not the mounted
product API. The production composition excludes both routes. The formatter's
JSON contains evidence, but CSV contains only control-level counts and human
text contains only a disclaimer. The existing S3 writer helper has no production
caller. Existing durable audit-export code is a reuse candidate for lower-level
storage/lease primitives, not proof of compliance-export semantics.

Implement the connected batch against M7-12, M7-13, M7-14, M7-15b, M7-15d and
M7-15, checking M7-10/11 and M7-15a/c prerequisites. Required outcome: authorized
current evidence with resolvable targets, durable jobs across restart, bounded
JSON/CSV/human packages persisted through S3, access-rechecked retrieval, and
filter/export/status UI. Keep unsupported controls and missing/stale evidence
honest; do not invent certification or live-provider evidence.

## Grouped verification

Use focused failing/passing checks while implementing. Run one feature-level
database/storage/API group and independent review across the connected changes.
Run the UI build and composed browser flow before publication. Each original
ID retains evidence attribution even when multiple IDs share one run.
Cross-tenant and cross-environment denial, revoked access, retries/restarts,
artifact integrity, source freshness, and error UI need explicit assertions.

Live S3/deployed service verification and the approved advisory/release gates
remain external requirements. Local substitutes do not close those gates.

Validation: the ledger checker accepts all 728 original rows and the corrected
counts; all 34 ledger-validator tests pass. Independent read-only review found
no Critical/Important issue in this correction and identified one stale current
count sentence, now corrected. No broad product suite was repeated for this
documentation/ledger-only change.
