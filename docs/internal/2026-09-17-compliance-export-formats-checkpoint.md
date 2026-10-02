# Compliance export formatter prerequisite

September 17, 2026. Component implementation only. Original M7-14 and the
connected compliance feature remain incomplete. No live-provider claim or push.

The builder retains canonical JSON and adds per-record CSV attribution:
evidence ID, asset, source and timestamp. Empty evidence has an explicit row.
Human text includes control identity/name/framework, expected evidence IDs,
freshness/expiry and collected records. Quoted metadata prevents source newlines
from creating headings. CSV neutralizes formula-prefixed cells.

Nested field/count limits prevent repeated-prefix amplification. Each format
is bounded at 4 MiB and the encoded package at 8 MiB. The writer rebuilds the
report from JSON and requires exact JSON/CSV/text equality before storage.
Quoted labels such as Access recertification are retained; substituted assurance
text is rejected. Generated text explicitly disclaims compliance attestation.

## Evidence

Initial RED a17713: three tests failed for absent record details, unsafe CSV and
the old 113-byte disclaimer. Package race22597 passed after implementation.

Review identified two Important issues: keyword-based rejection of legitimate
labels and nested raw input amplification. RED a61ea2 reproduced these and
unbound human text reaching storage. Both were corrected. Independent review
reran the package race suite (1.775s) and found no remaining blocking issue.

Final test-only refinements populate oversized collections with otherwise-valid
records/IDs and remove misleading writer-size fixtures that failed on invalid
canonical input. Final root run56589 exited0 in1.828s using Go's
test -race ./sessioncontrol -count=1 from services/platform, with local toolchain,
GOPROXY/GOSUMDB off and GOCACHE=/private/tmp/zasp-budget-go-cache.

Source Git blob: 47cf6b542032813042f7301a91acfe0209e98c74.
Final test blob: 9ef0a0d3a5541723a4b227da7413f946a3f1195a.
Files are services/platform/sessioncontrol/sessioncontrol.go and
compliance_export_formats_test.go. Reviewer covered the same source with
test predecessor5c603f89; root verified the final two test-only refinements.

Artifact persistence tests use a controlled store double, not S3. No database
or external provider was exercised. No UI suite was repeated for Go-only
component changes. UI verification remains mandatory before a push.

## Remaining feature work

Authorized current evidence projection, resolvable product targets, durable
tenant-scoped jobs, restart/retry behavior, S3 product composition, access-checked
retrieval, filtering/export/status UI and composed browser acceptance remain
required. The in-memory component handler must not become the product API.

M7-14 remains component-only; totals remain532/135/61. Live-provider,
release/advisory and deployment gates remain open.
