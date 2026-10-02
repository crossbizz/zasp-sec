# Connected compliance final review package

Review current connected feature against
`docs/internal/2026-09-18-compliance-production-design.md` and its implementation
plan, plus `docs/internal/compliance-ci-batch-brief.md`. Original scope M7-08
through M7-15 remains binding. This is not a review of the entire728-task product.

HEAD8733b16f8d939d38a8157dd2519e57fc6f630542 is unchanged. The worktree contains
unrelated inherited changes; do not use its broad HEAD diff. Task BEFORE/AFTER
blobs and incremental patches are the actual review range. Root verified the
92path chain through API final-fix2 without gaps or drift, before CI changes.
The CI manifest adds its5path delta and all AFTERs were independently verified.

## Diffs and reports

All paths below are under
`.superpowers/sdd/2026-09-18-compliance-production-plan/` in this shipping tree.
Read the reports and full patches, using manifests to distinguish final source
from superseded intermediate revisions:

- task-1: task-1-blobs.json and task-1-scoped.patch, current scoped sources.
- task-2: task-2-blobs.json and task-2-scoped.patch, durable job authority.
- task-3: task-3-blobs.json and task-3-scoped.patch, storage/runtime.
- task-4: task-4-blobs.json and task-4-scoped.patch, API/client.
- task-4-fix-1: incremental task-4-fix-1-blobs.json and task-4-fix-1-scoped.patch.
- task-5: task-5-blobs.json and task-5-scoped.patch, composed UI acceptance.
- task-5-fix-1: incremental task-5-fix-1-blobs.json and task-5-fix-1-scoped.patch.
- task-4-final-fix: incremental task-4-final-fix-blobs.json and
  task-4-final-fix-scoped.patch.
- task-4-final-fix-2: incremental task-4-final-fix-2-blobs.json and
  task-4-final-fix-2-scoped.patch.
- compliance-ci: compliance-ci-blobs.json and compliance-ci-scoped.patch.

Root retains local review receipts and evidence in docs/internal/compliance-
source-task1-20260918, compliance-jobs-task2-20260918,
compliance-runtime-task3-20260918, compliance-api-task4-20260918,
compliance-ui-task5-20260918 and compliance-ci-20260918. The progress.md ledger
contains rulings and historical findings. All task-level findings are now closed
locally. This review checks the assembled feature and cross-task seams; do not
duplicate test runs whose unchanged source already has saved evidence.

## Connected checks

Trace current scoped source identity/version and snapshot attribution through
SQL capture, frozen bytes, worker retry/lease, exact-version storage receipt,
grant verification/consume, API response and UI native download. Check current
authorization after waits, five source families/both frameworks, historical
test versions, quota and unresolved-write accounting, expiry/cleanup/read lease
interaction, release55 compatibility and release56 registration, runtime
configuration/readiness, and full current UI/CI wiring against the design.

The latest local browser job4d44712e-d23b-4a08-a91f-06415a504000 exercises current
API/worker with controlled storage. All6session checkpoints stay signed in;
final screenshot shows Staging controls/version8/export. It is not live AWS.
The isolated checksum adapter uses the pinned SDK's private concrete type;
its recorded maintenance ruling requires real-SDK regression coverage on upgrade.

## Evidence boundaries and output

Report strengths, severity/file:line findings, spec and quality verdicts, and
whether local feature integration is ready. Separately retain unresolved hosted
Linux execution, approved exact-lock advisory, deployed IAM/KMS/lifecycle/TLS,
live-provider, scale and production acceptance gates. Approval cannot promote
local fixtures to production availability or waive any728-task requirement.

Read-only review: no mutation, staging, commits, external calls, downloads or
subagents. Do not rerun suites. A focused test needs a concrete doubt not resolved
by existing output. Return report to root; root owns retained receipts and fixes.
