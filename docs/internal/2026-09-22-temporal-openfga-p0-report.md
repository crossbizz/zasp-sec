# P0 checkpoint: replacement work can start

2026-09-22. Documentation only; grouped independent SPEC and QUALITY review passed after the policy-deployment inventory correction. See [review](2026-09-22-temporal-openfga-p0-review.md). No commit,
push, deletion, runtime change or production promotion.

Branch: `codex/cached-runtime-ship-20260917`.
HEAD: `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`.
The existing linked worktree was used with its dirty overlay intact.

## Four owned paths

- [Crosswalk](2026-09-22-temporal-openfga-crosswalk.tsv), new.
- The [retirement inventory](2026-09-22-temporal-openfga-retirement.tsv) has 37 bounded runtime/dependency-family rows.
- [Main status ledger](implementation_status_v1.5.md), append only. Its original 615,239 bytes are unchanged.
- This report.

At capture, `git status --porcelain=v1 -uall` had 2,238 entries: the existing
2,235-path overlay recorded in the ordered-work reports, plus the approved
design, execution plan and parallel dependency research. The sorted path-plus-byte
baseline digest, excluding the independently owned dependency research, was
`cbbcbaa68ece967653e0074435f02447c5157579d2690d270d3e25f3fbd2c9d6`.
Rechecking the same original paths, using the ledger's original byte prefix,
matched that digest after the P0 edits. No baseline path was deleted or changed
by this packet outside the ledger append. The separate
[dependency research](2026-09-22-temporal-openfga-dependency-research.md) is not a
P0 edit. The original availability and ownership TSVs were not modified.

## What the crosswalk means

All 728 original IDs appear once. Each row carries the original task title and
full Deliverable text, its original Verify clause, current evidence and owner,
the unchanged production class, and the replacement packets or `unaffected`.
There are 162 unaffected rows. Packet mappings use task requirements and actual
API/workflow roles, not milestone-wide replacement rules.

The original PRD and task plan remain the product contract. In particular,
M7A-49 is **Security Agent run budget**; the architecture document's ordered-
execution shorthand does not rename it or remove its step/time/token/cost and
tenant-concurrency requirements. M7A-23 still needs export execution, artifact
delivery and scoped access proof. Starting the OSS services satisfies neither.

M2 role/grant/PAT/identity rows map to P5-P7 with Stytch retained. M3 connector
and sync requirements map to P4, but sensor/event ingestion remains its own
pipeline. M7/M7A exports, approvals, actions and cleanup have explicit mappings.
Deployment and recovery rows retain P9/P10 acceptance. Each row names its
existing production owner, including external gate owners.

SQS requirements remain explicit: M0-06, M1-13/33/41, M1A-04, M5-13, M7A-50,
M8-03/17c/34/59a3. Runtime ingestion, archive/index/correlation and queue-index
evidence are retained, not assumed to be replaced by Temporal.

## Old work stops here

The [ordered progress record](../../.superpowers/sdd/2026-09-20-security-agent-ordered-multistep-plan/progress.md)
and its frozen task reports remain untouched. Worker63's completed component
evidence is retained. Scheduler64's `6e7d7590` lock-order fix was awaiting scoped
independent re-review when the approved architecture change interrupted it.
This report does not supply that approval.

Unfinished worker63/scheduler64 feature work, including E2E2B production
composition, is superseded by P2-P4/P7-P9. Existing commits stay until equivalent
product behavior and safe retirement are verified. Findings solely about an
obsolete selector do not require further feature development. The shared SQL
AB/BA lock-order invariant still matters during coexistence and in retained
Activity transactions; P3/P7 must preserve it.

The missing-`Keys` failure in
`TestSecurityAgentRelease61CompositionPostgres` moves to P3 composition and P8
acceptance. Keep signing-key validation. The replacement must prove real API,
worker, receipt and read-model composition. The old fixture failure is not
waived, and the prior browser attempt's missing Stytch/signing/DB/KMS inputs
remain an explicit acceptance gap.

## Caller chains and remaining checks

The inventory traces Go adapters to worker63/scheduler64 SQL facades, their
execute grants, chained fingerprints/readiness, and release61 domain operations.
It separates obsolete polling and lease helpers from retained budgets,
approvals, receipts, provider intent and compensation. Active discovery,
red-team/tests, Attack Lab, export, recovery, runtime-stream and projection
families are accounted for.

One concrete deployment gap: the inspected migration CLI routes through
`up-to-60`; worker63/scheduler64 Runner methods do not establish a shipped CLI
upgrade route. Production Security Agent composition still uses the legacy
processor; the new ordered selector adapters have no demonstrated production
constructor. Neither gap warrants finishing the superseded scheduler.

P4 must choose the replacement or explicitly retained engine for tests, exports,
Attack Lab and recovery before P9 can retire their orchestration. P9 must repeat
fine-grained Go/SQL/grant/CLI/deploy reference checks at the actual cutover,
confirm no outstanding runs or cleanup, and retain applied historical migration
bytes. The inventory is a retirement boundary, not deletion authorization.

## Checks run

`node scripts/implementation-status-check.mjs` passed: 728 rows,
526 production-available, 141 component-only, 61 blocked/external, 0 missing.

An inline Node assertion batch passed exact ID-set equality across the original
plan, crosswalk, availability TSV and owner TSV, with no duplicate IDs. It also
checked every copied Deliverable and Verify clause, current evidence, owner and
production class against its source; all 37 retirement rows have six nonempty
columns. The baseline digest and original ledger prefix checks passed.

`git diff --check` passed for the P0 paths. No new test framework, documentation
snapshot suite or vendor-internal tests were added. No application tests were
rerun for this documentation-only packet.

These classes are historical baseline evidence. Temporal/OpenFGA acceptance
remains pending; P1-P10 must supply it. Start P1 after grouped P0 review.
