# P4C automatic-source first-adapter review

Spec compliance: Issues found. Code quality: Needs fixes.

Counts: Critical 0; Important 2; Minor 1. Do not accept this stage until the two Important findings are resolved. This is a task-scoped review, not approval to merge, publish, expose migration 77, or complete M7A-35 through M7A-38d.

## Scope and method

Reviewed the binding automatic-source brief, stage1 review brief, frozen design/execution plan/report, remaining-trigger caller inventory, and the complete 8,014-line `baseline-relative.patch`. The comparison is against the preserved pre-edit overlay, not HEAD. Both snapshots have HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. The packet identifies 88 source paths and 139 evidence paths; the controller independently checked those live hashes. I independently compared all 216 baseline historical migration SQL hashes to the current files: zero differences.

The diff was the principal change evidence, read in sequential sections; truncated tool output was recovered. No changed file was reread wholesale. Focused unchanged spans and predecessor functions were checked only for the named risks below. No tests, source edits, Git mutations, commits, or subagents were used. This report is the sole review write.

Paths below are relative to this worktree. `E` means `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-automatic-source-evidence/logs/`; `R` means the adjacent `p4c-automatic-source-review-stage1/reference/docs/internal/`.

## Strengths and verified boundaries

- Optional rule omission remains distinct from explicit manual rules; Go, raw-object validation, public schemas and UI carry the configured rule body. The new decoder rejects malformed discriminators, unknown fields, nulls and invalid bounds (`services/platform/securityagent/trigger_rules.go:36`). Installed 77 adds persisted validation and first-adapter activation restrictions (`services/platform/migrations/sql/0077_production_temporal_automatic_sources.rules.sql:12`). The pre-77 rollout exception is Important finding 1.
- Capture stores canonical references transactionally rather than premature snapshots; postcommit matching binds current tenant-scoped parents and children. Admission checks current configuration, grant and source again, persists occurrence consumption independently of cooldown deadlines, and uses the existing 75 capacity/admission boundary (`0077_production_temporal_automatic_sources.sources.sql:21`, `.matcher.sql:19`, `.admission.sql:46`, under the same migrations SQL directory).
- Temporal owns retries and continuation. Five-visited pages finish the sweep before deferred retries; continuation bounds Workflow history. Attempt-before-start outbox ordering and exact Workflow identity/history checks avoid treating arbitrary AlreadyStarted responses as delivery proof (`services/platform/orchestration/automatic_source.go:91`, `automatic_source_start.go:32`, `automatic_source_outbox.go:27`). No custom SQL lease scheduler was introduced. Worker shutdown joins activity borrowers before shared resources close.
- Risk annotation is optional, signed and domain-separated; omitted annotation retains the prior digest. Missing winning-contributor risk stays unknown. Actual decision/action evidence does not overwrite historical requested classification. Installed SQL/Go compiler, authenticated gateway capture, rollback, credential and catalog-negative evidence are present in `E/risk-installed-green4.log` and the native acceptance log. Saved predecessor pinning and narrowly enumerated effective compiler/fingerprint changes are additive; historical SQL is unchanged.
- Retained native evidence supports actual owned-worker replacement after the first five admissions and a completed Activity, the same Workflow/run, all 26 distinct receipts and completed-Workflow replay (`E/sources-native-expanded2.log:21`, `:23`). This passing case is separate from the later failing case in that command.
- The final grouped evidence passes Admission, Authority and Native, with exact mounted HTTP/repository terminal IDs, version, outcome, reason and digest equality (`E/sources-first-adapter-acceptance1.log:4`, `:8`, `:37`, `:41`, `:43`). I did not rerun it or reinterpret controlled external dependencies as production proof.

## Important findings

### 1. Configured definitions can activate before the enforcing release is installed

Primary changed locations: `services/platform/apiserver/workflow_handler.go:895` and `:940`; `services/platform/migrations/sql/0077_production_temporal_automatic_sources.rules.sql:32` and `:40`.

The handler accepts and persists `trigger_rules` without requiring the automatic-source capability. The database guard that makes unsupported configured activation fail closed is installed only by 77. This leaves the supported/default pre-77 deployment state unprotected, especially because 77 remains deliberately unexposed by the migration CLI (`services/platform/migrations/production_temporal_automatic_sources.go:69`).

Concrete boundary evidence: the registered database adapter calls `zasp_temporal74.configuration_write` and `zasp_temporal74.activate`, and its only release probe/readiness check is for 74 (`services/platform/apiserver/security_agent_temporal_test_activation.go:13`, `:21`, `:55`, `:61`). The 74 activation function checks 74 readiness, positively owns single run/rerun-test definitions, calls its existing activation core and grants service authority without a 77/rules capability check (`services/platform/migrations/sql/0074_production_temporal_test_executor.up.sql:92`, `:99`, `:129`, `:133`). The inherited test binding validates `existing_test` but does not reject extra top-level definition fields (`services/platform/migrations/sql/fragments/security_agent_run_context.sql:33`). The old selector enables an activated single-test definition without inspecting rules (`services/platform/migrations/sql/0075_production_temporal_test_selector.up.sql:63`); its scoped selection is copied from the pre-rules selector (`:137`). The new worker intentionally permits absent 77 (`services/platform/agentsec-worker/temporal_automatic_sources.go:20`, `:25`).

Consequently, a newly saved explicit-manual or severity/cooldown-configured single-test definition can pass the old activation path and enter rule-blind automatic selection. Valid 77 fixtures do not cover this partial-rollout state. A user-visible manual or filtering promise must not depend on an optional migration silently being present.

Required change/evidence: fail closed at the registered write/activation boundary when a configured definition is not supported by the installed ready authority. Preserve omission-based legacy behavior and safe draft semantics. Add a focused installed pre-77 regression for create/update, activation and selector/admission behavior with explicit manual and automatic rules, plus present-invalid 77 and supported-ready 77 cases. Cover activation of already stored configured drafts, not only new requests. Use an additive approach; do not rewrite historical SQL. This finding is source-proven; I did not execute a new pre-77 reproduction.

### 2. The later native occurrence exhausted SingleTest retries, and its first cause is unknown

Evidence locations: `E/sources-native-expanded2.log:40`, `:42`, `:49`; `E/sources-native-history-diagnostic1.log:31` through `:46`.

This is a real failure in the first-adapter acceptance path, not merely a setup failure. The retained history identifies the later run, successful planning and Observe-test phase, SingleTest scheduled event 23, start event 24 and failed event 25 with `MaximumAttemptsReached` / `product operation unavailable`. Cleanup then completes at event 31, and the Workflow fails at event 35. The exact run is `01a0d3f2-5c21-7b39-9dd0-57a3758639e7` in namespace `automatic-source77-1790262195761263000`.

The first application/database failure is not in the retained evidence. No second adapter stdout is insufficient to conclude that the adapter never began. Later diagnostic and grouped acceptance passes demonstrate successful executions, but neither explain this failed execution nor establish a fix. The report correctly preserves the uncertainty; that honesty does not satisfy the reliability gate.

Required evidence: reproduce the focused later-occurrence path with first-error capture at the SingleTest application/SQL boundary, correlated to Workflow/run, Activity attempt and safe static operation/phase. Capture SQLSTATE and allowlisted function/error identifiers without parameters or sensitive payloads. Establish whether the cause is production logic, fixture lifecycle, resource shutdown or another condition, then fix the identified cause and demonstrate the failed sequence passing. If exact reproduction remains elusive, provide bounded diagnostic evidence and an explicit controller decision; do not call it transient or resolved, or simply extend retries/timeouts. No broad suite rerun is requested by this review.

Severity is Important: local acceptance remains untrustworthy, but the evidence does not establish a production incident, authorization bypass, data corruption or the failed operation's first cause. It does not invalidate the independently passing middle-page crash/replay case.

## Minor finding

### 3. Focused UI test output is not clean

`E/rules-ui-green1.log:5`, `:7`, `:9` contain a `module.register()` deprecation warning and unavailable-localStorage warnings; the same warnings recur in `E/rules-detail-green2.log:5`, `:7` and `E/risk-ui-green2.log:5`, `:7`. These tests pass, and the evidence does not establish that the warnings were introduced by this change. They still violate the review rubric's clean-output expectation. Correct the affected test/runtime setup or explicitly track the originating dependency; do not blanket-suppress unrelated warnings. This does not block on the same grounds as the Important findings.

## Focused checks outside the diff

1. Risk: a newly accepted optional policy annotation might be stripped or rejected by the unchanged persistence route. Checked the policy public-handler decode boundary and the relevant configuration-writer spans in migrations 0003/0006. They preserve the body; no stripping defect was found. This is not an installed public policy API roundtrip proof.
2. Risk: configured rules could activate without 77. Checked the exact registered activation adapter, the unchanged activation method span in `security_agent_repository.go:319`, 74 activation, the generated 55 activation-core amendments, the predecessor activation body in migration 0018, the inherited test-binding function and 75 desired/selection construction. This check produced Important finding 1. It did not expand into unrelated routes.

## Cannot verify and scope that remains open

- This stage does not revalidate all 728 product requirements or all previously accepted manual, scheduled, SQS, approval and unknown-result behavior. Their preservation remains binding; no full-program completion claim is supported here.
- Configured runtime responders, potential-path activation, other single responder families and ordered actions remain open. The original response, temporary-policy, revocation, isolation, Attack Lab, export and webhook adapter work is not closed by the run/rerun-test adapter. Original M7A-35 through M7A-38d remain open.
- Seeded path states and grant revocation demonstrate actual database authority behavior, not a public verified-path-promotion or revocation UI flow. The native test replaced an owned worker, not the Temporal server.
- Provider/storage/OpenFGA HTTP and API identity are controlled fixtures. Production Stytch, real-provider behavior, deployed OpenFGA enforcement and deployment readiness are not established. Catalog readiness is not OpenFGA permission enforcement, and Stytch identity remains required.
- The installed public policy API annotation roundtrip and complete eventual retirement of saved compiler/finding-writer compatibility objects are not established by this stage's focused evidence. Preserve the enumerated compatibility pins and dependencies until the owning migration work explicitly retires them.
- The first cause of the native failure remains unknown, as detailed above.

## Gate decision

The implementation supplies substantial first-adapter functionality and meaningful local evidence, but it does not yet meet the staged activation or reliability acceptance gates. Resolve Important findings 1 and 2, retain the remaining-adapter and production limitations, then submit the bounded fixes and their focused evidence for rereview.
