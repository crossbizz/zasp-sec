# Export settlement client implementation plan

> **For agentic workers:** Use Superpowers TDD and independent batch review. Root implements Go files inline alongside the existing database implementer; SQL ownership stays separate.

**Goal:** Connect the registered dedicated export-link lease to a strictly checked Go authority client, then compose its worker without treating exports as remediation.

**Architecture:** Methods on SecurityAgentWorkerRepository call the release58 claim/settle functions with compiled pins. Claim uses the export-link lease, never ClaimSecurityAgentRuns. Exact closed receipts retain scoped run/step/export identities. This client alone doesn't expose catalog availability or start a worker.

**Tech Stack:** Existing Go QueryJSON boundary and migrations package, no dependencies.

**Spec:** docs/internal/2026-09-19-security-agent-evidence-export-design.md and agreed SQL in migrations/sql/fragments/security_agent_export_links.sql.

## Constraints

All728 original tasks remain in scope. Keep M7A-23 component-only. Preserve
legacy worker receipts, browser downloads, accepted render/decoder source and
SQL implementer ownership. No external provider calls or publication gates
bypassed. Settled facts aren't remediation. Source revocation doesn't prevent
recording existing storage obligations. Current SQL is authoritative for leases.

## Task 1: Registered client contract

Create services/platform/apiserver/security_agent_export_settlement.go and
security_agent_export_settlement_test.go.

Interfaces:

```go
type SecurityAgentExportSettlementClaim struct {
    OrganizationID string `json:"organization_id"`
    WorkspaceID string `json:"workspace_id"`
    EnvironmentID string `json:"environment_id"`
    RunID string `json:"run_id"`
    StepID string `json:"step_id"`
    ExportID string `json:"export_id"`
    RunVersion int64 `json:"run_version"`
    LeaseExpiresAt time.Time `json:"lease_expires_at"`
}
// Result is closed run_id,run_version,step_id,export_id,state,reason,settled,replayed.
// Methods on *SecurityAgentWorkerRepository:
// ClaimSecurityAgentExportSettlements(ctx, worker, token, seconds, limit)
//   ([]SecurityAgentExportSettlementClaim, error)
// SettleSecurityAgentExport(ctx, claim, worker, token, audit, correlation)
//   (SecurityAgentExportSettlementResult, error)
```

- [ ] RED: literal closed claim and settlement responses through a controlled QueryJSON boundary. Confirm correct argument scope, identities, lease, and compiled release58 pins. Keep package compiling using fail-closed method stubs if needed for concurrent SQL work.
- [ ] GREEN: validate context, database, worker/token, seconds30..300, limit1..25; call `SELECT public.zasp_sa_export_settlement_claim($1,$2,$3,$4,$5,$6)`. Reject null/nonarray, oversize response, duplicate run links, malformed IDs, run version outside1..1000000, missing/non-UTC expiry and unknown/duplicate fields.
- [ ] RED/GREEN: call `SELECT public.zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)` with full scope, run, worker/token, audit/correlation and exact pins. Require run/step/export match claim. Validate state/reason union: verifying/export_pending requires unsettled and not replayed; needs_human/export_available or export_failed requires settled and advancing version; cancelled/export_cancelled and terminal stopped/export_parent_stopped require settled, nondecreasing version. Never accept remediated/export_available. Lost-reply replay is SQL-authorized and must not be precluded solely by local lease expiry.
- [ ] Cover provider errors, no database call for invalid inputs, malformed JSON, cross-scope claim fields, wrong identities and illegal state/reason combinations. Use literal expectations; no production authority from fixtures.
- [ ] Run cached native focused RED/GREEN, then one grouped race run of `^TestSecurityAgentExportSettlement.*$`; record exact commands/output/exits. Independently review the frozen client and tests before acceptance.

## Connected integration, still required

### Task 2: Existing worker polling integration

Create agentsec-worker/security_agent_export_settlement_runtime.go and its
test. Modify security_agent_runtime.go RunOnce to reconcile export links before
normal scheduling. Add SecurityAgentExportsAvailable on the API worker
repository and PostgresJSONDatabase, using to_regprocedure followed by exact
release58 readiness. Absent release skips export calls; installed drift fails.

- [ ] Test the actual existing processor RunOnce with a worker-authority stub
  that also has export capability/claim/settle methods. Return one completed
  link and a first-call lost-response error, then the same committed receipt.
  Assert exactly two settlement calls with identical token/audit/correlation
  and one ordinary parent claim invocation, with no extra planner work.
- [ ] Add the optional runtime authority interface with capability, claim and
  settle methods matching Task1. Probe once under a five-second timeout. When
  available, obtain a fresh token, claim at configured seconds/limit, and
  settle each link using two fresh product IDs kept stable across at most two
  attempts. Bound each I/O by five seconds and propagate parent cancellation.
  Validate matched run/step/export and valid terminal union before success.
- [ ] Test unavailable capability skips new SQL; drift, claim failure,
  cancelled context and exhausted settlement retries fail without scheduling
  additional execution. Claim leases remain SQL-owned; never heartbeat parent
  or perform model/storage calls from this helper.
- [ ] Implement Postgres capability with read lock, closed-driver checks,
  installed-function probe and compiled checksum/fingerprint readiness, using
  the existing AttackLab capability pattern. Do not publish catalog capability
  until all planner/API/runtime admission paths are separately ready.
- [ ] Group focused processor/settlement native race tests, then independently
  review the client plus mounted polling adapter. Registered composed proof
  and runtime-readiness deployment evidence remain explicit gates.

Compose a bounded settlement polling loop with shutdown/cancel/retry and stable
audit/correlation IDs for lost replies. Route prepared export dispatch using
the exact persisted action under current authority, with a separate typed
pending receipt and parent verifying state. Add runtime readiness to action
admission, registered client/worker tests, and real planner/API/UI flows. These
steps need their exact runtime adapters mapped before code changes; Task1 does
not claim them complete. No commit or push while publication gates remain shut.
