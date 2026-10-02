# Connector Rejection Auditing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. One connected implementation/review batch.

**Goal:** Reject forbidden connector overrides and persist safe, currently authorized audit events through the real API.

**Architecture:** A narrow PostgresJSONDatabase capability owns a READ COMMITTED transaction. PostgresRepository delegates; the production pgxpool driver supplies transaction support and tracedJSONDatabase forwards the specific operation. No migration57 or new privileges.

**Tech Stack:** Go, PostgreSQL, existing product middleware; cached isolated Docker tests.

**Spec:** docs/internal/2026-09-18-connector-rejection-design.md

## Global Constraints

- Original728-task scope remains unchanged; local proof is not live release proof.
- No rejected URL, credential, body, intent, arbitrary key name or idempotency key is stored.
- BrowserSession and ProductAPIToken require current exact-scope manage_workflows; token permissions intersect existing direct scope authority.
- One event per authorized rejected attempt; no successful-workflow receipt or idempotency claim.
- Preserve valid webhook destination_url and existing replay/conflict/error contracts.
- No migration, grant, RLS or predecessor checksum/fingerprint change.
- Fresh authorization after waits, including INSERT; revoked authority rolls back.
- Focused RED/GREEN then one connected integration/review boundary.
- No staging, commit, push, host PostgreSQL, live/advisory calls, downloads or image pulls/builds. Join owned resources.

## Task 1: Mounted durable rejection audit

**Files:**

- Existing RED: services/platform/apiserver/connector_rejection_postgres_test.go and docs/internal/connector-rejection-20260918/.
- Create services/platform/apiserver/connector_rejection.go and connector_rejection_repository.go with focused unit tests.
- Modify necessary error branches in services/platform/apiserver/workflow_handler.go only.
- Implement the narrow transaction capability in services/platform/apiserver/postgres_database.go or a focused connector_rejection_database.go, with dedicated tests.
- Extend services/platform/agentsec-api/production_runtime.go for pgx transaction support and traced capability forwarding; test these actual adapters.
- Extend mounted PostgreSQL tests for both credentials, audit read visibility and observed-wait races.
- Use the existing local runtime harness if needed for assembled proof; preserve its assertions.
- No migration files, CLI release routing or schema version changes. Root owns ledgers and review.

**Safe boundary type:**

```go
type IntegrationRejection struct {
    CredentialDigest []byte
    Operation string
    TargetID string
    AuditID string
    CorrelationID string
}
type integrationRejectionAuditor interface {
    AuditIntegrationRejection(context.Context, RequestIdentity, IntegrationRejection) error
}
```

Operation permits only createIntegration/updateIntegration. Create target is selected environment; update target is verified same-scope integration. Identity carries credential kind, which must match the request and actual credential. Action is integration.setup.rejected, reason invalid_configuration. No client configuration can fit in this command.

- [x] **1. Observe mounted RED.** red-run-final.log exits1 with ten missing-audit failures only, four authorization controls passing and positive GitHub/webhook201. Test SHA2563a60078282104d84a6d8d7c3f6583f3013c4f4344e98056968845f42b7c214a6. The full report records setup corrections, identities and joined cleanup. Preserve this evidence unchanged.

- [ ] **2. Implement guarded transaction capability with focused tests.** Add optional driver transaction support using existing pgxpool BeginTx with explicit pgx.ReadCommitted. Expose only AuditIntegrationRejection at the JSON database boundary, not a generic public transaction callback. Validate command, registered principal readiness, current schema and credential proof before a preliminary authorized check. Insert safe event inside the transaction, then perform fresh locked authorization and final clock checks before commit. Defer bounded rollback on every noncommit path, including cancellation/panic; preserve closed-database synchronization and connection ownership.

Conceptual driver contract can use existing pgx.Tx rather than another general database abstraction:

```go
type postgresRejectionTransactionDriver interface {
    BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}
// The production pool already supports BeginTx.
// No fallback to independent database.Exec calls is allowed.
```

A missing driver/decorator capability returns fixed unavailable. Initial and final checks use separate READ COMMITTED statements. No single-snapshot CTE substitutes for fresh authorization. Registered role may already INSERT from legacy release10; add no privilege.

- [ ] **3. Stabilize final authority through commit.** After any blocked audit INSERT, lock active membership before current credential, matching existing resolve/deprovision lock order. Direct scopes use a locked positive grant row. Browser group scopes use membership FOR SHARE (registered group writers require FOR UPDATE), locked contributing existing mapping rows and a fresh effective-scopes check. Enumerate supported group writers before relying on this protocol; test actual resolve/deprovision contention. API cannot access member-group rows under current RLS, so do not grant it access. Avoid global table locks. Token authority stays direct-scope plus token-permission intersection. Lock/verify update target and recheck wall-clock expiry after all waits. Test blockers must allow the competing revocation to commit its own audit.

```sql
-- Every statement runs on the same transaction connection.
-- Lock concrete authority rows with FOR SHARE in documented order.
-- Final permission read occurs AFTER lock acquisition, not in an earlier snapshot.
-- Commit only after exact credential/scope/actor and current-time checks.
```

If a contributing row disappears or changes during a wait, re-evaluate or deny and rollback. Positive-grant union means new phantom grants cannot revoke a locked existing witness. Owner/bypass writes are outside registered product concurrency proof; document this explicitly.

- [ ] **4. Wire actual HTTP and production decorators.** Handle forbidden integration configuration in both the early sensitive-field refusal and later setup rejection. Keep canonical bounds, secret filter, successful replay/conflict precedence and existing non-disclosing statuses. Do not audit unauthorized/foreign/CSRF failures under selected tenant authority. Commit audit before ordinary400invalid_request; unavailable persistence returns fixed503. Preserve auth/authorization/not-found classifications when final authority fails.

```go
if err := auditor.AuditIntegrationRejection(request.Context(), identity, command); err != nil {
    // Classify known authority errors; unknown persistence errors stay unavailable.
    writeWorkflowMutationError(writer, request, classifiedRejectionAuditError(err))
    return
}
writeWorkflowMutationError(writer, request, originalRejection)
```

Define classifiedRejectionAuditError locally with an explicit allowlist of existing typed repository errors; never expose raw provider/SQL errors. tracedJSONDatabase forwards only this capability and records safe operation metadata, not command values. Production pgx adapter must return an actual transaction, not a fake or detached connection.

- [ ] **5. Prove connected GREEN.** Extend the original test for create/update, all override names, inline secret, retry and reused successful key. Assert safe audit fields through real audit read API, unchanged workflow/integration/connection/effect/success-receipt tables and stable public errors. Add token and group-authority cases, missing capability, close/cancel/commit/rollback errors, expired/revoked credentials, removed permission and target drift. Use observed PostgreSQL blockers for INSERT and authority waits. Test actual registered group writer contention and mapping removal/role change. Retain generic-webhook success. No raw API audit INSERT in product tests.

Run named-test enumeration first; then anchored focused tests using the retained cached container pattern. Log intended failures and final results. Do not rerun unrelated SQL suites. Local dispatch tripwires do not prove live egress.

- [ ] **6. Grouped acceptance and review.** Run affected Go race/database tests, actual production driver/decorator capability coverage, and one UI/types/lint/build boundary before publication. Verify source-identical release56 readiness and no migration drift. Freeze BEFORE/AFTER, scoped patch, commands/results and cleanup. Root dispatches one independent spec/quality review. Keep component-only until requirement evidence and dependency gates justify any classification change. No commit/push before release gates.

## Preflight and rulings

| Interface | Producer and consumer | Check |
| --- | --- | --- |
| Driver/database | pgx transaction used by dedicated audit capability | Same connection, explicit READ COMMITTED, commit/rollback ownership. |
| Repository/HTTP | Safe command and typed result | No rejected body in durable type; no400 without committed audit. |
| Runtime decorator | Forwards specific capability | Missing forwarding must fail a real adapter test. |
| Authority/data | Positive grant witness through commit | Fresh check after INSERT; group writers share membership lock protocol. |

Ruling: the observed legacy ACL disproves the earlier no-INSERT assumption.
A transaction capability achieves the same security behavior without release57
and its predecessor adapters. This supersedes all earlier57 steps and brief
versions. Cost if wrong: omitted driver/decorator or lock semantics could leave
a false-success path; focused actual adapter and observed-wait tests must catch it.

User-requested autonomy covers scoped local implementation. No authority for live
systems or advisory disclosure is inferred. Independent review remains required.
