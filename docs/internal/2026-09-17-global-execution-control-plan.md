# Platform-global execution control implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Follow the checked steps and independent review gates.

**Goal:** Provide an authenticated, audited operator read/stop/re-enable path without widening tenant authority or weakening recovery holds.

**Architecture:** Extend unpublished55 with guarded operator entrypoints, immutable full-intent receipts and an internal non-login capability role. Keep all historical migrations and client pins unchanged. Serialize stop with new committed authorization, not with already authorized external network I/O.

**Tech Stack:** Go, pgx, PostgreSQL18, existing agentsec-migrate executable and owned cached Docker fixtures.

**Spec:** docs/internal/2026-09-17-global-execution-control-design.md

## Global constraints

- Start only after the mounted browser batch stabilizes; do not change its55 pin while it runs.
- No host PostgreSQL server/initdb, image pulls, online provider calls or broad cleanup.
- Do not edit published27 or make historical53/54 client gates accept55.
- No tenant API/worker gets operator execution, role membership or receipt-table access.
- Preserve all728 task scope. Keep local composition distinct from live acceptance.
- Use focused RED/GREEN during implementation and one grouped integration/build/review per feature batch.
- Treat any existing55 publication as a stop condition for this in-place candidate plan; inspect remote main before edits.

## File and interface map

Create `services/platform/migrations/sql/fragments/security_agent_existing_test_global_control.sql` for role, receipts, RLS, trigger guards and operator entrypoints.
Modify `services/platform/migrations/security_agent_existing_tests_release.go` to embed/append it and calibrate only the final55 fingerprint.
Modify `services/platform/migrations/sql/0055_production_security_agent_existing_tests.up.sql` for complete new-object fingerprint coverage.
Modify its `.down.sql` for serialized unused rollback and exact trigger restoration.
Modify `services/platform/migrations/production_security_agent_existing_tests.go`
only to take the same operator-relation rollback fence before the runner's first55
readiness check; retain existing budget locks and SQL-down checks.
Create `services/platform/migrations/security_agent_global_control.go` and `_test.go` for typed, parameterized calls.
Create `services/platform/agentsec-migrate/security_agent_global_control.go`, `_test.go`, and `_postgres_test.go`; modify `agentsec-migrate/main.go` only for dispatch and safe output.
Create `services/platform/apiserver/security_agent_global_control_postgres_test.go` for operator/tenant authority and stop races alongside the existing lifecycle fixtures.
For the ordinary-login acceptance test only, allow an optional owned-database
starter in `security_agent_existing_test_versioned_postgres_test.go`,
`security_agent_budget_postgres_test.go` and
`security_agent_attack_path_postgres_test.go`. Defaults stay unchanged. A separate
non-bootstrap migration login is needed because PostgreSQL refuses bootstrap
superuser demotion; never bypass the system catalog or production readiness.

Go boundary:

```go
type GlobalExecutionControlRequest struct {
    Enabled bool
    ExpectedVersion int64
    RequestID string
    CorrelationID string
}
type GlobalExecutionControlResult struct {
    Enabled bool `json:"enabled"`
    Version int64 `json:"version"`
    Replayed bool `json:"replayed"`
}
```

Define `(*Runner).ReadGlobalExecutionControl(context.Context)` and
`(*Runner).SetGlobalExecutionControl(context.Context, GlobalExecutionControlRequest)`
returning `(GlobalExecutionControlResult, error)`.
The command parser is `loadGlobalExecutionControlRequest(getenv func(string) string) (migrations.GlobalExecutionControlRequest, error)`.
The SQL functions are
`zasp_production_security_agent_existing_tests_global_read(text,text)` and
`zasp_production_security_agent_existing_tests_global_set(text,text,boolean,bigint,text,text)`.
The first two arguments are compiled55 checksum/fingerprint supplied by Go.
Never insert new pin literals into fingerprinted helper bodies.

## Task 1: durable guarded operator transaction

- [x] Add an owned PostgreSQL test that calls the operator function with the current compiled pins and a registered migration session. The initial call must fail because the function does not exist, not because fixture readiness is broken. Owned session56841 reached the call after readiness and failed SQLSTATE42883; compile59602 succeeded and owned cleanup completed. See the Task1 report. This checks the initial RED only, not operator acceptance.

```sql
SELECT public.zasp_production_security_agent_existing_tests_global_set(
  $1,$2,false,$3,'pid_7f560001-0000-4000-8000-000000000001','global-stop-test');
```

- [x] Add the NOLOGIN capability role with NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS. Revoke transient installation membership before readiness. Only operator entrypoints run SECURITY DEFINER as this role; guards stay SECURITY INVOKER.
- [x] Add global-only RLS policies and minimal privileges on the exact `('*','*','*','*')` control and corresponding global audit INSERT. Leave canonical tenant recovery behavior unchanged. Reject mixed wildcard scope, action wildcard variants, identity movement, deletion and audit UPDATE/DELETE.
- [x] Add `zasp_security_agent_global_control_receipts` keyed by canonical ProductID request ID. Persist caller session identity, enabled intent, expected version, correlation, resulting version and full stored result. Validate correlation as 1..128 ASCII graphic bytes (`[!-~]`, no whitespace). Make committed receipts immutable; forbid API/worker reads and writes.
- [x] Lock operator receipt/control/audit relations against rollback, check exact55 and registered session binding, then lock the existing global control row. Missing row refuses. A replay compares every intent field and returns its original result; it never executes another mutation.
- [x] For a new intent, require expected version >0 and exact match. Write control version+1, matching full-intent receipt and one `kill_switch_changed` audit event in one transaction. Derive actor from session_user. Recheck release and binding after blocking writes. Guards must require capability current_user and durable same-transaction associations; no GUC-only provenance.
- [x] Retain tests for stale version, changed replay intent, same replay after later re-enable, null/malformed request fields, unauthorized login/role membership, direct registered-operator DML and failed audit/receipt insertion. A failure must leave all three authorities unchanged.
- [x] Save exact predecessor trigger definitions before replacing only the two targeted triggers. Extend55 fingerprint with role attributes/memberships, functions, receipt schema/constraints/indexes/RLS/ACLs, both trigger definitions and enabled state. Keep existing private ancestry and all historical pins intact.
- [x] Down migration takes conflicting locks on receipt/control/audit before readiness and repeats checks after waits. Any retained operator receipt/history refuses rollback atomically. Before use, restore exact triggers/ACLs and remove new objects/role in dependency order. Exclude private non-predecessor helpers from the generic restore loop.
- [x] Calibrate55 from an owned disposable database and run the targeted positive/refusal/rollback matrix. Do not publish calibration failures as passing tests. Independent review must inspect SQL authority and actual catalog coverage before Task2.

## Task 2: bounded real operator command

- [x] Add strict parser tests for `security-agent-global-read` and `security-agent-global-set`; reject additional arguments. Set uses these required environment values:

```text
ZASP_SECURITY_AGENT_GLOBAL_ENABLED=false
ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION=1
ZASP_SECURITY_AGENT_GLOBAL_REQUEST_ID=pid_7f560001-0000-4000-8000-000000000001
ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID=global-stop-test
```

- [x] Reject missing values, uppercase/alternative booleans, signed/zero/leading-zero/overflow versions, noncanonical ProductIDs and control/space-containing correlation identifiers. Preserve the existing bounded migration context and DSN handling. Read requires no mutation environment values.

```go
func TestGlobalExecutionControlRejectsNoncanonicalVersion(t *testing.T) {
    values := map[string]string{
        "ZASP_SECURITY_AGENT_GLOBAL_ENABLED": "false",
        "ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION": "01",
        "ZASP_SECURITY_AGENT_GLOBAL_REQUEST_ID": "pid_7f560001-0000-4000-8000-000000000001",
        "ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID": "global-stop-test",
    }
    if _, err := loadGlobalExecutionControlRequest(func(k string) string { return values[k] }); err == nil {
        t.Fatal("accepted noncanonical expected version")
    }
    values["ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION"] = "1"
    got, err := loadGlobalExecutionControlRequest(func(k string) string { return values[k] })
    if err != nil || got.ExpectedVersion != 1 || got.Enabled {
        t.Fatalf("valid stop request rejected: %+v %v", got, err)
    }
}
```

Run the host-safe parser selection with pinned Go, offline modules and the task
cache: `go test ./agentsec-migrate -run '^TestGlobalExecutionControlRejectsNoncanonicalVersion$' -count=1`.
The initial RED must reject a real invalid-input case after the parser compiles;
an undefined symbol alone is not validation evidence.
- [x] Implement the Go calls using parameterized SQL only:

```go
const globalSetSQL = `SELECT public.zasp_production_security_agent_existing_tests_global_set($1,$2,$3,$4,$5,$6)`
const globalReadSQL = `SELECT public.zasp_production_security_agent_existing_tests_global_read($1,$2)`
```

- [x] Decode only enabled/version/replayed, requiring all three fields with exact names and non-null types. Reject missing, duplicate, unknown or case-aliased fields, trailing JSON, fractional/overflow/nonpositive versions and oversized results. A missing enabled value must never become a false successful stop through Go's zero value. Print only the validated JSON object on success. Errors must not disclose DSN, credentials, raw SQL or receipt internals. Read must not advance version or write audit.
- [x] Execute the actual freshly built CLI against an owned registered55 authority: read, stop, exact replay, conflicting replay refusal, stale-version refusal and re-enable. Confirm row, receipt and audit identities through independent reads, not CLI output alone. Exercise bad authority, expired context and wrong-release inputs.
- [x] Run focused parser/transport tests before DB integration. Never select the package's PostgreSQL helpers on the host; compile the explicit binary for the owned container. Review the complete command transaction and safe-output paths before Task3.

## Task 3: stop barriers, retained history and shipping

- [x] Use existing public lifecycle fixtures to create real queued/approved work. Hold the exact global row in one connection, start admission in another, stop through the operator, release the wait and prove no newly committed authorization crosses the stop barrier.
- [x] Repeat at invocation-start and with operator binding revoked during a wait. Inspect actual wait state before releasing locks. Assert durable refusal/atomic rollback and a valid positive control after re-enable.
- [x] Add an explicit test/documented outcome for invocation authorization committed before stop: it may still initiate network I/O. Never call the stop operation external cancellation. Confirm cancellation, reconciliation and scoped history remain functional while disabled.
- [x] Place a tenant recovery hold, attempt tenant mutations before and after stop/re-enable and confirm refusal; release the hold and prove valid same-scope mutation. Global re-enable must not alter tenant/environment/action controls or clear holds.
- [x] Race unused rollback with operator use and prove one serialized result: successful unused rollback with operator refusal, or successful use with rollback refusal and retained history. Check exact release identity after waits.
- [x] Group the operator DB matrix, affected lifecycle/compiled55 checks, real mounted browser batch, CLI parser tests, UI build/import and actual local page/asset smoke. Reuse only unchanged evidence identified by candidate hash; rerun compiled55 consumers after pin changes.
- [ ] Obtain independent spec and code review, fix all Critical/Important findings, then stage only this feature's reviewed files and authoritative evidence. Verify remote main and fast-forward push without force. Record the exact pushed hash and CI result separately from deployment proof.

## Self-review and evidence boundary

Task1 covers operator authority, full replay intent, guards, RLS, fingerprints and
rollback. Task2 covers actual command parsing, parameterized execution and safe
output. Task3 covers stop/wait races, recovery holds and runnable publication.
Task1 checkboxes reflect the accepted local implementation, owned matrix5147 and
independent source review. Task2 is locally accepted after its CLI matrix83541
and independent review. Task3 remains open. No live operator execution,
production release, original-task promotion or728-task completion is claimed.
Continue with the existing autonomous SDD workflow without asking for a routine
execution-choice approval. Re-run affected final gates against the current55 pin.
