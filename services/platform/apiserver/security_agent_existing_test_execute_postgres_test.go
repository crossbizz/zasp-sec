package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentExistingTestLegacyExecutionPostgres(t *testing.T) {
	t.Setenv("ZASP_EXISTING_TEST_LEGACY_EXECUTION", "true")
	TestProductionSecurityAgentBudgetStopsNewPreparationAndDispatch(t)
}

func TestSecurityAgentExistingTestFinalWriteExpiryPostgres(t *testing.T) {
	t.Setenv("ZASP_EXISTING_TEST_LEGACY_EXECUTION", "true")
	t.Setenv("ZASP_EXISTING_TEST_FINAL_WRITE_EXPIRY", "true")
	TestProductionSecurityAgentBudgetStopsNewPreparationAndDispatch(t)
}

func assertExistingTestFinalWriteExpiry(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, claim SecurityAgentRunClaim, workerID, lease string) {
	t.Helper()
	for _, mode := range []string{"lease", "approval"} {
		t.Run(mode, func(t *testing.T) {
			var deadline time.Time
			query := `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '4 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
			if mode == "approval" {
				query = `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()+interval '4 seconds' WHERE run_id=$1 RETURNING expires_at`
			}
			if err := owner.QueryRow(ctx, query, claim.RunID).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			before := existingTestDispatchSnapshot(t, ctx, owner, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID)
			invoke := func() error {
				var raw json.RawMessage
				args := []any{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, lease, "pid_89f00c00-0000-4000-8000-00000000000c", "pid_89f00d00-0000-4000-8000-00000000000d"}
				statement := postgresSecurityAgentExecuteRunV24SQL
				if os.Getenv("ZASP_EXISTING_TEST_FINAL_WRITE_CONTROL") != "legacy" {
					statement = postgresSecurityAgentExistingTestExecuteSQL
					args = existingTestReadPins(args)
				}
				return worker.QueryRow(ctx, statement, args...).Scan(&raw)
			}
			err := existingTestAcceptanceWait(t, ctx, owner, worker, claim.RunID, "dispatch_final_"+mode, invoke, deadline)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" || pg.Message != "existing test execution authority expired" {
				t.Fatalf("final-write expiry did not roll back: %v", err)
			}
			if before != existingTestDispatchSnapshot(t, ctx, owner, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID) {
				t.Fatal("expired final write left durable effects")
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1; UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()+interval '10 minutes' WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, claim.RunID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertRegisteredExistingTestDispatchRefusals(t *testing.T, ctx context.Context, owner, api, worker *pgx.Conn, o, w, e, r, workerID, lease string) {
	t.Helper()
	before := existingTestDispatchSnapshot(t, ctx, owner, o, w, e, r)
	for _, mode := range []string{"owner", "api", "wrong_checksum", "wrong_fingerprint", "foreign_org", "wrong_worker", "wrong_lease"} {
		connection := worker
		args := []any{o, w, e, r, workerID, lease, "pid_89f00a00-0000-4000-8000-00000000000a", "pid_89f00b00-0000-4000-8000-00000000000b", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		code := "40001"
		switch mode {
		case "owner":
			connection = owner
			code = "42501"
		case "api":
			connection = api
			code = "42501"
		case "wrong_checksum":
			args[8] = "wrong"
			code = "55000"
		case "wrong_fingerprint":
			args[9] = "wrong"
			code = "55000"
		case "foreign_org":
			args[0] = "pid_9a000001-0000-4000-8000-000000000001"
		case "wrong_worker":
			args[4] = "other-worker"
		case "wrong_lease":
			args[5] = "wrong-execution-lease"
		}
		var raw json.RawMessage
		err := connection.QueryRow(ctx, postgresSecurityAgentExistingTestExecuteSQL, args...).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("registered dispatch refusal %s: %s %v", mode, raw, err)
		}
		if before != existingTestDispatchSnapshot(t, ctx, owner, o, w, e, r) {
			t.Fatalf("refused %s changed dispatch authority", mode)
		}
	}
}
