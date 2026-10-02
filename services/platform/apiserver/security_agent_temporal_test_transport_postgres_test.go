package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

func bindTemporalTestPlannerPricing(q map[string]any) {
	p := q["policy"].(map[string]any)
	p["request_token_limit"], p["request_policy_version"] = 512, "security-agent-planner-v1"
	digest := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
	p["credential_digest"] = "sha256:" + hex.EncodeToString(digest[:])
}

func TestTemporalTestExecutorTransportPostgres(t *testing.T) {
	runTemporalTestTransportFixture(t, false)
}

func TestTemporalTestExecutorLivePostgres(t *testing.T) {
	t.Setenv("ZASP_TEST74_LIVE", "true")
	runTemporalTestTransportFixture(t, true)
}

func TestTemporalTestExecutorCancellationPostgres(t *testing.T) {
	runTemporalTestTransportFixture(t, false, true)
}

func TestTemporalTestExecutorAutomaticPostgres(t *testing.T) {
	runTemporalTestTransportFixture(t, false, false, true)
}

func TestTemporalTestExecutorApprovalPostgres(t *testing.T) {
	runTemporalTestTransportFixture(t, false, false, false, true)
}

func TestTemporalTestExecutorApprovalReplayPostgres(t *testing.T) {
	runTemporalTestTransportFixture(t, false, false, false, true, true)
}

func runTemporalTestTransportFixture(t *testing.T, live bool, cancellation ...bool) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if live || len(cancellation) > 0 && cancellation[0] || len(cancellation) > 2 && cancellation[2] {
			// The live restart deliberately exercises a bounded drain timeout.
			// Approval/cancellation also group several current-authority probes.
			// Keep this owned fixture alive through those tests and join everything
			// before returning to the predecessor fixture's cleanup.
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
			defer cancel()
		}
		installTemporalTestExecutorFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE temporal_test_executor_login LOGIN; CREATE ROLE temporal_test_compensation_login LOGIN; SELECT zasp_temporal68.register_principals('temporal_test_executor_login','temporal_test_compensation_login'); UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "temporal_test_executor_login"
		executor, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(ctx)
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository := &PostgresRepository{database: db, securityAgentExecution: true}
		identity := fixtureRequestIdentity(t)
		ids := make([]domain.ProductID, 4)
		for i, id := range []string{o, w, e, actor} {
			ids[i], err = domain.ParseProductID(id)
			if err != nil {
				t.Fatal(err)
			}
		}
		identity.Scope, err = domain.NewScope(ids[0], ids[1], ids[2])
		if err != nil {
			t.Fatal(err)
		}
		identity.PrincipalID = ids[3]
		identity.CredentialKind = CredentialBrowserSession
		identity.FreshAuthenticated = true
		identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
		input := SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 1, IdempotencyKey: "test74-focused-transport", RunID: "pid_f0740000-0000-4000-8000-000000000191", AuditID: "pid_f0740000-0000-4000-8000-000000000192", CorrelationID: "pid_f0740000-0000-4000-8000-000000000192", ReceiptID: "pid_f0740000-0000-4000-8000-000000000193", TriggerKind: "manual"}
		if admitted, err := repository.runSecurityAgentManual(ctx, identity, input); err != nil || admitted.ID != input.RunID {
			t.Fatal("actual focused manual admission", admitted, err)
		}
		var raw []byte
		if !live {
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, input.RunID).Scan(&raw); err != nil || string(raw) == "null" {
				t.Fatal("actual focused untouched takeover", err)
			}
		}
		cfg = owner.Config().Copy()
		cfg.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		policy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
		encoded, _ := json.Marshal(selection)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		if len(cancellation) > 2 && cancellation[2] {
			assertTemporalTestApproval(t, ctx, owner, executor, api, repository, identity, testID, selection, len(cancellation) > 3 && cancellation[3])
			return
		}
		if len(cancellation) > 1 && cancellation[1] {
			assertTemporalTestAutomaticActor(t, ctx, owner, executor, adapter, repository, identity, testID, selection)
			return
		}
		if len(cancellation) > 0 && cancellation[0] {
			assertTemporalTestCancelledDelivery(t, ctx, owner, api, executor, redWorker, repository, identity, testID, input.RunID, selection)
			return
		}
		if live {
			prepareTemporalTestLiveTenant(t, ctx, owner, admin, repository, identity, testID)
		}
		assertTemporalTestTransport(t, ctx, owner, input.RunID, testID, 1, encoded)
		if live {
			if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
				t.Fatal(err)
			}
			var rerun string
			if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal74.run_owners WHERE source_kind='automatic73' AND action_key='rerun_test'`).Scan(&rerun); err != nil {
				t.Fatal(err)
			}
			if detail, err := repository.GetSecurityAgentRun(ctx, identity, rerun); err != nil || detail.Run.State != "remediated" || len(detail.ActionDetails) != 1 || detail.ActionDetails[0].ExistingTest == nil || detail.ActionDetails[0].ExistingTest.Verification == nil {
				t.Fatal("typed rerun verified public readback", detail, err)
			}
			// The nested worker has joined. Historical receipt probes get their
			// own bound; production execution deadlines remain unchanged.
			replayCtx, replayCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			assertTemporalTestTerminalApprovalReplay(t, replayCtx, owner, repository, identity)
			replayCancel()
		}
		if !live {
			assertTemporalTestCleanup(t, ctx, owner, executor, repository, identity, selection)
		}
	})
}

// These use real manual admission and74 takeover. Prepared request versions
// are controlled fixtures: no provider or artifact completion is invented.
func assertTemporalTestCleanup(t *testing.T, ctx context.Context, owner, executor *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, pricing map[string]any) {
	t.Helper()
	cfg := owner.Config().Copy()
	cfg.User = "temporal_test_compensation_login"
	comp, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(ctx)
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	call := func(c *pgx.Conn, sql string, q any) (map[string]any, error) {
		raw, _ := json.Marshal(q)
		var output []byte
		err := c.QueryRow(ctx, sql, raw).Scan(&output)
		var value map[string]any
		if err == nil {
			err = json.Unmarshal(output, &value)
		}
		return value, err
	}
	for index, phase := range []string{"queued", "prepared", "started"} {
		run := []string{"pid_f0740000-0000-4000-8000-000000000201", "pid_f0740000-0000-4000-8000-000000000211", "pid_f0740000-0000-4000-8000-000000000221"}[index]
		audit := []string{"pid_f0740000-0000-4000-8000-000000000202", "pid_f0740000-0000-4000-8000-000000000212", "pid_f0740000-0000-4000-8000-000000000222"}[index]
		receipt := []string{"pid_f0740000-0000-4000-8000-000000000203", "pid_f0740000-0000-4000-8000-000000000213", "pid_f0740000-0000-4000-8000-000000000223"}[index]
		input := SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 1, IdempotencyKey: "test74-cleanup-" + phase, RunID: run, AuditID: audit, CorrelationID: audit, ReceiptID: receipt, TriggerKind: "manual"}
		if _, err := repository.runSecurityAgentManual(ctx, identity, input); err != nil {
			t.Fatal("cleanup actual admission", phase, err)
		}
		var transferred []byte
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run).Scan(&transferred); err != nil {
			t.Fatal(err)
		}
		var digest string
		if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 1, "input_digest": digest, "reason": "workflow_cancelled"}
		if phase != "queued" {
			plan := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 1, "operation": "load"}
			if _, err := call(executor, `SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil {
				t.Fatal(err)
			}
			plan["operation"], plan["payload"] = "prepare", map[string]any{"pricing": pricing, "input_version": "test74-cleanup-" + phase}
			if _, err := call(executor, `SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil {
				t.Fatal(err)
			}
			if phase == "started" {
				plan["operation"], plan["payload"] = "start", map[string]any{}
				if value, err := call(executor, `SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil || value["send_permit"] != true {
					t.Fatal("cleanup unknown start", value, err)
				}
			}
		}
		if _, err := call(executor, `SELECT zasp_temporal74.cleanup($1::jsonb)`, q); err == nil {
			t.Fatal("executor used compensation stop")
		}
		result, err := call(comp, `SELECT zasp_temporal74.cleanup($1::jsonb)`, q)
		if err != nil || result["pending"] != (phase == "started") {
			t.Fatal("cleanup preserves actual obligations", phase, result, err)
		}
		if repeated, err := call(comp, `SELECT zasp_temporal74.cleanup($1::jsonb)`, q); err != nil || !jsonEqualMaps(result, repeated) {
			t.Fatal("cleanup replay changed", phase, repeated, err)
		}
		var safe bool
		if err := owner.QueryRow(ctx, `SELECT r.completed_at IS NOT NULL AND r.lease_token IS NULL AND zasp_temporal74.unresolved($2,$3,$4,$1)=$5 AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1) FROM zasp_security_agent_runs r WHERE run_id=$1`, run, o, w, e, phase == "started").Scan(&safe); err != nil || !safe {
			t.Fatal("cleanup lost unknown or manufactured effect", phase, safe, err)
		}
		q["input_digest"] = strings.Repeat("f", 64)
		if _, err := call(comp, `SELECT zasp_temporal74.cleanup($1::jsonb)`, q); err == nil {
			t.Fatal("cleanup accepted mismatched start")
		}
	}
}

func installTemporalTestExecutorFixture(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	if _, err := owner.Exec(ctx, `CREATE ROLE p4c_test_scheduler LOGIN INHERIT;
CREATE ROLE p4c_test_risk LOGIN INHERIT;
CREATE ROLE p4c_test_graph LOGIN INHERIT;
CREATE ROLE p4c_test_search LOGIN INHERIT;
SELECT zasp_execution_register_principals(session_user,'p4c_test_scheduler','security_agent_v33_discovery_worker_login','p4c_test_risk','p4c_test_graph','p4c_test_search')`); err != nil {
		t.Fatal(err)
	}
	runner := precisionMigrationRunner(t, owner)
	for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission} {
		if err := up(ctx); err != nil {
			t.Fatal("accepted predecessor", err)
		}
	}
	up, ok := any(runner).(interface{ UpProductionTemporalTestExecutor(context.Context) error })
	if !ok {
		t.Fatal("lease-free test executor authority is not installed")
	}
	if err := up.UpProductionTemporalTestExecutor(ctx); err != nil {
		tx, txErr := owner.Begin(ctx)
		if txErr != nil {
			t.Fatal(txErr)
		}
		defer tx.Rollback(ctx)
		_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalTestExecutor().UpSQL())
		var detail *pgconn.PgError
		if errors.As(ddlErr, &detail) {
			t.Logf("74 compile location position=%d internal=%d where=%s query=%s", detail.Position, detail.InternalPosition, detail.Where, detail.InternalQuery)
		}
		var fingerprint string
		queryErr := tx.QueryRow(ctx, `SELECT zasp_temporal74.fingerprint()`).Scan(&fingerprint)
		t.Logf("74 independent catalog compile DDL=%v query=%v fingerprint=%s", ddlErr, queryErr, fingerprint)
		t.Fatal("install test executor", err)
	}
}
