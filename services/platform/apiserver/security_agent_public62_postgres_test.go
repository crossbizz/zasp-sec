package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func public62GoRepository(t *testing.T, c *pgx.Conn, o, w, e, actor string) (*SecurityAgentPublicRepository, RequestIdentity) {
	t.Helper()
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: c})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewSecurityAgentPublicRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	oid, _ := domain.ParseProductID(o)
	wid, _ := domain.ParseProductID(w)
	eid, _ := domain.ParseProductID(e)
	pid, _ := domain.ParseProductID(actor)
	scope, err := domain.NewScope(oid, wid, eid)
	if err != nil {
		t.Fatal(err)
	}
	return repo, RequestIdentity{PrincipalID: pid, Scope: scope, CredentialKind: CredentialBrowserSession, CSRFToken: strings.Repeat("c", 32), Permissions: []string{"view", "manage_workflows", "run_tests"}}
}

func TestSecurityAgentPublic62RepositoryLifecyclePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if err := repo.Ready(ctx, id); err != nil {
			t.Fatal(err)
		}
		if activated, err := repo.Activate(ctx, id, public62Definition, 1); err != nil || activated.DefinitionVersion != 2 {
			t.Fatal(activated, err)
		}
		q := SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "public62-go-trigger-0001"}
		created, err := repo.Trigger(ctx, id, q)
		if err != nil {
			t.Fatal(err)
		}
		before := public62Snapshot(t, ctx, owner)
		for i := 0; i < 2; i++ {
			if i == 1 {
				conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(ctx)
				repo, id = public62GoRepository(t, conn, o, w, e, actor)
			}
			replay, err := repo.Trigger(ctx, id, q)
			if err != nil || replay != created || public62Snapshot(t, ctx, owner) != before {
				t.Fatal("replay changed authority", replay, err)
			}
		}
		q.TriggerVersion = 2
		if _, err := repo.Trigger(ctx, id, q); err != ErrRepositoryConflict || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("conflicting replay", err)
		}
		for _, state := range []string{"queued", "planning"} {
			if state == "planning" {
				_, err := orderedPlanningCall(ctx, worker, map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": created.RunID, "worker_id": "public62-go-planner", "lease_token": "public62-go-planner-lease-0001", "operation": "claim", "payload": map[string]any{}})
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := repo.Run(ctx, id, created.RunID)
			if err != nil || got.State != state || got.Admitted || len(got.Steps) != 0 {
				t.Fatal(state, got, err)
			}
			page, err := repo.Runs(ctx, id, "", 1)
			if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], got) || page.NextAfterRunID != nil {
				t.Fatal(page, err)
			}
			page, err = repo.Runs(ctx, id, created.RunID, 1)
			if err != nil || len(page.Items) != 0 {
				t.Fatal(page, err)
			}
		}
		before = public62Snapshot(t, ctx, owner)
		foreign := id
		other, _ := domain.ParseProductID("pid_ffffffff-ffff-4fff-8fff-ffffffffffff")
		foreign.Scope, _ = domain.NewScope(other, id.Scope.WorkspaceID(), id.Scope.EnvironmentID())
		_, foreignErr := repo.Run(ctx, foreign, created.RunID)
		_, missingErr := repo.Run(ctx, id, other.String())
		if foreignErr != ErrRepositoryUnavailable || missingErr != foreignErr || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("tenant denial", foreignErr, missingErr)
		}
		for _, op := range []string{"ready", "detail", "list"} {
			if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			mutation := `UPDATE zasp_security_agent_runs SET definition_version=999 WHERE run_id=$1`
			if op == "ready" {
				mutation = `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64) WHERE $1<>''`
			}
			if _, err := owner.Exec(ctx, mutation, created.RunID); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			badRepo, _ := public62GoRepository(t, owner, o, w, e, actor)
			var callErr error
			switch op {
			case "ready":
				callErr = badRepo.Ready(ctx, id)
			case "detail":
				_, callErr = badRepo.Run(ctx, id, created.RunID)
			case "list":
				_, callErr = badRepo.Runs(ctx, id, "", 1)
			}
			if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
				t.Fatal(err)
			}
			if callErr != ErrRepositoryUnavailable {
				t.Fatalf("%s malformed authority not unavailable: %v", op, callErr)
			}
		}
		// Seed a second finding input, never a run or a success receipt.
		otherFinding := "pid_8d300001-0000-4000-8000-000000000004"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Second public input','high','open')`, o, w, e, otherFinding); err != nil {
			t.Fatal(err)
		}
		q.TriggerID, q.TriggerVersion, q.IdempotencyKey = otherFinding, 1, "public62-go-trigger-0002"
		second, err := repo.Trigger(ctx, id, q)
		if err != nil {
			t.Fatal(err)
		}
		firstID, lastID := created.RunID, second.RunID
		if firstID > lastID {
			firstID, lastID = lastID, firstID
		}
		page, err := repo.Runs(ctx, id, "", 1)
		if err != nil || len(page.Items) != 1 || page.Items[0].RunID != firstID || page.NextAfterRunID == nil || *page.NextAfterRunID != firstID {
			t.Fatal("ascending first page", page, err)
		}
		page, err = repo.Runs(ctx, id, *page.NextAfterRunID, 1)
		if err != nil || len(page.Items) != 1 || page.Items[0].RunID != lastID || page.NextAfterRunID != nil {
			t.Fatal("ascending last page", page, err)
		}
	})
}

func TestSecurityAgentPublic62RepositoryAdmittedPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		got, err := repo.Run(ctx, id, run)
		if err != nil || !got.Admitted || len(got.Steps) != 2 || got.Steps[1].State != "blocked" {
			t.Fatal(got, err)
		}
		if _, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, run, steps[0], "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
		got, err = repo.Run(ctx, id, run)
		if err != nil || got.State != "running" || got.Steps[0].Approval.State != "approved" {
			t.Fatal(got, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=plan||'{"unexpected":true}'::jsonb WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Run(ctx, id, run); err != ErrRepositoryUnavailable {
			t.Fatal("malformed plan", err)
		}
	})
}

func TestSecurityAgentPublic62RepositoryTerminalPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, action *pgx.Conn, o, w, e, run string, steps []string) {
		var actor string
		if err := owner.QueryRow(ctx, `SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		got, err := repo.Run(ctx, id, run)
		if err != nil || got.Verification != "contained" || got.Steps[0].Cleanup.State != "pending" || got.Steps[1].Settlement != "not_reproduced" {
			t.Fatal(got, err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "claim", 10, 3, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		got, err = repo.Run(ctx, id, run)
		if err != nil || got.Steps[0].Cleanup.State != "leased" {
			t.Fatal(got, err)
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		if _, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "complete", 10, 5, 2), keys); err != nil {
			t.Fatal(err)
		}
		got, err = repo.Run(ctx, id, run)
		if err != nil || got.Verification != "remediated" || !got.Steps[0].Cleanup.Cleaned {
			t.Fatal(got, err)
		}
		page, err := repo.Runs(ctx, id, "", 10)
		if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], got) {
			t.Fatal(page, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET state='cleanup_pending' WHERE run_id=$1 AND action_key='create_temporary_policy'`, run); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Run(ctx, id, run); err != ErrRepositoryUnavailable {
			t.Fatal("false cleanup exposed", err)
		}
	}, false)
}

func TestSecurityAgentPublic62RepositoryPartialPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, action *pgx.Conn, o, w, e, run string, steps []string) {
		var actor string
		if err := owner.QueryRow(ctx, `SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "claim", 10, 4, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		stored := claim
		for _, target := range claim["targets"].([]any) {
			selected := cloneOrderedApplicationRequest(t, stored)
			selected["targets"] = []any{target}
			stored, err = orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, run, steps[0], selected, key), keys)
			if err != nil {
				t.Fatal(err)
			}
		}
		selected := cloneOrderedApplicationRequest(t, stored)
		selected["targets"] = []any{stored["targets"].([]any)[0]}
		deployOrderedCleanup(t, ctx, owner, key, selected)
		if _, err := owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, run); err != nil {
			t.Fatal(err)
		}
		if _, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "reconcile", 10, 7, 3), keys); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Run(ctx, id, run)
		if err != nil || got.Verification != "needs_human" || !got.Steps[0].Cleanup.Partial || got.Steps[0].Cleanup.Cleaned || got.Steps[0].Cleanup.State != "retryable" {
			t.Fatal(got, err)
		}
	}, true)
}

func TestSecurityAgentPublic62RepositoryPartialApplicationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
		defer deployment.Close(ctx)
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, run, steps[0], "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		if _, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, run, steps[0], claim, key), keys); err != nil {
			t.Fatal(err)
		}
		cancel := orderedProgressionRequest(o, w, e, run, steps[0], "cancel", orderedProgressionApprover, 5)
		cancel["approval_version"] = 2
		if _, err := orderedProgressionCall(ctx, api, "transition", cancel); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Run(ctx, id, run)
		if err != nil || got.Verification != "cancelled" || got.Steps[0].Receipt != nil {
			t.Fatal("cancelled partial application", got, err)
		}
		claim, err = orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "claim", 6, 2, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		got, err = repo.Run(ctx, id, run)
		if err != nil || !got.Steps[0].Cleanup.Partial || got.Steps[0].Cleanup.State != "leased" {
			t.Fatal("partial leased", got, err)
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		if _, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "complete", 6, 4, 2), keys); err != nil {
			t.Fatal(err)
		}
		got, err = repo.Run(ctx, id, run)
		if err != nil || got.Verification != "cancelled" || !got.Steps[0].Cleanup.Cleaned || !got.Steps[0].Cleanup.Partial || got.Steps[0].Receipt != nil {
			t.Fatal("partial removal invented remediation", got, err)
		}
	})
}
