package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
	"time"
)

// A scheduler label is audit attribution, not the product service principal.
func assertTemporalTestAutomaticActor(t *testing.T, ctx context.Context, owner, executor, adapter *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, testID string, selection map[string]any) {
	t.Helper()
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	run := startTemporalTestLiveAutomaticRerun(t, ctx, owner, repository, handler, identity, true)
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	var raw []byte
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run).Scan(&raw); err != nil || string(raw) == "null" {
		t.Fatal("automatic untouched takeover", err)
	}
	assertTemporalTestPlanningPreparation(t, ctx, owner, executor, o, w, e, run, testID, identity.PrincipalID.String(), selection)
	var approval string
	var serviceRequester bool
	if err := owner.QueryRow(ctx, `SELECT a.approval_id,a.requester_id=g.principal_id AND r.requested_by<>a.requester_id AND NOT m.active FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) JOIN zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(g.organization_id,g.grantor_id) WHERE x.run_id=$1`, run).Scan(&approval, &serviceRequester); err != nil || !serviceRequester {
		t.Fatal("automatic approval canonical service requester", serviceRequester, err)
	}
	const approver = "pid_f0740000-0000-4000-8000-000000000609"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-org','test74-approver','organization_admin');INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Approver','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, approver); err != nil {
		t.Fatal(err)
	}
	approvalIdentity := identity
	approvalIdentity.PrincipalID, _ = domain.ParseProductID(approver)
	if result, err := repository.DecideSecurityAgentApproval(ctx, approvalIdentity, SecurityAgentApprovalDecisionRequest{ApprovalID: approval, IdempotencyKey: "test74-automatic-approval", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: "pid_f0740000-0000-4000-8000-000000000610", CorrelationID: "pid_f0740000-0000-4000-8000-000000000611", ReceiptID: "pid_f0740000-0000-4000-8000-000000000612"}); err != nil || result.State != "approved" {
		t.Fatal("actual automatic service approval", result, err)
	}
	// Cleanup must also settle an admitted plan that failed before any effect.
	// Roll back this branch, then exercise the actual child reservation below.
	compConfig := owner.Config().Copy()
	compConfig.User = "temporal_test_compensation_login"
	comp, err := pgx.ConnectConfig(ctx, compConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(ctx)
	tx, err := comp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var start json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest,'reason','workflow_failed') FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&start); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){func(v map[string]any) { v["extra"] = true }, func(v map[string]any) { delete(v, "input_digest") }, func(v map[string]any) { v["run_id"] = nil }} {
		var malformed map[string]any
		if err := json.Unmarshal(start, &malformed); err != nil {
			t.Fatal(err)
		}
		mutate(malformed)
		q, _ := json.Marshal(malformed)
		if _, err := tx.Exec(ctx, "SAVEPOINT malformed"); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT zasp_temporal74.cleanup($1::jsonb)`, q).Scan(&raw); err == nil {
			t.Fatal("malformed cleanup accepted", malformed)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT malformed"); err != nil {
			t.Fatal(err)
		}
	}
	err = tx.QueryRow(ctx, `SELECT zasp_temporal74.cleanup($1::jsonb)`, start).Scan(&raw)
	tx.Rollback(ctx)
	if err != nil {
		t.Fatalf("admitted absent-effect cleanup: %T %v", err, err)
	}
	var cleanup struct {
		Pending  bool `json:"pending"`
		Evidence struct {
			Proof struct {
				Kind        string `json:"kind"`
				EffectState string `json:"effect_state"`
			} `json:"proof"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &cleanup); err != nil || cleanup.Pending || cleanup.Evidence.Proof.Kind != "admitted" || cleanup.Evidence.Proof.EffectState != "absent" {
		t.Fatal("absent effect cleanup proof", string(raw), err)
	}
	var step string
	if err := owner.QueryRow(ctx, `SELECT step_id FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&step); err != nil {
		t.Fatal(err)
	}
	q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}})
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.effect($1::jsonb)`, q).Scan(&raw); err != nil {
		t.Fatalf("actual automatic child reservation: %T %v", err, err)
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT c.requested_by=g.principal_id AND a.actor_id=g.principal_id AND g.principal_id=zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_definition_service',x.definition_id) AND NOT m.active AND r.requested_by='test74-live-automatic-rerun' AND NOT EXISTS(SELECT 1 FROM zasp_identity_memberships WHERE principal_id=g.principal_id) FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) JOIN zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(g.organization_id,g.grantor_id) JOIN zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id) JOIN zasp_red_team_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.resource_id,a.event_kind)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,'red_team_run_queued') WHERE x.run_id=$1`, run).Scan(&bound); err != nil || !bound {
		t.Fatal("canonical automatic child/audit service principal", bound, err)
	}
	var child, key string
	if err := owner.QueryRow(ctx, `SELECT x.test_run_id,f.effect_key FROM zasp_temporal74.effects f JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE f.run_id=$1`, run).Scan(&child, &key); err != nil {
		t.Fatal(err)
	}
	store, manifest := orderedTestInputArtifact(t, ctx, owner, o, w, e, run, step, child, testID, "rerun_test")
	id, _ := CanonicalDiscoveryID(identity.Scope, "security_agent_ordered_test_input", run+"\x1f"+step)
	body, err := orderedTestReadArtifact(ctx, store, identity.Scope, id, manifest, 65536)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"input", "dispatch"} {
		payload := map[string]any{}
		if operation == "input" {
			payload = map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(body)}
		}
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": operation, "payload": payload})
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.linked($1::jsonb)`, q).Scan(&raw); err != nil {
			t.Fatal("automatic adapter preparation", operation, err)
		}
	}
	resolve, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": key, "operation": "resolve", "payload": map[string]any{"category": "prompt_injection", "target_id": "pid_89000011-0000-4000-8000-000000000001", "target_kind": "agent_endpoint"}, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()})
	if err := adapter.QueryRow(ctx, `SELECT zasp_temporal74.invocation($1::jsonb)`, resolve).Scan(&raw); err != nil {
		if p, ok := err.(*pgconn.PgError); ok {
			t.Log("automatic adapter SQL context", p.Where)
		}
		t.Fatal("automatic actual adapter resolution", err)
	}
}
