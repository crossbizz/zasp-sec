package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"reflect"
	"testing"
	"time"
)

// Removing approval binding must not permit a supervised child reservation.
func assertTemporalTestApproval(t *testing.T, ctx context.Context, owner, executor, api *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, testID string, selection map[string]any, replayOnly bool) {
	t.Helper()
	assertTemporalTestFullActivation(t, ctx, owner, repository, identity, true)
	const definition = "pid_f0740000-0000-4000-8000-000000000101"
	const run = "pid_f0740000-0000-4000-8000-000000000601"
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	if _, err := repository.runSecurityAgentManual(ctx, identity, SecurityAgentRunRequest{DefinitionID: definition, ExpectedVersion: 3, IdempotencyKey: "test74-supervised-manual", RunID: run, AuditID: "pid_f0740000-0000-4000-8000-000000000602", CorrelationID: "pid_f0740000-0000-4000-8000-000000000603", ReceiptID: "pid_f0740000-0000-4000-8000-000000000604", TriggerKind: "manual"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run).Scan(&raw); err != nil || string(raw) == "null" {
		t.Fatal(err)
	}
	assertTemporalTestPlanningPreparation(t, ctx, owner, executor, o, w, e, run, testID, identity.PrincipalID.String(), selection)
	var step, approval string
	if err := owner.QueryRow(ctx, `SELECT step_id,approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND state='pending'`, run).Scan(&step, &approval); err != nil {
		t.Fatal(err)
	}
	effect := func() error {
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}})
		return executor.QueryRow(ctx, `SELECT zasp_temporal74.effect($1::jsonb)`, q).Scan(&raw)
	}
	if err := effect(); err == nil {
		t.Fatal("supervised effect without approval")
	}
	request := SecurityAgentApprovalDecisionRequest{ApprovalID: approval, IdempotencyKey: "test74-supervised-approval", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: "pid_f0740000-0000-4000-8000-000000000610", CorrelationID: "pid_f0740000-0000-4000-8000-000000000611", ReceiptID: "pid_f0740000-0000-4000-8000-000000000612"}
	if _, err := repository.DecideSecurityAgentApproval(ctx, identity, request); err == nil {
		t.Fatal("self approval accepted")
	}
	const approver = "pid_f0740000-0000-4000-8000-000000000609"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-org','test74-approver','organization_admin');INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Approver','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, approver); err != nil {
		t.Fatal(err)
	}
	identity.PrincipalID, _ = domain.ParseProductID(approver)
	if replayOnly {
		original, err := repository.DecideSecurityAgentApproval(ctx, identity, request)
		if err != nil || original.State != "approved" || original.Replayed {
			t.Fatal("original approval", original, err)
		}
		for _, statement := range []string{
			`UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
			`UPDATE zasp_security_agent_plans SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
			`UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
		} {
			if _, err := owner.Exec(ctx, statement, run); err != nil {
				t.Fatal(err)
			}
		}
		assertTemporalTestApprovalReceiptReplay(t, ctx, owner, repository, identity, request, original)
		if err := effect(); err == nil {
			t.Fatal("historical decision replay authorized expired fresh effect")
		}
		return
	}
	// Controlled negative rows only: a retained approval must not inherit74
	// decision authority merely because its request has the same shape.
	const retained = "pid_f0740000-0000-4000-8000-000000000698"
	for _, statement := range []string{
		`INSERT INTO zasp_security_agent_runs SELECT (jsonb_populate_record(NULL::zasp_security_agent_runs,to_jsonb(r)||jsonb_build_object('run_id',$2::text,'state','simulated'))).* FROM zasp_security_agent_runs r WHERE run_id=$1`,
		`INSERT INTO zasp_security_agent_approvals SELECT (jsonb_populate_record(NULL::zasp_security_agent_approvals,to_jsonb(a)||jsonb_build_object('run_id',$2::text,'approval_id',$2::text))).* FROM zasp_security_agent_approvals a WHERE run_id=$1`,
	} {
		if _, err := owner.Exec(ctx, statement, run, retained); err != nil {
			t.Fatal("retained negative fixture", err)
		}
	}
	if err := api.QueryRow(ctx, `SELECT zasp_temporal74.decide_approval($1,$2,$3,$4,$5,'retained-cancel',1,'cancelled',clock_timestamp(),$4,$4,$4)`, o, w, e, retained, approver).Scan(&raw); err != nil || len(raw) != 0 {
		t.Fatal("unowned approval claimed by74", string(raw), err)
	}
	retainedRequest := request
	retainedRequest.ApprovalID, retainedRequest.Decision = retained, "cancelled"
	if _, err := repository.DecideSecurityAgentApproval(ctx, identity, retainedRequest); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatal("retained decision readiness changed", err)
	}
	var retainedUnchanged bool
	if err := owner.QueryRow(ctx, `SELECT a.state='pending' AND a.version=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE resource_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.control_intents WHERE resource_id=$1) FROM zasp_security_agent_approvals a WHERE approval_id=$1`, retained).Scan(&retainedUnchanged); err != nil || !retainedUnchanged {
		t.Fatal("retained refusal wrote a decision", retainedUnchanged, err)
	}
	for _, mutate := range []func(*SecurityAgentApprovalDecisionRequest){func(q *SecurityAgentApprovalDecisionRequest) { q.FreshAuthAt = time.Now().UTC().Add(-10 * time.Minute) }, func(q *SecurityAgentApprovalDecisionRequest) { q.ExpectedVersion++ }, func(q *SecurityAgentApprovalDecisionRequest) {
		q.ApprovalID = "pid_f0740000-0000-4000-8000-000000000699"
	}} {
		q := request
		mutate(&q)
		if _, err := repository.DecideSecurityAgentApproval(ctx, identity, q); err == nil {
			t.Fatal("stale/foreign approval accepted", q)
		}
	}
	for _, change := range []struct{ bad, restore string }{
		{`UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows"]' WHERE principal_id=$1`, `UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests"]' WHERE principal_id=$1`},
		{`UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`},
	} {
		if _, err := owner.Exec(ctx, change.bad, approver); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.DecideSecurityAgentApproval(ctx, identity, request); err == nil {
			t.Fatal("current approval permission denied premise ignored")
		}
		if _, err := owner.Exec(ctx, change.restore, approver); err != nil {
			t.Fatal(err)
		}
	}
	var expires time.Time
	if err := owner.QueryRow(ctx, `SELECT expires_at FROM zasp_security_agent_approvals WHERE approval_id=$1`, approval).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE approval_id=$1`, approval); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.DecideSecurityAgentApproval(ctx, identity, request); err == nil {
		t.Fatal("expired approval accepted")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET expires_at=$2 WHERE approval_id=$1`, approval, expires); err != nil {
		t.Fatal(err)
	}
	var before string
	occupancy := `SELECT jsonb_build_object('owner',(SELECT to_jsonb(x) FROM zasp_temporal74.run_owners x WHERE run_id=$1),'parents',(SELECT count(*) FROM zasp_security_agent_runs),'jobs',(SELECT count(*) FROM zasp_temporal74.planning_jobs WHERE run_id=$1),'budgets',(SELECT count(*) FROM zasp_security_agent_run_budgets WHERE run_id=$1),'children',(SELECT count(*) FROM zasp_red_team_runs c JOIN zasp_temporal74.run_owners x ON x.test_run_id=c.run_id WHERE x.run_id=$1),'effects',(SELECT count(*) FROM zasp_temporal74.effects WHERE run_id=$1))::text`
	if err := owner.QueryRow(ctx, occupancy, run).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs c JOIN zasp_temporal74.run_owners x ON x.test_run_id=c.run_id WHERE x.run_id=$1)`, run).Scan(&absent); err != nil || !absent {
		t.Fatal("preapproval child/effect", absent, err)
	}
	installTemporalTestCaptureNegative(t, ctx, owner, api)
	for _, decision := range []string{"rejected", "cancelled"} {
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		q := request
		q.Decision = decision
		if result, err := repository.DecideSecurityAgentApproval(ctx, identity, q); err != nil || result.State != decision {
			tx.Rollback(ctx)
			t.Fatal("decision stop", decision, result, err)
		}
		if result, err := repository.DecideSecurityAgentApproval(ctx, identity, q); err != nil || !result.Replayed || result.State != decision {
			tx.Rollback(ctx)
			t.Fatal("decision stop immutable replay", decision, result, err)
		}
		if decision == "cancelled" {
			assertTemporalTestCaptureNegative(t, ctx, api)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		assertTemporalTestCaptureNoResidue(t, ctx, owner)
	}
	if result, err := repository.DecideSecurityAgentApproval(ctx, identity, request); err != nil || result.State != "approved" {
		t.Fatal("actual supervised approval", result, err)
	}
	if result, err := repository.DecideSecurityAgentApproval(ctx, identity, request); err != nil || !result.Replayed || result.State != "approved" {
		t.Fatal("approval receipt replay", result, err)
	}
	var after string
	if err := owner.QueryRow(ctx, occupancy, run).Scan(&after); err != nil || after != before {
		t.Fatal("approval changed logical occupancy/owner", before, after, err)
	}
	var oneReceipt bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_audit WHERE approval_id=$1 AND event_kind='approval_decided')=1 AND (SELECT count(*) FROM zasp_security_agent_request_receipts WHERE resource_id=$1 AND operation='decideSecurityAgentApproval')=1`, approval).Scan(&oneReceipt); err != nil || !oneReceipt {
		t.Fatal("approval replay duplicated receipt/audit", oneReceipt, err)
	}
	var pending json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending_controls()`).Scan(&pending); err != nil || string(pending) != "[]" {
		t.Fatal("unaccepted start control delivered", string(pending), err)
	}
	var digest string
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	start, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 3, "input_digest": digest})
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.accept_start($1::jsonb)`, start).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending_controls()`).Scan(&pending); err != nil {
		t.Fatal("accepted start control proof", err)
	}
	var controls []struct {
		ID       string          `json:"control_id"`
		Kind     string          `json:"kind"`
		Terminal bool            `json:"terminal"`
		Start    json.RawMessage `json:"start"`
	}
	if json.Unmarshal(pending, &controls) != nil || len(controls) != 1 || controls[0].Kind != "approval" || controls[0].Terminal {
		t.Fatal("pending exact approval control", string(pending))
	}
	if err := api.QueryRow(ctx, `SELECT zasp_temporal74.pending_controls()`).Scan(&raw); err == nil {
		t.Fatal("API impersonated registered control relay")
	}
	fields := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 3, "input_digest": digest, "control_id": controls[0].ID}
	for _, key := range []string{"control_id", "environment_id"} {
		foreign := map[string]any{}
		for k, v := range fields {
			foreign[k] = v
		}
		foreign[key] = "pid_f0740000-0000-4000-8000-000000000699"
		q, _ := json.Marshal(foreign)
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.accept_control($1::jsonb)`, q).Scan(&raw); err == nil {
			t.Fatal("foreign control acceptance", key)
		}
	}
	for _, table := range []struct{ read, corrupt, restore string }{
		{`SELECT body FROM zasp_security_agent_audit WHERE audit_id=$1`, `UPDATE zasp_security_agent_audit SET body=body||'{"tampered":true}'::jsonb WHERE audit_id=$1`, `UPDATE zasp_security_agent_audit SET body=$2::jsonb WHERE audit_id=$1`},
		{`SELECT response FROM zasp_security_agent_request_receipts WHERE audit_id=$1`, `UPDATE zasp_security_agent_request_receipts SET response=response||'{"tampered":true}'::jsonb WHERE audit_id=$1`, `UPDATE zasp_security_agent_request_receipts SET response=$2::jsonb WHERE audit_id=$1`},
	} {
		var original json.RawMessage
		if err := owner.QueryRow(ctx, table.read, request.AuditID).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, table.corrupt, request.AuditID); err != nil {
			t.Fatal(err)
		}
		readErr := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending_controls()`).Scan(&raw)
		_, restoreErr := owner.Exec(ctx, table.restore, request.AuditID, original)
		if restoreErr != nil || readErr == nil {
			t.Fatal("committed tampered decision proof accepted", readErr, restoreErr)
		}
	}
	if detail, err := repository.GetSecurityAgentApproval(ctx, identity, approval); err != nil || detail.State != "approved" {
		t.Fatal("typed approved reload", detail, err)
	}
	if page, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{RunID: run, Limit: 10}); err != nil || len(page.Items) != 1 || page.Items[0].ID != approval || page.Items[0].State != "approved" {
		t.Fatal("typed approval page", page, err)
	}
	if page, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{RunID: run, State: "pending", Limit: 1}); err != nil || len(page.Items) != 0 {
		t.Fatal("approval state filter", page, err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='[]' WHERE principal_id=$1`, approver); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetSecurityAgentApproval(ctx, identity, approval); err == nil {
		t.Fatal("revoked view detail accepted")
	}
	if _, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{RunID: run, Limit: 10}); err == nil {
		t.Fatal("revoked view page accepted")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests"]' WHERE principal_id=$1`, approver); err != nil {
		t.Fatal(err)
	}
	const otherOrg = "pid_9a000001-0000-4000-8000-000000000001"
	const otherWorkspace = "pid_9a000002-0000-4000-8000-000000000002"
	const otherEnvironment = "pid_9a000003-0000-4000-8000-000000000003"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-other','test74-other-viewer','read_only_viewer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Other scope','["view"]')`, pgx.QueryExecModeSimpleProtocol, otherOrg, otherWorkspace, otherEnvironment, approver); err != nil {
		t.Fatal(err)
	}
	oi, _ := domain.ParseProductID(otherOrg)
	wi, _ := domain.ParseProductID(otherWorkspace)
	ei, _ := domain.ParseProductID(otherEnvironment)
	foreign := identity
	foreign.Scope, _ = domain.NewScope(oi, wi, ei)
	if _, err := repository.GetSecurityAgentApproval(ctx, foreign, approval); !errors.Is(err, ErrRepositoryNotFound) {
		deadline, _ := ctx.Deadline()
		t.Fatal("foreign approval detail", err, "context", ctx.Err(), "deadline", deadline, "now", time.Now())
	}
	if page, err := repository.ListSecurityAgentApprovals(ctx, foreign, SecurityAgentApprovalPageRequest{RunID: run, Limit: 10}); err != nil || len(page.Items) != 0 {
		t.Fatal("foreign approval page", page, err)
	}
	if err := effect(); err != nil {
		t.Fatal("approved specialized effect", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE approval_id=$1`, approval); err != nil {
		t.Fatal(err)
	}
	if err := effect(); err == nil {
		t.Fatal("expired approval allowed effect replay")
	}
}

func assertTemporalTestApprovalReceiptReplay(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, request SecurityAgentApprovalDecisionRequest, original SecurityAgentApprovalResult) {
	t.Helper()
	var before, after string
	snapshot := `SELECT jsonb_build_object('audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE approval_id=$1),'receipt',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM zasp_security_agent_request_receipts r WHERE resource_id=$1),'control',(SELECT jsonb_agg(to_jsonb(c) ORDER BY control_id) FROM zasp_temporal74.control_intents c WHERE resource_id=$1))::text`
	if err := owner.QueryRow(ctx, snapshot, request.ApprovalID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	replayed, err := repository.DecideSecurityAgentApproval(ctx, identity, request)
	if err != nil || !replayed.Replayed {
		t.Fatal("historical approved receipt replay", replayed, err)
	}
	replayed.Replayed = false
	if !reflect.DeepEqual(original, replayed) {
		t.Fatal("historical replay changed original response", original, replayed)
	}
	for _, mutate := range []func(*SecurityAgentApprovalDecisionRequest){
		func(q *SecurityAgentApprovalDecisionRequest) { q.Decision = "rejected" },
		func(q *SecurityAgentApprovalDecisionRequest) { q.ExpectedVersion++ },
		func(q *SecurityAgentApprovalDecisionRequest) { q.FreshAuthAt = time.Now().UTC().Add(-10 * time.Minute) },
	} {
		q := request
		mutate(&q)
		if _, err := repository.DecideSecurityAgentApproval(ctx, identity, q); err == nil {
			t.Fatal("historical replay accepted changed intent/stale authentication", q)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows"]' WHERE principal_id=$1`, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	_, denied := repository.DecideSecurityAgentApproval(ctx, identity, request)
	if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests"]' WHERE principal_id=$1`, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if denied == nil {
		t.Fatal("historical replay ignored current actor permission")
	}
	var expires time.Time
	if err := owner.QueryRow(ctx, `SELECT expires_at FROM zasp_security_agent_request_receipts WHERE receipt_id=$1`, request.ReceiptID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET expires_at=clock_timestamp()-interval '1 second' WHERE receipt_id=$1`, request.ReceiptID); err != nil {
		t.Fatal(err)
	}
	_, denied = repository.DecideSecurityAgentApproval(ctx, identity, request)
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET expires_at=$2 WHERE receipt_id=$1`, request.ReceiptID, expires); err != nil {
		t.Fatal(err)
	}
	if denied == nil {
		t.Fatal("expired historical receipt replay accepted")
	}
	if err := owner.QueryRow(ctx, snapshot, request.ApprovalID).Scan(&after); err != nil || before != after {
		t.Fatal("historical replay changed audit/receipt/control", before, after, err)
	}
}

func assertTemporalTestTerminalApprovalReplay(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, identity RequestIdentity) {
	t.Helper()
	var request SecurityAgentApprovalDecisionRequest
	var original SecurityAgentApprovalResult
	var response json.RawMessage
	var actor string
	if err := owner.QueryRow(ctx, `SELECT rc.resource_id,rc.principal_id,rc.idempotency_key,rc.expected_version,rc.intent->>'decision',a.fresh_auth_at,rc.audit_id,rc.correlation_id,rc.receipt_id,rc.response FROM zasp_security_agent_request_receipts rc JOIN zasp_security_agent_approvals a ON(a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=(rc.organization_id,rc.workspace_id,rc.environment_id,rc.resource_id) JOIN zasp_security_agent_runs r ON(r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) JOIN zasp_temporal74.run_owners x ON(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) WHERE x.source_kind='automatic73' AND x.action_key='rerun_test' AND r.state='remediated' AND r.completed_at IS NOT NULL AND rc.operation='decideSecurityAgentApproval' AND rc.response->>'state'='approved'`).Scan(&request.ApprovalID, &actor, &request.IdempotencyKey, &request.ExpectedVersion, &request.Decision, &request.FreshAuthAt, &request.AuditID, &request.CorrelationID, &request.ReceiptID, &response); err != nil {
		t.Fatal("actual terminal approval receipt", err)
	}
	if err := decodeStrictDiscovery(response, &original); err != nil {
		t.Fatal(err)
	}
	request.FreshAuthAt = request.FreshAuthAt.UTC()
	identity.PrincipalID, _ = domain.ParseProductID(actor)
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(time.Minute)
	assertTemporalTestApprovalReceiptReplay(t, ctx, owner, repository, identity, request, original)
	t.Log("typed approved receipt replay after actual remediated parent settlement preserves original response and immutable audit/control; current actor, fresh-auth, intent and receipt-expiry negatives pass")
}
