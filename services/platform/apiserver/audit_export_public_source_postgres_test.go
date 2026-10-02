//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAuditExportPublicSourcePostgresCapturesActualPolicyMutation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	body := json.RawMessage(`{"id":"policy-audit-source","name":"Retained policy","scope":"environment","trigger":"tool","conditions":[],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	mutation := WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-audit-source", Operation: "createPolicy", IdempotencyKey: "audit-public-policy-create", Intent: json.RawMessage(`{"source":"actual-policy-mutation"}`), Body: body, AuditID: "pid_79200001-0000-4000-8000-000000000001", CorrelationID: "pid_79200002-0000-4000-8000-000000000001", ReceiptID: "pid_79200003-0000-4000-8000-000000000001"}
	result, err := repository.MutateWorkflow(ctx, f.identity, mutation)
	if err != nil || result.Version != 1 {
		t.Fatal("real policy mutation", err)
	}
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	_, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	var raw []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(common, 1)...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Events []audit.ExportEvent `json:"events"`
	}
	if json.Unmarshal(raw, &page) != nil {
		t.Fatal("page")
	}
	found := false
	for _, event := range page.Events {
		if event.ID == mutation.AuditID {
			found = true
			if event.Action != "policy.create" || event.TargetID != mutation.ID || event.ActorID != f.identity.PrincipalID.String() || event.Metadata["source_operation"] != "createPolicy" {
				t.Fatal("actual policy source mapping changed")
			}
		}
	}
	if !found {
		t.Fatal("actual committed policy mutation is absent from registered capture", mutation.AuditID)
	}
}

// Expectations come from the committed producer records, not from the view or
// SQL encoder. The fixture's preexisting runtime/Red Team setup is not counted
// as an actual mutation; only calls below produce these expected audit rows.
func auditExportPublicPolicyMutations(t *testing.T, ctx context.Context, f auditExportPG) []audit.ExportEvent {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	ops := []string{"createPolicy", "updatePolicy", "rolloutPolicy", "disablePolicy", "deletePolicy"}
	actions := []string{"policy.create", "policy.update", "policy.rollout", "policy.disable", "policy.delete"}
	var events []audit.ExportEvent
	for i, operation := range ops {
		verb := "update"
		if i == 0 {
			verb = "create"
		}
		if i == 4 {
			verb = "delete"
		}
		mutation := WorkflowMutation{Action: verb, Kind: "policy", ID: "policy-public-history", Operation: operation, IdempotencyKey: "public-source-policy-" + operation, ExpectedVersion: int64(i), Intent: json.RawMessage(`{"source":"actual-policy-mutation"}`), Body: json.RawMessage(`{"id":"policy-public-history","name":"Private definition","scope":"environment","trigger":"tool","conditions":[],"action":"monitor","rollout":"draft","failure_mode":"open"}`), AuditID: fmt.Sprintf("pid_79300001-0000-4000-8000-%012d", i+1), CorrelationID: fmt.Sprintf("pid_79300002-0000-4000-8000-%012d", i+1), ReceiptID: fmt.Sprintf("pid_79300003-0000-4000-8000-%012d", i+1)}
		if i == 2 || i == 3 {
			var policy map[string]any
			if json.Unmarshal(mutation.Body, &policy) != nil {
				t.Fatal("policy body")
			}
			policy["_target_environment_id"] = f.identity.Scope.EnvironmentID().String()
			policy["rollout"] = "monitor"
			if i == 3 {
				policy["rollout"] = "disabled"
			}
			mutation.Body, _ = json.Marshal(policy)
		}
		result, err := repository.MutateWorkflow(ctx, f.identity, mutation)
		if err != nil || result.Version != int64(i+1) {
			t.Fatal("actual policy mutation", operation, err)
		}
		replay, err := repository.MutateWorkflow(ctx, f.identity, mutation)
		if err != nil || replay.Version != result.Version {
			t.Fatal("policy replay", err)
		}
		var event audit.ExportEvent
		var at time.Time
		var correlation string
		var version int64
		err = f.admin.QueryRow(ctx, `SELECT organization_id,workspace_id,environment_id,audit_id,principal_id,resource_id,correlation_id,resource_version,created_at FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, f.identity.Scope.OrganizationID().String(), mutation.AuditID).Scan(&event.OrganizationID, &event.WorkspaceID, &event.EnvironmentID, &event.ID, &event.ActorID, &event.TargetID, &correlation, &version, &at)
		if err != nil || version != int64(i+1) {
			t.Fatal("retained policy audit", err)
		}
		event.Action, event.Outcome, event.OccurredAt = actions[i], "succeeded", at.UTC().Format("2006-01-02T15:04:05.000000Z")
		event.Metadata = map[string]string{"source": "workflow_policy", "source_operation": operation, "correlation_id": correlation, "resource_version": strconv.FormatInt(version, 10)}
		events = append(events, event)
		if i == 1 {
			mutation.IdempotencyKey += "-stale"
			mutation.ExpectedVersion = 1
			if _, err := repository.MutateWorkflow(ctx, f.identity, mutation); err == nil {
				t.Fatal("stale policy mutation succeeded")
			}
		}
	}
	var n int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_audit WHERE resource_id='policy-public-history'`).Scan(&n); err != nil || n != 5 {
		t.Fatal("policy replay/failed version added audit", n, err)
	}
	return events
}

func auditExportPublicTestMutations(t *testing.T, ctx context.Context, f auditExportPG) []audit.ExportEvent {
	t.Helper()
	if _, err := f.admin.Exec(ctx, `CREATE ROLE public_source_security_api LOGIN INHERIT; CREATE ROLE public_source_security_worker LOGIN INHERIT; SELECT zasp_security_agent_register_principals(session_user,'public_source_security_api','public_source_security_worker')`); err != nil {
		t.Fatal("register actual security API", err)
	}
	apiConfig := f.admin.Config().Copy()
	apiConfig.User = "public_source_security_api"
	api, err := pgx.ConnectConfig(ctx, apiConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close(context.Background()) })
	f.api = api
	args := f.createArgs()
	scope := args[:3]
	actor := args[3]
	const definition = "pid_79400001-0000-4000-8000-000000000001"
	const correlation = "pid_79400002-0000-4000-8000-000000000001"
	const safety = `{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}`
	var raw []byte
	create := `SELECT zasp_red_team_create_definition($1,$2,$3,$4,'public-source-test-create',$5,'Private test definition',$6,'agent_endpoint','["prompt_injection"]'::jsonb,$7::jsonb,$8)`
	createArgs := append(append([]any{}, scope...), actor, definition, invocationTarget, safety, correlation)
	if err := f.api.QueryRow(ctx, create, createArgs...).Scan(&raw); err != nil {
		t.Fatal("actual test create", err)
	}
	if err := f.api.QueryRow(ctx, create, createArgs...).Scan(&raw); err != nil {
		t.Fatal("test create replay", err)
	}
	if err := f.api.QueryRow(ctx, `SELECT zasp_red_team_update_definition($1,$2,$3,$4,'public-source-test-update',$5,1,'Private changed definition',$6,'agent_endpoint','["prompt_injection"]'::jsonb,$7::jsonb,true,$8)`, createArgs...).Scan(&raw); err != nil {
		t.Fatal("actual test update", err)
	}
	config := f.admin.Config().Copy()
	config.User = "invocation_worker"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	for i := 0; i < 2; i++ {
		runID := fmt.Sprintf("pid_79400003-0000-4000-8000-%012d", i+1)
		if err := f.api.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,$5,$6,2,$7,$8)`, append(append([]any{}, scope...), actor, fmt.Sprintf("public-source-test-run-%d", i), definition, runID, correlation)...).Scan(&raw); err != nil {
			t.Fatal("actual test queue", err)
		}
		if i == 1 {
			if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'public-source-worker',$5,60)`, append(append([]any{}, scope...), runID, bytes.Repeat([]byte{'a'}, 32))...).Scan(&raw); err != nil || !jsonContainsString(raw, "disposition", "claimed") {
				t.Fatal("actual test lease", string(raw), err)
			}
		}
		var version int64
		if err := f.admin.QueryRow(ctx, `SELECT version FROM zasp_red_team_runs WHERE run_id=$1`, runID).Scan(&version); err != nil {
			t.Fatal(err)
		}
		cancelArgs := append(append([]any{}, scope...), actor, fmt.Sprintf("public-source-test-cancel-%d", i), runID, version, correlation)
		if err := f.api.QueryRow(ctx, `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,$5,$6,$7,$8)`, cancelArgs...).Scan(&raw); err != nil {
			t.Fatal("actual test cancellation request", err)
		}
		if err := f.api.QueryRow(ctx, `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,$5,$6,$7,$8)`, cancelArgs...).Scan(&raw); err != nil {
			t.Fatal("cancel replay", err)
		}
		if i == 1 {
			var remains bool
			if err := f.admin.QueryRow(ctx, `SELECT state='leased' AND cancel_requested FROM zasp_red_team_runs WHERE run_id=$1`, runID).Scan(&remains); err != nil || !remains {
				t.Fatal("leased cancellation falsely claimed termination", err)
			}
		}
	}
	rows, err := f.admin.Query(ctx, `SELECT organization_id,workspace_id,environment_id,audit_id,actor_id,resource_id,event_kind,correlation_id,receipt_id,encode(event_digest,'hex'),created_at FROM zasp_red_team_audit WHERE correlation_id=$1`, correlation)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []audit.ExportEvent
	for rows.Next() {
		var event audit.ExportEvent
		var kind, corr, receipt, digest string
		var at time.Time
		if err := rows.Scan(&event.OrganizationID, &event.WorkspaceID, &event.EnvironmentID, &event.ID, &event.ActorID, &event.TargetID, &kind, &corr, &receipt, &digest, &at); err != nil {
			t.Fatal(err)
		}
		event.Action = map[string]string{"red_team_definition_created": "test.create", "red_team_definition_updated": "test.update", "red_team_run_queued": "test.run.queued", "red_team_run_cancelled": "test.run.cancel_requested"}[kind]
		event.Outcome, event.OccurredAt = "succeeded", at.UTC().Format("2006-01-02T15:04:05.000000Z")
		event.Metadata = map[string]string{"source": "red_team_mutation", "source_event_kind": kind, "correlation_id": corr, "receipt_id": receipt, "event_sha256": digest}
		events = append(events, event)
	}
	if rows.Err() != nil || len(events) != 6 {
		t.Fatal("actual test audit/replay counts", len(events), rows.Err())
	}
	return events
}

func TestAuditExportPublicSourcePostgresActualProtocolsAndFrozenResume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f, _ := auditExportRetainedIdentityFixture(t, ctx)
	expected := auditExportPublicPolicyMutations(t, ctx, f)
	expected = append(expected, auditExportPublicTestMutations(t, ctx, f)...)
	// Age only these owned receipt fixtures, then invoke the released owner cleanup
	// protocol. Historical policy audit remains eligible without its receipt.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_workflow_receipts SET created_at=transaction_timestamp()-interval '8 days',expires_at=transaction_timestamp()-interval '1 day' WHERE resource_id='policy-public-history'`); err != nil {
		t.Fatal(err)
	}
	var receiptPage []byte
	if err := f.admin.QueryRow(ctx, `SELECT zasp_workflow_receipt_cleanup(1000)`).Scan(&receiptPage); err != nil {
		t.Fatal("released expired receipt cleanup", err)
	}
	var receiptsGone bool
	if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_workflow_receipts WHERE resource_id='policy-public-history')`).Scan(&receiptsGone); err != nil || !receiptsGone {
		t.Fatal("expired receipts not cleaned", err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	args := f.createArgs()
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM zasp_environments WHERE (organization_id,workspace_id,id)=($1,$2,$3) ON CONFLICT DO NOTHING`, args[:3]...); err != nil {
		t.Fatal(err)
	}
	var version int64
	var environmentClass string
	if err := f.admin.QueryRow(ctx, `SELECT version,environment_class FROM zasp_data_controls WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, args[:3]...).Scan(&version, &environmentClass); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.MutateAdministration(ctx, f.identity, administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: 45, DeletionEnabled: true, ExpectedVersion: version, EnvironmentClass: environmentClass, AuditID: "pid_79400004-0000-4000-8000-000000000001"}); err != nil {
		t.Fatal("actual configuration mutation", err)
	}
	// Owner-only foreign/unrelated fixture controls must not broaden the source.
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT 'pid_79500001-0000-4000-8000-000000000001',workspace_id,environment_id,audit_id,principal_id,'policy.create',resource_id,'succeeded','{}',created_at FROM zasp_workflow_audit WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'; INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version) SELECT organization_id,workspace_id,environment_id,'pid_79500002-0000-4000-8000-000000000001','pid_79500003-0000-4000-8000-000000000001',principal_id,'notASelectedPolicyOperation','integration',resource_id,1 FROM zasp_workflow_audit WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`); err != nil {
		t.Fatal(err)
	}
	// The ordinary request creates its own admin audit. All admin expectations
	// use the previously reviewed raw-row decoder, never this new SQL view.
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	_, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	for _, raw := range auditExportIdentitySource(t, ctx, f) {
		event, err := audit.DecodeExportEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, event)
	}
	if len(expected) != 18 {
		t.Fatal("actual source family count", len(expected))
	}
	sort.Slice(expected, func(i, j int) bool {
		if expected[i].OccurredAt == expected[j].OccurredAt {
			return expected[i].ID > expected[j].ID
		}
		return expected[i].OccurredAt > expected[j].OccurredAt
	})
	var wanted [][]byte
	for i, event := range expected {
		event.Ordinal = int64(i + 1)
		event, err := audit.ProjectExportEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := audit.EncodeExportEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		wanted = append(wanted, raw)
	}
	var raw []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&raw); err != nil {
		t.Fatal("capture all actual protocols", err)
	}
	check := func() {
		t.Helper()
		if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(common, 1)...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var page struct {
			Events []json.RawMessage `json:"events"`
		}
		if json.Unmarshal(raw, &page) != nil || len(page.Events) != len(wanted) {
			t.Fatal("full source count", len(page.Events), len(wanted), string(raw))
		}
		for i, event := range page.Events {
			decoded, err := audit.DecodeExportEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := audit.EncodeExportEvent(decoded)
			if err != nil || !bytes.Equal(canonical, wanted[i]) {
				t.Fatal("independent canonical source mismatch", i, string(event), string(wanted[i]), err)
			}
		}
	}
	check()
	// Disposable owner cleanup proves capture does not join current records or
	// rely on retained request receipts, and source deletion cannot recapture.
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_workflow_receipts WHERE resource_id='policy-public-history'; DELETE FROM zasp_workflow_idempotency WHERE idempotency_key LIKE 'public-source-policy-%'; DELETE FROM zasp_workflow_audit WHERE resource_id='policy-public-history'`); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&raw); err != nil {
		t.Fatal("captured resume", err)
	}
	check()
}

func TestAuditExportPublicSourcePostgresInvalidCandidateIsAtomic(t *testing.T) {
	for _, test := range []struct{ name, change string }{
		{"cross-source-identical-ID", `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT organization_id,workspace_id,environment_id,audit_id,principal_id,'unrelated.action',resource_id,'succeeded','{}',created_at-interval '1 day' FROM zasp_workflow_audit WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`},
		{"admin-test-equal-time", `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT organization_id,workspace_id,environment_id,audit_id,actor_id,'unrelated.action',resource_id,'succeeded','{}',created_at FROM zasp_red_team_audit WHERE event_kind='red_team_definition_created' AND resource_id='pid_79400001-0000-4000-8000-000000000001'`},
		{"policy-test-different-time", `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,created_at) SELECT p.organization_id,p.workspace_id,p.environment_id,r.audit_id,'pid_79700001-0000-4000-8000-000000000001',p.principal_id,p.operation,p.resource_kind,p.resource_id,p.resource_version,r.created_at-interval '1 day' FROM zasp_workflow_audit p JOIN zasp_red_team_audit r ON r.organization_id=p.organization_id WHERE p.audit_id='pid_79300001-0000-4000-8000-000000000001' AND r.event_kind='red_team_definition_created' AND r.resource_id='pid_79400001-0000-4000-8000-000000000001'`},
		{"known-operation-wrong-kind", `UPDATE zasp_workflow_audit SET resource_kind='integration' WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`},
		{"invalid-correlation", `UPDATE zasp_workflow_audit SET correlation_id='not-a-product-id' WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`},
		{"zero-version", `UPDATE zasp_workflow_audit SET resource_version=0 WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`},
		{"invalid-target", `UPDATE zasp_workflow_audit SET resource_id='not-policy-target' WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`},
		{"invalid-time", `UPDATE zasp_workflow_audit SET created_at='infinity'::timestamptz WHERE audit_id='pid_79300001-0000-4000-8000-000000000001'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			auditExportPublicPolicyMutations(t, ctx, f)
			if strings.Contains(test.name, "-test-") {
				auditExportPublicTestMutations(t, ctx, f)
			}
			// The collision fixture copies the original producer's test audit ID.
			// It does not rewrite, deduplicate, or seed a successful export result.
			if changed, err := f.admin.Exec(ctx, test.change); err != nil || changed.RowsAffected() != 1 {
				t.Fatal("owned source corruption must affect exactly one row", err)
			}
			if strings.Contains(test.name, "-test-") {
				var exact bool
				query := `SELECT count(*)=1 AND bool_and(a.occurred_at=r.created_at) FROM zasp_admin_audit a JOIN zasp_red_team_audit r ON (r.organization_id,r.audit_id)=(a.organization_id,a.id)`
				if test.name == "policy-test-different-time" {
					query = `SELECT count(*)=1 AND bool_and(p.created_at=r.created_at-interval '1 day') FROM zasp_workflow_audit p JOIN zasp_red_team_audit r ON (r.organization_id,r.audit_id)=(p.organization_id,p.audit_id)`
				}
				if err := f.admin.QueryRow(ctx, query).Scan(&exact); err != nil || !exact {
					t.Fatal("collision pair/time fixture not established", err)
				}
			}
			worker, outbox := auditExportWorkerConnections(t, ctx, f)
			for _, connection := range []*pgx.Conn{f.api, worker, outbox} {
				if _, err := connection.Exec(ctx, `SELECT * FROM zasp_audit_export_public_source_v1`); auditExportSQLState(err) != "42501" {
					t.Fatal("raw shared source exposed", err)
				}
			}
			_, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			var raw []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&raw); err != nil || !jsonContainsString(raw, "failure_code", "invalid_source") {
				t.Fatal("invalid eligible candidate did not fail", string(raw), err)
			}
			var atomic bool
			if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_events) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_chunks) AND (SELECT status='failed' AND failure_code='invalid_source' AND NOT captured AND reserved_bytes=0 FROM zasp_audit_export_jobs) AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1 AND (SELECT outcome='rejected' AND metadata->>'failure_code'='invalid_source' FROM zasp_admin_audit WHERE action='audit_export.complete')`).Scan(&atomic); err != nil || !atomic {
				t.Fatal("partial invalid-source capture", err)
			}
			if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
				t.Fatal("failed capture evidence was removed")
			}
		})
	}
}

func TestAuditExportPublicSourcePostgresCatalogDriftRefuses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	for _, test := range []struct{ name, change string }{
		{"same-column-widening", `CREATE OR REPLACE VIEW zasp_audit_export_public_source_v1 WITH(security_barrier=true) AS SELECT * FROM (/* current */) original UNION ALL SELECT organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at,'administration'::text source_kind,true source_valid FROM zasp_admin_audit`},
		{"security-option", `ALTER VIEW zasp_audit_export_public_source_v1 SET(security_invoker=true)`},
		{"workflow-column-read", `GRANT SELECT(resource_id) ON zasp_workflow_audit TO zasp_audit_export_outbox`},
		{"workflow-owner-acl", `REVOKE SELECT ON zasp_workflow_audit FROM zasp_e2e`},
		{"workflow-owner", `ALTER TABLE zasp_workflow_audit OWNER TO zasp_discovery_authority`},
		{"workflow-grantor", `CREATE ROLE public_source_acl_grantor NOLOGIN; GRANT SELECT ON zasp_workflow_audit TO public_source_acl_grantor WITH GRANT OPTION; SET LOCAL ROLE public_source_acl_grantor; GRANT SELECT ON zasp_workflow_audit TO zasp_discovery_api; RESET ROLE`},
		{"admin-grantor", `CREATE ROLE public_source_acl_grantor NOLOGIN; GRANT SELECT ON zasp_admin_audit TO public_source_acl_grantor WITH GRANT OPTION; SET LOCAL ROLE public_source_acl_grantor; GRANT SELECT ON zasp_admin_audit TO zasp_discovery_api; RESET ROLE`},
		{"red-team-policy", `ALTER POLICY zasp_red_team_audit_authority ON zasp_red_team_audit USING(false)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if strings.Contains(test.change, "/* current */") {
				var definition string
				if err := tx.QueryRow(ctx, `SELECT pg_get_viewdef('zasp_audit_export_public_source_v1'::regclass,true)`).Scan(&definition); err != nil {
					t.Fatal(err)
				}
				test.change = strings.ReplaceAll(test.change, "/* current */", strings.TrimSuffix(strings.TrimSpace(definition), ";"))
			}
			if _, err := tx.Exec(ctx, test.change); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("changed source catalog remained ready", err)
			}
			if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("warmed 51 accepted changed source catalog", err)
			}
		})
	}
}

func auditExportPublicSourceSnapshot(t *testing.T, ctx context.Context, connection *pgx.Conn) string {
	t.Helper()
	var snapshot string
	if err := connection.QueryRow(ctx, `SELECT jsonb_build_object('admin',(SELECT jsonb_agg(to_jsonb(a) ORDER BY organization_id,id) FROM zasp_admin_audit a),'workflow',(SELECT jsonb_agg(to_jsonb(a) ORDER BY organization_id,audit_id) FROM zasp_workflow_audit a),'red_team',(SELECT jsonb_agg(to_jsonb(a) ORDER BY organization_id,audit_id) FROM zasp_red_team_audit a),'catalog',(SELECT jsonb_agg(jsonb_build_object('name',c.relname,'owner',c.relowner::regrole::text,'acl',c.relacl::text,'rls',c.relrowsecurity,'forced',c.relforcerowsecurity,'columns',(SELECT jsonb_agg(jsonb_build_object('name',a.attname,'acl',a.attacl::text) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped)) ORDER BY c.relname) FROM pg_class c WHERE c.oid IN('zasp_admin_audit'::regclass,'zasp_workflow_audit'::regclass,'zasp_red_team_audit'::regclass)))::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestAuditExportPublicSourcePostgresDownRetainsOriginalHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err != nil {
		t.Fatal(err)
	}
	auditExportProduceIdentityActions(t, ctx, f)
	auditExportPublicPolicyMutations(t, ctx, f)
	auditExportPublicTestMutations(t, ctx, f)
	before := auditExportPublicSourceSnapshot(t, ctx, f.admin)
	installAuditExports(t, ctx, f.admin)
	var ready bool
	if err := f.api.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("held 51 API refused clean52 source", err)
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err != nil {
		t.Fatal("source history wrongly blocked Down", err)
	}
	if before != auditExportPublicSourceSnapshot(t, ctx, f.admin) {
		t.Fatal("Down changed original source history or exact grants")
	}
	if err := f.admin.QueryRow(ctx, `SELECT to_regclass('zasp_audit_export_public_source_v1') IS NULL AND zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("Down did not restore exact51", err)
	}
	installAuditExports(t, ctx, f.admin)
}

func TestAuditExportPublicSourcePostgresConcurrentFreeze(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(fmt.Sprintf("catalog-drift-%t", drift), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			f.register(t, ctx)
			auditExportPublicPolicyMutations(t, ctx, f)
			auditExportPublicTestMutations(t, ctx, f)
			worker, _ := auditExportWorkerConnections(t, ctx, f)
			_, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
			f.api = worker
			err := auditExportBlockedCall(t, ctx, f, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common, `LOCK TABLE zasp_audit_export_chunks IN SHARE MODE`, nil, func(tx pgx.Tx) error {
				if drift {
					_, err := tx.Exec(ctx, `GRANT SELECT(resource_id) ON zasp_workflow_audit TO zasp_audit_export_outbox`)
					return err
				}
				// One concurrent owner transaction commits backdated additions to all
				// source families after the source INSERT has reached chunk planning.
				_, err := tx.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT organization_id,workspace_id,environment_id,'pid_79600001-0000-4000-8000-000000000001',actor_id,'late.configuration',target_id,'succeeded','{}','2020-01-01Z' FROM zasp_admin_audit LIMIT 1;
INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,created_at) SELECT organization_id,workspace_id,environment_id,'pid_79600002-0000-4000-8000-000000000001','pid_79600003-0000-4000-8000-000000000001',principal_id,'createPolicy','policy','policy-late',1,'2020-01-01Z' FROM zasp_workflow_audit LIMIT 1;
INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body,created_at) SELECT organization_id,workspace_id,environment_id,'pid_79600004-0000-4000-8000-000000000001','pid_79600005-0000-4000-8000-000000000001','pid_79600006-0000-4000-8000-000000000001',actor_id,event_kind,resource_id,event_digest,body,'2020-01-01Z' FROM zasp_red_team_audit LIMIT 1;`)
				return err
			})
			if drift {
				if auditExportSQLState(err) != "55000" {
					t.Fatal("source ACL drift after freeze accepted", err)
				}
				var empty bool
				if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_events) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_chunks) AND (SELECT status='processing' AND NOT captured AND reserved_bytes=0 FROM zasp_audit_export_jobs)`).Scan(&empty); err != nil || !empty {
					t.Fatal("source drift left snapshot", err)
				}
				return
			}
			if err != nil {
				t.Fatal("concurrent source writers blocked or corrupted capture", err)
			}
			var exact bool
			if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*)=12 FROM zasp_audit_export_events) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_events WHERE event_id LIKE 'pid_796%') AND (SELECT count(*)=15 FROM zasp_audit_export_public_source_v1 WHERE organization_id=$1)`, common[0]).Scan(&exact); err != nil || !exact {
				t.Fatal("concurrent committed sources entered frozen statement", err)
			}
		})
	}
}
