package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenancecutover"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Twenty-one durable eligible receipts come from complete signed planning
// across three actual publicly created, validated and supervised definitions.
// Original public cancellation releases organization capacity after each
// capture; these are not 21 simultaneous pending approval runs. Every original
// concurrency limit remains 10. No origin/task/delegation is inserted here.
func TestApprovalActivationNativeAuthenticCaptureOverflow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	runFindingResponseFixtureConfigured(t, nil, func(ctx context.Context, f findingResponseFixture, original, finding string) {
		// Create both additional definitions before expensive planning, while the
		// fixture's original fresh authentication is still valid. Public validation
		// and original activation writers derive their genuine service delegations.
		definitions := []string{f.definition}
		for n := 1; n <= 2; n++ {
			definitions = append(definitions, createApprovalOverflowDefinition(t, ctx, f, n))
		}
		runner := workerMigrationRunner(t, f.owner)
		for _, up := range []func(context.Context) error{runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("native overflow authorization profile refused", err)
			}
		}
		runtime := newApprovalActivationFamilyRuntime(t, ctx, f.owner, f.o, f.w, f.e, f.actor, owned, runtimeservices.Config{})
		if _, err := f.owner.Exec(ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned authentic overflow notifications','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, f.o, f.w, f.e, f.next()); err != nil {
			t.Fatal(err)
		}
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.WorkerForward), key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
		forward, err := authorization.NewApprovalOriginWorkerExecutor(ctx, runtime.poolFor("finding78_executor"), runtime.checker, runtime.pins.StoreID, runtime.pins.ModelID, key, migrations.ApprovalMaintenanceProfileChecksum())
		if err != nil {
			t.Fatal(err)
		}
		var pricing json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT lookup_request-'body'-'body_digest' FROM zasp_temporal78.planning_jobs WHERE run_id=$1`, original).Scan(&pricing); err != nil {
			t.Fatal(err)
		}
		for _, definition := range definitions {
			current := f
			current.definition = definition
			for range 7 {
				run := approvalActivationPlanFinding(t, ctx, current, original, forward, pricing, runtime.Reconcile)
				runtime.AssertCapture(run, "finding78", "captured_inactive")
				cancelApprovalOverflowCapturedRun(t, ctx, current, run)
				runtime.AssertCapture(run, "finding78", "captured_inactive")
				runtime.Reconcile()
			}
		}
		var authentic bool
		if err := f.owner.QueryRow(ctx, `SELECT
 (SELECT count(*)=21 AND bool_and(x.status='captured_inactive' AND x.family='finding78' AND x.delegation IS NOT NULL AND zasp_approval_activation_v1.eligible(x)) FROM zasp_approval_maintenance.origins x WHERE organization_id=$1)
 AND(SELECT count(*)=3 AND bool_and(d.activation='supervised' AND d.body->>'concurrency_limit'='10' AND g.grantor_id=$2 AND g.definition_digest=h.definition_digest)
 FROM public.zasp_security_agent_definitions d JOIN zasp_temporal78.service_grants g USING(organization_id,workspace_id,environment_id,definition_id,definition_version)
 JOIN public.zasp_security_agent_definition_versions h ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.definition_version)
 WHERE d.organization_id=$1 AND d.definition_id=ANY($3::text[]))
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions d WHERE d.organization_id=$1 AND d.definition_id=ANY($3::text[]) AND(SELECT count(*) FROM public.zasp_security_agent_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.definition_id)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id) AND r.state IN('queued','planning','waiting_approval','running','verifying'))>10)`, f.o, f.actor, definitions).Scan(&authentic); err != nil || !authentic {
			t.Fatal("overflow receipts lack original native eligibility/delegation/concurrency evidence", err)
		}
		runtime.Reconcile()
		cutover, closeCutover, err := connectormaintenancecutover.NewCombinedControlled(connectormaintenancecutover.Config{Endpoint: owned.endpoint, StoreID: runtime.pins.StoreID, ModelID: runtime.pins.ModelID, OldTokenFile: owned.oldFile, NewTokenFile: owned.newFile, ProfileChecksum: runtime.connectorPin, ApprovalProfileChecksum: runtime.approvalPin, OperatorPool: runtime.poolFor(f.owner.Config().User)}, runtime.activationPin)
		if err != nil {
			t.Fatal(err)
		}
		defer closeCutover()
		pid, stop := startApprovalActivationWriter(t, f.owner.Config().ConnString(), runtime.outbox, owned, runtime.pins, f.o)
		permit, err := cutover.Prepare(ctx, f.o, pid)
		if err != nil {
			t.Log("connector cutover prepare stage=" + connectormaintenancecutover.PrepareRefusalStage(err))
			t.Fatal("actual old writer observation unavailable")
		}
		before := approvalOverflowSnapshot(t, ctx, f)
		stop()
		owned.withdrawOld(t)
		err = cutover.Activate(ctx, permit)
		if err == nil || connectormaintenancecutover.ActivationRefusalStage(err) != "sql-activation" {
			t.Fatal("authentic over-bound captures did not refuse native activation")
		}
		if after := approvalOverflowSnapshot(t, ctx, f); after != before {
			t.Fatal("over-bound activation changed durable origins, either family, revision or audit")
		}
		var inactive bool
		if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE active) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE active)
 AND NOT EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations)
 AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.projection_activations)
 AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.projection_activations)
 AND(SELECT count(*)=21 AND bool_and(status='captured_inactive') FROM zasp_approval_maintenance.origins WHERE organization_id=$1)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE organization_id=$1 AND event_kind LIKE 'approval_notification_%')`, f.o).Scan(&inactive); err != nil || !inactive {
			t.Fatal("overflow refusal leaked activation, lost receipt or fabricated delivery evidence", err)
		}
		// The permit is consumed by the failed attempt and the old credential is
		// already withdrawn. This fixture never resumes the obsolete writer.
		if err := cutover.Activate(ctx, permit); err == nil || connectormaintenancecutover.ActivationRefusalStage(err) != "permit" {
			t.Fatal("failed activation permit was reusable")
		}
	}, true, 10)
}

func createApprovalOverflowDefinition(t *testing.T, ctx context.Context, f findingResponseFixture, index int) string {
	t.Helper()
	var raw json.RawMessage
	if err := f.owner.QueryRow(ctx, `SELECT body-'id' FROM public.zasp_security_agent_definitions WHERE definition_id=$1`, f.definition).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		t.Fatal("original public definition invalid")
	}
	body["name"], body["enabled"], body["definition_version"] = fmt.Sprintf("Owned authentic overflow definition %d", index), false, 1
	// The accepted original value10 is retained, never changed to bypass limits.
	if body["concurrency_limit"] != float64(10) {
		t.Fatal("original accepted concurrency limit changed")
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, f.identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(encoded))
	request.Header.Set("Idempotency-Key", fmt.Sprintf("approval-overflow-definition-%d", index))
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatal("genuine public overflow definition creation refused", response.Code)
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || !validProductID(result.ID) {
		t.Fatal("genuine public overflow definition identity unavailable")
	}
	for n, target := range []string{"validated", "supervised"} {
		receipt, err := f.repository.ActivateSecurityAgent(ctx, f.identity, SecurityAgentActivation{DefinitionID: result.ID, ExpectedVersion: int64(n + 1), TargetActivation: target, FreshAuthExpiresAt: f.identity.FreshAuthExpiresAt, IdempotencyKey: fmt.Sprintf("approval-overflow-%d-%s", index, target), AuditID: f.next(), CorrelationID: f.next(), ReceiptID: f.next()})
		if err != nil || receipt.Version != int64(n+2) || receipt.Activation != target {
			t.Fatal("genuine overflow definition activation refused", target, err)
		}
	}
	return result.ID
}

func approvalOverflowSnapshot(t *testing.T, ctx context.Context, f findingResponseFixture) string {
	t.Helper()
	var digest string
	if err := f.owner.QueryRow(ctx, `SELECT encode(digest(convert_to(jsonb_build_object(
 'approval_registration',(SELECT jsonb_agg(to_jsonb(x) ORDER BY singleton) FROM zasp_approval_maintenance.registration x),
 'connector_registration',(SELECT jsonb_agg(to_jsonb(x) ORDER BY singleton) FROM zasp_connector_maintenance.registration x),
 'combined',(SELECT jsonb_agg(to_jsonb(x) ORDER BY organization_id) FROM zasp_approval_activation_v1.organizations x),
 'approval_activation',(SELECT jsonb_agg(to_jsonb(x) ORDER BY organization_id) FROM zasp_approval_maintenance.projection_activations x),
 'connector_activation',(SELECT jsonb_agg(to_jsonb(x) ORDER BY organization_id) FROM zasp_connector_maintenance.projection_activations x),
 'origins',(SELECT jsonb_agg(to_jsonb(x) ORDER BY workspace_id,environment_id,delivery_id) FROM zasp_approval_maintenance.origins x WHERE organization_id=$1),
 'tasks',(SELECT jsonb_agg(to_jsonb(x) ORDER BY workspace_id,environment_id,effect_id) FROM zasp_connector_maintenance.tasks x WHERE organization_id=$1),
 'notifications',(SELECT jsonb_agg(to_jsonb(x) ORDER BY workspace_id,environment_id,delivery_id) FROM public.zasp_security_agent_approval_notifications x WHERE organization_id=$1),
 'revision',(SELECT to_jsonb(x) FROM zasp_authorization79.organizations x WHERE organization_id=$1),
 'audit',(SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM public.zasp_security_agent_audit x WHERE organization_id=$1))::text,'UTF8'),'sha256'),'hex')`, f.o).Scan(&digest); err != nil {
		t.Fatal("overflow durable snapshot unavailable", err)
	}
	return digest
}

// Genuine public cancellation frees the original organization quota without
// inventing a terminal state or losing the independently durable notification.
// Native cancellation audit/receipt and deferred 78 manager checks remain intact.
func cancelApprovalOverflowCapturedRun(t *testing.T, ctx context.Context, f findingResponseFixture, run string) {
	t.Helper()
	snapshot := func() string {
		t.Helper()
		var value string
		if err := f.owner.QueryRow(ctx, `SELECT encode(digest(convert_to(jsonb_build_array(to_jsonb(o),to_jsonb(n))::text,'UTF8'),'sha256'),'hex')
 FROM zasp_approval_maintenance.origins o JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id)
 WHERE(o.organization_id,o.workspace_id,o.environment_id,o.run_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, run).Scan(&value); err != nil {
			t.Fatal("original durable capture snapshot unavailable")
		}
		return value
	}
	before := snapshot()
	var version int64
	var state string
	if err := f.owner.QueryRow(ctx, `SELECT version,state FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, run).Scan(&version, &state); err != nil || state != "waiting_approval" {
		t.Fatal("genuine captured run is not waiting for approval")
	}
	input := SecurityAgentCancelRequest{RunID: run, ExpectedVersion: version, IdempotencyKey: "approval-overflow-cancel-" + run, AuditID: f.next(), CorrelationID: f.next(), ReceiptID: f.next()}
	result, err := f.repository.CancelSecurityAgentRun(ctx, f.identity, input)
	if err != nil || result.ID != run || result.State != "cancelled" || result.Version != version+1 || result.Replayed || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID {
		t.Fatal("original public overflow cancellation failed")
	}
	if after := snapshot(); after != before {
		t.Fatal("public cancellation rewrote authentic origin or pending notification evidence")
	}
	var valid bool
	if err := f.owner.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM public.zasp_security_agent_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.definition_id,r.state,r.version)=($1,$2,$3,$4,$5,'cancelled',$6+1) AND r.completed_at IS NOT NULL AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL)
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.audit_id,a.correlation_id,a.actor_id,a.event_kind)=($1,$2,$3,$4,$7,$8,$9,'run_cancelled') AND a.body=jsonb_build_object('run_id',$4::text,'prior_state','waiting_approval','version',$6::bigint+1) AND a.event_digest=digest(convert_to(jsonb_build_object('run_id',$4::text,'expected_version',$6::bigint)::text,'UTF8'),'sha256'))
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts rc WHERE(rc.organization_id,rc.workspace_id,rc.environment_id,rc.principal_id,rc.operation,rc.idempotency_key,rc.resource_id,rc.expected_version,rc.audit_id,rc.correlation_id,rc.receipt_id)=($1,$2,$3,$9,'cancelSecurityAgentRun',$10,$4,$6,$7,$8,$11) AND rc.intent=jsonb_build_object('run_id',$4::text,'expected_version',$6::bigint) AND rc.intent_digest=digest(convert_to(rc.intent::text,'UTF8'),'sha256') AND rc.response->>'id'=$4 AND rc.response->>'state'='cancelled' AND rc.response->'version'=to_jsonb($6::bigint+1))
 AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins o JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE(o.organization_id,o.workspace_id,o.environment_id,o.run_id)=($1,$2,$3,$4) AND o.status='captured_inactive' AND o.delegation IS NOT NULL AND zasp_approval_activation_v1.eligible(o) AND n.state='pending' AND n.attempt=0 AND n.completed_at IS NULL AND n.lease_token IS NULL)
 AND EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id)=($1,$2,$3,$4) AND p.settled_at IS NOT NULL AND p.total_tokens=30 AND p.cost_nano_credits=30000)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id)=($1,$2,$3,$4) AND p.settled_at IS NULL AND p.released_at IS NULL)
 AND NOT zasp_temporal74.unresolved($1,$2,$3,$4)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=($1,$2,$3,$4))
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=($1,$2,$3,$4))`, f.o, f.w, f.e, run, f.definition, version, input.AuditID, input.CorrelationID, f.actor, input.IdempotencyKey, input.ReceiptID).Scan(&valid); err != nil || !valid {
		t.Fatal("public cancellation lacks exact receipt/audit, released capacity or preserved native capture")
	}
}
