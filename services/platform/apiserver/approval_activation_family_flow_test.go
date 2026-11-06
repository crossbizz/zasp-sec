package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type approvalActivationTest74Admission struct {
	ctx                 context.Context
	owner               *pgx.Conn
	o, w, e, run, actor string
	config              runtimeservices.Config
}
type approvalActivationTest74AdmissionConsumer func(approvalActivationTest74Admission)

// The original manual76->untouched74 takeover->signed complete planner remains
// the producer. The opt-in hook runs after its full native capture/accounting
// assertions and keeps the old human/effect fixture paths unchanged.
func TestApprovalActivationNativeTest74DeliveryFlow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	consumed := false
	runApprovalOriginTest74PlanningFixtureWithAdmission(t, "approval-activation", func(c approvalActivationTest74Admission) {
		runtime := newApprovalActivationFamilyRuntime(t, c.ctx, c.owner, c.o, c.w, c.e, c.actor, owned, c.config)
		runtime.AssertCapture(c.run, "test74", "captured_inactive")
		runtime.Activate()
		runtime.AssertCapture(c.run, "test74", "active")
		runtime.DeliverWithRevocation(c.run, "test74")
		consumed = true
	})
	if !t.Failed() && !consumed {
		t.Fatal("genuine74 native admission consumer was not reached")
	}
}

func TestApprovalActivationNativeOrderedPlanningDeliveryFlow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	runWorkerOrdered68PlanningFixture(t, "lifecycle", func(t *testing.T, ctx context.Context, owner, executor, api *pgx.Conn, identity json.RawMessage) {
		var ref struct {
			Organization string `json:"organization_id"`
			Workspace    string `json:"workspace_id"`
			Environment  string `json:"environment_id"`
			Run          string `json:"run_id"`
		}
		if json.Unmarshal(identity, &ref) != nil || ref.Run == "" {
			t.Fatal("actual ordered admission identity unavailable")
		}
		var actor string
		if err := owner.QueryRow(ctx, `SELECT requested_by FROM public.zasp_security_agent_runs WHERE run_id=$1`, ref.Run).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		// Original pricing fixture configuration; native admission/task authorities
		// are still derived by the unchanged public writer and worker Prepare call.
		if _, err := owner.Exec(ctx, `UPDATE public.zasp_identity_memberships SET role='organization_admin' WHERE organization_id=$1 AND principal_id=$2;UPDATE public.zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE organization_id=$1 AND principal_id=$2`, pgx.QueryExecModeSimpleProtocol, ref.Organization, actor); err != nil {
			t.Fatal(err)
		}
		runtime := newApprovalActivationFamilyRuntime(t, ctx, owner, ref.Organization, ref.Workspace, ref.Environment, actor, owned, runtimeservices.Config{})
		if _, err := owner.Exec(ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned ordered approval delivery','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, ref.Organization, ref.Workspace, ref.Environment, productID(98003)); err != nil {
			t.Fatal(err)
		}
		adminCfg := owner.Config().Copy()
		adminCfg.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, adminCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		policy := orderedPricingAdminRequest(ref.Organization, ref.Workspace, ref.Environment, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal("original ordered pricing refused", err)
		}
		selection := orderedPricingLookupRequest(ref.Organization, ref.Workspace, ref.Environment, policy["policy"].(map[string]any), pricing)
		delete(selection, "body")
		delete(selection, "body_digest")
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.WorkerForward), key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
		forward, err := authorization.NewApprovalOriginWorkerExecutor(ctx, runtime.poolFor(executor.Config().User), runtime.checker, runtime.pins.StoreID, runtime.pins.ModelID, key, migrations.ApprovalMaintenanceProfileChecksum())
		if err != nil {
			t.Fatal(err)
		}
		approvalActivationPlanOrdered(t, ctx, owner, forward, identity, selection, runtime.Reconcile)
		runtime.AssertCapture(ref.Run, "ordered68", "captured_inactive")
		runtime.Activate()
		runtime.AssertCapture(ref.Run, "ordered68", "active")
		runtime.Deliver(ref.Run, "ordered68")
		// A second real public trigger is admitted in the SAME activated organization.
		// Neither its task nor its notification/delegation is inserted by this test.
		nextFinding := productID(98004)
		if _, err := owner.Exec(ctx, `INSERT INTO public.zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Fresh ordered approval trigger','high','open')`, ref.Organization, ref.Workspace, ref.Environment, nextFinding); err != nil {
			t.Fatal(err)
		}
		q := public62Request(ref.Organization, ref.Workspace, ref.Environment, actor, "trigger_resource")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, nextFinding, 1, "approval-activated-ordered-future"
		q["trigger_kind"], q["trigger_source"] = "finding", "credential"
		admitted, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal("fresh real ordered admission refused", err)
		}
		next, ok := admitted["id"].(string)
		if !ok || !validProductID(next) || next == ref.Run {
			t.Fatal("fresh original ordered admission identity invalid")
		}
		var fresh json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.run_id,'definition_version',r.definition_version,'input_digest',c.input_digest) FROM public.zasp_security_agent_runs r JOIN zasp_temporal65.commands c USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND c.kind='start' AND c.execution_owner='temporal'`, next).Scan(&fresh); err != nil {
			t.Fatal(err)
		}
		forward, err = authorization.NewActivatedCurrentMaintenanceWorkerExecutor(ctx, runtime.poolFor(executor.Config().User), runtime.checker, runtime.pins.StoreID, runtime.pins.ModelID, key, runtime.approvalPin, runtime.connectorPin, runtime.activationPin)
		if err != nil {
			t.Fatal(err)
		}
		approvalActivationPlanOrdered(t, ctx, owner, forward, fresh, selection, runtime.Reconcile)
		runtime.Reconcile()
		runtime.AssertCapture(next, "ordered68", "active")
		runtime.DeliverWithRevocation(next, "ordered68")
	})
}

// The same original signed planning operation set used by the production
// ordered executor; controlled provider output is input, never authority.
func approvalActivationPlanOrdered(t *testing.T, ctx context.Context, owner *pgx.Conn, forward *authorization.WorkerExecutor, ref json.RawMessage, selection any, reconcile func()) {
	t.Helper()
	if err := forward.PrepareOrdered68(ctx, ref); err != nil {
		t.Fatal("original ordered task derivation refused", err)
	}
	reconcile()
	var identity map[string]any
	if json.Unmarshal(ref, &identity) != nil {
		t.Fatal("original ordered reference invalid")
	}
	delete(identity, "input_digest")
	call := func(op string, payload any) map[string]any {
		t.Helper()
		q := map[string]any{}
		for k, v := range identity {
			q[k] = v
		}
		q["operation"] = op
		if op != "load" {
			q["payload"] = payload
		}
		raw, _ := json.Marshal(q)
		decision, err := forward.Authorize(ctx, authorization.WorkerOperation("ordered68.planning."+op), raw)
		if err != nil {
			t.Fatal("original ordered signed authorization refused", op, err)
		}
		result, err := forward.Execute(ctx, decision)
		if err != nil {
			t.Fatal("original ordered signed execution refused", op, err)
		}
		var body map[string]any
		if json.Unmarshal(result, &body) != nil {
			t.Fatal("ordered native result invalid")
		}
		return body
	}
	if result := call("load", nil); result["state"] != "loaded" {
		t.Fatal("ordered original context unavailable")
	}
	reconcile()
	if result := call("prepare", map[string]any{"pricing": selection, "input_version": "approval-ordered-input-v1"}); result["state"] != "prepared" {
		t.Fatal("ordered original planner not prepared")
	}
	if result := call("start", map[string]any{}); result["send_permit"] != true {
		t.Fatal("ordered original provider permit refused")
	}
	var test string
	if err := owner.QueryRow(ctx, `SELECT test_id FROM zasp_authorization80_worker.ordered_associations WHERE run_id=$1`, identity["run_id"]).Scan(&test); err != nil {
		t.Fatal(err)
	}
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": identity["environment_id"]}, map[string]any{"index": 1, "action": "run_test", "target_id": test}}})
	provider, _ := json.Marshal(map[string]any{"id": "approval-ordered-controlled", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
	call("result", map[string]any{"raw": string(provider)})
	settled := call("settle", map[string]any{})
	call("artifacts", map[string]any{"input_version": "approval-ordered-input-v1", "output_version": "approval-ordered-output-v1", "output_digest": settled["output_digest"]})
	if receipt := call("admit", map[string]any{}); receipt["outcome"] != "admitted" {
		t.Fatal("genuine ordered planning admission refused")
	}
}
