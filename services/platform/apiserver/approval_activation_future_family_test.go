package apiserver

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// This explicit test seam switches only the executor used by the genuine final
// signed admission. It cannot supply a capture, delegation or notification.
type approvalActivationTest74BeforeAdmit func(approvalActivationTest74Admission) *authorization.WorkerExecutor

func approvalActivationTest74HooksValid(mode string, consumer, before, seam bool, afterCount int) bool {
	if before {
		return mode == "approval-activation-future" && consumer && !seam && afterCount == 0
	}
	if mode == "approval-activation-future" {
		return false
	}
	if consumer {
		return mode == "approval-activation" && !seam && afterCount == 0
	}
	return true
}
func approvalActivationCaptureStateValid(state string) bool {
	return state == "captured_inactive" || state == "active"
}

func TestApprovalActivationFutureFixtureSeamsAreClosed(t *testing.T) {
	for _, mode := range []string{"", "effect", "approval-activation", "runtime-retained", "recovery-driver"} {
		if approvalActivationTest74HooksValid(mode, true, true, false, 0) {
			t.Fatal("pre-admit hook entered an existing fixture mode")
		}
	}
	for _, c := range []struct {
		consumer, before, seam bool
		after                  int
	}{{false, true, false, 0}, {true, false, false, 0}, {true, true, true, 0}, {true, true, false, 1}} {
		if approvalActivationTest74HooksValid("approval-activation-future", c.consumer, c.before, c.seam, c.after) {
			t.Fatal("partial or overlapping future fixture seam accepted")
		}
	}
	if !approvalActivationTest74HooksValid("approval-activation-future", true, true, false, 0) || !approvalActivationTest74HooksValid("approval-activation", true, false, false, 0) || !approvalActivationTest74HooksValid("effect", false, false, false, 0) {
		t.Fatal("explicit future or original fixture path refused")
	}
	for _, s := range []string{"", "pending", "paused_denied", "any"} {
		if approvalActivationCaptureStateValid(s) {
			t.Fatal("unknown capture expectation accepted")
		}
	}
	if !approvalActivationCaptureStateValid("active") || !approvalActivationCaptureStateValid("captured_inactive") {
		t.Fatal("closed capture expectation refused")
	}
}

// The public manual76 admission, untouched74 takeover and complete signed
// planning all happen in the original producer. Actual organization activation
// precedes only its final signed admit, which must create a NEW active origin.
func TestApprovalActivationNativeFutureTest74DeliveryFlow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	var runtime *approvalActivationFamilyRuntime
	consumed := false
	before := func(c approvalActivationTest74Admission) *authorization.WorkerExecutor {
		if runtime != nil {
			t.Fatal("future74 activation hook repeated")
		}
		runtime = newApprovalActivationFamilyRuntime(t, c.ctx, c.owner, c.o, c.w, c.e, c.actor, owned, c.config)
		runtime.Activate()
		assertApprovalActivationNoPriorFamilyEnqueue(t, c)
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		if err != nil {
			t.Fatal("original74 forward verifier unavailable")
		}
		forward, err := authorization.NewActivatedCurrentMaintenanceWorkerExecutor(c.ctx, runtime.poolFor("worker_test_executor"), runtime.checker, runtime.pins.StoreID, runtime.pins.ModelID, key, runtime.approvalPin, runtime.connectorPin, runtime.activationPin)
		if err != nil {
			t.Fatal("activated74 signed admission executor refused", err)
		}
		return forward
	}
	consume := func(c approvalActivationTest74Admission) {
		if runtime == nil {
			t.Fatal("future74 enqueue preceded measured activation")
		}
		runtime.AssertCapture(c.run, "test74", "active")
		runtime.Reconcile()
		runtime.DeliverWithRevocation(c.run, "test74")
		consumed = true
	}
	runApprovalOriginTest74PlanningFixtureWithAdmissionHooks(t, "approval-activation-future", consume, before)
	if !t.Failed() && !consumed {
		t.Fatal("future native74 admission did not reach delivery")
	}
}

// The original applied Block is retained. Its late Test approval is created
// only AFTER measured organization activation, using the activated progress
// executor and the real original human approval/replay assertions.
func TestApprovalActivationNativeFutureOrderedProgressDeliveryFlow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	consumed := false
	runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{phase: "application-complete", connectedConsumer: true, application: func(c ordered68TestFlowContext) {
		var ids struct {
			Organization string `json:"organization_id"`
			Workspace    string `json:"workspace_id"`
			Environment  string `json:"environment_id"`
			Run          string `json:"run_id"`
		}
		if json.Unmarshal(c.identity, &ids) != nil || ids.Run == "" {
			t.Fatal("actual future ordered progress identity unavailable")
		}
		var grantor string
		if err := c.owner.QueryRow(c.ctx, `SELECT grantor_id FROM zasp_authorization80_worker.ordered_associations WHERE(organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, ids.Organization, ids.Workspace, ids.Environment, ids.Run).Scan(&grantor); err != nil {
			t.Fatal("actual future progress grantor unavailable", err)
		}
		runtime := newApprovalActivationFamilyRuntime(t, c.ctx, c.owner, ids.Organization, ids.Workspace, ids.Environment, grantor, owned, c.config)
		if _, err := c.owner.Exec(c.ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned future progress approval delivery','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, ids.Organization, ids.Workspace, ids.Environment, productID(98002)); err != nil {
			t.Fatal("original future notification configuration refused", err)
		}
		runtime.Activate()
		assertApprovalActivationNoPriorFamilyEnqueue(t, approvalActivationTest74Admission{ctx: c.ctx, owner: c.owner, o: ids.Organization, w: ids.Workspace, e: ids.Environment, run: ids.Run})
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
		if err != nil {
			t.Fatal("original ordered forward verifier unavailable")
		}
		c.forward, err = authorization.NewActivatedCurrentMaintenanceWorkerExecutor(c.ctx, runtime.poolFor(c.forwardLogin), runtime.checker, runtime.pins.StoreID, runtime.pins.ModelID, key, runtime.approvalPin, runtime.connectorPin, runtime.activationPin)
		if err != nil {
			t.Fatal("activated signed progress executor refused", err)
		}
		c.checker = runtime.checker
		c.reconcile = runtime.Reconcile
		approved := assertApprovalOriginOrdered68TestApprovalWithState(c, "active")
		if approved.run != ids.Run {
			t.Fatal("future progress captured another native run")
		}
		runtime.AssertCapture(ids.Run, "ordered68_progress", "active")
		runtime.Reconcile()
		runtime.DeliverWithRevocation(ids.Run, "ordered68_progress")
		consumed = true
	}})
	if !t.Failed() && !consumed {
		t.Fatal("future signed progress did not reach delivery")
	}
}

func assertApprovalActivationNoPriorFamilyEnqueue(t *testing.T, c approvalActivationTest74Admission) {
	t.Helper()
	var absent bool
	if err := c.owner.QueryRow(c.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations a JOIN zasp_authorization79.organizations v USING(organization_id,store_id,model_id) WHERE a.organization_id=$1 AND v.desired=v.applied) AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins WHERE(organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approval_notifications WHERE(organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4))`, c.o, c.w, c.e, c.run).Scan(&absent); err != nil || !absent {
		t.Fatal("future family notification already existed or activation was not acknowledged", err)
	}
}
