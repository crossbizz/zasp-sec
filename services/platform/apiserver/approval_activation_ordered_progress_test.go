package apiserver

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This flow starts with the actual checked Block application, then creates the
// late Test approval through the original signed progress operation. The shared
// runtime measures local writer withdrawal, projects the real family union and
// verifies owned signed HTTPS delivery and canonical audit settlement. It does
// not establish a deployed provider, fleet withdrawal or a fresh future run.
func TestApprovalActivationNativeOrderedProgressDeliveryFlow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	consumed := false
	runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{
		phase: "application-complete", connectedConsumer: true, application: func(c ordered68TestFlowContext) {
			var identity struct {
				Organization string `json:"organization_id"`
				Workspace    string `json:"workspace_id"`
				Environment  string `json:"environment_id"`
				Run          string `json:"run_id"`
			}
			if json.Unmarshal(c.identity, &identity) != nil || identity.Run == "" {
				t.Fatal("actual ordered progress identity unavailable")
			}
			var grantor string
			if err := c.owner.QueryRow(c.ctx, `SELECT grantor_id FROM zasp_authorization80_worker.ordered_associations WHERE(organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, identity.Organization, identity.Workspace, identity.Environment, identity.Run).Scan(&grantor); err != nil {
				t.Fatal("actual signed ordered grantor unavailable", err)
			}
			runtime := newApprovalActivationFamilyRuntime(t, c.ctx, c.owner, identity.Organization, identity.Workspace, identity.Environment, grantor, owned, c.config)
			if _, err := c.owner.Exec(c.ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned late progress approval delivery','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, identity.Organization, identity.Workspace, identity.Environment, productID(98002)); err != nil {
				t.Fatal("original approval notification configuration refused", err)
			}
			// The original signed Block flow already registered this exact forward
			// verifier. Reuse that identity and its real restricted pool; do not register
			// another execution authority or fabricate a progress receipt.
			key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
			if err != nil {
				t.Fatal("original ordered forward key unavailable")
			}
			c.forward, err = authorization.NewApprovalOriginWorkerExecutor(c.ctx, runtime.poolFor(c.forwardLogin), runtime.checker, c.storeID, c.modelID, key, migrations.ApprovalMaintenanceProfileChecksum())
			if err != nil {
				t.Fatal("native approval-origin progress executor refused", err)
			}
			c.checker = runtime.checker
			c.reconcile = runtime.Reconcile
			approved := assertApprovalOriginOrdered68TestApproval(c)
			if approved.run != identity.Run {
				t.Fatal("progress captured another native run")
			}
			runtime.AssertCapture(identity.Run, "ordered68_progress", "captured_inactive")
			runtime.Activate()
			runtime.AssertCapture(identity.Run, "ordered68_progress", "active")
			runtime.DeliverWithRevocation(identity.Run, "ordered68_progress")
			consumed = true
		},
	})
	if !t.Failed() && !consumed {
		t.Fatal("actual applied Block did not reach activated progress delivery")
	}
}
