package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"testing"
	"time"
)

// DRAFT only. Real Block application prefix, signed progress, human approval,
// exact no-send/replay assertions retained; no grant/task/approval is seeded.
func TestApprovalMaintenanceGenuineLateProgressEnqueueInactive(t *testing.T) {
	consumed := false
	runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{
		phase: "application-complete", application: func(c ordered68TestFlowContext) {
			runner := workerMigrationRunner(t, c.owner)
			if err := runner.UpProductionApprovalMaintenanceProfile(c.ctx); err != nil {
				t.Fatal("actual supplementary origin module", err)
			}
			var ids struct {
				Organization string `json:"organization_id"`
				Workspace    string `json:"workspace_id"`
				Environment  string `json:"environment_id"`
			}
			if json.Unmarshal(c.identity, &ids) != nil || ids.Organization == "" {
				t.Fatal("actual ordered scope refused")
			}
			if _, err := c.owner.Exec(c.ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned approval fixture','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, ids.Organization, ids.Workspace, ids.Environment, productID(98002)); err != nil {
				t.Fatal("original unversioned notification destination", err)
			}
			cfg, err := pgxpool.ParseConfig(c.owner.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			cfg.ConnConfig.User = c.forwardLogin
			cfg.MaxConns = 2
			pool, err := pgxpool.NewWithConfig(c.ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			// Existing source assertOrdered68SignedPolicyFlow creates/registers this
			// exact WorkerForward key before actual Block execution. Reuse it; no new
			// native verifier or invented authority is registered in this consumer.
			key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
			if err != nil {
				t.Fatal(err)
			}
			c.forward, err = authorization.NewApprovalOriginWorkerExecutor(c.ctx, pool, c.checker, c.storeID, c.modelID, key, migrations.ApprovalMaintenanceProfileChecksum())
			if err != nil {
				t.Fatal(err)
			}
			assertApprovalOriginOrdered68TestApproval(c)
			consumed = true
		}})
	if !t.Failed() && !consumed {
		t.Fatal("actual applied Block did not reach native origin progress")
	}
}

func assertApprovalOriginOrdered68TestApproval(c ordered68TestFlowContext) ordered68ApprovedTestContext {
	t, ctx := c.t, c.ctx
	t.Helper()
	var identity struct {
		Organization string `json:"organization_id"`
		Workspace    string `json:"workspace_id"`
		Environment  string `json:"environment_id"`
		Run          string `json:"run_id"`
		Version      int64  `json:"definition_version"`
	}
	if json.Unmarshal(c.identity, &identity) != nil || identity.Run == "" || identity.Version < 1 {
		t.Fatal("invalid actual ordered identity")
	}
	ids := make([]domain.ProductID, 3)
	for index, value := range []string{identity.Organization, identity.Workspace, identity.Environment} {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = id
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	step, err := CanonicalDiscoveryID(scope, "security_agent_step", identity.Run+"\x1f1")
	if err != nil {
		t.Fatal(err)
	}
	var version int64
	var sourceStep string
	if err := c.owner.QueryRow(ctx, `SELECT r.version,p.plan->'steps'->1->>'step_id' FROM zasp_security_agent_runs r JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$3,$4)`, identity.Organization, identity.Workspace, identity.Environment, identity.Run).Scan(&version, &sourceStep); err != nil || sourceStep != step {
		t.Fatal("actual Test successor identity", err)
	}
	request, err := json.Marshal(map[string]any{"organization_id": identity.Organization, "workspace_id": identity.Workspace, "environment_id": identity.Environment, "run_id": identity.Run, "step_id": step, "operation": "progress", "actor_id": "temporal-executor", "run_version": version, "approval_version": 1, "fresh_auth_at": time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func() json.RawMessage {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		began := time.Now()
		decision, err := c.forward.Authorize(bounded, "ordered68.progress", request)
		authorized := time.Now()
		if err != nil {
			t.Fatal("Test progress authorize", err)
		}
		result, err := c.forward.Execute(bounded, decision)
		t.Log("ordered Test progress", "authorize_ms", authorized.Sub(began).Milliseconds(), "execute_ms", time.Since(authorized).Milliseconds(), "class", ordered62TraceClass(err))
		if err != nil {
			t.Fatal("Test progress execute", err)
		}
		return result
	}
	evidence := func() []byte {
		t.Helper()
		var result []byte
		if err := c.owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY step_index) FROM zasp_security_agent_steps s WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY approval_id) FROM zasp_security_agent_approvals a WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id,generation) FROM zasp_temporal68.effects f WHERE run_id=$1))`, identity.Run).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	c.reconcile()
	first := invoke()
	var response struct {
		Outcome string `json:"outcome"`
		State   string `json:"run_state"`
	}
	if json.Unmarshal(first, &response) != nil || response.Outcome != "ready" || response.State != "waiting_approval" {
		t.Fatal("applied Block did not produce pending Test approval")
	}
	var nativeCapture bool
	if err := c.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(o.status='captured_inactive' AND o.family='ordered68_progress' AND o.delegation->>'purpose'='approval_notification_delivery' AND public.zasp_valid_product_id(o.delegation->>'task_id') AND o.delegation->>'grantor_id'=o.facts->>'grantor_id' AND o.delegation->>'principal_id'=o.facts->>'principal_id' AND o.payload_digest=n.payload_digest AND o.destination_url=n.destination_url AND o.secret_reference=n.secret_reference AND n.attempt=0 AND n.state='pending' AND jsonb_array_length(o.facts->'checks')=2) FROM zasp_approval_maintenance.origins o JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE o.run_id=$1 AND n.approval_id IN(SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND step_id=$2)`, identity.Run, step).Scan(&nativeCapture); err != nil || !nativeCapture {
		t.Fatal("genuine signed late progress failed inactive notification capture", err)
	}
	var projected bool
	if err := c.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_approval_maintenance.delivery_grants WHERE organization_id=$1)`, identity.Organization).Scan(&projected); err != nil || projected {
		t.Fatal("inactive late progress issued delivery authority", err)
	}
	before := evidence()
	c.reconcile()
	if replay := invoke(); !bytes.Equal(first, replay) || !bytes.Equal(before, evidence()) {
		t.Fatal("waiting-approval progress replay changed native evidence")
	}
	var approval string
	var approvalVersion int64
	var pending bool
	if err := c.owner.QueryRow(ctx, `SELECT a.approval_id,a.version,a.state='pending' AND s.state='waiting_approval'
 AND (SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$4 AND step_id=$5)=1
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$4 AND step_id=$5)
 FROM zasp_security_agent_approvals a JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id)=($1,$2,$3,$4,$5)`, identity.Organization, identity.Workspace, identity.Environment, identity.Run, step).Scan(&approval, &approvalVersion, &pending); err != nil || !pending || approvalVersion != 1 {
		t.Fatal("progress bypassed Test approval or created send intent", err)
	}
	approved := c.approve(approval, approvalVersion)
	if approved.Code != http.StatusOK {
		t.Fatal("actual checked Test approval status", approved.Code)
	}
	var authorized bool
	if err := c.owner.QueryRow(ctx, `SELECT a.state='approved' AND a.version=2 AND s.state='authorized'
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$1 AND step_id=$2)
 FROM zasp_security_agent_approvals a JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 WHERE a.run_id=$1 AND a.step_id=$2`, identity.Run, step).Scan(&authorized); err != nil || !authorized {
		t.Fatal("checked approval did not authorize the real Test successor", err)
	}
	c.reconcile()
	return ordered68ApprovedTestContext{ordered68TestFlowContext: c, scope: scope, run: identity.Run, step: step, definitionVersion: identity.Version}
}
