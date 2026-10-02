package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// The context is produced only after real checked Block approval, native
// reservation/start, signed delivery/readback and application receipt replay.
// It carries the existing authorities, not synthetic Test scope or effects.
type ordered68TestFlowContext struct {
	t                                     *testing.T
	ctx                                   context.Context
	owner                                 *pgx.Conn
	identity                              json.RawMessage
	forward, compensation                 *authorization.WorkerExecutor
	checker                               authorization.Checker
	storeID, modelID, forwardLogin, actor string
	config                                runtimeservices.Config
	reconcile                             func()
	approve                               func(string, int64) *httptest.ResponseRecorder
	policyKeys                            policy.GatewayPolicyKeys
	policySigner                          func(context.Context, policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error)
}

type ordered68ApprovedTestContext struct {
	ordered68TestFlowContext
	scope             domain.Scope
	run, step         string
	definitionVersion int64
}

// Requiring Test-send grants to create its approval, skipping human approval,
// or generating another approval on replay must break this real native flow.
func TestP7OrderedTestProgressApproval(t *testing.T) {
	consumed := false
	runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{
		phase: "application-complete", application: func(c ordered68TestFlowContext) {
			assertOrdered68TestApproval(c)
			consumed = true
		},
	})
	if !t.Failed() && !consumed {
		t.Fatal("actual applied Block did not reach Test progress")
	}
}

// This is the shared prefix for actual runner and reserved/started recovery
// consumers. It never inserts a Test scope, approval, child or effect itself.
func assertOrdered68TestApproval(c ordered68TestFlowContext) ordered68ApprovedTestContext {
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
