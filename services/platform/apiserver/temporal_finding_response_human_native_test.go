package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Catches human admission losing its initiating actor/receipt while passing
// through the real finding planner, distinct approval and atomic effect.
func TestTemporalFindingResponseHumanNativePostgres(t *testing.T) {
	// Compile once before owning a database/native runtime. Other lanes may
	// keep editing disjoint Go packages while this fixed executable runs.
	worker := filepath.Join(t.TempDir(), "finding-human-worker.test")
	paths := []string{
		"agentsec-worker/temporal_finding_response_live_test.go",
		"agentsec-worker/production_runtime.go",
		"agentsec-worker/security_agent_temporal_runtime.go",
		"orchestration/finding_response_workflow.go",
		"orchestration/finding_response_start.go",
	}
	before := map[string][32]byte{}
	for _, path := range paths {
		body, err := os.ReadFile(filepath.Join("..", path))
		if err != nil {
			t.Fatal(err)
		}
		before[path] = sha256.Sum256(body)
	}
	build := exec.Command("go", "test", "-c", "./agentsec-worker", "-o", worker)
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Log(string(output))
		t.Fatal("prebuild owned human worker", err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(filepath.Join("..", path))
		if err != nil || sha256.Sum256(body) != before[path] {
			t.Fatal("worker source changed during prebuild", path)
		}
		t.Logf("prebuilt source path=%s sha256=%x", path, before[path])
	}
	compiled, err := os.ReadFile(worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owned worker executable sha256=%x", sha256.Sum256(compiled))
	runFindingResponseNativeOrigin(t, "approved", true, worker)
}

func findingNativeDistinctApprover(t *testing.T, ctx context.Context, f findingResponseFixture) RequestIdentity {
	t.Helper()
	approver := f.next()
	if _, err := f.owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) SELECT $2,organization_id,organization_reference,$2,role,true FROM zasp_identity_memberships WHERE principal_id=$1 AND organization_id=$3;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) SELECT $2,organization_id,workspace_id,environment_id,label,'["view","manage_workflows"]'::jsonb,false FROM zasp_authorized_scopes WHERE principal_id=$1 AND organization_id=$3 AND workspace_id=$4 AND environment_id=$5`, pgx.QueryExecModeSimpleProtocol, f.actor, approver, f.o, f.w, f.e); err != nil {
		t.Fatal("distinct current approver prerequisite", err)
	}
	_, identity := orderedResourceGo(t, f.api, f.o, f.w, f.e, approver)
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(3 * time.Minute)
	return identity
}

func findingNativeHumanAdmission(t *testing.T, ctx context.Context, f findingResponseFixture, finding string) string {
	t.Helper()
	call := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"environment_id": f.e, "trigger_kind": "finding", "trigger_id": finding, "trigger_version": 2, "trigger_source": "credential"})
		req := workflowRequest(t, f.identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": f.definition}, http.MethodPost, "/api/v1/security-agents/"+f.definition+"/runs", string(body))
		req.Header.Set("If-Match", `"3"`)
		req.Header.Set("Idempotency-Key", "finding78-native-human")
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, req)
		return response
	}
	first, replay := call(), call()
	var run SecurityAgentRun
	if first.Code != http.StatusAccepted || replay.Code != http.StatusAccepted || json.Unmarshal(first.Body.Bytes(), &run) != nil || run.State != "queued" || run.AgentID != f.definition || run.DefinitionVersion != 3 {
		t.Fatal("mounted human admission/replay", first.Code, replay.Code)
	}
	assertAutomaticRuleJSON(t, "exact human native admission replay", first.Body.Bytes(), replay.Body.Bytes())
	var exact bool
	if err := f.owner.QueryRow(ctx, `SELECT x.source_kind='human78' AND x.trigger_id=$2 AND x.trigger_version=2 AND r.requested_by=$3 AND r.requested_by<>zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_definition_service',x.definition_id)
 AND c.execution_owner='legacy' AND c.definition_version=x.definition_version AND c.input_digest=x.input_digest
 AND m.kind='start' AND m.execution_owner='legacy' AND m.definition_version=x.definition_version AND m.input_digest=x.input_digest
 AND p.operation='runSecurityAgent' AND p.principal_id=$3 AND p.idempotency_key='finding78-native-human' AND p.resource_id=x.definition_id AND p.expected_version=x.definition_version AND p.response->>'id'=x.run_id
 AND p.intent_digest=digest(convert_to(p.intent::text,'UTF8'),'sha256') AND p.intent->>'trigger_id'=x.trigger_id AND p.intent->'trigger_version'='2'::jsonb
 AND a.actor_id=$3 AND a.run_id=x.run_id AND a.event_kind='run_queued' AND encode(a.event_digest,'hex')=x.input_digest
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences WHERE run_id=x.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE run_id=x.run_id)
 AND (SELECT count(*)=1 FROM zasp_security_agent_request_receipts WHERE principal_id=$3 AND operation='runSecurityAgent' AND idempotency_key='finding78-native-human')
 FROM zasp_temporal78.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_temporal66.run_owners c USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal65.commands m USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_request_receipts p ON(p.organization_id,p.workspace_id,p.environment_id,p.receipt_id)=(m.organization_id,m.workspace_id,m.environment_id,m.event_id)
 JOIN zasp_security_agent_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=(p.organization_id,p.workspace_id,p.environment_id,p.audit_id)
 WHERE x.run_id=$1`, run.ID, finding, f.actor).Scan(&exact); err != nil || !exact {
		t.Fatal("human native request/actor/command provenance", exact, err)
	}
	return run.ID
}

func assertFindingNativeHumanProof(t *testing.T, ctx context.Context, f findingResponseFixture, run, finding, approver string) {
	t.Helper()
	if approver == f.actor {
		t.Fatal("human native approver equals requester")
	}
	var exact bool
	if err := f.owner.QueryRow(ctx, `SELECT x.source_kind='human78' AND r.requested_by=$3 AND r.state='remediated' AND x.trigger_id=$2 AND x.trigger_version=2
 AND rf.status='under_review' AND rf.version=3 AND m.expected_version=2 AND m.result_version=3 AND m.assignee_id=$3 AND m.response_status='investigating' AND m.note='Investigate the credential exposure'
 AND (SELECT count(*)=1 FROM zasp_security_agent_effects WHERE run_id=$1)
 AND EXISTS(SELECT 1 FROM zasp_security_agent_approvals ap WHERE ap.run_id=$1 AND ap.requester_id=$3 AND ap.approver_id=$4 AND ap.state='approved' AND ap.fresh_auth_at IS NOT NULL AND ap.plan_hash=r.plan_hash)
 AND EXISTS(SELECT 1 FROM zasp_temporal78.control_intents ci JOIN zasp_temporal78.control_deliveries cd USING(organization_id,workspace_id,environment_id,control_id) WHERE ci.run_id=$1 AND ci.actor_id=$4 AND ci.operation='decideSecurityAgentApproval' AND cd.accepted_at IS NOT NULL)
 AND (SELECT count(*)=1 FROM zasp_temporal78.control_intents WHERE run_id=$1)
 AND EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations p JOIN zasp_temporal78.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)
 WHERE p.run_id=$1 AND p.settled_at IS NOT NULL AND p.released_at IS NULL AND p.prompt_tokens=20 AND p.completion_tokens=10 AND p.total_tokens=30
 AND p.total_tokens<=b.max_tokens AND p.cost_nano_credits<=b.max_cost_nano_credits AND p.cost_nano_credits=(j.result_value->'usage'->>'cost_nano_credits')::bigint
 AND j.state='admitted' AND j.input_version IS NOT NULL AND j.output_version IS NOT NULL AND j.reservation_id=p.reservation_id
 AND p.output_digest=decode(substr(j.provider_digest,8),'hex'))
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_security_agent_runs WHERE definition_id=$5 AND trigger_id=$2)
 FROM zasp_temporal78.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_temporal78.response_metadata m USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_risk_findings rf ON(rf.organization_id,rf.workspace_id,rf.environment_id,rf.id)=(x.organization_id,x.workspace_id,x.environment_id,x.trigger_id)
 WHERE x.run_id=$1`, run, finding, f.actor, approver, f.definition).Scan(&exact); err != nil || !exact {
		t.Fatal("human native atomic effect/approval/usage proof", exact, err)
	}
	t.Log("human78: exact mounted admission replay, distinct approver, one settled planner reservation/effect, public metadata; no automatic occurrence or test owner")
}
