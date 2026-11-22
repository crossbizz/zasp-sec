package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The V24 worker already has independent signed-bundle tests. This fixture
// supplies its verified source rows and exercises target registration, expiry,
// overlapping releases and data-plane readback on the installed database.
func installedWorkloadContainment(t *testing.T, b *installedBaseline, h *workloadActionHandler, admin, first installedPrincipal, bound workloadBinding, issue func(string, string) installedPrincipal) {
	t.Helper()
	other := issue("Neighbour workload", `["decide_actions"]`)
	target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		h.containment(w, r, op)
	})
	data := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		h.serve(w, r, op)
	})
	type source struct{ run, step, device, approval string }
	mkSource := func(session string) source {
		s := source{b.id(), b.id(), b.id(), b.id()}
		b.seed(func() {
			b.exec(`INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
VALUES($1,$2,$3,$4,$5,1,digest($4,'sha256'),'security-agent-actions-v1',jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('action','isolate_session','step_id',$6::text,'session_id',$7::text,'device_id',$8::text,'scope',$3::text))),digest($4,'sha256'),now()+interval '1 hour')`, b.o, b.w, b.e, s.run, b.id(), s.step, session, s.device)
			b.exec(`INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,approver_id,fresh_auth_at,expires_at,decided_at)
VALUES($1,$2,$3,$4,$5,$6,digest($5,'sha256'),'approved',$7,$8,now(),now()+interval '1 hour',now())`, b.o, b.w, b.e, s.approval, s.run, s.step, b.id(), b.id())
			b.exec(`INSERT INTO zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,device_id,credential_id,action_key,phase,sequence,policy_version,state,key_id,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest,stored_at,verified_at)
VALUES($1,$2,$3,$4,$5,$6,$7,'isolate_session','apply',1,1,'verified','fixturekey',now(),now()+interval '5 minutes','closed',digest($4,'sha256'),'[]',decode(repeat('11',64),'hex'),digest($5,'sha256'),now(),now())`, b.o, b.w, b.e, s.run, s.step, s.device, b.id())
		})
		return s
	}
	control := func(s source, op, method string, body string) *httptest.ResponseRecorder {
		return b.serve(target, admin, op, method, "/api/v1/runtime/workload-bindings/"+bound.Credential+"/containments/"+s.run, map[string]string{"id": bound.Credential, "runId": s.run}, body, nil)
	}
	approve := func(s source) *httptest.ResponseRecorder {
		return control(s, "authorizeWorkloadContainment", http.MethodPut, `{"step_id":"`+s.step+`"}`)
	}
	check := func(s source, state, receipt string) {
		response := control(s, "getWorkloadContainment", http.MethodGet, "")
		var row struct {
			State   string  `json:"state"`
			Block   *string `json:"block_receipt_id"`
			Release *string `json:"release_receipt_id"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &row) != nil || row.State != state || receipt == "block" && row.Block == nil || receipt == "released" && row.Release == nil {
			t.Fatalf("state %s, want %s/%s: %d %s", s.run, state, receipt, response.Code, response.Body)
		}
	}
	dispatch := func(workload installedPrincipal, block bool) {
		action := b.id()
		response := b.serve(data, workload, "createWorkloadActionDecision", http.MethodPost, "/api/v1/runtime/action-decisions", nil, `{"schema_version":"action.v1","action_id":"`+action+`","action_kind":"tool_call","operation":"ticket.read","resource":{"kind":"ticket","classification":"internal"}}`, map[string]string{"Idempotency-Key": action})
		var receipt workloadReceipt
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &receipt) != nil || (receipt.Verdict == "block") != block || block && receipt.Reason != "supervised_session_isolation" {
			t.Fatalf("dispatch block=%v: %d %s", block, response.Code, response.Body)
		}
		status := "returned"
		if block {
			status = "not_dispatched"
		}
		out := `{"schema_version":"action-outcome.v1","action_id":"` + action + `","decision_id":"` + receipt.DecisionID + `","status":"` + status + `"}`
		response = b.serve(data, workload, "recordWorkloadActionOutcome", http.MethodPost, "/api/v1/runtime/actions/"+action+"/outcomes", map[string]string{"actionId": action}, out, map[string]string{"Idempotency-Key": action + "-outcome"})
		if response.Code != 200 {
			t.Fatalf("report %d %s", response.Code, response.Body)
		}
	}
	wrong := mkSource(b.id())
	if r := approve(wrong); r.Code != 404 {
		t.Fatalf("unrelated source admitted: %d %s", r.Code, r.Body)
	}
	one, two := mkSource(bound.Session), mkSource(bound.Session)
	dispatch(first, false)
	for _, s := range []source{one, two} {
		if r := approve(s); r.Code != 200 {
			t.Fatalf("approve %d %s", r.Code, r.Body)
		}
		check(s, "pending_readback", "")
	}
	dispatch(first, true)
	dispatch(other, false)
	check(one, "adapter_confirmed", "block")
	released := control(one, "releaseWorkloadContainment", http.MethodDelete, "")
	if released.Code != 200 || !strings.Contains(released.Body.String(), `"released"`) {
		t.Fatalf("release: %d %s", released.Code, released.Body)
	}
	dispatch(first, true)
	check(one, "released", "released")
	check(two, "adapter_confirmed", "block")
	// Move only the second recorded deadline in this disposable fixture.
	b.exec(`UPDATE zasp_workload_containments SET authorized_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE (organization_id,workspace_id,environment_id,credential_id,run_id)=($1,$2,$3,$4,$5)`, b.o, b.w, b.e, bound.Credential, two.run)
	dispatch(first, false)
	check(two, "expired", "released")
}
