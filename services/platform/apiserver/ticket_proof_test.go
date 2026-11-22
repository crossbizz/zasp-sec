package apiserver

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

func TestImportedTicketProofOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	var bundle redteam.TicketProofBundle
	for _, file := range []struct {
		name string
		dst  any
	}{{"scenario", &bundle.Scenario}, {"adapter", &bundle.Adapter}, {"recorder", &bundle.Recorder}} {
		raw, err := os.ReadFile("../cmd/verify-ticket/testdata/" + file.name + ".json")
		if err != nil || redteam.DecodeTicketExport(raw, file.dst) != nil {
			t.Fatal("invalid test export", file.name, err)
		}
	}
	run, target, def := b.id(), b.id(), b.id()
	now := time.Now().UTC().Truncate(time.Millisecond)
	start := now.Add(-2 * time.Minute)
	end := start.Add(time.Minute)
	bundle.Scenario.TicketRunBinding = redteam.TicketRunBinding{Scope: redteam.TicketScope{OrganizationID: b.o, WorkspaceID: b.w, EnvironmentID: b.e}, RunID: run, TargetID: target, Operation: "synthetic_ticket_update"}
	bundle.Scenario.WindowStart = start
	bundle.Scenario.WindowEnd = end
	bundle.Adapter.TicketRunBinding = bundle.Scenario.TicketRunBinding
	bundle.Recorder.TicketRunBinding = bundle.Scenario.TicketRunBinding
	bundle.Adapter.Decisions[0].DecidedAt = start.Add(time.Second)
	bundle.Recorder.Writes[0].RecordedAt = start.Add(2 * time.Second)
	bundle.Adapter.Decisions[1].DecidedAt = start.Add(3 * time.Second)
	bundle.Recorder.CompleteFrom = start
	bundle.Recorder.CompleteThrough = end
	b.seed(func() {
		b.exec(`INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Ticket verification',$5,'agent_endpoint','["tool_abuse"]','{"environment":"staging","credential_class":"test_write","expected_side_effects":["synthetic_ticket_update"]}',$6)`, b.o, b.w, b.e, def, target, admin.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest,queued_at) VALUES($1,$2,$3,$4,$5,1,$6,decode(repeat('ab',32),'hex'),$7)`, b.o, b.w, b.e, run, def, admin.identity.PrincipalID.String(), start.Add(-time.Minute))
	})
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	path := "/api/v1/test-runs/" + run + "/ticket-verification"
	params := map[string]string{"id": run}
	request := func(op, method, body string, want int) string {
		t.Helper()
		out := b.serve(surface, admin, op, method, path, params, body, nil)
		if out.Code != want {
			t.Fatalf("%s got %d, want %d: %s", op, out.Code, want, out.Body)
		}
		return out.Body.String()
	}
	data, _ := json.Marshal(bundle)
	request("getTicketVerification", "GET", "", 404)
	request("putTicketVerification", "PUT", string(data), 400)
	b.seed(func() {
		b.exec(`UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, b.o, b.w, b.e)
	})
	request("putTicketVerification", "PUT", strings.Replace(string(data), target, b.id(), 1), 400)
	receipt := request("putTicketVerification", http.MethodPut, string(data), 200)
	var result struct {
		Source string                     `json:"evidence_source"`
		Result redteam.TicketVerification `json:"result"`
	}
	if json.Unmarshal([]byte(receipt), &result) != nil || result.Source != "operator_import" || result.Result.Verdict != "passed" || result.Result.RunID != run {
		t.Fatal(receipt)
	}
	if request("getTicketVerification", "GET", "", 200) != receipt || request("putTicketVerification", "PUT", string(data), 200) != receipt {
		t.Fatal("receipt changed")
	}
	bundle.Recorder.Healthy = false
	other, _ := json.Marshal(bundle)
	request("putTicketVerification", "PUT", string(other), 409)
	if state := b.text(`SELECT state FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, b.o, b.w, b.e, run); state != "queued" {
		t.Fatalf("import changed original run %s", state)
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getTicketVerification", PathParameters: params}, ticketProofGetSQL, b.o, b.w, b.id(), run); installedSQLState(err) != "42501" {
		t.Fatalf("unfenced ticket proof %v", err)
	}
}
