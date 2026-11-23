package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
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
	// Use an independently pinned source per role on a second queued run.
	// Existing immutable operator imports retain their original classification.
	if !strings.Contains(receipt, `"evidence_qualification":"tested_control"`) {
		t.Fatal(receipt)
	}
	bundle.Recorder.Healthy = true
	run = b.id()
	bundle.Scenario.RunID, bundle.Adapter.RunID, bundle.Recorder.RunID = run, run, run
	b.seed(func() {
		b.exec(`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest,queued_at) VALUES($1,$2,$3,$4,$5,1,$6,decode(repeat('bc',32),'hex'),$7)`, b.o, b.w, b.e, run, def, admin.identity.PrincipalID.String(), start.Add(-time.Minute))
	})
	path = "/api/v1/test-runs/" + run + "/ticket-verification"
	params = map[string]string{"id": run}
	trustPath := installTestTicketAttestations(t, &bundle, end)
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", trustPath)
	data, _ = json.Marshal(bundle)
	signed := request("putTicketVerification", http.MethodPut, string(data), 200)
	if !strings.Contains(signed, `"evidence_qualification":"verified_prevention"`) || request("getTicketVerification", "GET", "", 200) != signed {
		t.Fatal(signed)
	}
	bundle.Attestations.Recorder = bundle.Attestations.Adapter
	data, _ = json.Marshal(bundle)
	request("putTicketVerification", http.MethodPut, string(data), 400)
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", "")
	if missing := request("getTicketVerification", "GET", "", 200); !strings.Contains(missing, `"evidence_qualification":"unknown"`) {
		t.Fatal(missing)
	}
}

// installTestTicketAttestations is local staging test infrastructure. Both
// ephemeral private keys leave scope before the HTTP request is sent.
func installTestTicketAttestations(t *testing.T, bundle *redteam.TicketProofBundle, issued time.Time) string {
	t.Helper()
	s := bundle.Scenario
	trust := redteam.TicketTrust{}
	sign := func(role, id string, source any) redteam.TicketAttestation {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key := redteam.TicketVerificationKey{KeyID: role + "-fixture-key", AuthorityID: role + "-fixture-source", Role: role, Scope: s.Scope, TargetID: s.TargetID, SourceID: id, PublicKey: base64.StdEncoding.EncodeToString(pub), ValidFrom: s.WindowStart.Add(-time.Hour), ValidUntil: issued.Add(time.Hour)}
		trust.Keys = append(trust.Keys, key)
		a, err := redteam.SignTicketSource(s, role, key.KeyID, issued, source, private)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	bundle.Attestations = &redteam.TicketAttestations{Adapter: sign("adapter", s.AdapterID, bundle.Adapter), Recorder: sign("recorder", s.RecorderID, bundle.Recorder)}
	raw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted-public-keys.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
