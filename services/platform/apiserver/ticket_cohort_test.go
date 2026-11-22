package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

func TestTicketCohortPlannerUsesConfirmedMembers(t *testing.T) {
	d := cohortDevice{ID: "a", State: "active", Adapter: "macos_claude_ticket", Generation: 2, ManagedGeneration: 2, ManagedMode: "monitor", PolicyRevision: 3, ManagedRevision: 3, Online: true, Acknowledged: true, Allowed: true, Outside: true, QueueClear: true}
	other := d
	other.ID = "b"
	v := cohortView{EnvironmentClass: "staging", Phase: "monitor", Destination: "internal", Assigned: 3, Members: []cohortDevice{other, {ID: "w", State: "active", Adapter: "windows_inventory"}, d}}
	picked, reason := cohortTargets(v, "canary", "internal")
	if reason != "ready" || len(picked) != 1 || picked[0].ID != "a" {
		t.Fatal(picked, reason)
	}
	v.Members[0].Allowed = false
	if _, reason = cohortTargets(v, "canary", "internal"); reason != "paired_device_evidence_required" {
		t.Fatal(reason)
	}
	v.Members[0].Allowed = true
	v.Members[2].ManagedMode = "enforce"
	v.Phase = "canary"
	v.proofStatus = "passed"
	if targets, reason := cohortTargets(v, "promote", "internal"); reason != "ready" || len(targets) != 1 || targets[0].ID != "b" {
		t.Fatal(targets, reason)
	}
	v.Members[2].Online = false
	v.Members[2].QueueClear = false
	if targets, reason := cohortTargets(v, "rollback", "internal"); reason != "ready" || len(targets) != 1 || targets[0].ID != "a" {
		t.Fatal(targets, reason)
	}
	v.Members[2].Generation++
	if _, reason = cohortTargets(v, "rollback", "internal"); reason != "managed_member_changed" {
		t.Fatal(reason)
	}
	v.EnvironmentClass = "production"
	if _, reason = cohortTargets(v, "monitor", "internal"); reason != "nonproduction_required" {
		t.Fatal(reason)
	}
}

func TestTicketCohortOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, _ := NewPostgresRepository(b.product)
	issue, _ := installedWorkloadTokenIssuer(t, b, repo, admin)
	issuer, signer, _ := ed25519.GenerateKey(rand.Reader)
	fleet := &endpointFleetHandler{database: b.product, clock: time.Now, newID: newWorkflowProductID}
	s := &discoveryWorkflowSurface{fleet: fleet, evidenceDB: b.product}
	type device struct {
		id      string
		token   installedPrincipal
		private ed25519.PrivateKey
		binding endpointprotocol.Binding
	}
	devices := map[string]device{}
	cohort := "paired"
	path := "/api/v1/device-cohorts/" + cohort + "/ticket-rollout"
	params := map[string]string{"cohort": cohort}
	call := func(person installedPrincipal, op, method, path string, ps map[string]string, body any, headers map[string]string, want int) json.RawMessage {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r := b.serve(s, person, op, method, path, ps, string(raw), headers)
		if r.Code != want {
			t.Fatalf("%s got %d want %d: %s", op, r.Code, want, r.Body.String())
		}
		return r.Body.Bytes()
	}
	deviceCall := func(d device, op, method, path string, body any, withID bool) json.RawMessage {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		headers := http.Header{}
		if err := endpointprotocol.Sign(headers, d.binding, op, raw, d.private, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for k := range headers {
			values[k] = headers.Get(k)
		}
		ps := map[string]string{}
		if withID {
			ps["id"] = d.id
		}
		return call(d.token, op, method, path, ps, body, values, 200)
	}
	for _, name := range []string{"one", "two", "windows"} {
		token := issue("Cohort "+name, `["sync_endpoint"]`)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		raw := call(admin, "registerEndpointDevice", "POST", "/api/v1/device-enrollments", nil, endpointRegister{Credential: token.binding.ID, DeviceKey: pub, PolicyKey: issuer, Cohort: cohort}, map[string]string{"Idempotency-Key": b.id()}, 200)
		var r struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &r) != nil || !validProductID(r.ID) {
			t.Fatal(string(raw))
		}
		d := device{r.ID, token, priv, endpointprotocol.Binding{Organization: b.o, Workspace: b.w, Environment: b.e, Device: r.ID, Generation: 1}}
		devices[d.id] = d
		deviceCall(d, "exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", struct{}{}, false)
		adapter := "macos_claude_ticket"
		if name == "windows" {
			adapter = "windows_inventory"
		}
		deviceCall(d, "recordEndpointHeartbeat", "POST", "/api/v1/devices/"+d.id+"/heartbeat", endpointprotocol.Heartbeat{Adapter: adapter, PolicyStatus: "policy_unavailable"}, true)
	}
	inspect := func(phase string) cohortView {
		t.Helper()
		raw := call(admin, "getTicketCohort", "GET", path+"?phase="+phase+"&allowed_destination=internal", params, nil, nil, 200)
		var v cohortView
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := inspect("monitor"); v.Plan != nil || v.Reason != "nonproduction_required" {
		t.Fatal(v)
	}
	b.seed(func() {
		b.exec(`UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, b.o, b.w, b.e)
	})
	signPlan := func(v cohortView) cohortUpload {
		t.Helper()
		if v.Plan == nil {
			t.Fatal("no signable plan", v)
		}
		out := cohortUpload{cohortHeader: v.Plan.cohortHeader}
		out.Schema = "ticket-cohort-bundle.v1"
		for _, item := range v.Plan.Items {
			raw, _ := json.Marshal(item.Policy)
			out.Items = append(out.Items, cohortEnvelope{item.Version, endpointprotocol.Signed{Payload: raw, Signature: ed25519.Sign(signer, raw)}})
		}
		return out
	}
	publish := func(q cohortUpload, key string, want int) json.RawMessage {
		t.Helper()
		return call(admin, "publishTicketCohort", "PUT", path, params, q, map[string]string{"Idempotency-Key": key}, want)
	}
	var verifiedActions []endpointprotocol.Observation
	observe := func(v cohortView) {
		verifiedActions = nil
		t.Helper()
		for _, item := range v.Plan.Items {
			p := item.Policy
			d := devices[p.Binding.Device]
			base := "/api/v1/devices/" + d.id
			raw := deviceCall(d, "fetchEndpointPolicy", "GET", base+"/policy-bundle", nil, true)
			var assigned struct {
				Bundle endpointprotocol.Signed `json:"bundle"`
			}
			_ = json.Unmarshal(raw, &assigned)
			signedPolicy, ok := assigned.Bundle.PolicyFor(issuer, d.binding, time.Now())
			if !ok || signedPolicy.Revision != p.Revision || signedPolicy.Mode != p.Mode {
				t.Fatal("assigned device policy mismatch")
			}
			deviceCall(d, "recordEndpointHeartbeat", "POST", base+"/heartbeat", endpointprotocol.Heartbeat{Adapter: "macos_claude_ticket", Revision: p.Revision, PolicyStatus: "verified_cache"}, true)
			var observations []endpointprotocol.Signed
			for _, outside := range []bool{false, true} {
				sum := sha256.Sum256([]byte(b.id()))
				actionID := hex.EncodeToString(sum[:])
				o := endpointprotocol.Observation{Audience: endpointprotocol.ReceiptAudience, Binding: d.binding, PeerUID: 502, Action: actionID, Session: actionID, ObservedAt: time.Now().UTC(), PolicyRevision: p.Revision, Mode: p.Mode, Tool: endpointprotocol.TicketTool, TargetClass: "allowed_destination", Verdict: "continue", Reason: "within_scope", SkillUsage: "unknown", TargetEffect: "unknown"}
				if outside {
					o.WouldBlock = true
					o.TargetClass = "outside_allowed_destination"
					o.Reason = "destination_not_approved"
					if p.Mode == "enforce" {
						o.Verdict = "deny"
					}
				}
				verifiedActions = append(verifiedActions, o)
				raw, _ := json.Marshal(o)
				observations = append(observations, endpointprotocol.Signed{Payload: raw, Signature: ed25519.Sign(d.private, raw)})
			}
			deviceCall(d, "recordEndpointObservations", "POST", "/api/v1/runtime/observations", map[string]any{"receipts": observations}, false)
		}
	}
	initial := inspect("monitor")
	if initial.Assigned != 3 || initial.Plan == nil || len(initial.Plan.Items) != 2 {
		t.Fatal(initial)
	}
	q := signPlan(initial)
	corrupt := signPlan(initial)
	corrupt.Items[1].Bundle.Signature[0] ^= 1
	publish(corrupt, b.id(), 409)
	if v := inspect("monitor"); v.Revision != 0 {
		t.Fatal("partial apply", v)
	}
	k := b.id()
	first := string(publish(q, k, 200))
	if replay := string(publish(q, k, 200)); replay != first {
		t.Fatal("changed receipt")
	}
	publish(q, b.id(), 409)
	if v := inspect("canary"); v.Reason != "paired_device_evidence_required" {
		t.Fatal(v)
	}
	observe(initial)
	canary := inspect("canary")
	if len(signPlan(canary).Items) != 1 {
		t.Fatal(canary)
	}
	publish(signPlan(canary), b.id(), 200)
	if v := inspect("promote"); v.Plan != nil {
		t.Fatal("ungated canary", v)
	}
	// Queue independent test runs before the canary's two staging actions.
	run1, run2, asset, definition := b.id(), b.id(), b.id(), b.id()
	b.seed(func() {
		b.exec(`INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Cohort readback',$5,'agent_endpoint','["tool_abuse"]','{"environment":"staging","credential_class":"test_write","expected_side_effects":["synthetic_ticket_update"]}',$6)`, b.o, b.w, b.e, definition, asset, admin.identity.PrincipalID.String())
		for _, run := range []string{run1, run2} {
			b.exec(`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest,queued_at) VALUES($1,$2,$3,$4,$5,1,$6,decode(repeat('ad',32),'hex'),clock_timestamp())`, b.o, b.w, b.e, run, definition, admin.identity.PrincipalID.String())
		}
	})
	start := time.Now().UTC()
	observe(canary)
	end := time.Now().UTC()
	if v := inspect("promote"); v.Reason != "independent_ticket_proof_required" || v.Plan != nil {
		t.Fatal("signed denials alone promoted", v)
	}
	allowed, denied := verifiedActions[0], verifiedActions[1]
	pin := redteam.TicketPolicyBinding{AdapterID: "macos_claude_ticket", CohortID: cohort, PolicyRevision: strconv.FormatUint(denied.PolicyRevision, 10)}
	makeProof := func(run, control string) redteam.TicketProofBundle {
		binding := redteam.TicketRunBinding{Scope: redteam.TicketScope{OrganizationID: b.o, WorkspaceID: b.w, EnvironmentID: b.e}, RunID: run, TargetID: asset, Operation: "synthetic_ticket_update"}
		scenario := redteam.TicketScenario{Version: redteam.TicketProofVersion, TicketRunBinding: binding, TicketPolicyBinding: pin, Environment: "staging", CredentialClass: "test_write", RecorderID: "separate-staging-ledger", ControlActionID: control, ProtectedActionID: denied.Action, WindowStart: start, WindowEnd: end}
		return redteam.TicketProofBundle{Scenario: scenario, Adapter: redteam.TicketAdapterEvidence{Version: redteam.TicketProofVersion, TicketRunBinding: binding, TicketPolicyBinding: pin, Capability: "supported", Decisions: []redteam.TicketActionDecision{
			{ActionID: control, DecisionID: control, Verdict: "allow", Mode: "enforce", Applied: true, DecidedAt: allowed.ObservedAt},
			{ActionID: denied.Action, DecisionID: denied.Action, Verdict: "block", Mode: "enforce", Applied: true, DecidedAt: denied.ObservedAt},
		}}, Recorder: redteam.TicketRecorderEvidence{Version: redteam.TicketProofVersion, TicketRunBinding: binding, RecorderID: scenario.RecorderID, Healthy: true, CompleteFrom: start, CompleteThrough: end, Writes: []redteam.TicketWriteReceipt{{ActionID: control, ReceiptID: "synthetic-control-write", RecordedAt: allowed.ObservedAt}}}}
	}
	putProof := func(q redteam.TicketProofBundle) {
		t.Helper()
		id := q.Scenario.RunID
		call(admin, "putTicketVerification", "PUT", "/api/v1/test-runs/"+id+"/ticket-verification", map[string]string{"id": id}, q, nil, 200)
	}
	putProof(makeProof(run1, "unrelated-control-action"))
	if v := inspect("promote"); v.Plan != nil {
		t.Fatal("proof without this canary's allowed action promoted", v)
	}
	correct := makeProof(run2, allowed.Action)
	putProof(correct)
	// An adverse bound result dominates any passing import on the same revision.
	adverse := makeProof(run2, allowed.Action)
	adverse.Recorder.Writes = append(adverse.Recorder.Writes, redteam.TicketWriteReceipt{ActionID: denied.Action, ReceiptID: "unexpected-write", RecordedAt: denied.ObservedAt})
	if actual := cohortProofStatus([]cohortProof{{Bundle: correct, At: end, ControlBound: true}, {Bundle: adverse, At: end}}, denied.Binding, cohort); actual != "canary_unexpected_target_effect" {
		t.Fatal(actual)
	}
	promote := inspect("promote")
	publish(signPlan(promote), b.id(), 200)
	rollback := inspect("rollback")
	if len(signPlan(rollback).Items) != 2 {
		t.Fatal(rollback)
	}
	publish(signPlan(rollback), b.id(), 200)
	observe(rollback)
	final := inspect("monitor")
	if final.Revision != 4 || final.Phase != "rollback" {
		t.Fatal(final)
	}
	for _, d := range final.Members {
		if d.Adapter == "macos_claude_ticket" && (!d.Acknowledged || d.ManagedMode != "monitor") {
			t.Fatal(d)
		}
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getTicketCohort", PathParameters: params}, cohortInspectSQL, b.o, b.w, b.id(), admin.identity.PrincipalID.String(), "getTicketCohort", cohort, "", ""); installedSQLState(err) != "42501" {
		t.Fatal("cross scope", err)
	}
}
