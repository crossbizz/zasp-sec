package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestEndpointFleetOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, tokenSecrets := installedWorkloadTokenIssuer(t, b, repo, admin)
	token := issue("Pilot device", `["sync_endpoint"]`)
	other := issue("Unrelated device", `["sync_endpoint"]`)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	issuer, signer, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	h := endpointFleetHandler{database: b.product, clock: time.Now, newID: newWorkflowProductID}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		h.serve(w, r, op)
	})
	request := func(person installedPrincipal, op, method, path, id string, v any, headers map[string]string, want int) map[string]any {
		t.Helper()
		params := map[string]string{}
		if id != "" {
			params["id"] = id
		}
		var raw []byte
		if v != nil {
			raw, _ = json.Marshal(v)
		}
		reply := b.serve(surface, person, op, method, path, params, string(raw), headers)
		if reply.Code != want {
			t.Fatalf("%s want %d got %d %s", op, want, reply.Code, reply.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(reply.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	body := endpointRegister{Credential: token.binding.ID, DeviceKey: pub, PolicyKey: issuer, Cohort: "pilot"}
	adminKey := map[string]string{"Idempotency-Key": "register-" + b.id()}
	registered := request(admin, "registerEndpointDevice", "POST", "/api/v1/device-enrollments", "", body, adminKey, 200)
	id := registered["id"].(string)
	if replay := request(admin, "registerEndpointDevice", "POST", "/api/v1/device-enrollments", "", body, adminKey, 200); replay["id"] != id {
		t.Fatal("duplicate registration")
	}
	binding := endpointprotocol.Binding{Organization: b.o, Workspace: b.w, Environment: b.e, Device: id, Generation: 1}
	machine := func(actor installedPrincipal, private ed25519.PrivateKey, op, method, path, id string, data any, want int) map[string]any {
		t.Helper()
		var raw []byte
		if data != nil {
			raw, _ = json.Marshal(data)
		}
		headers := http.Header{}
		if err := endpointprotocol.Sign(headers, binding, op, raw, private, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for k := range headers {
			values[k] = headers.Get(k)
		}
		return request(actor, op, method, path, id, data, values, want)
	}
	base := "/api/v1/devices/" + id
	heartbeat := func(actor installedPrincipal, pkey ed25519.PrivateKey, want int) {
		t.Helper()
		machine(actor, pkey, "recordEndpointHeartbeat", "POST", base+"/heartbeat", id, endpointprotocol.Heartbeat{Adapter: "macos_claude_ticket", Revision: 1, PolicyStatus: "verified_cache"}, want)
	}
	lookup, lookupErr := b.fenced("zasp_svc_api", token, RoutedOperation{OperationID: "recordEndpointHeartbeat", PathParameters: map[string]string{"id": id}}, endpointMachineSQL, b.o, b.w, b.e, token.identity.PrincipalID.String(), "recordEndpointHeartbeat", id, int64(1), "key", `{}`)
	if lookupErr != nil || string(lookup) != `"forbidden"` {
		t.Fatalf("pending device database gate returned %s: %v", lookup, lookupErr)
	}
	heartbeat(token, key, 403)
	machine(other, key, "exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", "", struct{}{}, 403)
	machine(token, signer, "exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", "", struct{}{}, 403)
	machine(token, key, "exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", "", struct{}{}, 200)
	pol := endpointprotocol.Policy{Audience: endpointprotocol.PolicyAudience, Binding: binding, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Mode: "monitor", Tool: endpointprotocol.TicketTool, AllowedDestination: "internal"}
	bytes, _ := json.Marshal(pol)
	signed := endpointprotocol.Signed{Payload: bytes, Signature: ed25519.Sign(signer, bytes)}
	edit := func(revision int) map[string]string {
		return map[string]string{"If-Match": fmt.Sprintf("\"%d\"", revision), "Idempotency-Key": "endpoint-edit-" + b.id()}
	}
	request(admin, "publishEndpointPolicy", "PUT", base+"/policy-bundle", id, signed, edit(1), 200)
	got := machine(token, key, "fetchEndpointPolicy", "GET", base+"/policy-bundle", id, nil, 200)
	if got["bundle"] == nil {
		t.Fatal("no assigned bundle")
	}
	heartbeat(token, key, 200)
	page := request(admin, "listEndpointDevices", "GET", "/api/v1/devices", "", nil, nil, 200)
	if page["counts"].(map[string]any)["acknowledged"] != float64(1) {
		t.Fatal("incorrect denominator", page)
	}
	complete := true
	impactDigest := "sha256:" + strings.Repeat("b", 64)
	impact := installedDigestImpact(t, b, admin, issue("Fleet digest submission", `["submit_addon_scans"]`), impactDigest)
	inv := endpointprotocol.Inventory{Partition: strings.Repeat("a", 64), Generation: 1, Complete: &complete, Items: []endpointprotocol.Installation{{ID: strings.Repeat("b", 64), Digest: impactDigest}}}
	machine(token, key, "recordEndpointInventory", "POST", base+"/inventory-snapshots", id, inv, 200)
	complete = false
	inv.Generation++
	inv.Items = []endpointprotocol.Installation{}
	machine(token, key, "recordEndpointInventory", "POST", base+"/inventory-snapshots", id, inv, 200)
	if got := b.text("SELECT jsonb_array_length(complete_snapshot->'installations')::text FROM public.zasp_endpoint_partitions WHERE device_id=$1", id); got != "1" {
		t.Fatal("partial snapshot erased installation", got)
	}
	obs := endpointprotocol.Observation{Audience: endpointprotocol.ReceiptAudience, Binding: binding, PeerUID: 501, Action: strings.Repeat("c", 64), Session: strings.Repeat("a", 64), ObservedAt: now, PolicyRevision: 1, Mode: "monitor", Tool: endpointprotocol.TicketTool, TargetClass: "outside_allowed_destination", Verdict: "continue", WouldBlock: true, Reason: "destination_not_approved", SkillUsage: "unknown", TargetEffect: "unknown"}
	data, _ := json.Marshal(obs)
	batch := map[string]any{"receipts": []endpointprotocol.Signed{{Payload: data, Signature: ed25519.Sign(key, data)}}}
	for range 2 {
		machine(token, key, "recordEndpointObservations", "POST", "/api/v1/runtime/observations", "", batch, 200)
	}
	detail := request(admin, "getEndpointDevice", "GET", base, id, nil, nil, 200)
	if detail["reported_adapter"] != "macos_claude_ticket" || detail["observation_count"] != float64(1) || detail["inventory_partitions"] != float64(1) {
		t.Fatal(detail)
	}
	if rows := detail["recent_observations"].([]any); len(rows) != 1 || rows[0].(map[string]any)["session_ref"] != obs.Session || rows[0].(map[string]any)["skill_usage"] != "unknown" || rows[0].(map[string]any)["target_effect"] != "unknown" {
		t.Fatal("receipt lineage", rows)
	}
	root := detail["partition_summaries"].([]any)[0].(map[string]any)
	if root["complete"] != false || root["observed_count"] != float64(0) || root["last_complete_generation"] != float64(1) || root["confirmed_installations"].([]any)[0].(map[string]any)["installation_id"] != strings.Repeat("b", 64) {
		t.Fatal("incomplete root lost confirmed installations", root)
	}
	rows, cursor := impact("")
	if len(rows) != 1 || cursor != "" || rows[0]["device_id"] != id || rows[0]["observation"] != "last_complete" || rows[0]["generation"] != float64(1) || rows[0]["latest_generation"] != float64(2) || rows[0]["reported_at"] == nil || rows[0]["latest_reported_at"] == nil {
		t.Fatal("retained install", rows, cursor)
	}
	priorTime := rows[0]["latest_reported_at"]
	machine(token, key, "recordEndpointInventory", "POST", base+"/inventory-snapshots", id, inv, 200)
	rows, _ = impact("")
	if rows[0]["latest_reported_at"] != priorTime {
		t.Fatal("same generation reset inventory freshness")
	}
	inv.Generation = 3
	inv.Items = []endpointprotocol.Installation{{ID: strings.Repeat("d", 64), Digest: impactDigest}}
	machine(token, key, "recordEndpointInventory", "POST", base+"/inventory-snapshots", id, inv, 200)
	rows, cursor = impact("")
	if len(rows) != 1 || cursor == "" || rows[0]["observation"] != "last_complete" {
		t.Fatal("missing retained first page", rows, cursor)
	}
	rows, cursor = impact(cursor)
	if len(rows) != 1 || cursor != "" || rows[0]["observation"] != "partial" || rows[0]["generation"] != float64(3) {
		t.Fatal("missing new partial evidence", rows, cursor)
	}
	complete = true
	inv.Generation = 4
	inv.Items = []endpointprotocol.Installation{}
	machine(token, key, "recordEndpointInventory", "POST", base+"/inventory-snapshots", id, inv, 200)
	rows, _ = impact("")
	if len(rows) != 0 {
		t.Fatal("confirmed removal retained digest", rows)
	}
	// An inventory-only device can report assigned-user inventory without
	// claiming that an endpoint policy is active.
	windowsHealth := endpointprotocol.Heartbeat{Adapter: "windows_inventory", PolicyStatus: "policy_unavailable"}
	machine(token, key, "recordEndpointHeartbeat", "POST", base+"/heartbeat", id, windowsHealth, 200)
	inventoryDevice := request(admin, "getEndpointDevice", "GET", base, id, nil, nil, 200)
	if inventoryDevice["reported_adapter"] != "windows_inventory" || inventoryDevice["acknowledged"] != false {
		t.Fatal("incorrect inventory-only coverage", inventoryDevice)
	}
	windowsHealth.Revision = 1
	windowsHealth.PolicyStatus = "verified_cache"
	machine(token, key, "recordEndpointHeartbeat", "POST", base+"/heartbeat", id, windowsHealth, 400)
	pol.Mode = "enforce"
	pol.Revision = 2
	payload, _ := json.Marshal(pol)
	request(admin, "publishEndpointPolicy", "PUT", base+"/policy-bundle", id, endpointprotocol.Signed{Payload: payload, Signature: ed25519.Sign(signer, payload)}, edit(2), 200)
	t.Run("daemon and hook through installed HTTP", func(t *testing.T) {
		exerciseInstalledEndpoint(t, b, surface, repo, binding, key, issuer, tokenSecrets["Pilot device"])
	})
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	request(admin, "rotateEndpointCredential", "POST", base+"/credential-rotations", id, endpointRegister{Credential: other.binding.ID, DeviceKey: newPub}, edit(3), 200)
	heartbeat(token, key, 403)
	binding.Generation++
	machine(other, newKey, "exchangeEndpointEnrollment", "POST", "/api/v1/device-enrollments/exchange", "", struct{}{}, 200)
	request(admin, "retireEndpointDevice", "POST", base+"/retire", id, nil, edit(4), 200)
	heartbeat(other, newKey, 403)
}
