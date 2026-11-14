package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	packAgent      = "pid_10000001-0000-4000-8000-000000000001"
	packOtherAgent = "pid_10000009-0000-4000-8000-000000000009"
	packFinding    = "pid_30000001-0000-4000-8000-000000000001"
	packFinding2   = "pid_30000002-0000-4000-8000-000000000002"
	packRun        = "pid_40000001-0000-4000-8000-000000000001"
	packTest       = "pid_60000001-0000-4000-8000-000000000001"
	packTestRun    = "pid_70000001-0000-4000-8000-000000000001"
)

// evidencePackProduct stands in for the product router: it answers the read
// operations the pack is composed from, and records each request.
type evidencePackProduct struct {
	requests []string
	headers  []http.Header
	// status overrides the answer of a path prefix.
	status map[string]int
	// findingPages is the number of full pages of other agents' findings
	// before the page that holds this agent's.
	findingPages int
}

func (product *evidencePackProduct) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	product.requests = append(product.requests, request.URL.RequestURI())
	product.headers = append(product.headers, request.Header.Clone())
	path := request.URL.Path
	for prefix, status := range product.status {
		if strings.HasPrefix(path, prefix) {
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(`{"code":"request_forbidden","message":"Request forbidden","correlation_id":"x","retryable":false}`))
			return
		}
	}
	finding := func(id, agent, rule string) string {
		return `{"id":"` + id + `","source":"posture","rule":"` + rule + `","title":"Agent has no owner | review","severity":"high","status":"open","agent_id":"` + agent + `","evidence_ids":["pid_20000001-0000-4000-8000-000000000001"],"risk_factors":[],"version":1,"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z","frameworks":[{"framework":"owasp_agentic_top10_2026","control":"ASI10","title":"Rogue Agents"}]}`
	}
	writer.Header().Set("Content-Type", "application/json")
	switch {
	case path == "/api/v1/agents/"+packAgent:
		_, _ = writer.Write([]byte(`{"summary":{"id":"` + packAgent + `","name":"Support <agent>","kind":"agent","owner":"","team":"","provider":"aws","source_kind":"aws_bedrock_agent","discovery":{"method":"inferred","platform":"lambda_function","signals":["invoke:bedrock_model","env:openai"]},"management_state":"unmanaged","last_activity_at":"2026-11-10T00:00:00Z","activity_state":"active","first_seen":"2026-10-01T00:00:00Z","last_seen":"2026-11-10T00:00:00Z","observed_at":"2026-11-10T00:00:00Z"},"sources":[{"integration_id":"pid_30000001-0000-4000-8000-000000000001","provider":"aws","source":"aws","snapshot_id":"pid_40000001-0000-4000-8000-000000000001","evidence_id":"pid_20000001-0000-4000-8000-000000000001","observed_at":"2026-11-10T00:00:00Z","winning":true}],"evidence":[{"id":"pid_20000001-0000-4000-8000-000000000001","checksum":"sha256:aa","collected_at":"2026-11-10T00:00:00Z"}]}`))
	case path == "/api/v1/findings":
		cursor := request.URL.Query().Get("cursor")
		page := 0
		if cursor != "" {
			_, _ = fmt.Sscanf(cursor, "page%d", &page)
		}
		if page < product.findingPages {
			items := make([]string, 100)
			for index := range items {
				items[index] = finding(fmt.Sprintf("pid_3%07d-0000-4000-8000-%012d", page*100+index+10, index), packOtherAgent, "ownerless_agent")
			}
			_, _ = writer.Write([]byte(`{"items":[` + strings.Join(items, ",") + `],"page_info":{"next_cursor":"` + fmt.Sprintf("page%d", page+1) + `","has_more":true}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"items":[` + finding(packFinding, packAgent, "ownerless_agent") + `,` + finding("pid_30000009-0000-4000-8000-000000000009", packOtherAgent, "ownerless_agent") + `,` + finding(packFinding2, packAgent, "shell_credential") + `],"page_info":{"next_cursor":null,"has_more":false}}`))
	case strings.HasPrefix(path, "/api/v1/security-agent-activity/finding/"):
		// Both findings relate to the same run.
		_, _ = writer.Write([]byte(`{"items":[{"id":"` + packRun + `","agent_id":"pid_50000001-0000-4000-8000-000000000001","state":"remediated","evidence_ids":["` + packFinding + `"],"definition_version":1,"version":3}],"coverage":"complete"}`))
	case path == "/api/v1/security-agent-runs/"+packRun:
		_, _ = writer.Write([]byte(`{"run":{"id":"` + packRun + `","agent_id":"pid_50000001-0000-4000-8000-000000000001","state":"remediated","evidence_ids":["` + packFinding + `"],"definition_version":1,"version":3},"evidence_ids":["` + packFinding + `"],"plan":{"plan_hash":"sha256:aa","catalog_version":"security-agent-actions-v1","expires_at":"2026-11-03T00:00:00Z","steps":[{"id":"pid_41000001-0000-4000-8000-000000000001","index":0,"action":"update_finding_response","authorization":"approval_required","state":"succeeded","version":2}]},"authorization":{},"approvals":[{"id":"pid_42000001-0000-4000-8000-000000000001","run_id":"` + packRun + `","step_id":"pid_41000001-0000-4000-8000-000000000001","state":"approved","expected_effect":"Assign investigator and update finding response"}],"execution":{},"verification":{}}`))
	case path == "/api/v1/tests":
		_, _ = writer.Write([]byte(`{"items":[{"id":"` + packTest + `","version":1,"name":"Prompt injection sweep","target_id":"` + packAgent + `","target_kind":"agent_endpoint","categories":["prompt_injection","tool_abuse"]},{"id":"pid_60000002-0000-4000-8000-000000000002","version":1,"name":"Other","target_id":"` + packOtherAgent + `","target_kind":"agent_endpoint","categories":["data_leakage"]}]}`))
	case path == "/api/v1/test-runs":
		_, _ = writer.Write([]byte(`{"items":[{"id":"` + packTestRun + `","version":2,"definition_id":"` + packTest + `","definition_version":1,"status":"complete","attempt":1,"cancel_requested":false,"queued_at":"2026-11-05T00:00:00Z","completed_at":"2026-11-05T00:10:00Z","verdict":"fail"},{"id":"pid_70000002-0000-4000-8000-000000000002","version":1,"definition_id":"pid_60000002-0000-4000-8000-000000000002","definition_version":1,"status":"queued","attempt":0,"cancel_requested":false,"queued_at":"2026-11-05T00:00:00Z"}]}`))
	default:
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte(`{"code":"not_found"}`))
	}
}

func evidencePackRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	request := inventoryRequest(t, "getAgentEvidencePack", "https://app.zasp.test/api/v1/agents/"+packAgent+"/evidence-pack"+target)
	request.Header.Set("Authorization", "Bearer zasp_pat_fixture")
	request.Header.Set("Cookie", "zasp_session=fixture")
	request.Header.Set(expectedScopeHeader, "scope")
	request.Header.Set("X-CSRF-Token", "must-not-be-forwarded")
	return request
}

type evidencePackResponse struct {
	Pack     AgentEvidencePack `json:"pack"`
	Markdown string            `json:"markdown"`
}

func evidencePackCall(t *testing.T, product *evidencePackProduct, target string) (*httptest.ResponseRecorder, evidencePackResponse) {
	t.Helper()
	handler := &agentEvidencePackHandler{now: func() time.Time { return time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC) }}
	response := httptest.NewRecorder()
	request := evidencePackRequest(t, target)
	handler.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), productRouterContextKey{}, http.Handler(product))))
	var decoded evidencePackResponse
	if response.Code == http.StatusOK && strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("pack is not JSON: %v\n%s", err, response.Body.String())
		}
	}
	return response, decoded
}

func TestAgentEvidencePackComposesWhatTheCallerMayRead(t *testing.T) {
	product := &evidencePackProduct{}
	response, body := evidencePackCall(t, product, "")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	pack := body.Pack
	if pack.SchemaVersion != "agent-evidence-pack-v1" || pack.GeneratedAt != "2026-11-14T09:00:00Z" || pack.OrganizationID != inventoryScope(t).OrganizationID().String() || pack.EnvironmentID != inventoryScope(t).EnvironmentID().String() {
		t.Fatalf("pack header = %#v", pack)
	}
	if !strings.Contains(string(pack.Agent), `"signals":["invoke:bedrock_model","env:openai"]`) || !strings.Contains(string(pack.Agent), `"sources":[`) {
		t.Fatalf("discovery evidence = %s", pack.Agent)
	}
	// Only this agent's findings, each with its framework references.
	if pack.Findings.Status != "complete" || len(pack.Findings.Items) != 2 || evidencePackString(pack.Findings.Items[0], "id") != packFinding || evidencePackString(pack.Findings.Items[1], "id") != packFinding2 || !strings.Contains(string(pack.Findings.Items[0]), `"control":"ASI10"`) {
		t.Fatalf("findings = %#v", pack.Findings)
	}
	// The run both findings relate to, once, with its approvals.
	if pack.SecurityAgentRuns.Status != "complete" || len(pack.SecurityAgentRuns.Items) != 1 {
		t.Fatalf("security agent runs = %#v", pack.SecurityAgentRuns)
	}
	var run struct {
		FindingIDs []string `json:"finding_ids"`
		Run        struct {
			Approvals []struct {
				State string `json:"state"`
			} `json:"approvals"`
		} `json:"run"`
	}
	if json.Unmarshal(pack.SecurityAgentRuns.Items[0], &run) != nil || len(run.FindingIDs) != 2 || len(run.Run.Approvals) != 1 || run.Run.Approvals[0].State != "approved" {
		t.Fatalf("run = %s", pack.SecurityAgentRuns.Items[0])
	}
	// The red team definitions that target the agent, and their runs.
	if pack.RedTeamTests.Status != "complete" || len(pack.RedTeamTests.Items) != 1 || evidencePackString(pack.RedTeamTests.Items[0], "id") != packTest || pack.RedTeamRuns.Status != "complete" || len(pack.RedTeamRuns.Items) != 1 || evidencePackString(pack.RedTeamRuns.Items[0], "id") != packTestRun {
		t.Fatalf("red team = %#v / %#v", pack.RedTeamTests, pack.RedTeamRuns)
	}
	// Every part was read as the caller: the credential and scope headers of
	// the request, and nothing else of it.
	if len(product.requests) != 7 || product.requests[0] != "/api/v1/agents/"+packAgent || product.requests[1] != "/api/v1/findings?limit=100" {
		t.Fatalf("reads = %v", product.requests)
	}
	for index, header := range product.headers {
		if header.Get("Authorization") != "Bearer zasp_pat_fixture" || header.Get("Cookie") != "zasp_session=fixture" || header.Get(expectedScopeHeader) != "scope" || header.Get("X-CSRF-Token") != "" || len(header) != 3 {
			t.Fatalf("read %d carried %v", index, header)
		}
	}
	// The rendering names every part, and provider text cannot break it.
	for _, want := range []string{
		"# Agent evidence pack: Support &lt;agent&gt;", "## Discovery evidence", "`invoke:bedrock\\_model`", "Activity: active, last activity 2026-11-10T00:00:00Z",
		"## Findings", "### Agent has no owner \\| review", "owasp\\_agentic\\_top10\\_2026 ASI10: Rogue Agents", "rule `shell\\_credential`",
		"## Security Agent actions and approvals", "### Run `" + packRun + "`", "Step 1: update\\_finding\\_response, authorization approval\\_required, state succeeded", "Approval `pid_42000001-0000-4000-8000-000000000001`: approved, for Assign investigator and update finding response",
		"## Red team definitions", "| `" + packTest + "` | Prompt injection sweep | agent\\_endpoint | prompt\\_injection, tool\\_abuse |",
		"## Red team results", "| `" + packTestRun + "` | Prompt injection sweep | complete | fail | 2026-11-05T00:10:00Z |",
	} {
		if !strings.Contains(body.Markdown, want) {
			t.Errorf("the rendering lacks %q:\n%s", want, body.Markdown)
		}
	}
	if strings.Contains(body.Markdown, packOtherAgent) || strings.Contains(body.Markdown, "<agent>") {
		t.Fatalf("the rendering holds another agent's record or raw markup:\n%s", body.Markdown)
	}
	// The Markdown format is the same rendering as a download.
	markdown, _ := evidencePackCall(t, &evidencePackProduct{}, "?format=markdown")
	if markdown.Code != http.StatusOK || markdown.Header().Get("Content-Type") != "text/markdown; charset=utf-8" || !strings.Contains(markdown.Header().Get("Content-Disposition"), "agent-evidence-"+packAgent+".md") || markdown.Body.String() != body.Markdown {
		t.Fatalf("markdown status=%d headers=%v", markdown.Code, markdown.Header())
	}
}

func TestAgentEvidencePackMarksWhatItDoesNotHold(t *testing.T) {
	// A caller that may not read findings: the findings and the runs that
	// depend on them are marked, and the rest of the pack is still there.
	_, body := evidencePackCall(t, &evidencePackProduct{status: map[string]int{"/api/v1/findings": http.StatusForbidden}}, "")
	if body.Pack.Findings.Status != "not_permitted" || len(body.Pack.Findings.Items) != 0 || body.Pack.SecurityAgentRuns.Status != "not_permitted" || body.Pack.RedTeamTests.Status != "complete" || len(body.Pack.RedTeamRuns.Items) != 1 {
		t.Fatalf("pack = %#v", body.Pack)
	}
	if !strings.Contains(body.Markdown, "Not included: the requester may not read this section.") {
		t.Fatalf("the rendering does not say what is missing:\n%s", body.Markdown)
	}
	// An API token cannot read the run relations (a browser-session read).
	_, body = evidencePackCall(t, &evidencePackProduct{status: map[string]int{"/api/v1/security-agent-activity/": http.StatusUnauthorized}}, "")
	if body.Pack.SecurityAgentRuns.Status != "browser_session_required" || len(body.Pack.Findings.Items) != 2 {
		t.Fatalf("pack = %#v", body.Pack)
	}
	// A failing read is unavailable, never an empty complete section.
	_, body = evidencePackCall(t, &evidencePackProduct{status: map[string]int{"/api/v1/tests": http.StatusServiceUnavailable, "/api/v1/security-agent-runs/": http.StatusServiceUnavailable}}, "")
	if body.Pack.RedTeamTests.Status != "unavailable" || body.Pack.RedTeamRuns.Status != "unavailable" || body.Pack.SecurityAgentRuns.Status != "unavailable" || len(body.Pack.SecurityAgentRuns.Items) != 0 {
		t.Fatalf("pack = %#v", body.Pack)
	}
	// More pages of findings than the bound: truncated, and so are the runs.
	product := &evidencePackProduct{findingPages: agentEvidencePackFindingPages}
	_, body = evidencePackCall(t, product, "")
	if body.Pack.Findings.Status != "truncated" || len(body.Pack.Findings.Items) != 0 || body.Pack.SecurityAgentRuns.Status != "truncated" {
		t.Fatalf("pack = %#v / %#v", body.Pack.Findings, body.Pack.SecurityAgentRuns)
	}
	if !strings.Contains(body.Markdown, "This section reached its bound and is not complete.") {
		t.Fatalf("the rendering does not say it is truncated:\n%s", body.Markdown)
	}
	// Findings found after other agents' pages are still found.
	_, body = evidencePackCall(t, &evidencePackProduct{findingPages: 3}, "")
	if body.Pack.Findings.Status != "complete" || len(body.Pack.Findings.Items) != 2 {
		t.Fatalf("paged findings = %#v", body.Pack.Findings)
	}
}

func TestAgentEvidencePackRefusals(t *testing.T) {
	for name, item := range map[string]struct {
		product *evidencePackProduct
		target  string
		status  int
	}{
		"an agent the caller may not read": {&evidencePackProduct{status: map[string]int{"/api/v1/agents/": http.StatusForbidden}}, "", http.StatusForbidden},
		"an agent that does not exist":     {&evidencePackProduct{status: map[string]int{"/api/v1/agents/": http.StatusNotFound}}, "", http.StatusNotFound},
		"an agent that cannot be read":     {&evidencePackProduct{status: map[string]int{"/api/v1/agents/": http.StatusServiceUnavailable}}, "", http.StatusServiceUnavailable},
		"an unknown format":                {&evidencePackProduct{}, "?format=html", http.StatusBadRequest},
		"an unknown parameter":             {&evidencePackProduct{}, "?agent_id=" + packOtherAgent, http.StatusBadRequest},
	} {
		response, _ := evidencePackCall(t, item.product, item.target)
		if response.Code != item.status {
			t.Errorf("%s: status %d, want %d: %s", name, response.Code, item.status, response.Body.String())
		}
		if item.status == http.StatusBadRequest && len(item.product.requests) != 0 {
			t.Errorf("%s: read %v before refusing", name, item.product.requests)
		}
	}
	// Another operation is not served.
	handler := &agentEvidencePackHandler{}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, inventoryRequest(t, "getAgent", "https://app.zasp.test/api/v1/agents/"+packAgent))
	if response.Code != http.StatusNotFound {
		t.Fatalf("another operation = %d", response.Code)
	}
}

func TestAgentEvidencePackIsMounted(t *testing.T) {
	found := false
	for _, operation := range CoreOperations() {
		if operation.OperationID == "getAgentEvidencePack" {
			found = operation.Method == http.MethodGet && operation.Pattern == "/api/v1/agents/{id}/evidence-pack" && operation.Permission == "view"
		}
	}
	policy, err := authorizationTargetPolicy("getAgentEvidencePack")
	if !found || err != nil || policy.Mode != "object" || policy.Kind != "agent" || policy.Parameter != "id" {
		t.Fatalf("operation mounted=%v policy=%#v / %v", found, policy, err)
	}
}

// evidencePackDependency is one mounted dependency of the composition: it
// records the operation the router dispatched to it and answers as the
// product stand-in does.
type evidencePackDependencyStub struct {
	product    *evidencePackProduct
	operations *[]string
}

func (stub *evidencePackDependencyStub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, _ := RoutedOperationFromRequest(request)
	*stub.operations = append(*stub.operations, routed.OperationID)
	stub.product.ServeHTTP(writer, request)
}

// The pack is read through the composed router: every part is routed,
// credential-checked and permission-checked as its own operation.
func TestAgentEvidencePackReadsEachPartAsItsOwnOperation(t *testing.T) {
	product := &evidencePackProduct{}
	operations := []string{}
	dependency := func() http.Handler { return &evidencePackDependencyStub{product: product, operations: &operations} }
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: dependency(), Risk: dependency(), Workflow: dependency(), Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	call := func(identity RequestIdentity) (int, evidencePackResponse) {
		t.Helper()
		operations = operations[:0]
		request := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+packAgent+"/evidence-pack", nil)
		request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		response := httptest.NewRecorder()
		composition.ServeHTTP(response, request)
		var decoded evidencePackResponse
		if response.Code == http.StatusOK {
			if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("pack is not JSON: %v\n%s", err, response.Body.String())
			}
		}
		return response.Code, decoded
	}
	// A browser session with the view permission reads every part.
	browser := fixtureRequestIdentity(t)
	browser.Permissions = []string{"view"}
	browser.CredentialKind = CredentialBrowserSession
	status, body := call(browser)
	if status != http.StatusOK || body.Pack.Findings.Status != "complete" || len(body.Pack.Findings.Items) != 2 || body.Pack.SecurityAgentRuns.Status != "complete" || len(body.Pack.SecurityAgentRuns.Items) != 1 || len(body.Pack.RedTeamRuns.Items) != 1 {
		t.Fatalf("browser pack status=%d pack=%#v", status, body.Pack)
	}
	want := []string{"getAgent", "listFindings", "listSecurityAgentActivityRuns", "listSecurityAgentActivityRuns", "getSecurityAgentRun", "listTests", "listTestRuns"}
	if !slices.Equal(operations, want) {
		t.Fatalf("operations = %v, want %v", operations, want)
	}
	// An API token: the run relations are a browser-session operation, so the
	// router refuses that part and the pack says so.
	token := browser
	token.CredentialKind = CredentialBearerToken
	status, body = call(token)
	if status != http.StatusOK || body.Pack.SecurityAgentRuns.Status != "browser_session_required" || len(body.Pack.Findings.Items) != 2 || slices.Contains(operations, "listSecurityAgentActivityRuns") || slices.Contains(operations, "getSecurityAgentRun") {
		t.Fatalf("token pack status=%d runs=%#v operations=%v", status, body.Pack.SecurityAgentRuns, operations)
	}
	// A caller without the view permission does not reach the handler.
	denied := browser
	denied.Permissions = []string{"view_audit"}
	if status, _ := call(denied); status != http.StatusForbidden || len(operations) != 0 {
		t.Fatalf("a caller without view: status=%d operations=%v", status, operations)
	}
}
