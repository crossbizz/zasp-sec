package microsoftdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const microsoftTestAIToken = "ai-token-sentinel-value-0004"

var microsoftTestFoundryCredential = []byte(`{"ai_token":"` + microsoftTestAIToken + `","arm_token":"` + microsoftTestARMToken + `","graph_token":"` + microsoftTestGraphToken + `"}`)

const (
	foundryAccountPath = "/subscriptions/" + azureSubscriptionA + "/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/contoso-foundry"
	foundryProjects    = `{"value":[` +
		`{"id":"` + foundryAccountPath + `/projects/support","name":"contoso-foundry/support","properties":{"provisioningState":"Succeeded","displayName":"Support","endpoints":{"AI Foundry API":"https://contoso-foundry.services.ai.azure.com/api/projects/support"}}},` +
		`{"id":"` + foundryAccountPath + `/projects/research","name":"research","properties":{"provisioningState":"Succeeded"}}]}`
	foundryPolicies = `{"value":[` +
		`{"name":"Microsoft.DefaultV2","properties":{"mode":"Blocking","contentFilters":[{"name":"Hate","enabled":true,"blocking":true,"severityThreshold":"Medium","source":"Prompt"},{"name":"Violence","enabled":true,"blocking":true,"severityThreshold":"Medium","source":"Completion"},{"name":"Jailbreak","enabled":false,"blocking":false,"source":"Prompt"}]}},` +
		`{"name":"annotate-only","properties":{"contentFilters":[{"name":"Hate","enabled":true,"blocking":false,"severityThreshold":"Medium","source":"Prompt"},{"name":"Sexual","enabled":true,"blocking":true,"severityThreshold":"Low","source":"Prompt"}]}},` +
		`{"name":"strict","properties":{"contentFilters":[{"name":"Hate","enabled":true,"blocking":true,"severityThreshold":"Low","source":"Prompt"},{"name":"Selfharm","enabled":true,"blocking":true,"severityThreshold":"Low","source":"Prompt"}]}}]}`
	foundryDeployments = `{"value":[{"id":"x","name":"gpt-4o","properties":{"model":{"format":"OpenAI","name":"gpt-4o","version":"2024-08-06"},"provisioningState":"Succeeded","raiPolicyName":"annotate-only"}},` +
		`{"id":"y","name":"gpt-4o-mini","properties":{"model":{"format":"OpenAI","name":"gpt-4o-mini","version":"1"},"provisioningState":"Succeeded","raiPolicyName":"Microsoft.DefaultV2"}}]}`
)

func foundryAgent(name, state, definition string) string {
	return `{"object":"agent","id":"` + name + `","name":"` + name + `","state":"` + state + `","versions":{"latest":{"object":"agent.version","id":"` + name + `:3","name":"` + name + `","version":"3","status":"active","metadata":{"owner":"do-not-keep-owner"},"definition":` + definition + `}}}`
}

// The whole collection of a tenant with one AI Foundry account, to a typed
// snapshot: the agents of its projects, each with the content moderation of
// the filter policy that applies to it, read with the Foundry token from the
// project endpoints only.
func TestMicrosoftCollectionListsFoundryAgentsWithTheirContentFilter(t *testing.T) {
	t.Parallel()
	subscription := `{"value":[{"id":"/subscriptions/` + azureSubscriptionA + `","subscriptionId":"` + azureSubscriptionA + `","displayName":"Production","state":"Enabled"}]}`
	api, roundTripper := newMicrosoftTestAPI(t,
		microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty),
		microsoftOK(subscription),
		microsoftOK(`{"value":[`+azureAccount(azureSubscriptionA, "contoso-foundry", "AIServices", `,"customSubDomainName":"contoso-foundry"`)+`]}`),
		microsoftOK(foundryDeployments),
		microsoftOK(foundryProjects),
		microsoftOK(foundryPolicies),
		// Project support, two pages.
		microsoftOK(`{"object":"list","data":[`+
			foundryAgent("triage", "enabled", `{"kind":"prompt","model":"gpt-4o","instructions":"Never disclose the escalation code 5150.","tools":[{"type":"code_interpreter"},{"type":"mcp","server_url":"https://mcp.do-not-keep.example/sse"}]}`)+`,`+
			foundryAgent("refunds", "disabled", `{"kind":"prompt","model":"gpt-4o-mini","rai_config":{"rai_policy_name":"`+foundryAccountPath+`/raiPolicies/strict"},"tools":[{"type":"function","name":"issue_refund"}]}`)+
			`],"first_id":"triage","last_id":"refunds","has_more":true}`),
		microsoftOK(`{"object":"list","data":[`+foundryAgent("router", "enabled", `{"kind":"workflow"}`)+`],"first_id":"router","last_id":"router","has_more":false}`),
		// Project research states no endpoint: the account's subdomain is used.
		microsoftOK(`{"object":"list","data":[`+foundryAgent("reader", "enabled", `{"kind":"prompt","model":"gpt-4o-mini","tools":[{"type":"file_search"}]}`)+`],"has_more":false}`),
	)
	driver := &microsoftSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewMicrosoftCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 6)
	for index := range ids {
		if ids[index], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", index+1, index+1)); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderMicrosoft, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialMicrosoftClient, CredentialReference: "ref:microsoft/connection/customer-0001", ExpectedSubject: microsoftTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 50, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	outcome, err := client.CollectWithCredential(context.Background(), request, bytes.Clone(microsoftTestFoundryCredential))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	arm := "https://management.azure.com" + foundryAccountPath
	agents := "/agents?api-version=v1&limit=100&order=asc"
	assertMicrosoftRequestURLs(t, roundTripper,
		"https://graph.microsoft.com/v1.0/organization?$select=id,displayName",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100",
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100",
		"https://management.azure.com/subscriptions?api-version=2022-12-01",
		"https://management.azure.com/subscriptions/"+azureSubscriptionA+"/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01",
		arm+"/deployments?api-version=2023-05-01",
		arm+"/projects?api-version=2025-12-01",
		arm+"/raiPolicies?api-version=2025-12-01",
		"https://contoso-foundry.services.ai.azure.com/api/projects/support"+agents,
		"https://contoso-foundry.services.ai.azure.com/api/projects/support"+agents+"&after=refunds",
		"https://contoso-foundry.services.ai.azure.com/api/projects/research"+agents,
	)
	// Each token goes to its own host and to no other.
	for index, sent := range roundTripper.requests {
		want := microsoftTestGraphToken
		switch sent.URL.Host {
		case "management.azure.com":
			want = microsoftTestARMToken
		case "contoso-foundry.services.ai.azure.com":
			want = microsoftTestAIToken
		}
		if sent.Header.Get("Authorization") != "Bearer "+want {
			t.Fatalf("request %d to %s carries the wrong token", index, sent.URL.Host)
		}
	}
	snapshot := complete.Snapshot()
	var entities []struct {
		Kind                  string          `json:"kind"`
		DisplayName           string          `json:"display_name"`
		SourceNativeID        string          `json:"source_native_id"`
		StableFields          json.RawMessage `json:"stable_fields"`
		Attributes            json.RawMessage `json:"attributes"`
		ProductKind           string          `json:"product_kind"`
		ConfidenceBasisPoints int             `json:"confidence_basis_points"`
	}
	if err := json.Unmarshal(snapshot.Entities(), &entities); err != nil || !snapshot.TypedObservations() {
		t.Fatalf("snapshot: %v", err)
	}
	got := map[string]string{}
	for _, entity := range entities {
		if entity.Kind == "microsoft_copilot_agent" {
			if entity.ProductKind != "agent" || entity.ConfidenceBasisPoints != 9500 {
				t.Fatalf("envelope of %s = %s %d", entity.DisplayName, entity.ProductKind, entity.ConfidenceBasisPoints)
			}
			got[entity.DisplayName] = string(entity.StableFields) + string(entity.Attributes)
		}
		if entity.Kind == "microsoft_ai_resource" && !strings.Contains(string(entity.Attributes), `"agents":"listed"`) {
			t.Fatalf("account = %s", entity.Attributes)
		}
	}
	posture := func(active, shell bool) string {
		return fmt.Sprintf(`"posture":{"human_credential":false,"credential_fingerprint":"","untrusted_input":false,"production_write":false,"shell_execution":%t,"production_credential":false,"unrestricted_egress":false,"sensitive_data_reach":false,"unapproved_remote_tool":false,"destructive_tool":false,"runtime_control":false,"production_agent":false,"runtime_policy_supported":false,"host_filesystem":false,"privileged":false,"cicd_write":false,"production_secret_reach":false,"credential_active":%t}`, shell, active)
	}
	stable := func(project, name string) string {
		return `{"environment":"contoso-foundry.services.ai.azure.com/` + project + `","name":"` + name + `","object_type":"foundry_agent","tenant":"` + microsoftTestTenant + `"}`
	}
	want := map[string]string{
		// The deployment's policy (annotate-only) applies: a harm filter does not block.
		"support/triage": stable("support", "triage") + `{"agent_type":"prompt","content_moderation":"low","discovery":{"method":"provider_api","platform":"azure_ai_foundry","signals":["tool:code_interpreter","tool:mcp"]},"model":"gpt-4o",` + posture(true, true) + `,"rai_policy":"annotate-only","status":"ACTIVE"}`,
		// The agent's own policy (strict) wins over its deployment's.
		"support/refunds": stable("support", "refunds") + `{"agent_type":"prompt","content_moderation":"high","discovery":{"method":"provider_api","platform":"azure_ai_foundry","signals":["tool:function"]},"model":"gpt-4o-mini",` + posture(false, false) + `,"rai_policy":"strict","status":"INACTIVE"}`,
		// A workflow agent names no model: no policy is known for it.
		"support/router":  stable("support", "router") + `{"agent_type":"workflow","discovery":{"method":"provider_api","platform":"azure_ai_foundry","signals":[]},` + posture(true, false) + `,"status":"ACTIVE"}`,
		"research/reader": stable("research", "reader") + `{"agent_type":"prompt","content_moderation":"medium","discovery":{"method":"provider_api","platform":"azure_ai_foundry","signals":["tool:file_search"]},"model":"gpt-4o-mini",` + posture(true, false) + `,"rai_policy":"microsoft.defaultv2","status":"ACTIVE"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("agents = %v", got)
	}
	for name, expected := range want {
		if !sameMicrosoftJSON(t, got[name], expected) {
			t.Errorf("%s =\n%s\nwant\n%s", name, got[name], expected)
		}
	}
	// No token and nothing of an agent's content is stored.
	for key, object := range driver.objects {
		for _, value := range []string{microsoftTestGraphToken, microsoftTestARMToken, microsoftTestAIToken, "escalation code", "do-not-keep", "issue_refund"} {
			if bytes.Contains(object.Body, []byte(value)) {
				t.Fatalf("artifact %s stores %q", key, value)
			}
		}
	}
}

// sameMicrosoftJSON compares two concatenated JSON objects member by member.
func sameMicrosoftJSON(t *testing.T, got, want string) bool {
	t.Helper()
	decode := func(value string) []any {
		decoder := json.NewDecoder(strings.NewReader(value))
		var parts []any
		for decoder.More() {
			var part any
			if err := decoder.Decode(&part); err != nil {
				t.Fatalf("not JSON: %s", value)
			}
			parts = append(parts, part)
		}
		return parts
	}
	left, _ := json.Marshal(decode(got))
	right, _ := json.Marshal(decode(want))
	return bytes.Equal(left, right)
}

// Without the role that may list a project's agents the account is recorded
// as such and the collection completes; without a Foundry token nothing of
// the data plane is asked.
func TestMicrosoftFoundryAgentsDegradeWithoutTheDataRole(t *testing.T) {
	t.Parallel()
	subscription := `{"value":[{"id":"/subscriptions/` + azureSubscriptionA + `","subscriptionId":"` + azureSubscriptionA + `","state":"Enabled"}]}`
	account := `{"value":[` + azureAccount(azureSubscriptionA, "contoso-foundry", "AIServices", `,"customSubDomainName":"contoso-foundry"`) + `]}`
	state := microsoftPageState{Phase: microsoftPhaseAzure, Lineage: 4}
	cursor, _, ok := nextMicrosoftStateCursor(microsoftTestSubject, state)
	if !ok {
		t.Fatal("cursor")
	}
	request := CollectionPageRequest{Provider: collection.ProviderMicrosoft, Subject: microsoftTestSubject, Cursor: cursor, Page: 4, RemainingItems: 100, RemainingRelationships: 100, RemainingBytes: 1 << 20}
	for name, test := range map[string]struct {
		credential []byte
		responses  []microsoftHTTPResponse
		want       string
		calls      int
	}{
		"data role missing": {microsoftTestFoundryCredential, []microsoftHTTPResponse{microsoftOK(subscription), microsoftOK(account), microsoftOK(foundryDeployments), microsoftOK(foundryProjects), microsoftOK(foundryPolicies),
			{status: http.StatusForbidden, body: `{"error":{"code":"PermissionDenied"}}`}}, `"agents":"access_denied"`, 6},
		"projects not readable": {microsoftTestFoundryCredential, []microsoftHTTPResponse{microsoftOK(subscription), microsoftOK(account), microsoftOK(foundryDeployments), {status: http.StatusForbidden, body: `{}`}}, `"agents":"not_listed"`, 4},
		"policies not readable": {microsoftTestFoundryCredential, []microsoftHTTPResponse{microsoftOK(subscription), microsoftOK(account), microsoftOK(foundryDeployments), microsoftOK(`{"value":[]}`), {status: http.StatusForbidden, body: `{}`}}, `"agents":"listed"`, 5},
		"no foundry token":      {microsoftTestARMCredential, []microsoftHTTPResponse{microsoftOK(subscription), microsoftOK(account), microsoftOK(foundryDeployments)}, `"deployments":"listed"`, 3},
		// The project endpoint cannot be reached (the test transport has no
		// further answer): the agents are not listed, the account is.
		"endpoint unreachable": {microsoftTestFoundryCredential, []microsoftHTTPResponse{microsoftOK(subscription), microsoftOK(account), microsoftOK(foundryDeployments), microsoftOK(foundryProjects), microsoftOK(foundryPolicies)}, `"agents":"not_listed"`, 6},
	} {
		api, roundTripper := newMicrosoftTestAPI(t, test.responses...)
		page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(test.credential), request)
		if err != nil || !page.Complete || !strings.Contains(string(page.Raw), test.want) || strings.Contains(string(page.Raw), "foundry_agent") || roundTripper.calls() != test.calls {
			t.Errorf("%s: err %v, calls %d, page %s", name, err, roundTripper.calls(), page.Raw)
		}
		if name == "no foundry token" && strings.Contains(string(page.Raw), `"agents"`) {
			t.Errorf("%s: the account states an agents status", name)
		}
	}
}

func TestMicrosoftRAIModerationAndProjectHost(t *testing.T) {
	yes, no := true, false
	for name, test := range map[string]struct {
		filters []microsoftRAIFilter
		want    string
	}{
		"no harm filter":      {[]microsoftRAIFilter{{Name: "Jailbreak", Enabled: &no}}, ""},
		"all strict":          {[]microsoftRAIFilter{{Name: "Hate", Enabled: &yes, Blocking: &yes, SeverityThreshold: "Low"}, {Name: "self_harm", Enabled: &yes, Blocking: &yes, SeverityThreshold: "low"}}, "high"},
		"default":             {[]microsoftRAIFilter{{Name: "Hate", Enabled: &yes, Blocking: &yes, SeverityThreshold: "Medium"}, {Name: "Sexual", Enabled: &yes, Blocking: &yes, SeverityThreshold: "Low"}}, "medium"},
		"switched off":        {[]microsoftRAIFilter{{Name: "Violence", Enabled: &no, Blocking: &yes, SeverityThreshold: "Low"}}, "low"},
		"annotates only":      {[]microsoftRAIFilter{{Name: "Hate", Enabled: &yes, Blocking: &no, SeverityThreshold: "Low"}}, "low"},
		"high severity only":  {[]microsoftRAIFilter{{Name: "Sexual", Enabled: &yes, Blocking: &yes, SeverityThreshold: "High"}}, "low"},
		"threshold not given": {[]microsoftRAIFilter{{Name: "Hate", Enabled: &yes, Blocking: &yes}}, "medium"},
	} {
		if got := microsoftRAIModeration(test.filters); got != test.want {
			t.Errorf("%s = %q, want %q", name, got, test.want)
		}
	}
	for name, test := range map[string]struct {
		endpoints map[string]string
		subdomain string
		want      string
	}{
		"stated":              {map[string]string{"AI Foundry API": "https://contoso.services.ai.azure.com/api/projects/support"}, "", "contoso.services.ai.azure.com"},
		"another project":     {map[string]string{"AI Foundry API": "https://contoso.services.ai.azure.com/api/projects/other"}, "fallback", "fallback.services.ai.azure.com"},
		"another domain":      {map[string]string{"AI Foundry API": "https://contoso.example.com/api/projects/support"}, "", ""},
		"plain http":          {map[string]string{"AI Foundry API": "http://contoso.services.ai.azure.com/api/projects/support"}, "", ""},
		"a port":              {map[string]string{"AI Foundry API": "https://contoso.services.ai.azure.com:8443/api/projects/support"}, "", ""},
		"a hostile subdomain": {nil, "contoso.example.com/x", ""},
		"nothing":             {nil, "", ""},
	} {
		if got := microsoftFoundryProjectHost(test.endpoints, "support", test.subdomain); got != test.want {
			t.Errorf("%s = %q, want %q", name, got, test.want)
		}
	}
	// A Foundry token comes only with a Resource Manager token, before it.
	for name, credential := range map[string]string{
		"ai without arm": `{"ai_token":"` + microsoftTestAIToken + `","graph_token":"` + microsoftTestGraphToken + `"}`,
		"ai after arm":   `{"arm_token":"` + microsoftTestARMToken + `","ai_token":"` + microsoftTestAIToken + `","graph_token":"` + microsoftTestGraphToken + `"}`,
		"two ai tokens":  `{"ai_token":"` + microsoftTestAIToken + `","ai_token":"` + microsoftTestAIToken + `","arm_token":"` + microsoftTestARMToken + `","graph_token":"` + microsoftTestGraphToken + `"}`,
		"short ai token": `{"ai_token":"short","arm_token":"` + microsoftTestARMToken + `","graph_token":"` + microsoftTestGraphToken + `"}`,
	} {
		if _, ok := decodeMicrosoftCredential([]byte(credential)); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if envelope, ok := decodeMicrosoftCredential(microsoftTestFoundryCredential); !ok || string(envelope.aiToken) != microsoftTestAIToken || string(envelope.armToken) != microsoftTestARMToken || string(envelope.graphToken) != microsoftTestGraphToken {
		t.Errorf("the Foundry credential is refused")
	}
}
