package providercollection

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
)

var discoveredAgentSchemaCases = []struct {
	provider collection.Provider
	subject  collection.SubjectBinding
	kind     string
	stable   string
	extra    string
	agent    bool
}{
	{collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, "aws_bedrock_agent", `{"account_id":"123456789012","agent_id":"AGENT12345","arn":"arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345","name":"support","region":"us-east-1"}`, `"model":"anthropic.claude","state":"PREPARED",`, true},
	{collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, "aws_agentcore_runtime", `{"account_id":"123456789012","arn":"arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1","name":"rt","region":"us-east-1","runtime_id":"rt-1"}`, `"state":"READY",`, true},
	{collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, "aws_agentcore_gateway", `{"account_id":"123456789012","arn":"arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1","gateway_id":"gw-1","name":"gw","region":"us-east-1"}`, `"state":"READY"`, false},
	{collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, "aws_inferred_agent", `{"account_id":"123456789012","arn":"arn:aws:lambda:us-east-1:123456789012:function:bot","name":"bot","region":"us-east-1","resource_type":"lambda_function"}`, ``, true},
	{collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, "kubernetes_inferred_agent", `{"api_group":"apps","api_version":"v1","cluster":"api.example.com/production","name":"bot","namespace":"production","resource_kind":"Deployment","service_account":"bot"}`, `"namespaced":true,`, true},
	{collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "42"}, "github_agent_project", `{"installation_id":42,"name":"acme/service","owner":"acme","repository":"service"}`, ``, true},
	{collection.ProviderOkta, collection.SubjectBinding{Kind: "okta_tenant", ID: "tenant.example.com"}, "okta_ai_application", `{"name":"ChatGPT","object_type":"application","tenant":"tenant.example.com"}`, `"status":"ACTIVE",`, true},
}

func discoveredAgentAttributesJSON(t *testing.T, extra string, agent bool, discovery string) string {
	t.Helper()
	if !agent {
		return "{" + extra + "}"
	}
	posture, err := json.Marshal(agentsignals.Posture{})
	if err != nil {
		t.Fatal(err)
	}
	return "{" + extra + `"discovery":` + discovery + `,"posture":` + string(posture) + "}"
}

func TestProviderSchemaAcceptsDiscoveredAgentKinds(t *testing.T) {
	t.Parallel()
	for index, test := range discoveredAgentSchemaCases {
		rule, found := inventoryprojection.LookupRule(string(test.provider), test.kind)
		if !found || (rule.ProductKind == inventoryprojection.KindAgent) != test.agent {
			t.Fatalf("%s rule = %+v, found=%t", test.kind, rule, found)
		}
		attributes := discoveredAgentAttributesJSON(t, test.extra, test.agent, `{"method":"inferred","platform":"example_platform","signals":["env:openai","package:langgraph"]}`)
		entity := json.RawMessage(fmt.Sprintf(`{"id":"pid_47000000-0000-4000-8000-%012x","kind":%q,"source_native_id":"native-%d","display_name":"Item %d","stable_fields":%s,"attributes":%s}`, index+1, test.kind, index+1, index+1, test.stable, attributes))
		cursor := collection.Cursor{Provider: test.provider, Version: "cursor_v1", Value: "complete"}
		if _, err := NewPage(test.provider, test.subject, cursor, true, []json.RawMessage{entity}, nil); err != nil {
			t.Fatalf("%s rejected: %v\n%s", test.kind, err, entity)
		}
	}
}

func TestProviderSchemaRejectsMalformedAgentDiscovery(t *testing.T) {
	t.Parallel()
	test := discoveredAgentSchemaCases[4]
	cursor := collection.Cursor{Provider: test.provider, Version: "cursor_v1", Value: "complete"}
	many := make([]string, 17)
	for index := range many {
		many[index] = fmt.Sprintf(`"env:provider%02d"`, index)
	}
	for name, discovery := range map[string]string{
		"declared method":         `{"method":"declared","platform":"kubernetes_workload","signals":[]}`,
		"inferred without signal": `{"method":"inferred","platform":"kubernetes_workload","signals":[]}`,
		"unsorted signals":        `{"method":"inferred","platform":"kubernetes_workload","signals":["package:langgraph","env:openai"]}`,
		"duplicate signals":       `{"method":"inferred","platform":"kubernetes_workload","signals":["env:openai","env:openai"]}`,
		"provider value":          `{"method":"inferred","platform":"kubernetes_workload","signals":["env:OPENAI_API_KEY=sk-live"]}`,
		"no class":                `{"method":"inferred","platform":"kubernetes_workload","signals":["openai"]}`,
		"too many":                `{"method":"inferred","platform":"kubernetes_workload","signals":[` + strings.Join(many, ",") + `]}`,
		"extra member":            `{"method":"inferred","platform":"kubernetes_workload","signals":["env:openai"],"value":"x"}`,
		"bad platform":            `{"method":"inferred","platform":"Kubernetes Workload","signals":["env:openai"]}`,
		"not an object":           `"inferred"`,
	} {
		attributes := discoveredAgentAttributesJSON(t, test.extra, true, discovery)
		entity := json.RawMessage(fmt.Sprintf(`{"id":"pid_47100000-0000-4000-8000-000000000001","kind":%q,"source_native_id":"deployment/bot","display_name":"production/bot","stable_fields":%s,"attributes":%s}`, test.kind, test.stable, attributes))
		if _, err := NewPage(test.provider, test.subject, cursor, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	// A discovered agent without posture or discovery is refused, and a tool
	// may not carry them.
	for name, attributes := range map[string]string{
		"agent without discovery": `{"namespaced":true,"posture":` + mustJSON(t, agentsignals.Posture{}) + `}`,
		"agent without posture":   `{"namespaced":true,"discovery":{"method":"inferred","platform":"kubernetes_workload","signals":["env:openai"]}}`,
	} {
		entity := json.RawMessage(fmt.Sprintf(`{"id":"pid_47100000-0000-4000-8000-000000000002","kind":%q,"source_native_id":"deployment/bot","display_name":"production/bot","stable_fields":%s,"attributes":%s}`, test.kind, test.stable, attributes))
		if _, err := NewPage(test.provider, test.subject, cursor, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	gateway := discoveredAgentSchemaCases[2]
	entity := json.RawMessage(fmt.Sprintf(`{"id":"pid_47100000-0000-4000-8000-000000000003","kind":%q,"source_native_id":"gw","display_name":"gw","stable_fields":%s,"attributes":{"discovery":{"method":"provider_api","platform":"agentcore_gateway","signals":[]}}}`, gateway.kind, gateway.stable))
	if _, err := NewPage(gateway.provider, gateway.subject, collection.Cursor{Provider: gateway.provider, Version: "cursor_v1", Value: "complete"}, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
		t.Fatalf("gateway with discovery: error = %v", err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestProviderSchemaAllowsDiscoveredAgentRelationships(t *testing.T) {
	t.Parallel()
	for provider, triples := range map[collection.Provider][]string{
		collection.ProviderAWS:        {"aws_account|contains|aws_bedrock_agent", "aws_account|contains|aws_agentcore_runtime", "aws_account|contains|aws_agentcore_gateway", "aws_account|contains|aws_inferred_agent", "aws_bedrock_agent|uses_identity|aws_role", "aws_agentcore_runtime|uses_identity|aws_role", "aws_inferred_agent|uses_identity|aws_role"},
		collection.ProviderKubernetes: {"kubernetes_namespace|attached_to|kubernetes_inferred_agent", "kubernetes_inferred_agent|uses_identity|kubernetes_service_account"},
		collection.ProviderGitHub:     {"github_repository|contains|github_agent_project"},
		collection.ProviderOkta:       {"okta_tenant|contains|okta_ai_application", "okta_group|assigned_to|okta_ai_application", "okta_user|assigned_to|okta_ai_application", "okta_service_principal|assigned_to|okta_ai_application"},
	} {
		for _, triple := range triples {
			parts := strings.Split(triple, "|")
			attributes := `{"type":"x"}`
			if provider == collection.ProviderAWS {
				attributes = `{}`
			}
			relationship := json.RawMessage(fmt.Sprintf(`{"id":"pid_47200000-0000-4000-8000-000000000001","kind":%q,"source_native_id":"a|b","from_entity_id":"pid_47200000-0000-4000-8000-000000000002","to_entity_id":"pid_47200000-0000-4000-8000-000000000003","attributes":%s}`, parts[1], attributes))
			if !validProviderRelationship(provider, relationship) || !validProviderRelationshipEndpointKinds(provider, relationship, parts[0], parts[2]) {
				t.Errorf("%s: %s refused", provider, triple)
			}
			if validProviderRelationshipEndpointKinds(provider, relationship, parts[2], parts[0]) {
				t.Errorf("%s: reversed %s accepted", provider, triple)
			}
		}
	}
}
