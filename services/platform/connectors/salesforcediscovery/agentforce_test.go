package salesforcediscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	salesforceTestAgentUser = "0055g00000AgentAAU"
	salesforceTestPlanner   = "16j5g0000004P1AAAU"
	salesforceTestTopicOne  = "0tq5g0000004T1AAAU"
	salesforceTestTopicTwo  = "0tq5g0000004T2AAAU"
	salesforceTestActionOne = "1795g0000004A1AAAU"
	salesforceTestActionTwo = "1795g0000004A2AAAU"

	salesforceNamedActiveVersion = `,"BotVersions":{"totalSize":1,"done":true,"records":[{"attributes":{"type":"BotVersion"},"Id":"0X95g0000004D1AAAU","DeveloperName":"v2"}]}`
)

func salesforceTrustResponse(settings string) *salesforceHTTPResponse {
	return &salesforceHTTPResponse{status: http.StatusOK, body: `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><readMetadataResponse><result><records xsi:type="EinsteinAISettings"><fullName>EinsteinAI</fullName>` +
		settings + `</records></result></readMetadataResponse></soapenv:Body></soapenv:Envelope>`}
}

func salesforceAgentforceResponses() []salesforceHTTPResponse {
	ok := func(body string) salesforceHTTPResponse {
		return salesforceHTTPResponse{status: http.StatusOK, body: body}
	}
	assignment := func(name string, profile, modify, view bool) string {
		return fmt.Sprintf(`{"attributes":{"type":"PermissionSetAssignment"},"AssigneeId":%q,"PermissionSet":{"attributes":{"type":"PermissionSet"},"Name":%q,"IsOwnedByProfile":%t,"PermissionsModifyAllData":%t,"PermissionsViewAllData":%t}}`, salesforceTestAgentUser, name, profile, modify, view)
	}
	return []salesforceHTTPResponse{
		ok(salesforceTestOrgBody),
		ok(salesforceQueryBody(true, "",
			salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"Type":"ExternalCopilot","AgentType":"EinsteinServiceAgent","BotUserId":"`+salesforceTestAgentUser+`"`+salesforceNamedActiveVersion),
			salesforceBotRecord(salesforceTestBotTwo, "Legacy_Bot", "", `,"Type":"Bot","AgentType":null,"BotUserId":null,"BotVersions":null`))),
		// The permission sets of the agent user: a profile, two permission
		// sets, one of which reads every record.
		ok(salesforceQueryBody(true, "", assignment("X00e5g000001AbCdAAK", true, false, false), assignment("Agentforce_Service_Agent_Secure_Base", false, false, false), assignment("Support_Data_Export", false, false, true))),
		// The planner of the active version, beside another agent's whose
		// name starts the same way.
		ok(salesforceQueryBody(true, "",
			`{"attributes":{"type":"GenAiPlannerDefinition"},"Id":"16j5g0000004P9AAAU","DeveloperName":"Support_Agent_Pilot_v2","PlannerType":"AiCopilot__ReAct"}`,
			`{"attributes":{"type":"GenAiPlannerDefinition"},"Id":"`+salesforceTestPlanner+`","DeveloperName":"Support_Agent_v2","PlannerType":"AiCopilot__ReAct"}`)),
		ok(salesforceQueryBody(true, "",
			`{"attributes":{"type":"GenAiPluginDefinition"},"Id":"`+salesforceTestTopicOne+`","DeveloperName":"Order_Inquiries_16j","MasterLabel":"Order Inquiries","PluginType":"Topic","Scope":"do-not-keep-scope"}`,
			`{"attributes":{"type":"GenAiPluginDefinition"},"Id":"`+salesforceTestTopicTwo+`","DeveloperName":"Escalation_16j","MasterLabel":null,"PluginType":"Topic"}`)),
		ok(salesforceQueryBody(true, "",
			`{"attributes":{"type":"GenAiFunctionDefinition"},"Id":"`+salesforceTestActionOne+`","DeveloperName":"Issue_Refund","MasterLabel":"Issue Refund","InvocationTargetType":"flow","IsConfirmationRequired":true,"PluginId":"`+salesforceTestTopicOne+`","Description":"do-not-keep-description"}`,
			`{"attributes":{"type":"GenAiFunctionDefinition"},"Id":"`+salesforceTestActionTwo+`","DeveloperName":"Run_Apex_Cleanup","MasterLabel":"Run Cleanup","InvocationTargetType":"apex","IsConfirmationRequired":false,"PluginId":"`+salesforceTestTopicOne+`"}`)),
	}
}

// The whole collection of an org with one Agentforce agent, to a typed
// snapshot: the agent with the user it runs as, that user's permission sets,
// the org's guardrail level, and its topics and actions as tools.
func TestSalesforceCollectionRecordsAnAgentsUserPermissionsGuardrailsAndTools(t *testing.T) {
	t.Parallel()
	api, roundTripper := newSalesforceTestAPI(t, salesforceAgentforceResponses()...)
	roundTripper.soap = salesforceTrustResponse(`<enableAIFeedbackWithDC>true</enableAIFeedbackWithDC><enableAITrustInputToxicityDetection>false</enableAITrustInputToxicityDetection><enableAITrustPromptInjectionDetection>false</enableAITrustPromptInjectionDetection><enableTrustPIIMasking>true</enableTrustPIIMasking>`)
	driver := &salesforceSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewSalesforceCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
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
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderSalesforce, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialSalesforceClient, CredentialReference: "ref:salesforce/connection/customer-0001", ExpectedSubject: salesforceTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 50, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	outcome, err := client.CollectWithCredential(context.Background(), request, salesforceTestCredential(salesforceTestToken, salesforceTestHost))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	snapshot := complete.Snapshot()
	// The org, two agents, two topics and two actions; each but the org has
	// one relationship.
	if !snapshot.TypedObservations() || snapshot.EntityCount() != 7 || snapshot.RelationshipCount() != 6 {
		t.Fatalf("snapshot entities=%d relationships=%d", snapshot.EntityCount(), snapshot.RelationshipCount())
	}
	var entities []struct {
		ID           string          `json:"id"`
		Kind         string          `json:"kind"`
		DisplayName  string          `json:"display_name"`
		StableFields json.RawMessage `json:"stable_fields"`
		Attributes   map[string]any  `json:"attributes"`
		ProductKind  string          `json:"product_kind"`
	}
	var relationships []struct {
		From       string `json:"from_entity_id"`
		To         string `json:"to_entity_id"`
		Attributes struct {
			Type string `json:"type"`
		} `json:"attributes"`
	}
	if json.Unmarshal(snapshot.Entities(), &entities) != nil || json.Unmarshal(snapshot.Relationships(), &relationships) != nil {
		t.Fatal("snapshot documents")
	}
	byName := map[string]int{}
	names := map[string]string{}
	for index, entity := range entities {
		byName[entity.Kind+" "+entity.DisplayName] = index
		names[entity.ID] = entity.DisplayName
	}
	org := entities[byName["salesforce_org Acme Corporation"]].Attributes
	if org["trust_input_toxicity_detection"] != "disabled" || org["trust_prompt_injection_detection"] != "disabled" || org["trust_pii_masking"] != "enabled" || len(org) != 3 {
		t.Fatalf("org = %v", org)
	}
	agent := entities[byName["salesforce_agent Support Agent"]].Attributes
	posture := agent["posture"].(map[string]any)
	if agent["run_as_user"] != salesforceTestAgentUser || agent["permission_sets"] != "Agentforce_Service_Agent_Secure_Base,Support_Data_Export" || agent["tools"] != "listed" || agent["content_moderation"] != "low" ||
		posture["sensitive_data_reach"] != true || posture["credential_active"] != true || posture["production_write"] != false {
		t.Fatalf("agent = %v", agent)
	}
	// An agent with no user and no active version has none of the facts but
	// the org's guardrail level.
	if legacy := entities[byName["salesforce_agent Legacy_Bot"]].Attributes; legacy["run_as_user"] != nil || legacy["permission_sets"] != nil || legacy["tools"] != nil || legacy["content_moderation"] != "low" {
		t.Fatalf("legacy agent = %v", legacy)
	}
	refund := entities[byName["salesforce_agent_tool Issue Refund"]]
	if refund.ProductKind != "tool" || refund.Attributes["target_type"] != "flow" || refund.Attributes["confirmation_required"] != true || refund.Attributes["status"] != "ACTIVE" || !strings.Contains(string(refund.StableFields), `"object_type":"agent_action"`) {
		t.Fatalf("action = %+v", refund)
	}
	if cleanup := entities[byName["salesforce_agent_tool Run Cleanup"]].Attributes; cleanup["target_type"] != "apex" || cleanup["confirmation_required"] != false {
		t.Fatalf("apex action = %v", cleanup)
	}
	// A topic without a label is shown by its API name.
	if _, found := byName["salesforce_agent_tool Escalation_16j"]; !found {
		t.Fatalf("entities = %v", byName)
	}
	var edges []string
	for _, relationship := range relationships {
		if relationship.Attributes.Type != "org_object" {
			edges = append(edges, names[relationship.From]+" -"+relationship.Attributes.Type+"-> "+names[relationship.To])
		}
	}
	for _, want := range []string{"Support Agent -agent_topic-> Order Inquiries", "Support Agent -agent_topic-> Escalation_16j", "Order Inquiries -topic_action-> Issue Refund", "Order Inquiries -topic_action-> Run Cleanup"} {
		if !strings.Contains(strings.Join(edges, "\n"), want) {
			t.Fatalf("relationships = %v", edges)
		}
	}
	// The queries, in order, and where each was sent.
	queries := []string{
		"SELECT Id,Name FROM Organization", salesforceAgentQueryVariants[0].soql,
		"SELECT AssigneeId,PermissionSet.Name,PermissionSet.IsOwnedByProfile,PermissionSet.PermissionsModifyAllData,PermissionSet.PermissionsViewAllData FROM PermissionSetAssignment WHERE AssigneeId IN ('" + salesforceTestAgentUser + "') ORDER BY AssigneeId,PermissionSetId",
		`SELECT Id,DeveloperName,PlannerType FROM GenAiPlannerDefinition WHERE DeveloperName LIKE 'Support\_Agent%\_v2'`,
		"SELECT Id,DeveloperName,MasterLabel,PluginType FROM GenAiPluginDefinition WHERE PlannerId = '" + salesforceTestPlanner + "' ORDER BY Id",
		"SELECT Id,DeveloperName,MasterLabel,InvocationTargetType,IsConfirmationRequired,PluginId FROM GenAiFunctionDefinition WHERE PluginId IN ('" + salesforceTestTopicOne + "','" + salesforceTestTopicTwo + "') ORDER BY Id",
	}
	if roundTripper.calls() != len(queries) {
		t.Fatalf("calls = %d", roundTripper.calls())
	}
	for index, sent := range roundTripper.requests {
		path := "/services/data/v62.0/query"
		if index >= 3 {
			path = "/services/data/v62.0/tooling/query"
		}
		if sent.Method != http.MethodGet || sent.URL.Host != "acme.my.salesforce.com" || sent.URL.Path != path || sent.URL.Query().Get("q") != queries[index] || sent.Header.Get("Authorization") != "Bearer "+salesforceTestToken {
			t.Fatalf("request %d = %s %s", index, sent.Method, sent.URL)
		}
	}
	// The Trust Layer read is one readMetadata call to the same host.
	if len(roundTripper.soapRequests) != 1 || roundTripper.soapRequests[0].Method != http.MethodPost || roundTripper.soapRequests[0].URL.String() != salesforceTestHost+"/services/Soap/m/66.0" || roundTripper.soapRequests[0].Header.Get("Authorization") != "" ||
		!strings.Contains(roundTripper.soapBodies[0], "<met:readMetadata><met:type>EinsteinAISettings</met:type><met:fullNames>EinsteinAI</met:fullNames></met:readMetadata>") || !strings.Contains(roundTripper.soapBodies[0], "<met:sessionId>"+salesforceTestToken+"</met:sessionId>") ||
		strings.Contains(roundTripper.soapBodies[0], "updateMetadata") || strings.Contains(roundTripper.soapBodies[0], "deploy") {
		t.Fatalf("metadata request = %v %s", roundTripper.soapRequests, roundTripper.soapBodies)
	}
	// No token and nothing that was not selected is stored.
	for key, object := range driver.objects {
		for _, value := range []string{salesforceTestToken, "do-not-keep", "X00e5g000001AbCdAAK"} {
			if bytes.Contains(object.Body, []byte(value)) {
				t.Fatalf("artifact %s stores %q", key, value)
			}
		}
	}
}

// Each optional read can be refused without failing the collection; an
// outage of one retries the page like the agents query.
func TestSalesforceOptionalReadsDegradeAndClassify(t *testing.T) {
	t.Parallel()
	responses := salesforceAgentforceResponses()
	refused := salesforceHTTPResponse{status: http.StatusBadRequest, body: salesforceErrorBody("INVALID_TYPE")}
	forbidden := salesforceHTTPResponse{status: http.StatusForbidden, body: `[{"errorCode":"API_DISABLED_FOR_ORG"}]`}
	for name, test := range map[string]struct {
		agentsPage []salesforceHTTPResponse
		want       []string
		absent     []string
	}{
		"assignments refused": {[]salesforceHTTPResponse{responses[1], refused, responses[3], responses[4], responses[5]}, []string{`"run_as_user":"` + salesforceTestAgentUser + `"`, `"tools":"listed"`, `"sensitive_data_reach":false`}, []string{"permission_sets"}},
		"tooling forbidden":   {[]salesforceHTTPResponse{responses[1], responses[2], forbidden}, []string{`"permission_sets":"Agentforce_Service_Agent_Secure_Base,Support_Data_Export"`, `"tools":"not_listed"`}, []string{"salesforce_agent_tool"}},
		"no planner":          {[]salesforceHTTPResponse{responses[1], responses[2], {status: http.StatusOK, body: salesforceQueryBody(true, "")}}, []string{`"tools":"not_listed"`}, []string{"salesforce_agent_tool"}},
		"ambiguous planner": {[]salesforceHTTPResponse{responses[1], responses[2], {status: http.StatusOK, body: salesforceQueryBody(true, "",
			`{"Id":"16j5g0000004P8AAAU","DeveloperName":"Support_Agent_Pilot_v2","PlannerType":"x"}`, `{"Id":"16j5g0000004P9AAAU","DeveloperName":"Support_Agent_Beta_v2","PlannerType":"x"}`)}}, []string{`"tools":"not_listed"`}, []string{"salesforce_agent_tool"}},
		"topics refused":  {[]salesforceHTTPResponse{responses[1], responses[2], responses[3], refused}, []string{`"tools":"not_listed"`}, []string{"salesforce_agent_tool"}},
		"actions refused": {[]salesforceHTTPResponse{responses[1], responses[2], responses[3], responses[4], refused}, []string{`"tools":"partial"`, `"object_type":"agent_topic"`}, []string{"agent_action"}},
	} {
		api, roundTripper := newSalesforceTestAPI(t, test.agentsPage...)
		page, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceAgentsRequest(t))
		if err != nil || !page.Complete || roundTripper.calls() != len(test.agentsPage) {
			t.Errorf("%s: err %v, calls %d", name, err, roundTripper.calls())
			continue
		}
		for _, want := range test.want {
			if !strings.Contains(string(page.Raw), want) {
				t.Errorf("%s: page lacks %s: %s", name, want, page.Raw)
			}
		}
		for _, absent := range test.absent {
			if strings.Contains(string(page.Raw), absent) {
				t.Errorf("%s: page holds %s", name, absent)
			}
		}
	}
	// A rate limit of an optional read is a rate limit of the page.
	api, _ := newSalesforceTestAPI(t, responses[1], salesforceHTTPResponse{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"30"}}, body: `[]`})
	_, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceAgentsRequest(t))
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureRateLimited {
		t.Fatalf("rate limited optional read: %v", err)
	}
}

func TestSalesforceTrustSettingsAreReadOnlyFromAReadableRecord(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		response *salesforceHTTPResponse
		want     string
		org      string
	}{
		"refused":       {nil, "", `"attributes":{}`},
		"both on":       {salesforceTrustResponse(`<enableAITrustInputToxicityDetection>true</enableAITrustInputToxicityDetection><enableAITrustPromptInjectionDetection>true</enableAITrustPromptInjectionDetection>`), "high", `"trust_input_toxicity_detection":"enabled"`},
		"one on":        {salesforceTrustResponse(`<enableAITrustInputToxicityDetection>true</enableAITrustInputToxicityDetection><enableAITrustPromptInjectionDetection>false</enableAITrustPromptInjectionDetection>`), "medium", `"trust_prompt_injection_detection":"disabled"`},
		"one stated":    {salesforceTrustResponse(`<enableTrustPIIMasking>false</enableTrustPIIMasking>`), "", `"attributes":{"trust_pii_masking":"disabled"}`},
		"no record":     {salesforceTrustResponse(``), "", `"attributes":{}`},
		"not a boolean": {salesforceTrustResponse(`<enableAITrustInputToxicityDetection>maybe</enableAITrustInputToxicityDetection>`), "", `"attributes":{}`},
		"stated twice":  {salesforceTrustResponse(`<enableTrustPIIMasking>false</enableTrustPIIMasking><enableTrustPIIMasking>true</enableTrustPIIMasking>`), "", `"attributes":{}`},
		"not xml":       {&salesforceHTTPResponse{status: http.StatusOK, body: `{"enableTrustPIIMasking":true}`}, "", `"attributes":{}`},
	} {
		api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
		roundTripper.soap = test.response
		page, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceInitialRequest())
		if err != nil || !strings.Contains(string(page.Raw), test.org) {
			t.Errorf("%s: err %v, page %s", name, err, page.Raw)
			continue
		}
		// The level travels in the cursor to the agents pages.
		state, ok := validSalesforcePageRequest(CollectionPageRequest{Provider: collection.ProviderSalesforce, Subject: salesforceTestSubject, Cursor: page.Cursor, Page: 2, RemainingItems: 10, RemainingRelationships: 10, RemainingBytes: 1 << 20})
		if !ok || state.Moderation != test.want {
			t.Errorf("%s: cursor moderation = %q (%t), want %q", name, state.Moderation, ok, test.want)
		}
	}
}
