package microsoftdiscovery

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
	microsoftTestARMToken = "arm-token-sentinel-value-0003"
	azureSubscriptionA    = "aaaaaaaa-0000-4000-8000-00000000000a"
	azureSubscriptionB    = "bbbbbbbb-0000-4000-8000-00000000000b"
	azureSubscriptions    = `{"value":[{"id":"/subscriptions/BBBBBBBB-0000-4000-8000-00000000000B","subscriptionId":"BBBBBBBB-0000-4000-8000-00000000000B","displayName":"Research","state":"Enabled"},` +
		`{"id":"/subscriptions/aaaaaaaa-0000-4000-8000-00000000000a","subscriptionId":"aaaaaaaa-0000-4000-8000-00000000000a","displayName":"Production","state":"Enabled"},` +
		`{"id":"/subscriptions/cccccccc-0000-4000-8000-00000000000c","subscriptionId":"cccccccc-0000-4000-8000-00000000000c","displayName":"Closed","state":"Disabled"}]}`
)

var microsoftTestARMCredential = []byte(`{"arm_token":"` + microsoftTestARMToken + `","graph_token":"` + microsoftTestGraphToken + `"}`)

func azureAccount(subscription, name, kind, extra string) string {
	return `{"id":"/subscriptions/` + subscription + `/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/` + name + `","name":"` + name + `","type":"Microsoft.CognitiveServices/accounts","kind":"` + kind + `","location":"eastus",` +
		`"properties":{"provisioningState":"Succeeded","endpoint":"https://` + name + `.openai.azure.com/","publicNetworkAccess":"Enabled","disableLocalAuth":false,"apiProperties":{"secret":"` + microsoftTestARMToken + `-not-kept"}` + extra + `}}`
}

// The whole collection of a tenant whose application has a role in two
// Azure subscriptions, through the collection client to a typed snapshot:
// the Azure OpenAI and AI Foundry accounts with their model deployments,
// read from Resource Manager only.
func TestMicrosoftCollectionClientCompletesATypedSnapshotWithAzureAIResources(t *testing.T) {
	t.Parallel()
	accountsA := "https://management.azure.com/subscriptions/" + azureSubscriptionA + "/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01"
	api, roundTripper := newMicrosoftTestAPI(t,
		microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty),
		// Subscription A, first page: an Azure OpenAI account with two
		// deployments, and a speech account that is not inventory.
		microsoftOK(azureSubscriptions),
		microsoftOK(`{"nextLink":`+string(mustMicrosoftJSON(t, accountsA+"&$skiptoken=page2"))+`,"value":[`+azureAccount(azureSubscriptionA, "contoso-openai", "OpenAI", "")+`,`+azureAccount(azureSubscriptionA, "contoso-speech", "SpeechServices", "")+`]}`),
		microsoftOK(`{"value":[{"id":"x","name":"gpt-4o","properties":{"model":{"format":"OpenAI","name":"gpt-4o","version":"2024-08-06"},"provisioningState":"Succeeded"}},{"id":"y","name":"embed","properties":{"model":{"format":"OpenAI","name":"text-embedding-3-large","version":"1"},"provisioningState":"Creating"}}]}`),
		// Subscription A, second page: a Foundry account whose deployments
		// the role may not read.
		microsoftOK(azureSubscriptions),
		microsoftOK(`{"value":[`+azureAccount(azureSubscriptionA, "contoso-foundry", "AIServices", `,"unknownMember":1`)+`]}`),
		microsoftHTTPResponse{status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed"}}`},
		// Subscription B: no AI account.
		microsoftOK(azureSubscriptions),
		microsoftOK(`{"value":[]}`),
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
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderMicrosoft, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialMicrosoftClient, CredentialReference: "ref:microsoft/connection/customer-0001", ExpectedSubject: microsoftTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	outcome, err := client.CollectWithCredential(context.Background(), request, bytes.Clone(microsoftTestARMCredential))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	assertMicrosoftRequestURLs(t, roundTripper,
		"https://graph.microsoft.com/v1.0/organization?$select=id,displayName",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100",
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100",
		"https://management.azure.com/subscriptions?api-version=2022-12-01",
		accountsA,
		"https://management.azure.com/subscriptions/"+azureSubscriptionA+"/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/contoso-openai/deployments?api-version=2023-05-01",
		"https://management.azure.com/subscriptions?api-version=2022-12-01",
		accountsA+"&$skiptoken=page2",
		"https://management.azure.com/subscriptions/"+azureSubscriptionA+"/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/contoso-foundry/deployments?api-version=2023-05-01",
		"https://management.azure.com/subscriptions?api-version=2022-12-01",
		"https://management.azure.com/subscriptions/"+azureSubscriptionB+"/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01",
	)
	for index, sent := range roundTripper.requests {
		want := microsoftTestGraphToken
		if index >= 3 {
			want = microsoftTestARMToken
		}
		if sent.Header.Get("Authorization") != "Bearer "+want {
			t.Fatalf("request %d carries the wrong token", index)
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
		if entity.Kind == "microsoft_tenant" {
			continue
		}
		if entity.ProductKind != "asset" || entity.ConfidenceBasisPoints != 9500 {
			t.Fatalf("envelope of %s = %s %d", entity.DisplayName, entity.ProductKind, entity.ConfidenceBasisPoints)
		}
		got[entity.Kind+" "+entity.DisplayName] = string(entity.StableFields) + string(entity.Attributes)
	}
	want := map[string]string{
		"microsoft_ai_resource contoso-openai": `{"name":"contoso-openai","object_type":"azure_ai_account","region":"eastus","subscription":"` + azureSubscriptionA + `","tenant":"` + microsoftTestTenant + `"}` +
			`{"deployments":"listed","endpoint_host":"contoso-openai.openai.azure.com","local_auth_disabled":false,"public_network_access":"enabled","resource_kind":"azure_openai","status":"SUCCEEDED"}`,
		"microsoft_ai_resource contoso-foundry": `{"name":"contoso-foundry","object_type":"azure_ai_account","region":"eastus","subscription":"` + azureSubscriptionA + `","tenant":"` + microsoftTestTenant + `"}` +
			`{"deployments":"not_listed","endpoint_host":"contoso-foundry.openai.azure.com","local_auth_disabled":false,"public_network_access":"enabled","resource_kind":"azure_ai_foundry","status":"SUCCEEDED"}`,
		"microsoft_ai_deployment contoso-openai/gpt-4o": `{"name":"gpt-4o","object_type":"azure_ai_deployment","resource":"contoso-openai","subscription":"` + azureSubscriptionA + `","tenant":"` + microsoftTestTenant + `"}` +
			`{"model":"gpt-4o","model_version":"2024-08-06","status":"SUCCEEDED"}`,
		"microsoft_ai_deployment contoso-openai/embed": `{"name":"embed","object_type":"azure_ai_deployment","resource":"contoso-openai","subscription":"` + azureSubscriptionA + `","tenant":"` + microsoftTestTenant + `"}` +
			`{"model":"text-embedding-3-large","model_version":"1","status":"CREATING"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("azure entities = %v", got)
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Fatalf("%s\n got %s\nwant %s", name, got[name], expected)
		}
	}
	if snapshot.RelationshipCount() != 4 {
		t.Fatalf("relationships = %d", snapshot.RelationshipCount())
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(microsoftTestGraphToken)) || bytes.Contains(object.Body, []byte(microsoftTestARMToken)) || bytes.Contains(object.Body, []byte("apiProperties")) {
			t.Fatalf("artifact %s stores a token or an unread member", key)
		}
	}
}

// An application with no Azure role, a refusal later in the phase, and a
// credential without a Resource Manager token.
func TestMicrosoftAzurePhaseIsOptionalAndBounded(t *testing.T) {
	t.Parallel()
	// Refused on the first Resource Manager call: the phase ends, the
	// collection completes with the tenant alone.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty), microsoftHTTPResponse{status: status, body: `{}`})
		pages := collectMicrosoftPages(t, api, microsoftTestARMCredential, microsoftTestRequest(), 8)
		if len(pages) != 4 || !pages[3].Complete || len(pages[3].Entities) != 0 || roundTripper.calls() != 4 {
			t.Fatalf("status %d: pages=%d calls=%d", status, len(pages), roundTripper.calls())
		}
	}
	// No subscription is visible: nothing to read.
	api, _ := newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty), microsoftOK(`{"value":[]}`))
	if pages := collectMicrosoftPages(t, api, microsoftTestARMCredential, microsoftTestRequest(), 8); len(pages) != 4 || !pages[3].Complete {
		t.Fatalf("no subscriptions: pages=%d", len(pages))
	}
	// Without the token the phase does not exist: three calls, no Resource Manager.
	api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty))
	if pages := collectMicrosoftPages(t, api, []byte(`{"graph_token":"`+microsoftTestGraphToken+`"}`), microsoftTestRequest(), 8); len(pages) != 3 || !pages[2].Complete || roundTripper.calls() != 3 {
		t.Fatalf("graph only: pages=%d calls=%d", len(pages), roundTripper.calls())
	}
	// A refusal on a later page of the phase is a failure, not a skip.
	later := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseAzure, Lineage: 2, Subscription: azureSubscriptionA})
	api, _ = newMicrosoftTestAPI(t, microsoftHTTPResponse{status: http.StatusForbidden, body: `{}`})
	request := microsoftTestRequest()
	request.Cursor, request.Page = later, 2
	var failure *collection.Failure
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestARMCredential), request); !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("later refusal = %v", err)
	}
	// An azure cursor with a credential that carries no Resource Manager token is refused.
	api, roundTripper = newMicrosoftTestAPI(t)
	if _, err := api.FetchCollectionPage(context.Background(), []byte(`{"graph_token":"`+microsoftTestGraphToken+`"}`), request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
		t.Fatalf("azure page without the token = %v", err)
	}
	// Malformed account ids, an account of another subscription and a
	// continuation that leaves the host are refused.
	for name, accounts := range map[string]string{
		"another subscription": `{"value":[` + azureAccount(azureSubscriptionB, "contoso-openai", "OpenAI", "") + `]}`,
		"id with a query":      `{"value":[` + strings.Replace(azureAccount(azureSubscriptionA, "contoso-openai", "OpenAI", ""), "accounts/contoso-openai\"", "accounts/contoso-openai?x=1\"", 1) + `]}`,
		"foreign next link":    `{"nextLink":"https://evil.example/subscriptions?$skiptoken=x","value":[]}`,
	} {
		api, _ := newMicrosoftTestAPI(t, microsoftOK(azureSubscriptions), microsoftOK(accounts))
		if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestARMCredential), request); !errors.As(err, &failure) || failure.Code() != collection.FailureMalformed {
			t.Fatalf("%s = %v", name, err)
		}
	}
}

func TestMicrosoftCredentialEnvelopeWithResourceManagerToken(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		credential string
		arm, valid bool
	}{
		"graph only":            {`{"graph_token":"` + microsoftTestGraphToken + `"}`, false, true},
		"arm and graph":         {string(microsoftTestARMCredential), true, true},
		"arm, dataverse, graph": {`{"arm_token":"` + microsoftTestARMToken + `","dataverse_token":"` + microsoftTestDataverseToken + `","dataverse_url":"https://org1.crm4.dynamics.com","graph_token":"` + microsoftTestGraphToken + `"}`, true, true},
		"arm after graph":       {`{"graph_token":"` + microsoftTestGraphToken + `","arm_token":"` + microsoftTestARMToken + `"}`, false, false},
		"arm alone":             {`{"arm_token":"` + microsoftTestARMToken + `"}`, false, false},
		"short arm token":       {`{"arm_token":"short","graph_token":"` + microsoftTestGraphToken + `"}`, false, false},
	} {
		envelope, ok := decodeMicrosoftCredential([]byte(test.credential))
		if ok != test.valid || ok && (envelope.armToken != nil) != test.arm || ok && test.arm && string(envelope.armToken) != microsoftTestARMToken {
			t.Errorf("%s: ok=%t arm=%q", name, ok, envelope.armToken)
		}
	}
}
