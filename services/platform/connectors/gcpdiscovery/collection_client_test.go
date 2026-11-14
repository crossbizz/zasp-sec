package gcpdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	gcpTestToken = "gcptest-access-token-0123456789abcdef"
	// What must never leave the provider: values of environment variables
	// and the address of a person.
	gcpTestSecretValue = "ENV-VALUE-MUST-NOT-LEAK"
	gcpTestPerson      = "alice@example.com"
)

var (
	gcpTestSubject    = collection.SubjectBinding{Kind: "gcp_scope", ID: "organizations/123456789012"}
	gcpTestCredential = []byte(`{"access_token":"` + gcpTestToken + `"}`)
)

// fakeGoogle is a fake of the Google APIs the collector reads: a real HTTP
// server whose routes are "host path" of the request the collector meant to
// send. Every request must carry the test token.
type fakeGoogle struct {
	t      *testing.T
	mutex  sync.Mutex
	routes map[string]fakeGoogleRoute
	calls  map[string]int
	server *httptest.Server
}

type fakeGoogleRoute struct {
	status int
	body   string
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	fake := &fakeGoogle{t: t, routes: map[string]fakeGoogleRoute{}, calls: map[string]int{}}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		key := request.Header.Get("X-Fake-Host") + " " + request.URL.Path
		body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		fake.mutex.Lock()
		route, found := fake.routes[key]
		// A route "host path#text" answers a request whose body holds text.
		for candidate, value := range fake.routes {
			if text, isBodyRoute := strings.CutPrefix(candidate, key+"#"); isBodyRoute && bytes.Contains(body, []byte(text)) {
				route, found = value, true
			}
		}
		fake.calls[key]++
		fake.mutex.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer "+gcpTestToken {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`)
			return
		}
		if !found {
			// Like Google: a location or resource that is not there.
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"error":{"code":404,"status":"NOT_FOUND"}}`)
			return
		}
		writer.WriteHeader(route.status)
		_, _ = io.WriteString(writer, route.body)
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeGoogle) ok(host, path, body string) {
	fake.routes[host+" "+path] = fakeGoogleRoute{http.StatusOK, body}
}

func (fake *fakeGoogle) denied(host, path string) {
	fake.routes[host+" "+path] = fakeGoogleRoute{http.StatusForbidden, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"IAM_PERMISSION_DENIED","domain":"iam.googleapis.com"}]}}`}
}

func (fake *fakeGoogle) disabled(host, path string) {
	fake.routes[host+" "+path] = fakeGoogleRoute{http.StatusForbidden, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED","domain":"googleapis.com"}]}}`}
}

// RoundTrip sends the request to the fake server, keeping the host the
// collector addressed in a header.
func (fake *fakeGoogle) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, errors.New("the collector must use https")
	}
	clone := request.Clone(request.Context())
	clone.Header.Set("X-Fake-Host", request.URL.Host)
	target := *request.URL
	target.Scheme, target.Host = "http", strings.TrimPrefix(fake.server.URL, "http://")
	clone.URL, clone.Host = &target, target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func (fake *fakeGoogle) called(host, path string) int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return fake.calls[host+" "+path]
}

// gcpTestOrganization fills the fake with one organization: alpha-prod under
// a folder, with every kind of object; beta-locked, which refuses or has
// switched off every API; and a project of another organization.
func gcpTestOrganization(t *testing.T, now time.Time) *fakeGoogle {
	fake := newFakeGoogle(t)
	crm := gcpResourceManagerHost
	fake.ok(crm, "/v3/organizations/123456789012", `{"name":"organizations/123456789012","displayName":"Acme","state":"ACTIVE"}`)
	fake.ok(crm, "/v3/projects:search", `{"projects":[
		{"name":"projects/333","projectId":"other-org-proj","parent":"folders/900","state":"ACTIVE","displayName":"Elsewhere"},
		{"name":"projects/222","projectId":"beta-locked","parent":"organizations/123456789012","state":"ACTIVE","displayName":"Beta"},
		{"name":"projects/444","projectId":"going-away","parent":"organizations/123456789012","state":"DELETE_REQUESTED","displayName":"Gone"},
		{"name":"projects/555","projectId":"gamma-shared","parent":"organizations/123456789012","state":"ACTIVE","displayName":"Shared"},
		{"name":"projects/111","projectId":"alpha-prod","parent":"folders/700","state":"ACTIVE","displayName":"Alpha production"}]}`)
	// The folder above alpha-prod makes the invoking service account a
	// folder administrator; the organization's policy may not be read.
	fake.ok(crm, "/v3/folders/700:getIamPolicy", `{"bindings":[{"role":"roles/resourcemanager.folderAdmin","members":["serviceAccount:batch-invoker@alpha-prod.iam.gserviceaccount.com","user:`+gcpTestPerson+`"]}]}`)
	fake.denied(crm, "/v3/organizations/123456789012:getIamPolicy")
	// gamma-shared holds a service account a workload of alpha-prod runs as.
	const shared = "shared-runner@gamma-shared.iam.gserviceaccount.com"
	fake.ok(crm, "/v3/projects/gamma-shared", `{"name":"projects/555","projectId":"gamma-shared","parent":"organizations/123456789012","state":"ACTIVE","displayName":"Shared"}`)
	fake.ok(gcpIAMHost, "/v1/projects/gamma-shared/serviceAccounts", `{"accounts":[{"email":"`+shared+`"}]}`)
	fake.ok(gcpIAMHost, "/v1/projects/gamma-shared/serviceAccounts/"+shared, `{"email":"`+shared+`"}`)
	fake.ok(crm, "/v3/folders/700", `{"name":"folders/700","parent":"organizations/123456789012","state":"ACTIVE"}`)
	fake.ok(crm, "/v3/folders/900", `{"name":"folders/900","parent":"organizations/999999999999","state":"ACTIVE"}`)

	// alpha-prod
	runner, compute, invoker := "agent-runner@alpha-prod.iam.gserviceaccount.com", "111-compute@developer.gserviceaccount.com", "batch-invoker@alpha-prod.iam.gserviceaccount.com"
	fake.ok(gcpIAMHost, "/v1/projects/alpha-prod/serviceAccounts", `{"accounts":[{"email":"`+runner+`"},{"email":"`+compute+`"},{"email":"`+invoker+`","disabled":false},{"email":"unused@alpha-prod.iam.gserviceaccount.com"}]}`)
	fake.ok(crm, "/v3/projects/alpha-prod:getIamPolicy", `{"version":3,"bindings":[
		{"role":"roles/owner","members":["serviceAccount:`+runner+`","user:`+gcpTestPerson+`"]},
		{"role":"roles/editor","members":["serviceAccount:`+compute+`"]},
		{"role":"roles/aiplatform.user","members":["serviceAccount:`+runner+`","serviceAccount:`+invoker+`"]}]}`)
	fake.ok(gcpAIPlatformHost, "/v1/projects/alpha-prod/locations", `{"locations":[{"locationId":"us-central1"},{"locationId":"europe-west4"},{"locationId":"global"}]}`)
	fake.ok("us-central1-"+gcpAIPlatformHost, "/v1/projects/alpha-prod/locations/us-central1/reasoningEngines", `{"reasoningEngines":[{"name":"projects/111/locations/us-central1/reasoningEngines/8001","displayName":"Refund agent",
		"spec":{"agentFramework":"google-adk","serviceAccount":"`+runner+`","identityType":"SERVICE_ACCOUNT","deploymentSpec":{"env":[{"name":"OPENAI_API_KEY","value":"`+gcpTestSecretValue+`"}]}}}]}`)
	fake.ok("us-central1-"+gcpAIPlatformHost, "/v1/projects/alpha-prod/locations/us-central1/endpoints", `{"endpoints":[{"name":"projects/111/locations/us-central1/endpoints/5001","displayName":"Tuned model",
		"deployedModels":[{"id":"7001","model":"projects/111/locations/us-central1/models/42","modelVersionId":"3","displayName":"tuned-v3","serviceAccount":"`+runner+`"}]}]}`)
	fake.ok("europe-west4-"+gcpAIPlatformHost, "/v1/projects/alpha-prod/locations/europe-west4/reasoningEngines", `{}`)
	fake.ok("europe-west4-"+gcpAIPlatformHost, "/v1/projects/alpha-prod/locations/europe-west4/endpoints", `{}`)
	fake.ok(gcpDialogflowHost, "/v3/projects/alpha-prod/locations", `{"locations":[{"locationId":"global"}]}`)
	fake.ok(gcpDialogflowHost, "/v3/projects/alpha-prod/locations/global/agents", `{"agents":[{"name":"projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001","displayName":"Order status"}]}`)
	fake.ok(gcpDialogflowHost, "/v3/projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001/tools", `{"tools":[
		{"name":"projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001/tools/t-1","displayName":"run_shell","description":"`+gcpTestSecretValue+`","openApiSpec":{"textSchema":"`+gcpTestSecretValue+`"}},
		{"name":"projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001/tools/t-2","displayName":"lookup order"}]}`)
	engine := "/v1alpha/projects/alpha-prod/locations/global/collections/default_collection/engines"
	fake.ok(gcpDiscoveryEngineHost, engine, `{"engines":[{"name":"projects/111/locations/global/collections/default_collection/engines/workspace-app","displayName":"Workspace"}]}`)
	fake.ok(gcpDiscoveryEngineHost, engine+"/workspace-app/assistants/default_assistant/agents", `{"agents":[{"name":"projects/111/locations/global/collections/default_collection/engines/workspace-app/assistants/default_assistant/agents/9001","displayName":"Expense helper","state":"ENABLED"}]}`)
	fake.ok(gcpRunHost, "/v1/projects/alpha-prod/locations", `{"locations":[{"locationId":"us-central1"}]}`)
	fake.ok(gcpRunHost, "/v2/projects/alpha-prod/locations/us-central1/services", `{"services":[
		{"name":"projects/alpha-prod/locations/us-central1/services/support-bot","ingress":"INGRESS_TRAFFIC_ALL","invokerIamDisabled":true,"template":{"containers":[{"image":"us-docker.pkg.dev/alpha-prod/apps/support-bot:1","env":[{"name":"ANTHROPIC_API_KEY","value":"`+gcpTestSecretValue+`"}]}]}},
		{"name":"projects/alpha-prod/locations/us-central1/services/docs-mcp","functionalType":"FUNCTIONAL_TYPE_MCP_SERVER","uri":"https://docs-mcp-abc123-uc.a.run.app","ingress":"INGRESS_TRAFFIC_ALL","invokerIamDisabled":true,"template":{"containers":[{"image":"us-docker.pkg.dev/alpha-prod/apps/docs:1"}]}},
		{"name":"projects/alpha-prod/locations/us-central1/services/repo-tools","uri":"https://repo-tools-abc123-uc.a.run.app","template":{"containers":[{"image":"ghcr.io/github/github-mcp-server:1","args":["--token","`+gcpTestSecretValue+`"]}]}},
		{"name":"projects/alpha-prod/locations/us-central1/services/cross-bot","template":{"serviceAccount":"`+shared+`","containers":[{"image":"us-docker.pkg.dev/alpha-prod/apps/cross:1","env":[{"name":"OPENAI_API_KEY","value":"`+gcpTestSecretValue+`"}]}]}},
		{"name":"projects/alpha-prod/locations/us-central1/services/plain-web","template":{"serviceAccount":"unused@alpha-prod.iam.gserviceaccount.com","containers":[{"image":"us-docker.pkg.dev/alpha-prod/apps/web:1","env":[{"name":"PORT","value":"8080"}]}]}},
		{"name":"projects/alpha-prod/locations/us-central1/services/fn-backed","template":{"serviceAccount":"`+runner+`","containers":[{"image":"us-docker.pkg.dev/alpha-prod/gcf/fn:1","env":[{"name":"GEMINI_API_KEY","value":"`+gcpTestSecretValue+`"}]}]}}]}`)
	fake.ok(gcpFunctionsHost, "/v2/projects/alpha-prod/locations/-/functions", `{"functions":[{"name":"projects/alpha-prod/locations/us-central1/functions/summarizer","state":"ACTIVE","environment":"GEN_2",
		"serviceConfig":{"service":"projects/alpha-prod/locations/us-central1/services/fn-backed","serviceAccountEmail":"`+runner+`","environmentVariables":{"GEMINI_API_KEY":"`+gcpTestSecretValue+`"}}}]}`)
	fake.ok(gcpModelArmorHost, "/v1/projects/alpha-prod/locations/global/floorSetting", `{"name":"projects/alpha-prod/locations/global/floorSetting","enableFloorSettingEnforcement":false}`)
	fake.ok("modelarmor.us-central1.rep.googleapis.com", "/v1/projects/alpha-prod/locations/us-central1/templates", `{}`)
	at := now.Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	entry := func(method, principal, resource string) string {
		return `{"timestamp":"` + at + `","protoPayload":{"serviceName":"aiplatform.googleapis.com","methodName":"` + method + `","resourceName":"` + resource + `","authenticationInfo":{"principalEmail":"` + principal + `"},"request":{"contents":"` + gcpTestSecretValue + `"}}}`
	}
	fake.ok(gcpLoggingHost, "/v2/entries:list#projects/alpha-prod", `{"entries":[`+strings.Join([]string{
		entry("google.cloud.aiplatform.v1.PredictionService.GenerateContent", runner, "projects/111/locations/us-central1/publishers/google/models/gemini"),
		entry("google.cloud.aiplatform.v1.PredictionService.GenerateContent", invoker, "projects/111/locations/us-central1/publishers/google/models/gemini"),
		entry("google.cloud.aiplatform.v1.PredictionService.GenerateContent", gcpTestPerson, "projects/111/locations/us-central1/publishers/google/models/gemini"),
		entry("google.cloud.aiplatform.v1.ReasoningEngineExecutionService.QueryReasoningEngine", runner, "projects/111/locations/us-central1/reasoningEngines/8001"),
		entry("google.cloud.aiplatform.v1.ModelService.ListModels", "unused@alpha-prod.iam.gserviceaccount.com", "projects/111/locations/us-central1"),
	}, ",")+`]}`)

	// beta-locked: a refusal or a switched-off API everywhere.
	fake.denied(gcpLoggingHost, "/v2/entries:list#projects/beta-locked")
	fake.denied(gcpIAMHost, "/v1/projects/beta-locked/serviceAccounts")
	fake.denied(crm, "/v3/projects/beta-locked:getIamPolicy")
	fake.disabled(gcpAIPlatformHost, "/v1/projects/beta-locked/locations")
	fake.disabled(gcpDialogflowHost, "/v3/projects/beta-locked/locations")
	for _, host := range []string{gcpDiscoveryEngineHost, "discoveryengine.us.rep.googleapis.com", "discoveryengine.eu.rep.googleapis.com"} {
		location := map[string]string{gcpDiscoveryEngineHost: "global", "discoveryengine.us.rep.googleapis.com": "us", "discoveryengine.eu.rep.googleapis.com": "eu"}[host]
		fake.denied(host, "/v1alpha/projects/beta-locked/locations/"+location+"/collections/default_collection/engines")
	}
	fake.disabled(gcpRunHost, "/v1/projects/beta-locked/locations")
	fake.denied(gcpFunctionsHost, "/v2/projects/beta-locked/locations/-/functions")
	return fake
}

type gcpSnapshotArtifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *gcpSnapshotArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *gcpSnapshotArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *gcpSnapshotArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*gcpSnapshotArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://gcp-discovery-evidence/" + locator.Key, nil
}

// The whole collection, driven by the shared collection client exactly as
// the worker drives it, ends in a typed snapshot. A project that refuses
// everything does not fail it, and nothing secret is stored.
func TestGCPCollectionClientCompletesATypedSnapshot(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	fake := gcpTestOrganization(t, now)
	api, err := NewGCPCollectionAPI(CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	driver := &gcpSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewGCPCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
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
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderGCP, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialGCPAccessToken, CredentialReference: "ref:gcp/workload-identity/acme-security/zasp-reader", ExpectedSubject: gcpTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 30 * time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, bytes.Clone(gcpTestCredential))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	snapshot := complete.Snapshot()
	// scope, 3 projects, 5 service accounts, engine, endpoint, deployed
	// model, 2 listed agents and 2 tools, 4 inferred agents, 2 MCP servers,
	// 11 services; 5 findings.
	if !snapshot.TypedObservations() || snapshot.EntityCount() != 33 || snapshot.EvidenceCount() != 38 {
		t.Fatalf("collection: typed=%v entities=%d relationships=%d evidence=%d", snapshot.TypedObservations(), snapshot.EntityCount(), snapshot.RelationshipCount(), snapshot.EvidenceCount())
	}
	for key, object := range driver.objects {
		for _, secret := range []string{gcpTestToken, gcpTestSecretValue, gcpTestPerson} {
			if bytes.Contains(object.Body, []byte(secret)) {
				t.Fatalf("artifact %s stores %q", key, secret)
			}
		}
	}
	// The project of another organization was never read.
	if fake.called(gcpIAMHost, "/v1/projects/other-org-proj/serviceAccounts") != 0 || fake.called(gcpIAMHost, "/v1/projects/going-away/serviceAccounts") != 0 {
		t.Fatal("a project outside the scope, or one being deleted, was read")
	}
}

type gcpTestEntity struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	SourceNativeID string         `json:"source_native_id"`
	DisplayName    string         `json:"display_name"`
	StableFields   map[string]any `json:"stable_fields"`
	Attributes     map[string]any `json:"attributes"`
}

// collectGCPPages drives the collector page by page and returns what it emitted.
func collectGCPPages(t *testing.T, api *GCPCollectionAPI, subject collection.SubjectBinding) (map[string]gcpTestEntity, []map[string]any, []map[string]any) {
	t.Helper()
	entities := map[string]gcpTestEntity{}
	var relationships, findings []map[string]any
	cursor := collection.Cursor{}
	for page := 1; page <= 20; page++ {
		result, err := api.FetchCollectionPage(context.Background(), bytes.Clone(gcpTestCredential), CollectionPageRequest{Provider: collection.ProviderGCP, Subject: subject, Cursor: cursor, Page: page, RemainingItems: 1000, RemainingRelationships: 1000, RemainingFindings: 1000, RemainingBytes: 16 << 20})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, raw := range result.Entities {
			var entity gcpTestEntity
			if err := json.Unmarshal(raw, &entity); err != nil {
				t.Fatal(err)
			}
			entities[entity.SourceNativeID] = entity
		}
		for _, raw := range result.Relationships {
			var relationship map[string]any
			_ = json.Unmarshal(raw, &relationship)
			relationships = append(relationships, relationship)
		}
		for _, raw := range result.Findings {
			var finding map[string]any
			_ = json.Unmarshal(raw, &finding)
			findings = append(findings, finding)
		}
		if result.Complete {
			return entities, relationships, findings
		}
		cursor = result.Cursor
	}
	t.Fatal("the collection did not complete")
	return nil, nil, nil
}

func TestGCPCollectorNormalizesAgentsIdentitiesFindingsAndCoverage(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.November, 14, 10, 30, 0, 0, time.UTC)
	fake := gcpTestOrganization(t, now)
	api, err := NewGCPCollectionAPI(CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	entities, relationships, findings := collectGCPPages(t, api, gcpTestSubject)
	invokedAt := now.Add(-3 * time.Hour).Format("2006-01-02T15:00:00Z")
	runner := "agent-runner@alpha-prod.iam.gserviceaccount.com"
	discovery := func(entity gcpTestEntity) (string, string, []string) {
		value, _ := entity.Attributes["discovery"].(map[string]any)
		var signals []string
		for _, signal := range value["signals"].([]any) {
			signals = append(signals, signal.(string))
		}
		return value["method"].(string), value["platform"].(string), signals
	}

	engine := entities["gcp:projects/alpha-prod/locations/us-central1/reasoningEngines/8001"]
	if method, platform, signals := discovery(engine); engine.Kind != "gcp_agent_engine" || engine.DisplayName != "Refund agent" || method != "provider_api" || platform != "vertex_ai_agent_engine" || len(signals) != 0 ||
		engine.Attributes["agent_framework"] != "google-adk" || engine.Attributes["identity_type"] != "service_account" || engine.Attributes["service_account"] != runner ||
		engine.Attributes["last_invoked_at"] != invokedAt || engine.Attributes["model_armor"] != "none" || engine.StableFields["location"] != "us-central1" || engine.StableFields["project"] != "alpha-prod" {
		t.Fatalf("reasoning engine = %#v", engine)
	}
	if posture, _ := engine.Attributes["posture"].(map[string]any); len(posture) != 18 || posture["credential_active"] != true {
		t.Fatalf("posture = %#v", engine.Attributes["posture"])
	}
	bot := entities["gcp:projects/alpha-prod/locations/us-central1/services/support-bot"]
	if method, platform, signals := discovery(bot); bot.Kind != "gcp_inferred_agent" || method != "inferred" || platform != "cloud_run_service" || strings.Join(signals, " ") != "env:anthropic" ||
		bot.Attributes["service_account"] != "111-compute@developer.gserviceaccount.com" || bot.StableFields["resource_type"] != "cloud_run_service" || bot.Attributes["posture"].(map[string]any)["untrusted_input"] != true {
		t.Fatalf("Cloud Run agent = %#v", bot)
	}
	function := entities["gcp:projects/alpha-prod/locations/us-central1/functions/summarizer"]
	if _, platform, signals := discovery(function); function.Kind != "gcp_inferred_agent" || platform != "cloud_function" || strings.Join(signals, " ") != "env:google iam:vertex_ai_user invoke:vertex_ai_agent invoke:vertex_ai_model" || function.Attributes["last_invoked_at"] != invokedAt {
		t.Fatalf("function agent = %#v", function)
	}
	invoker := entities["gcp:projects/alpha-prod/invokers/batch-invoker@alpha-prod.iam.gserviceaccount.com"]
	if _, platform, signals := discovery(invoker); invoker.Kind != "gcp_inferred_agent" || platform != "service_account" || strings.Join(signals, " ") != "iam:vertex_ai_user invoke:vertex_ai_model" || invoker.StableFields["resource_type"] != "service_account" {
		t.Fatalf("invoking service account = %#v", invoker)
	}
	for _, absent := range []string{
		"gcp:projects/alpha-prod/locations/us-central1/services/plain-web",           // no signal
		"gcp:projects/alpha-prod/locations/us-central1/services/fn-backed",           // listed as its function
		"gcp:projects/alpha-prod/locations/us-central1/services/docs-mcp",            // an MCP server, not an agent
		"gcp:projects/alpha-prod/invokers/unused@alpha-prod.iam.gserviceaccount.com", // ListModels is not an invocation
		"gcp:project:other-org-proj", "gcp:project:going-away",
	} {
		if _, present := entities[absent]; present {
			t.Fatalf("%s must not be inventory", absent)
		}
	}
	account := entities["gcp:service_account:"+runner]
	if account.Kind != "gcp_service_account" || account.Attributes["status"] != "ACTIVE" || account.Attributes["roles"] != "roles/aiplatform.user,roles/owner" || account.Attributes["admin_roles"] != "roles/owner" {
		t.Fatalf("service account = %#v", account)
	}
	// Every service account the project lists is an identity; a role bound
	// on the folder above the project is one of its roles.
	if unused := entities["gcp:service_account:unused@alpha-prod.iam.gserviceaccount.com"]; unused.Kind != "gcp_service_account" || unused.Attributes["status"] != "ACTIVE" || unused.Attributes["roles"] != nil {
		t.Fatalf("unused service account = %#v", unused)
	}
	if inherited := entities["gcp:service_account:batch-invoker@alpha-prod.iam.gserviceaccount.com"]; inherited.Attributes["roles"] != "roles/aiplatform.user,roles/resourcemanager.folderAdmin" || inherited.Attributes["admin_roles"] != "roles/resourcemanager.folderAdmin" {
		t.Fatalf("service account with an inherited role = %#v", inherited)
	}
	// A service account of another project in scope is that project's
	// identity, and the workload that runs as it refers to it.
	shared := entities["gcp:service_account:shared-runner@gamma-shared.iam.gserviceaccount.com"]
	cross := entities["gcp:projects/alpha-prod/locations/us-central1/services/cross-bot"]
	crossLinked := false
	for _, relationship := range relationships {
		crossLinked = crossLinked || relationship["kind"] == "uses_identity" && relationship["from_entity_id"] == cross.ID && relationship["to_entity_id"] == shared.ID
	}
	if shared.Kind != "gcp_service_account" || shared.StableFields["project"] != "gamma-shared" || cross.Kind != "gcp_inferred_agent" || cross.Attributes["service_account"] != "shared-runner@gamma-shared.iam.gserviceaccount.com" || !crossLinked {
		t.Fatalf("cross-project identity: account=%#v agent=%#v linked=%t", shared, cross, crossLinked)
	}
	// Cloud Run MCP servers: one by Cloud Run's own record and open to
	// anyone, one by its image and behind the IAM invoker check.
	declared := entities["gcp:projects/alpha-prod/locations/us-central1/services/docs-mcp:mcp_server"]
	byImage := entities["gcp:projects/alpha-prod/locations/us-central1/services/repo-tools:mcp_server"]
	if declared.Kind != "gcp_mcp_server" || declared.Attributes["auth"] != "none" || declared.Attributes["endpoint_host"] != "docs-mcp-abc123-uc.a.run.app" || declared.Attributes["source"] != "workload" || declared.Attributes["transport"] != "http" ||
		byImage.Kind != "gcp_mcp_server" || byImage.Attributes["auth"] != "declared" || byImage.Attributes["endpoint_host"] != "repo-tools-abc123-uc.a.run.app" {
		t.Fatalf("MCP servers: %#v / %#v", declared, byImage)
	}
	// The tools a Conversational Agents agent declares, classified by name.
	shell := entities["gcp:projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001/tools/t-1"]
	lookup := entities["gcp:projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001/tools/t-2"]
	if shell.Kind != "gcp_agent_tool" || shell.DisplayName != "run_shell" || shell.Attributes["risk"] != "execute" || shell.StableFields["agent"] != "Order status" || lookup.Kind != "gcp_agent_tool" || lookup.DisplayName != "lookup order" {
		t.Fatalf("agent tools: %#v / %#v", shell, lookup)
	}
	if model := entities["gcp:projects/alpha-prod/locations/us-central1/endpoints/5001/deployedModels/7001"]; model.Kind != "gcp_deployed_model" || model.Attributes["model_version"] != "3" || model.StableFields["endpoint"] != "Tuned model" {
		t.Fatalf("deployed model = %#v", model)
	}
	if agent := entities["gcp:projects/alpha-prod/locations/global/collections/default_collection/engines/workspace-app/assistants/default_assistant/agents/9001"]; agent.Kind != "gcp_gemini_enterprise_agent" || agent.Attributes["status"] != "ENABLED" {
		t.Fatalf("Gemini Enterprise agent = %#v", agent)
	}
	if agent := entities["gcp:projects/alpha-prod/locations/global/agents/0a1b2c3d-0000-4000-8000-000000000001"]; agent.Kind != "gcp_conversational_agent" || agent.DisplayName != "Order status" {
		t.Fatalf("conversational agent = %#v", agent)
	}

	// Coverage: what beta-locked refused or has switched off.
	statuses := map[string]string{}
	for _, entity := range entities {
		if entity.Kind == "gcp_service" {
			statuses[entity.StableFields["service"].(string)] = fmt.Sprint(entity.Attributes["status"], "/", entity.Attributes["affected_projects"])
		}
	}
	want := map[string]string{
		"resource-manager": "collected/<nil>", "agent-engine": "collected/<nil>", "vertex-endpoints": "collected/<nil>", "conversational-agents": "collected/<nil>", "cloud-run": "collected/<nil>",
		"gemini-enterprise": "access_denied/1", "cloud-functions": "access_denied/1", "iam": "access_denied/1", "model-armor": "collected/<nil>", "audit-logs": "access_denied/1", "iam-inherited": "access_denied/3",
	}
	if fmt.Sprint(statuses) != fmt.Sprint(want) {
		t.Fatalf("coverage = %v, want %v", statuses, want)
	}

	// Findings: three agents run as an administrator, one has no Model Armor.
	checks := []string{}
	for _, finding := range findings {
		for _, entity := range entities {
			if entity.ID == finding["entity_id"] {
				checks = append(checks, finding["check_id"].(string)+" "+entity.DisplayName)
			}
		}
		if finding["severity"] != "high" || finding["status"] != "FAIL" || finding["observed_at"] != "2026-11-14T10:30:00Z" {
			t.Fatalf("finding = %#v", finding)
		}
	}
	sort.Strings(checks)
	// The invoking service account is an administrator only through the
	// folder above its project.
	if strings.Join(checks, "|") != "agent_model_armor_missing Refund agent|agent_service_account_admin_role Refund agent|agent_service_account_admin_role batch-invoker@alpha-prod.iam.gserviceaccount.com|agent_service_account_admin_role summarizer|agent_service_account_admin_role support-bot" {
		t.Fatalf("findings = %v", checks)
	}
	identityLinks := 0
	for _, relationship := range relationships {
		if relationship["kind"] == "uses_identity" {
			identityLinks++
		}
	}
	// engine, support-bot, summarizer, cross-bot, the invoker itself, and the deployed model.
	if identityLinks != 6 {
		t.Fatalf("uses_identity relationships = %d", identityLinks)
	}
}

// A project named as the scope is read alone, without a project search.
func TestGCPCollectorReadsASingleProjectScope(t *testing.T) {
	t.Parallel()
	fake := newFakeGoogle(t)
	fake.ok(gcpResourceManagerHost, "/v3/projects/solo-project", `{"name":"projects/555","projectId":"solo-project","parent":"organizations/123456789012","state":"ACTIVE","displayName":"Solo"}`)
	api, err := NewGCPCollectionAPI(CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	entities, _, findings := collectGCPPages(t, api, collection.SubjectBinding{Kind: "gcp_scope", ID: "projects/solo-project"})
	if project := entities["gcp:project:solo-project"]; project.StableFields["project_number"] != "555" || len(entities) != 13 || len(findings) != 0 || fake.called(gcpResourceManagerHost, "/v3/projects:search") != 0 {
		t.Fatalf("entities = %d, findings = %d, project = %#v", len(entities), len(findings), project)
	}
}

// A scope the token cannot read is a denial; a rejected token fails the
// page; a credential of another shape is refused before any call.
func TestGCPCollectorRefusesWhatItMustNotRead(t *testing.T) {
	t.Parallel()
	fake := newFakeGoogle(t)
	fake.denied(gcpResourceManagerHost, "/v3/organizations/123456789012")
	api, err := NewGCPCollectionAPI(CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionPageRequest{Provider: collection.ProviderGCP, Subject: gcpTestSubject, Page: 1, RemainingItems: 100, RemainingRelationships: 100, RemainingFindings: 100, RemainingBytes: 1 << 20}
	var failure *collection.Failure
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(gcpTestCredential), request); !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("refused scope = %v", err)
	}
	if _, err := api.FetchCollectionPage(context.Background(), []byte(`{"access_token":"gcptest-another-token-0123456789"}`), request); err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("rejected token = %v", err)
	}
	for _, credential := range []string{``, `{"access_token":"short"}`, `{"token":"` + gcpTestToken + `"}`, `{"access_token":"` + gcpTestToken + `","x":"y"}`} {
		if _, err := api.FetchCollectionPage(context.Background(), []byte(credential), request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("credential %q = %v", credential, err)
		}
	}
	other := request
	other.Subject = collection.SubjectBinding{Kind: "gcp_scope", ID: "organizations/0"}
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(gcpTestCredential), other); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid scope = %v", err)
	}
	// A cursor of one scope is refused for another.
	fake.ok(gcpResourceManagerHost, "/v3/organizations/123456789012", `{"name":"organizations/123456789012","displayName":"Acme"}`)
	first, err := api.FetchCollectionPage(context.Background(), bytes.Clone(gcpTestCredential), request)
	if err != nil {
		t.Fatal(err)
	}
	moved := request
	moved.Subject, moved.Cursor, moved.Page = collection.SubjectBinding{Kind: "gcp_scope", ID: "organizations/999999999999"}, first.Cursor, 2
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(gcpTestCredential), moved); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cursor of another scope = %v", err)
	}
}

func TestGCPCollectionReadinessNeedsGoogleToRefuseAnAnonymousCall(t *testing.T) {
	t.Parallel()
	fake := newFakeGoogle(t)
	api, err := NewGCPCollectionAPI(CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("readiness = %v", err)
	}
	fake.server.Close()
	if err := api.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrProvider) {
		t.Fatalf("readiness without the provider = %v", err)
	}
}
