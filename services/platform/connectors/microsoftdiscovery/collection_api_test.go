package microsoftdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const (
	microsoftTestTenant         = "1111aaaa-2222-4333-8444-555555555555"
	microsoftTestGraphToken     = "graph-token-sentinel-value-0001"
	microsoftTestDataverseToken = "dataverse-token-sentinel-value-0002"
	microsoftTestOrganization   = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#organization(id,displayName)","value":[{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":"Contoso"}]}`
	microsoftTestEmpty          = `{"value":[]}`
)

var (
	microsoftTestSubject             = collection.SubjectBinding{Kind: "microsoft_tenant", ID: microsoftTestTenant}
	microsoftTestGraphCredential     = []byte(`{"graph_token":"` + microsoftTestGraphToken + `"}`)
	microsoftTestDataverseCredential = []byte(`{"dataverse_token":"` + microsoftTestDataverseToken + `","dataverse_url":"https://org1.crm4.dynamics.com","graph_token":"` + microsoftTestGraphToken + `"}`)
)

type microsoftRoundTripper struct {
	mu        sync.Mutex
	requests  []*http.Request
	responses []microsoftHTTPResponse
}

type microsoftHTTPResponse struct {
	status int
	body   string
	header http.Header
}

func (roundTripper *microsoftRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	roundTripper.requests = append(roundTripper.requests, request.Clone(request.Context()))
	if len(roundTripper.responses) == 0 {
		return nil, errors.New("microsoft-provider-secret")
	}
	response := roundTripper.responses[0]
	roundTripper.responses = roundTripper.responses[1:]
	return &http.Response{StatusCode: response.status, Header: response.header, Body: io.NopCloser(strings.NewReader(response.body)), Request: request}, nil
}

func (roundTripper *microsoftRoundTripper) calls() int {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	return len(roundTripper.requests)
}

func microsoftTestClock() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }

func newMicrosoftTestAPI(t *testing.T, responses ...microsoftHTTPResponse) (CollectionAPI, *microsoftRoundTripper) {
	t.Helper()
	roundTripper := &microsoftRoundTripper{responses: responses}
	api, err := NewMicrosoftCollectionAPI(CollectionAPIConfig{Transport: roundTripper, Timeout: time.Second, Clock: microsoftTestClock})
	if err != nil {
		t.Fatalf("NewMicrosoftCollectionAPI() error = %v", err)
	}
	return api, roundTripper
}

func microsoftOK(body string) microsoftHTTPResponse {
	return microsoftHTTPResponse{status: http.StatusOK, body: body}
}

func microsoftTestRequest() CollectionPageRequest {
	return CollectionPageRequest{Provider: collection.ProviderMicrosoft, Subject: microsoftTestSubject, Page: 1, RemainingItems: 1000, RemainingRelationships: 2000, RemainingBytes: 1 << 20}
}

func microsoftTestCursor(t *testing.T, subject collection.SubjectBinding, state microsoftPageState) collection.Cursor {
	t.Helper()
	cursor, _, ok := nextMicrosoftStateCursor(subject, state)
	if !ok {
		t.Fatalf("cursor for %+v refused", state)
	}
	return cursor
}

// collectMicrosoftPages drives the API the way the collection client does:
// the returned cursor becomes the next request cursor, the page number is the
// lineage, and the budgets shrink.
func collectMicrosoftPages(t *testing.T, api CollectionAPI, credential []byte, request CollectionPageRequest, maximum int) []CollectionPage {
	t.Helper()
	pages := make([]CollectionPage, 0, maximum)
	for pageNumber := request.Page; pageNumber < request.Page+maximum; pageNumber++ {
		current := request
		current.Page = pageNumber
		page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(credential), current)
		if err != nil {
			t.Fatalf("FetchCollectionPage(%d) error = %v", pageNumber, err)
		}
		assertMicrosoftPageClean(t, page)
		if page.Cursor == request.Cursor || page.Subject != request.Subject {
			t.Fatalf("page %d cursor/subject = %#v / %#v", pageNumber, page.Cursor, page.Subject)
		}
		pages = append(pages, page)
		request.Cursor = page.Cursor
		request.RemainingItems -= len(page.Entities)
		request.RemainingRelationships -= len(page.Relationships)
		if page.Complete {
			return pages
		}
	}
	t.Fatalf("collection not complete after %d pages", maximum)
	return nil
}

func assertMicrosoftPageClean(t *testing.T, page CollectionPage) {
	t.Helper()
	canonical, err := NewMicrosoftCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil || !bytes.Equal(canonical.Raw, page.Raw) {
		t.Fatalf("page is not canonical: %v\n%s", err, page.Raw)
	}
	values := [][]byte{page.Raw, []byte(page.Cursor.Value)}
	for _, item := range append(append([]json.RawMessage{}, page.Entities...), page.Relationships...) {
		values = append(values, item)
	}
	for _, value := range values {
		for _, secret := range []string{microsoftTestGraphToken, microsoftTestDataverseToken} {
			if bytes.Contains(value, []byte(secret)) {
				t.Fatalf("token present in page: %s", value)
			}
		}
	}
}

type microsoftTestEntity struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	SourceNativeID string `json:"source_native_id"`
	DisplayName    string `json:"display_name"`
	StableFields   struct {
		Environment string `json:"environment"`
		Name        string `json:"name"`
		ObjectType  string `json:"object_type"`
		Tenant      string `json:"tenant"`
	} `json:"stable_fields"`
	Attributes struct {
		Status    string                  `json:"status"`
		Posture   *agentsignals.Posture   `json:"posture"`
		Discovery *agentsignals.Discovery `json:"discovery"`
	} `json:"attributes"`
}

type microsoftTestRelationship struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	SourceNativeID string `json:"source_native_id"`
	FromEntityID   string `json:"from_entity_id"`
	ToEntityID     string `json:"to_entity_id"`
	Attributes     struct {
		Type string `json:"type"`
	} `json:"attributes"`
}

func microsoftTestInventory(t *testing.T, pages []CollectionPage) ([]microsoftTestEntity, []microsoftTestRelationship) {
	t.Helper()
	var entities []microsoftTestEntity
	var relationships []microsoftTestRelationship
	for _, page := range pages {
		for _, raw := range page.Entities {
			var entity microsoftTestEntity
			if err := json.Unmarshal(raw, &entity); err != nil {
				t.Fatalf("entity %s: %v", raw, err)
			}
			entities = append(entities, entity)
		}
		for _, raw := range page.Relationships {
			var relationship microsoftTestRelationship
			if err := json.Unmarshal(raw, &relationship); err != nil {
				t.Fatalf("relationship %s: %v", raw, err)
			}
			relationships = append(relationships, relationship)
		}
	}
	return entities, relationships
}

func microsoftFailureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}

func assertMicrosoftRequestURLs(t *testing.T, roundTripper *microsoftRoundTripper, want ...string) {
	t.Helper()
	if len(roundTripper.requests) != len(want) {
		t.Fatalf("provider calls = %d, want %d", len(roundTripper.requests), len(want))
	}
	for index, request := range roundTripper.requests {
		if request.Method != http.MethodGet || request.URL.String() != want[index] || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("request %d = %s %s, want %s", index, request.Method, request.URL, want[index])
		}
	}
}

func TestMicrosoftCollectionAPICollectsTenantAgentIdentitiesAndAIApplications(t *testing.T) {
	t.Parallel()
	api, roundTripper := newMicrosoftTestAPI(t,
		microsoftOK(microsoftTestOrganization),
		microsoftOK(`{"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100&$skiptoken=RFNwdAIAAQ%3D%3D","value":[{"@odata.type":"#microsoft.graph.agentIdentity","id":"aaaaaaaa-0000-4000-8000-000000000001","appId":"bbbbbbbb-0000-4000-8000-000000000001","displayName":"Invoice agent","accountEnabled":true}]}`),
		microsoftOK(`{"value":[{"id":"AAAAAAAA-0000-4000-8000-000000000002","appId":"bbbbbbbb-0000-4000-8000-000000000002","displayName":"Retired agent","accountEnabled":false}]}`),
		microsoftOK(`{"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100&$skiptoken=X%2744537074%27","value":[`+
			`{"id":"cccccccc-0000-4000-8000-000000000001","appId":"dddddddd-0000-4000-8000-000000000001","displayName":"ChatGPT Enterprise","accountEnabled":true,"servicePrincipalType":"Application"},`+
			`{"id":"cccccccc-0000-4000-8000-000000000002","appId":"dddddddd-0000-4000-8000-000000000002","displayName":"Contoso HR","accountEnabled":true,"servicePrincipalType":"Application"},`+
			`{"id":"cccccccc-0000-4000-8000-000000000003","appId":"dddddddd-0000-4000-8000-000000000003","displayName":"Claude","accountEnabled":true,"servicePrincipalType":"ManagedIdentity"},`+
			`{"@odata.type":"#microsoft.graph.agentIdentity","id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"Claude agent","accountEnabled":true,"servicePrincipalType":"Application"},`+
			`{"id":"cccccccc-0000-4000-8000-000000000004","displayName":null,"accountEnabled":null,"servicePrincipalType":"Legacy"}]}`),
		microsoftOK(`{"value":[{"id":"cccccccc-0000-4000-8000-000000000005","displayName":"Claude Code","accountEnabled":false,"servicePrincipalType":"Application"}]}`),
	)
	pages := collectMicrosoftPages(t, api, microsoftTestGraphCredential, microsoftTestRequest(), 8)
	if len(pages) != 5 {
		t.Fatalf("pages = %d", len(pages))
	}
	for index, prefix := range []string{"microsoft:agentidentities:2:", "microsoft:agentidentities:3:", "microsoft:serviceprincipals:4:", "microsoft:serviceprincipals:5:", "microsoft:complete:"} {
		if !strings.HasPrefix(pages[index].Cursor.Value, prefix) || pages[index].Complete != (index == 4) || len(pages[index].Cursor.Value) > 2048 {
			t.Fatalf("page %d cursor = %q complete=%t", index+1, pages[index].Cursor.Value, pages[index].Complete)
		}
	}
	assertMicrosoftRequestURLs(t, roundTripper,
		"https://graph.microsoft.com/v1.0/organization?$select=id,displayName",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100&$skiptoken=RFNwdAIAAQ%3D%3D",
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100",
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100&$skiptoken=X%2744537074%27",
	)
	for index, request := range roundTripper.requests {
		if request.Header.Get("Authorization") != "Bearer "+microsoftTestGraphToken || request.Header.Get("Prefer") != "" {
			t.Fatalf("request %d headers = %#v", index, request.Header)
		}
	}
	entities, relationships := microsoftTestInventory(t, pages)
	tenantID := deterministicMicrosoftInventoryID(microsoftTestSubject, "microsoft_tenant", microsoftTestTenant)
	type summary struct{ kind, source, name, objectType, status, method, platform, signals string }
	got := make([]summary, 0, len(entities))
	for _, entity := range entities {
		item := summary{kind: entity.Kind, source: entity.SourceNativeID, name: entity.StableFields.Name, objectType: entity.StableFields.ObjectType, status: entity.Attributes.Status}
		if entity.StableFields.Tenant != microsoftTestTenant || entity.DisplayName != entity.StableFields.Name || entity.StableFields.Environment != "" {
			t.Fatalf("entity = %+v", entity)
		}
		if entity.Kind == "microsoft_tenant" {
			if entity.ID != tenantID || entity.Attributes.Posture != nil || entity.Attributes.Discovery != nil {
				t.Fatalf("tenant = %+v", entity)
			}
		} else {
			want := agentsignals.Posture{CredentialActive: entity.Attributes.Status == "ACTIVE"}
			if entity.Attributes.Posture == nil || *entity.Attributes.Posture != want || entity.Attributes.Discovery == nil {
				t.Fatalf("agent posture/discovery = %+v", entity)
			}
			item.method, item.platform, item.signals = entity.Attributes.Discovery.Method, entity.Attributes.Discovery.Platform, strings.Join(entity.Attributes.Discovery.Signals, ",")
		}
		got = append(got, item)
	}
	want := []summary{
		{"microsoft_tenant", "microsoft:tenant:" + microsoftTestTenant, "Contoso", "", "", "", "", ""},
		{"microsoft_agent_identity", "microsoft:agent_identity:aaaaaaaa-0000-4000-8000-000000000001", "Invoice agent", "agent_identity", "ACTIVE", "provider_api", "entra_agent_identity", ""},
		{"microsoft_agent_identity", "microsoft:agent_identity:aaaaaaaa-0000-4000-8000-000000000002", "Retired agent", "agent_identity", "INACTIVE", "provider_api", "entra_agent_identity", ""},
		{"microsoft_ai_application", "microsoft:service_principal:cccccccc-0000-4000-8000-000000000001", "ChatGPT Enterprise", "service_principal", "ACTIVE", "inferred", "saas_assistant", "app:chatgpt"},
		{"microsoft_ai_application", "microsoft:service_principal:cccccccc-0000-4000-8000-000000000005", "Claude Code", "service_principal", "INACTIVE", "inferred", "saas_assistant", "app:claude,app:claude_code"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("entities =\n%v\nwant\n%v", got, want)
	}
	if len(relationships) != 4 {
		t.Fatalf("relationships = %d", len(relationships))
	}
	for index, relationship := range relationships {
		if relationship.Kind != "contains" || relationship.FromEntityID != tenantID || relationship.ToEntityID != entities[index+1].ID || relationship.Attributes.Type != "tenant_object" || !strings.HasPrefix(relationship.SourceNativeID, "microsoft:tenant:"+microsoftTestTenant+":") {
			t.Fatalf("relationship %d = %+v", index, relationship)
		}
	}
}

func TestMicrosoftCollectionAPIAttestsTheTenant(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		body string
		code collection.FailureCode
	}{
		"another tenant":    {`{"value":[{"id":"99999999-2222-4333-8444-555555555555","displayName":"Fabrikam"}]}`, collection.FailureDenied},
		"no organization":   {`{"value":[]}`, collection.FailureMalformed},
		"two organizations": {`{"value":[{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":"Contoso"},{"id":"99999999-2222-4333-8444-555555555555","displayName":"Fabrikam"}]}`, collection.FailureMalformed},
		"not a tenant id":   {`{"value":[{"id":"contoso.onmicrosoft.com","displayName":"Contoso"}]}`, collection.FailureMalformed},
		"missing value":     {`{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":"Contoso"}`, collection.FailureMalformed},
		"paged":             {`{"@odata.nextLink":"https://graph.microsoft.com/v1.0/organization?$skiptoken=next","value":[{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":"Contoso"}]}`, collection.FailureMalformed},
		"empty name":        {`{"value":[{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":""}]}`, collection.FailureMalformed},
		"trailing data":     {microsoftTestOrganization + `{}`, collection.FailureMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(test.body))
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), microsoftTestRequest()); !microsoftFailureHasCode(err, test.code) || roundTripper.calls() != 1 {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	// The match is on the directory GUID whatever its letter case; the
	// initial cursor may be absent, "initial" or the previous run's complete
	// cursor of the same tenant.
	complete := nextMicrosoftCompleteCursor(collection.Cursor{}, microsoftTestSubject)
	for _, cursor := range []collection.Cursor{{}, {Provider: collection.ProviderMicrosoft, Version: "cursor_v1", Value: "initial"}, complete} {
		api, _ := newMicrosoftTestAPI(t, microsoftOK(`{"value":[{"id":"1111AAAA-2222-4333-8444-555555555555","displayName":"Contoso"}]}`))
		request := microsoftTestRequest()
		request.Cursor = cursor
		page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request)
		if err != nil || page.Complete || len(page.Entities) != 1 || len(page.Relationships) != 0 || !strings.HasPrefix(page.Cursor.Value, "microsoft:agentidentities:2:") {
			t.Fatalf("tenant page = %#v, %v", page, err)
		}
	}
	foreignComplete := nextMicrosoftCompleteCursor(collection.Cursor{}, collection.SubjectBinding{Kind: "microsoft_tenant", ID: "99999999-2222-4333-8444-555555555555"})
	api, roundTripper := newMicrosoftTestAPI(t)
	request := microsoftTestRequest()
	request.Cursor = foreignComplete
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
		t.Fatalf("foreign complete cursor error/calls = %v / %d", err, roundTripper.calls())
	}
}

func TestMicrosoftCollectionAPISkipsAgentIdentitiesWhenTheTenantCannotServeThem(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t,
				microsoftOK(microsoftTestOrganization),
				microsoftHTTPResponse{status: status, body: `{"error":{"code":"Authorization_RequestDenied","message":"` + microsoftTestGraphToken + `"}}`},
				microsoftOK(`{"value":[{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"ChatGPT Enterprise","accountEnabled":true,"servicePrincipalType":"Application"}]}`),
			)
			pages := collectMicrosoftPages(t, api, microsoftTestGraphCredential, microsoftTestRequest(), 4)
			if len(pages) != 3 || len(pages[1].Entities) != 0 || len(pages[1].Relationships) != 0 || pages[1].Complete || !strings.HasPrefix(pages[1].Cursor.Value, "microsoft:serviceprincipals:3:") || len(pages[2].Entities) != 1 || roundTripper.calls() != 3 {
				t.Fatalf("pages = %#v", pages)
			}
		})
	}
	subject := microsoftTestSubject
	first := microsoftTestCursor(t, subject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: 2})
	continued := microsoftTestCursor(t, subject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: 2, Continuation: "next"})
	principals := microsoftTestCursor(t, subject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 2})
	for name, test := range map[string]struct {
		cursor collection.Cursor
		status int
		code   collection.FailureCode
	}{
		"unauthorized is not skipped":           {first, http.StatusUnauthorized, collection.FailureDenied},
		"server error is not skipped":           {first, http.StatusBadGateway, collection.FailureRetryable},
		"conflict is not skipped":               {first, http.StatusConflict, collection.FailureTerminal},
		"redirect is not skipped":               {first, http.StatusFound, collection.FailureMalformed},
		"continuation forbidden":                {continued, http.StatusForbidden, collection.FailureDenied},
		"continuation not found":                {continued, http.StatusNotFound, collection.FailureTerminal},
		"service principals forbidden":          {principals, http.StatusForbidden, collection.FailureDenied},
		"service principals not found":          {principals, http.StatusNotFound, collection.FailureTerminal},
		"service principals unsupported":        {principals, http.StatusBadRequest, collection.FailureTerminal},
		"rate limit without a usable retry":     {first, http.StatusTooManyRequests, collection.FailureMalformed},
		"continuation rate limit without retry": {continued, http.StatusTooManyRequests, collection.FailureMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftHTTPResponse{status: test.status, body: `{}`, header: http.Header{"Location": []string{"https://evil.example/"}}})
			request := microsoftTestRequest()
			request.Cursor, request.Page = test.cursor, 2
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !microsoftFailureHasCode(err, test.code) || roundTripper.calls() != 1 {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
}

func TestMicrosoftCollectionAPICollectsCopilotStudioAgents(t *testing.T) {
	t.Parallel()
	const nextLink = `https://org1.crm4.dynamics.com/api/data/v9.2/bots?$select=botid,name,schemaname,statecode,accesscontrolpolicy,authenticationmode,configuration&$skiptoken=%3Ccookie%20pagenumber=%222%22%20pagingcookie=%22%253ccookie%2520page%253d%25221%2522%253e%22%20istracking=%22False%22%20/%3E`
	api, roundTripper := newMicrosoftTestAPI(t,
		microsoftOK(microsoftTestOrganization),
		microsoftOK(microsoftTestEmpty),
		microsoftOK(microsoftTestEmpty),
		microsoftOK(`{"@odata.context":"https://org1.crm4.dynamics.com/api/data/v9.2/$metadata#bots","@odata.nextLink":`+string(mustMicrosoftJSON(t, nextLink))+`,"value":[`+
			`{"@odata.etag":"W/\"1\"","botid":"eeeeeeee-0000-4000-8000-000000000001","name":"Help desk","schemaname":"cr1_helpDesk","statecode":0,"accesscontrolpolicy":0,"authenticationmode":1,"configuration":"{\"$kind\":\"BotConfiguration\",\"aISettings\":{\"$kind\":\"AISettings\",\"contentModeration\":\"Low\",\"instructions\":\"never keep this\"}}"},`+
			`{"@odata.etag":"W/\"2\"","botid":"eeeeeeee-0000-4000-8000-000000000002","name":"Payroll","schemaname":"cr1_payroll","statecode":0,"accesscontrolpolicy":1,"authenticationmode":2,"configuration":"{\"aISettings\":{\"contentModeration\":\"High\"}}"}]}`),
		microsoftOK(`{"value":[`+
			`{"botid":"eeeeeeee-0000-4000-8000-000000000003","name":"Old bot","schemaname":"cr1_old","statecode":1,"accesscontrolpolicy":0,"authenticationmode":1,"configuration":"not json"},`+
			`{"botid":"eeeeeeee-0000-4000-8000-000000000004","name":"Draft","schemaname":"cr1_draft","statecode":1,"accesscontrolpolicy":0,"authenticationmode":null}]}`),
	)
	pages := collectMicrosoftPages(t, api, microsoftTestDataverseCredential, microsoftTestRequest(), 8)
	if len(pages) != 5 || !strings.HasPrefix(pages[2].Cursor.Value, "microsoft:copilotagents:4:") || !strings.HasPrefix(pages[3].Cursor.Value, "microsoft:copilotagents:5:") || !pages[4].Complete {
		t.Fatalf("pages = %#v", pages)
	}
	const botsURL = "https://org1.crm4.dynamics.com/api/data/v9.2/bots?$select=botid,name,schemaname,statecode,accesscontrolpolicy,authenticationmode,configuration"
	// The moderation level is the one member read out of a configuration;
	// nothing else of it reaches a page.
	for index, want := range []string{`"content_moderation":"low"`, `"content_moderation":"high"`} {
		if !bytes.Contains(pages[3].Entities[index], []byte(want)) {
			t.Fatalf("agent %d has no %s: %s", index, want, pages[3].Entities[index])
		}
	}
	for _, page := range pages {
		if bytes.Contains(page.Raw, []byte("never keep this")) || bytes.Contains(page.Raw, []byte("BotConfiguration")) || bytes.Contains(page.Raw, []byte("not json")) {
			t.Fatalf("a page keeps the configuration: %s", page.Raw)
		}
	}
	for _, entity := range pages[4].Entities {
		if bytes.Contains(entity, []byte("content_moderation")) {
			t.Fatalf("an agent without a stated level has one: %s", entity)
		}
	}
	assertMicrosoftRequestURLs(t, roundTripper,
		"https://graph.microsoft.com/v1.0/organization?$select=id,displayName",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100",
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100",
		botsURL,
		botsURL+"&$skiptoken=%3Ccookie%20pagenumber%3D%222%22%20pagingcookie%3D%22%253ccookie%2520page%253d%25221%2522%253e%22%20istracking%3D%22False%22%20%2F%3E",
	)
	if got := roundTripper.requests[4].URL.Query().Get("$skiptoken"); got != `<cookie pagenumber="2" pagingcookie="%3ccookie%20page%3d%221%22%3e" istracking="False" />` {
		t.Fatalf("continuation = %q", got)
	}
	for index, request := range roundTripper.requests {
		token, version, prefer := microsoftTestGraphToken, "", ""
		if index >= 3 {
			token, version, prefer = microsoftTestDataverseToken, "4.0", "odata.maxpagesize=100"
		}
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("OData-MaxVersion") != version || request.Header.Get("OData-Version") != version || request.Header.Get("Prefer") != prefer || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("request %d headers = %#v", index, request.Header)
		}
	}
	entities, relationships := microsoftTestInventory(t, pages)
	if len(entities) != 5 || len(relationships) != 4 {
		t.Fatalf("inventory = %d / %d", len(entities), len(relationships))
	}
	tenantID := deterministicMicrosoftInventoryID(microsoftTestSubject, "microsoft_tenant", microsoftTestTenant)
	for index, want := range []struct {
		id, name, status  string
		active, untrusted bool
	}{
		{"eeeeeeee-0000-4000-8000-000000000001", "Help desk", "ACTIVE", true, true},
		{"eeeeeeee-0000-4000-8000-000000000002", "Payroll", "ACTIVE", true, false},
		{"eeeeeeee-0000-4000-8000-000000000003", "Old bot", "INACTIVE", false, true},
		{"eeeeeeee-0000-4000-8000-000000000004", "Draft", "INACTIVE", false, false},
	} {
		entity, relationship := entities[index+1], relationships[index]
		posture := agentsignals.Posture{CredentialActive: want.active, UntrustedInput: want.untrusted}
		discovery := agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "copilot_studio", nil)
		if entity.Kind != "microsoft_copilot_agent" || entity.SourceNativeID != "microsoft:copilot_studio:org1.crm4.dynamics.com:"+want.id || entity.DisplayName != want.name || entity.StableFields.Name != want.name || entity.StableFields.Environment != "org1.crm4.dynamics.com" || entity.StableFields.ObjectType != "copilot_studio_agent" || entity.StableFields.Tenant != microsoftTestTenant ||
			entity.Attributes.Status != want.status || entity.Attributes.Posture == nil || *entity.Attributes.Posture != posture || entity.Attributes.Discovery == nil || fmt.Sprint(*entity.Attributes.Discovery) != fmt.Sprint(discovery) {
			t.Fatalf("agent %d = %+v", index, entity)
		}
		if relationship.Kind != "contains" || relationship.FromEntityID != tenantID || relationship.ToEntityID != entity.ID || relationship.Attributes.Type != "tenant_object" {
			t.Fatalf("relationship %d = %+v", index, relationship)
		}
	}
}

func TestMicrosoftCollectionAPITreatsCopilotStudioDenialAndShapeAsFailures(t *testing.T) {
	t.Parallel()
	cursor := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: 4, Environment: "org1.crm4.dynamics.com"})
	for name, test := range map[string]struct {
		response microsoftHTTPResponse
		code     collection.FailureCode
	}{
		"forbidden":         {microsoftHTTPResponse{status: http.StatusForbidden, body: `{}`}, collection.FailureDenied},
		"not found":         {microsoftHTTPResponse{status: http.StatusNotFound, body: `{}`}, collection.FailureTerminal},
		"missing statecode": {microsoftOK(`{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"Help desk","authenticationmode":1}]}`), collection.FailureMalformed},
		"text statecode":    {microsoftOK(`{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"Help desk","statecode":"0"}]}`), collection.FailureMalformed},
		"bad bot id":        {microsoftOK(`{"value":[{"botid":"help-desk","name":"Help desk","statecode":0}]}`), collection.FailureMalformed},
		"empty name":        {microsoftOK(`{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"","statecode":0}]}`), collection.FailureMalformed},
		"duplicate bot":     {microsoftOK(`{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"A","statecode":0},{"botid":"EEEEEEEE-0000-4000-8000-000000000001","name":"B","statecode":0}]}`), collection.FailureMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, test.response)
			request := microsoftTestRequest()
			request.Cursor, request.Page = cursor, 4
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestDataverseCredential), request); !microsoftFailureHasCode(err, test.code) || roundTripper.calls() != 1 {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	// The environment is part of the cursor: no Dataverse credential, or one
	// for another environment, cannot continue it.
	for name, credential := range map[string][]byte{
		"graph only":          microsoftTestGraphCredential,
		"another environment": []byte(`{"dataverse_token":"` + microsoftTestDataverseToken + `","dataverse_url":"https://org2.crm4.dynamics.com","graph_token":"` + microsoftTestGraphToken + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestEmpty))
			request := microsoftTestRequest()
			request.Cursor, request.Page = cursor, 4
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(credential), request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
}

func TestMicrosoftCollectionAPIAcceptsOnlySameHostSamePathNextLinks(t *testing.T) {
	t.Parallel()
	principals := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 3, Continuation: "prior"})
	identities := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: 3})
	bots := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: 3, Environment: "org1.crm4.dynamics.com"})
	for name, test := range map[string]struct {
		cursor collection.Cursor
		link   string
	}{
		"another host":             {principals, "https://evil.example/v1.0/servicePrincipals?$skiptoken=next"},
		"host suffix":              {principals, "https://graph.microsoft.com.evil.example/v1.0/servicePrincipals?$skiptoken=next"},
		"userinfo":                 {principals, "https://graph.microsoft.com@evil.example/v1.0/servicePrincipals?$skiptoken=next"},
		"credentials":              {principals, "https://user:pass@graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next"},
		"port":                     {principals, "https://graph.microsoft.com:8443/v1.0/servicePrincipals?$skiptoken=next"},
		"plain http":               {principals, "http://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next"},
		"relative":                 {principals, "/v1.0/servicePrincipals?$skiptoken=next"},
		"another path":             {principals, "https://graph.microsoft.com/v1.0/users?$skiptoken=next"},
		"beta path":                {principals, "https://graph.microsoft.com/beta/servicePrincipals?$skiptoken=next"},
		"deeper path":              {principals, "https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$skiptoken=next"},
		"shallower path":           {identities, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next"},
		"fragment":                 {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next#fragment"},
		"no token":                 {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$top=100"},
		"empty token":              {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken="},
		"duplicate token":          {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=a&$skiptoken=b"},
		"unknown parameter":        {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next&$filter=x"},
		"control character":        {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=a%0Ab"},
		"oversized token":          {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=" + strings.Repeat("a", 1025)},
		"same token again":         {principals, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=prior"},
		"not a URL":                {principals, "://"},
		"empty":                    {principals, ""},
		"dataverse to graph":       {bots, "https://graph.microsoft.com/api/data/v9.2/bots?$skiptoken=next"},
		"dataverse to another org": {bots, "https://org2.crm4.dynamics.com/api/data/v9.2/bots?$skiptoken=next"},
		"dataverse another table":  {bots, "https://org1.crm4.dynamics.com/api/data/v9.2/systemusers?$skiptoken=next"},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(`{"@odata.nextLink":`+string(mustMicrosoftJSON(t, test.link))+`,"value":[]}`))
			request := microsoftTestRequest()
			request.Cursor, request.Page = test.cursor, 3
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestDataverseCredential), request); !microsoftFailureHasCode(err, collection.FailureMalformed) || roundTripper.calls() != 1 {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(`{"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id&$top=100&$skiptoken=after","value":[]}`), microsoftOK(microsoftTestEmpty))
	request := microsoftTestRequest()
	request.Cursor, request.Page = principals, 3
	page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request)
	if err != nil || page.Complete || !strings.HasPrefix(page.Cursor.Value, "microsoft:serviceprincipals:4:") {
		t.Fatalf("page = %#v, %v", page, err)
	}
	request.Cursor, request.Page = page.Cursor, 4
	if page, err = api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); err != nil || !page.Complete {
		t.Fatalf("last page = %#v, %v", page, err)
	}
	if got := roundTripper.requests[1].URL.String(); got != "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100&$skiptoken=after" {
		t.Fatalf("continuation request = %s", got)
	}
}

func TestMicrosoftCollectionAPIRefusesHostileCredentialEnvelopes(t *testing.T) {
	t.Parallel()
	graph, dataverse := microsoftTestGraphToken, microsoftTestDataverseToken
	for name, credential := range map[string]string{
		"empty":                     ``,
		"bare token":                graph,
		"unknown member":            `{"graph_token":"` + graph + `","tenant":"x"}`,
		"unknown member first":      `{"audience":"x","graph_token":"` + graph + `"}`,
		"duplicate member":          `{"graph_token":"` + graph + `","graph_token":"` + graph + `"}`,
		"short token":               `{"graph_token":"short-token-015"}`,
		"oversized token":           `{"graph_token":"` + strings.Repeat("a", 8193) + `"}`,
		"empty token":               `{"graph_token":""}`,
		"token with space":          `{"graph_token":"graph token sentinel value"}`,
		"token with escape":         `{"graph_token":"graph` + "\\" + `u002dtoken-sentinel-value"}`,
		"token with newline":        "{\"graph_token\":\"graph-token-sentinel\nvalue\"}",
		"token not ascii":           `{"graph_token":"graph-token-sentinel-välue"}`,
		"token not a string":        `{"graph_token":1234567890123456}`,
		"whitespace":                `{"graph_token": "` + graph + `"}`,
		"trailing data":             `{"graph_token":"` + graph + `"}{}`,
		"array":                     `["` + graph + `"]`,
		"dataverse url only":        `{"dataverse_url":"https://org1.crm4.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse token only":      `{"dataverse_token":"` + dataverse + `","graph_token":"` + graph + `"}`,
		"dataverse without graph":   `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.crm4.dynamics.com"}`,
		"unsorted members":          `{"graph_token":"` + graph + `","dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.crm4.dynamics.com"}`,
		"short dataverse token":     `{"dataverse_token":"short","dataverse_url":"https://org1.crm4.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url path":        `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.crm4.dynamics.com/","graph_token":"` + graph + `"}`,
		"dataverse url port":        `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.crm4.dynamics.com:443","graph_token":"` + graph + `"}`,
		"dataverse url userinfo":    `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://user@org1.crm4.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url http":        `{"dataverse_token":"` + dataverse + `","dataverse_url":"http://org1.crm4.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url other host":  `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.crm4.dynamics.com.evil.example","graph_token":"` + graph + `"}`,
		"dataverse url not crm":     `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.api.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url subdomain":   `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://a.org1.crm4.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url upper case":  `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://ORG1.crm4.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url three digit": `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org1.crm123.dynamics.com","graph_token":"` + graph + `"}`,
		"dataverse url graph":       `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://graph.microsoft.com","graph_token":"` + graph + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization))
			_, err := api.FetchCollectionPage(context.Background(), []byte(credential), microsoftTestRequest())
			if !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 || strings.Contains(err.Error(), graph) || strings.Contains(err.Error(), dataverse) {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	for name, credential := range map[string]string{
		"graph only":       string(microsoftTestGraphCredential),
		"with dataverse":   string(microsoftTestDataverseCredential),
		"regional suffix":  `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://org-1.crm11.dynamics.com","graph_token":"` + graph + `"}`,
		"no region number": `{"dataverse_token":"` + dataverse + `","dataverse_url":"https://o.crm.dynamics.com","graph_token":"` + graph + `"}`,
		"jwt punctuation":  `{"graph_token":"eyJ0eXAiOiJKV1Qi.eyJhdWQiOiJodHRwczovL2dyYXBo._-~+/=sig"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := decodeMicrosoftCredential([]byte(credential)); !ok {
				t.Fatal("valid envelope refused")
			}
		})
	}
	envelope, ok := decodeMicrosoftCredential(microsoftTestDataverseCredential)
	if !ok || string(envelope.graphToken) != graph || string(envelope.dataverseToken) != dataverse || envelope.dataverseHost != "org1.crm4.dynamics.com" {
		t.Fatalf("envelope = %+v", envelope)
	}
}

func TestMicrosoftCollectionAPINeverRepeatsATokenFromProviderData(t *testing.T) {
	t.Parallel()
	cursors := map[string]collection.Cursor{
		microsoftPhaseAgentIdentities:   microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: 2}),
		microsoftPhaseServicePrincipals: microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 2}),
		microsoftPhaseCopilotAgents:     microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: 2, Environment: "org1.crm4.dynamics.com"}),
	}
	for name, test := range map[string]struct {
		phase string
		body  string
	}{
		"tenant name":            {microsoftPhaseTenant, `{"value":[{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":"` + microsoftTestGraphToken + `"}]}`},
		"agent identity name":    {microsoftPhaseAgentIdentities, `{"value":[{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"agent ` + microsoftTestGraphToken + `","accountEnabled":true}]}`},
		"application name":       {microsoftPhaseServicePrincipals, `{"value":[{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"ChatGPT ` + microsoftTestDataverseToken + `","accountEnabled":true,"servicePrincipalType":"Application"}]}`},
		"copilot agent name":     {microsoftPhaseCopilotAgents, `{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"` + microsoftTestDataverseToken + `","statecode":0}]}`},
		"copilot other token":    {microsoftPhaseCopilotAgents, `{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"` + microsoftTestGraphToken + `","statecode":0}]}`},
		"continuation":           {microsoftPhaseServicePrincipals, `{"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=` + microsoftTestGraphToken + `","value":[]}`},
		"copilot continuation":   {microsoftPhaseCopilotAgents, `{"@odata.nextLink":"https://org1.crm4.dynamics.com/api/data/v9.2/bots?$skiptoken=` + microsoftTestDataverseToken + `","value":[]}`},
		"identity continuation":  {microsoftPhaseAgentIdentities, `{"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$skiptoken=` + microsoftTestGraphToken + `","value":[]}`},
		"whole envelope as name": {microsoftPhaseTenant, `{"value":[{"id":"1111aaaa-2222-4333-8444-555555555555","displayName":` + string(mustMicrosoftJSON(t, string(microsoftTestDataverseCredential))) + `}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(test.body))
			request := microsoftTestRequest()
			if test.phase != microsoftPhaseTenant {
				request.Cursor, request.Page = cursors[test.phase], 2
			}
			page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestDataverseCredential), request)
			if !microsoftFailureHasCode(err, collection.FailureMalformed) || roundTripper.calls() != 1 || len(page.Raw) != 0 || strings.Contains(err.Error(), microsoftTestGraphToken) || strings.Contains(err.Error(), microsoftTestDataverseToken) {
				t.Fatalf("token echo page/error/calls = %s / %v / %d", page.Raw, err, roundTripper.calls())
			}
		})
	}
	// Tokens leave only in the Authorization header of their own host.
	api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty))
	collectMicrosoftPages(t, api, microsoftTestDataverseCredential, microsoftTestRequest(), 4)
	for index, request := range roundTripper.requests {
		own, other := microsoftTestGraphToken, microsoftTestDataverseToken
		if request.URL.Host != "graph.microsoft.com" {
			own, other = other, own
			if request.URL.Host != "org1.crm4.dynamics.com" {
				t.Fatalf("request %d host = %s", index, request.URL.Host)
			}
		}
		if request.URL.Scheme != "https" || strings.Contains(request.URL.String(), own) || strings.Contains(request.URL.String(), other) || request.Header.Get("Authorization") != "Bearer "+own {
			t.Fatalf("request %d = %s", index, request.URL)
		}
		for key, values := range request.Header {
			if strings.Contains(strings.Join(values, ","), other) || key != "Authorization" && strings.Contains(strings.Join(values, ","), own) {
				t.Fatalf("request %d header %s carries a token", index, key)
			}
		}
	}
}

// An environment that refuses the configuration column is read without it,
// on the first page and on every later one.
func TestMicrosoftCollectionAPIReadsCopilotStudioAgentsWithoutTheConfigurationColumn(t *testing.T) {
	t.Parallel()
	const basicURL = "https://org1.crm4.dynamics.com/api/data/v9.2/bots?$select=botid,name,schemaname,statecode,accesscontrolpolicy,authenticationmode"
	api, roundTripper := newMicrosoftTestAPI(t,
		microsoftOK(microsoftTestOrganization), microsoftOK(microsoftTestEmpty), microsoftOK(microsoftTestEmpty),
		microsoftHTTPResponse{status: http.StatusBadRequest, body: `{"error":{"code":"0x0","message":"Could not find a property named 'configuration' on type 'Microsoft.Dynamics.CRM.bot'."}}`},
		microsoftOK(`{"@odata.nextLink":`+string(mustMicrosoftJSON(t, basicURL+"&$skiptoken=next"))+`,"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"Help desk","statecode":0,"authenticationmode":2}]}`),
		microsoftOK(`{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000002","name":"Payroll","statecode":0,"authenticationmode":2}]}`),
	)
	pages := collectMicrosoftPages(t, api, microsoftTestDataverseCredential, microsoftTestRequest(), 8)
	if len(pages) != 5 || !pages[4].Complete || len(pages[3].Entities) != 1 || len(pages[4].Entities) != 1 || bytes.Contains(pages[3].Entities[0], []byte("content_moderation")) {
		t.Fatalf("pages = %#v", pages)
	}
	assertMicrosoftRequestURLs(t, roundTripper,
		"https://graph.microsoft.com/v1.0/organization?$select=id,displayName",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled&$top=100",
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=100",
		basicURL+",configuration", basicURL, basicURL+"&$skiptoken=next",
	)
}

func TestMicrosoftCollectionAPIClassifiesProviderFailuresLikeOkta(t *testing.T) {
	t.Parallel()
	retryAt := microsoftTestClock().Add(7 * time.Second)
	cursors := map[string]collection.Cursor{
		microsoftPhaseTenant:            {},
		microsoftPhaseServicePrincipals: microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 2}),
		microsoftPhaseCopilotAgents:     microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: 2, Environment: "org1.crm4.dynamics.com"}),
	}
	for phase, cursor := range cursors {
		for _, test := range []struct {
			status     int
			retryAfter string
			code       collection.FailureCode
		}{
			{http.StatusUnauthorized, "", collection.FailureDenied},
			{http.StatusForbidden, "", collection.FailureDenied},
			{http.StatusTooManyRequests, "7", collection.FailureRateLimited},
			{http.StatusTooManyRequests, "", collection.FailureMalformed},
			{http.StatusTooManyRequests, "86400", collection.FailureMalformed},
			{http.StatusInternalServerError, "", collection.FailureRetryable},
			{http.StatusServiceUnavailable, "7", collection.FailureRetryable},
			{http.StatusGatewayTimeout, "", collection.FailureRetryable},
			{http.StatusMovedPermanently, "", collection.FailureMalformed},
			{http.StatusFound, "", collection.FailureMalformed},
			{http.StatusTemporaryRedirect, "", collection.FailureMalformed},
			{http.StatusNoContent, "", collection.FailureMalformed},
			{http.StatusNotFound, "", collection.FailureTerminal},
			{http.StatusBadRequest, "", collection.FailureTerminal},
		} {
			t.Run(fmt.Sprintf("%s/%d/%s", phase, test.status, test.retryAfter), func(t *testing.T) {
				header := http.Header{"Location": []string{"https://evil.example/steal"}}
				if test.retryAfter != "" {
					header.Set("Retry-After", test.retryAfter)
				}
				refused := microsoftHTTPResponse{status: test.status, body: `{"error":{"message":"` + microsoftTestGraphToken + `"}}`, header: header}
				// The first Copilot Studio page is asked for once more without
				// the configuration column when the environment answers 400;
				// a second 400 is the failure.
				calls, second := 1, microsoftOK(microsoftTestOrganization)
				if phase == microsoftPhaseCopilotAgents && test.status == http.StatusBadRequest {
					calls, second = 2, refused
				}
				api, roundTripper := newMicrosoftTestAPI(t, refused, second)
				request := microsoftTestRequest()
				if phase != microsoftPhaseTenant {
					request.Cursor, request.Page = cursor, 2
				}
				_, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestDataverseCredential), request)
				// The redirect is not followed: one call, and the same code
				// the shared classifier (which the Okta collector uses) gives.
				want := providercollection.ClassifyProviderHTTPFailure(context.Background(), nil, test.status, test.retryAfter, microsoftTestClock())
				var failure, wantFailure *collection.Failure
				if !errors.As(err, &failure) || !errors.As(want, &wantFailure) || failure.Code() != test.code || failure.Code() != wantFailure.Code() || !failure.RetryAt().Equal(wantFailure.RetryAt()) || roundTripper.calls() != calls {
					t.Fatalf("failure/calls = %v (want %v) / %d", err, want, roundTripper.calls())
				}
				if test.code == collection.FailureRateLimited && !failure.RetryAt().Equal(retryAt) {
					t.Fatalf("retry at = %s", failure.RetryAt())
				}
				if strings.Contains(err.Error(), microsoftTestGraphToken) || strings.Contains(err.Error(), microsoftTestDataverseToken) {
					t.Fatalf("token in error %q", err)
				}
			})
		}
	}
	api, roundTripper := newMicrosoftTestAPI(t)
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), microsoftTestRequest()); !microsoftFailureHasCode(err, collection.FailureRetryable) || roundTripper.calls() != 1 || strings.Contains(err.Error(), "microsoft-provider-secret") {
		t.Fatalf("transport failure = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	api, roundTripper = newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization))
	if _, err := api.FetchCollectionPage(cancelled, bytes.Clone(microsoftTestGraphCredential), microsoftTestRequest()); !microsoftFailureHasCode(err, collection.FailureCancelled) || roundTripper.calls() != 0 {
		t.Fatalf("cancelled failure = %v", err)
	}
	for name, body := range map[string]string{"empty body": ``, "not JSON": `<html>`, "array": `[]`, "null value": `{"value":null}`, "value object": `{"value":{}}`} {
		api, _ = newMicrosoftTestAPI(t, microsoftOK(body))
		if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), microsoftTestRequest()); !microsoftFailureHasCode(err, collection.FailureMalformed) {
			t.Fatalf("%s failure = %v", name, err)
		}
	}
}

func TestMicrosoftCollectionAPIHonoursPageBudgets(t *testing.T) {
	t.Parallel()
	identities := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: 2})
	principals := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 2})
	bots := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: 2, Environment: "org1.crm4.dynamics.com"})
	identity := func(index int) string {
		return fmt.Sprintf(`{"id":"aaaaaaaa-0000-4000-8000-%012d","displayName":"Agent %d","accountEnabled":true}`, index, index)
	}
	// The page size is the smaller remaining budget, so a page always fits.
	for name, test := range map[string]struct {
		cursor        collection.Cursor
		items         int
		relationships int
		want          string
	}{
		"items":         {identities, 3, 2000, "$top=3"},
		"relationships": {principals, 1000, 2, "$top=2"},
		"maximum":       {principals, 1000, 2000, "$top=100"},
		"copilot":       {bots, 7, 2000, "odata.maxpagesize=7"},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestEmpty))
			request := microsoftTestRequest()
			request.Cursor, request.Page, request.RemainingItems, request.RemainingRelationships = test.cursor, 2, test.items, test.relationships
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestDataverseCredential), request); err != nil {
				t.Fatalf("error = %v", err)
			}
			sent := roundTripper.requests[0]
			if !strings.HasSuffix(sent.URL.RawQuery, test.want) && sent.Header.Get("Prefer") != test.want {
				t.Fatalf("request = %s / %q", sent.URL, sent.Header.Get("Prefer"))
			}
		})
	}
	request := microsoftTestRequest()
	request.Cursor, request.Page, request.RemainingItems = identities, 2, 2
	api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+identity(1)+`,`+identity(2)+`]}`))
	page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request)
	if err != nil || len(page.Entities) != 2 || len(page.Relationships) != 2 {
		t.Fatalf("page within budget = %#v, %v", page, err)
	}
	// A provider that ignores the requested page size is not trusted.
	api, _ = newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+identity(1)+`,`+identity(2)+`,`+identity(3)+`]}`))
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !microsoftFailureHasCode(err, collection.FailureMalformed) {
		t.Fatalf("oversized provider page error = %v", err)
	}
	// No relationship budget: nothing is requested.
	request.RemainingRelationships = 0
	api, roundTripper = newMicrosoftTestAPI(t, microsoftOK(microsoftTestEmpty))
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !errors.Is(err, providercollection.ErrPageCapacity) || roundTripper.calls() != 0 {
		t.Fatalf("relationship budget error/calls = %v / %d", err, roundTripper.calls())
	}
	// A page larger than the remaining bytes is a capacity stop, not data.
	request = microsoftTestRequest()
	request.Cursor, request.Page, request.RemainingBytes = identities, 2, 4096
	values := make([]string, 0, 40)
	for index := 1; index <= 40; index++ {
		values = append(values, identity(index))
	}
	api, _ = newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+strings.Join(values, ",")+`]}`))
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !errors.Is(err, providercollection.ErrPageCapacity) {
		t.Fatalf("byte budget error = %v", err)
	}
	api, _ = newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+identity(1)+`]}`))
	if page, err = api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); err != nil || int64(len(page.Raw)) > request.RemainingBytes {
		t.Fatalf("small page = %d bytes, %v", len(page.Raw), err)
	}
	for name, mutate := range map[string]func(*CollectionPageRequest){
		"no items":      func(request *CollectionPageRequest) { request.RemainingItems = 0 },
		"too few bytes": func(request *CollectionPageRequest) { request.RemainingBytes = 4095 },
	} {
		api, roundTripper = newMicrosoftTestAPI(t, microsoftOK(microsoftTestOrganization))
		request = microsoftTestRequest()
		mutate(&request)
		if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
			t.Fatalf("%s error/calls = %v / %d", name, err, roundTripper.calls())
		}
	}
	// A provider response beyond the fixed bound is refused unread.
	api, _ = newMicrosoftTestAPI(t, microsoftOK(`{"value":[],"padding":"`+strings.Repeat("a", int(microsoftMaximumResponseBytes))+`"}`))
	request = microsoftTestRequest()
	request.Cursor, request.Page = principals, 2
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !microsoftFailureHasCode(err, collection.FailureMalformed) {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestMicrosoftCollectionAPIBindsCursorsToTheSubject(t *testing.T) {
	t.Parallel()
	other := collection.SubjectBinding{Kind: "microsoft_tenant", ID: "99999999-2222-4333-8444-555555555555"}
	valid := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 3, Continuation: "next"})
	foreign := microsoftTestCursor(t, other, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 3, Continuation: "next"})
	parts := strings.Split(valid.Value, ":")
	foreignParts := strings.Split(foreign.Value, ":")
	if len(parts) != 5 || parts[3] != foreignParts[3] || parts[4] == foreignParts[4] {
		t.Fatalf("cursors = %q / %q", valid.Value, foreign.Value)
	}
	tampered := func(index int, value string) collection.Cursor {
		copied := append([]string(nil), parts...)
		copied[index] = value
		return collection.Cursor{Provider: collection.ProviderMicrosoft, Version: "cursor_v1", Value: strings.Join(copied, ":")}
	}
	otherPayload := strings.Split(microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 3, Continuation: "other"}).Value, ":")[3]
	for name, test := range map[string]struct {
		cursor  collection.Cursor
		subject collection.SubjectBinding
		page    int
	}{
		"another tenant's cursor":  {foreign, microsoftTestSubject, 3},
		"cursor at another tenant": {valid, other, 3},
		"another page":             {valid, microsoftTestSubject, 4},
		"another phase":            {tampered(1, microsoftPhaseAgentIdentities), microsoftTestSubject, 3},
		"another lineage":          {tampered(2, "4"), microsoftTestSubject, 4},
		"another continuation":     {tampered(3, otherPayload), microsoftTestSubject, 3},
		"another binding":          {tampered(4, "0000000000000000"), microsoftTestSubject, 3},
		"tenant phase cursor":      {tampered(1, microsoftPhaseTenant), microsoftTestSubject, 3},
		"another provider":         {collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: valid.Value}, microsoftTestSubject, 3},
		"another version":          {collection.Cursor{Provider: collection.ProviderMicrosoft, Version: "cursor_v2", Value: valid.Value}, microsoftTestSubject, 3},
		"unknown value":            {collection.Cursor{Provider: collection.ProviderMicrosoft, Version: "cursor_v1", Value: "microsoft:serviceprincipals"}, microsoftTestSubject, 3},
		"initial after page one":   {collection.Cursor{}, microsoftTestSubject, 2},
		"another subject kind":     {collection.Cursor{}, collection.SubjectBinding{Kind: "okta_tenant", ID: microsoftTestTenant}, 1},
		"subject not a tenant id":  {collection.Cursor{}, collection.SubjectBinding{Kind: "microsoft_tenant", ID: "contoso.onmicrosoft.com"}, 1},
		"upper case tenant id":     {collection.Cursor{}, collection.SubjectBinding{Kind: "microsoft_tenant", ID: strings.ToUpper(microsoftTestTenant)}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestEmpty))
			request := microsoftTestRequest()
			request.Cursor, request.Subject, request.Page = test.cursor, test.subject, test.page
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
				t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	api, roundTripper := newMicrosoftTestAPI(t, microsoftOK(microsoftTestEmpty))
	request := microsoftTestRequest()
	request.Cursor, request.Page = valid, 3
	if page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); err != nil || !page.Complete || roundTripper.calls() != 1 {
		t.Fatalf("valid cursor page = %#v, %v", page, err)
	}
	request.Provider = collection.ProviderOkta
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another provider error = %v", err)
	}
	// The cursor is bounded: an oversized continuation never becomes one.
	if _, _, ok := nextMicrosoftStateCursor(microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 3, Continuation: strings.Repeat("a", microsoftMaximumContinuationBytes+1)}); ok {
		t.Fatal("oversized continuation accepted")
	}
	longest, _, ok := nextMicrosoftStateCursor(microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: 999_999, Continuation: strings.Repeat("a", 900), Environment: "org1.crm4.dynamics.com"})
	if !ok || len(longest.Value) > 2048 {
		t.Fatalf("long cursor = %d bytes, ok=%t", len(longest.Value), ok)
	}
	if _, _, ok := nextMicrosoftStateCursor(microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 3, Continuation: strings.Repeat("<", microsoftMaximumContinuationBytes)}); ok {
		t.Fatal("continuation that outgrows the cursor accepted")
	}
}

func TestMicrosoftCollectionAPIFailsThePageOnUnusableAgentFields(t *testing.T) {
	t.Parallel()
	identities := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: 2})
	principals := microsoftTestCursor(t, microsoftTestSubject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: 2})
	for name, test := range map[string]struct {
		cursor collection.Cursor
		item   string
	}{
		"identity without a name":        {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"","accountEnabled":true}`},
		"identity with a null name":      {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":null,"accountEnabled":true}`},
		"identity name too long":         {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"` + strings.Repeat("a", 257) + `","accountEnabled":true}`},
		"identity name control":          {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"agent\u0000one","accountEnabled":true}`},
		"identity name padded":           {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":" agent","accountEnabled":true}`},
		"identity without a state":       {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"agent"}`},
		"identity state text":            {identities, `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"agent","accountEnabled":"true"}`},
		"identity without an id":         {identities, `{"displayName":"agent","accountEnabled":true}`},
		"identity id not a GUID":         {identities, `{"id":"agent-1","displayName":"agent","accountEnabled":true}`},
		"application name too long":      {principals, `{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"ChatGPT ` + strings.Repeat("a", 250) + `","accountEnabled":true,"servicePrincipalType":"Application"}`},
		"application name control":       {principals, `{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"ChatGPT\u0007","accountEnabled":true,"servicePrincipalType":"Application"}`},
		"application without a state":    {principals, `{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"ChatGPT","accountEnabled":null,"servicePrincipalType":"Application"}`},
		"principal id not a GUID":        {principals, `{"id":"x","displayName":"Contoso HR","accountEnabled":true,"servicePrincipalType":"Application"}`},
		"principal is not an object":     {principals, `"cccccccc-0000-4000-8000-000000000001"`},
		"principal type is not a string": {principals, `{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"Contoso HR","accountEnabled":true,"servicePrincipalType":1}`},
	} {
		t.Run(name, func(t *testing.T) {
			api, _ := newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+test.item+`]}`))
			request := microsoftTestRequest()
			request.Cursor, request.Page = test.cursor, 2
			if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !microsoftFailureHasCode(err, collection.FailureMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	duplicate := `{"id":"aaaaaaaa-0000-4000-8000-000000000001","displayName":"agent","accountEnabled":true}`
	api, _ := newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+duplicate+`,`+duplicate+`]}`))
	request := microsoftTestRequest()
	request.Cursor, request.Page = identities, 2
	if _, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request); !microsoftFailureHasCode(err, collection.FailureMalformed) {
		t.Fatalf("duplicate identity error = %v", err)
	}
	// A principal this collector does not list is dropped whatever its name.
	api, _ = newMicrosoftTestAPI(t, microsoftOK(`{"value":[`+
		`{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"","accountEnabled":null,"servicePrincipalType":"Application"},`+
		`{"id":"cccccccc-0000-4000-8000-000000000002","displayName":" Contoso HR\u0000`+strings.Repeat("a", 300)+`","servicePrincipalType":"Application"},`+
		`{"id":"cccccccc-0000-4000-8000-000000000003","displayName":"ChatGPT\u0000","servicePrincipalType":"ManagedIdentity"}]}`))
	request.Cursor = principals
	page, err := api.FetchCollectionPage(context.Background(), bytes.Clone(microsoftTestGraphCredential), request)
	if err != nil || !page.Complete || len(page.Entities) != 0 || len(page.Relationships) != 0 {
		t.Fatalf("unlisted principals page = %#v, %v", page, err)
	}
}

func TestMicrosoftCollectionAPIReadinessNeedsGraphsBearerChallenge(t *testing.T) {
	t.Parallel()
	challenge := http.Header{"Www-Authenticate": []string{`Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize"`}}
	api, roundTripper := newMicrosoftTestAPI(t, microsoftHTTPResponse{status: http.StatusUnauthorized, body: `{"error":{"code":"InvalidAuthenticationToken"}}`, header: challenge})
	if err := api.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("CheckCollectionReadiness() error = %v", err)
	}
	if roundTripper.calls() != 1 || roundTripper.requests[0].URL.String() != "https://graph.microsoft.com/v1.0/organization?$select=id" || roundTripper.requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("readiness requests = %#v", roundTripper.requests)
	}
	for name, response := range map[string]microsoftHTTPResponse{
		"redirect":          {status: http.StatusFound, body: `{}`, header: http.Header{"Location": []string{"https://evil.example"}}},
		"anonymous success": {status: http.StatusOK, body: microsoftTestOrganization, header: challenge},
		"no challenge":      {status: http.StatusUnauthorized, body: `{}`},
		"basic challenge":   {status: http.StatusUnauthorized, body: `{}`, header: http.Header{"Www-Authenticate": []string{`Basic realm="proxy"`}}},
		"unavailable":       {status: http.StatusServiceUnavailable, body: `{}`, header: challenge},
	} {
		api, roundTripper = newMicrosoftTestAPI(t, response)
		if err := api.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrProvider) || roundTripper.calls() != 1 {
			t.Fatalf("%s readiness error/calls = %v / %d", name, err, roundTripper.calls())
		}
	}
	api, _ = newMicrosoftTestAPI(t)
	if err := api.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "microsoft-provider-secret") {
		t.Fatalf("transport readiness error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := api.CheckCollectionReadiness(cancelled); !errors.Is(err, ErrProvider) {
		t.Fatalf("cancelled readiness error = %v", err)
	}
}

func TestMicrosoftConstructorsValidateConfiguration(t *testing.T) {
	t.Parallel()
	for name, config := range map[string]CollectionAPIConfig{
		"no timeout":    {},
		"short timeout": {Timeout: 99 * time.Millisecond},
		"long timeout":  {Timeout: 31 * time.Second},
	} {
		if api, err := NewMicrosoftCollectionAPI(config); !errors.Is(err, ErrInvalid) || api != nil {
			t.Fatalf("%s: api/error = %v / %v", name, api, err)
		}
	}
	api, err := NewMicrosoftCollectionAPI(CollectionAPIConfig{Timeout: time.Second})
	if err != nil || api == nil {
		t.Fatalf("default transport api/error = %v / %v", api, err)
	}
	clock := func() time.Time { return microsoftTestClock() }
	client, err := NewMicrosoftCollectionClient(api, microsoftTestArtifacts{}, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: clock})
	if err != nil || client == nil {
		t.Fatalf("NewMicrosoftCollectionClient() = %v, %v", client, err)
	}
	if _, err := NewMicrosoftCollectionClient(nil, microsoftTestArtifacts{}, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: clock}); err == nil {
		t.Fatal("client without an API accepted")
	}
}

func TestMicrosoftInventoryIDsAreDeterministicAndScoped(t *testing.T) {
	t.Parallel()
	other := collection.SubjectBinding{Kind: "microsoft_tenant", ID: "99999999-2222-4333-8444-555555555555"}
	first := deterministicMicrosoftInventoryID(microsoftTestSubject, "microsoft_agent_identity", "aaaaaaaa-0000-4000-8000-000000000001")
	if first != deterministicMicrosoftInventoryID(microsoftTestSubject, "microsoft_agent_identity", "aaaaaaaa-0000-4000-8000-000000000001") ||
		first == deterministicMicrosoftInventoryID(other, "microsoft_agent_identity", "aaaaaaaa-0000-4000-8000-000000000001") ||
		first == deterministicMicrosoftInventoryID(microsoftTestSubject, "microsoft_ai_application", "aaaaaaaa-0000-4000-8000-000000000001") ||
		!strings.HasPrefix(first, "pid_") || len(first) != 40 {
		t.Fatalf("inventory id = %q", first)
	}
}

func mustMicrosoftJSON(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type microsoftTestArtifacts struct{}

func (microsoftTestArtifacts) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{Locator: request.Locator, MediaType: request.MediaType, Body: bytes.Clone(request.Body), Size: int64(len(request.Body)), SHA256: sha256.Sum256(request.Body)}, nil
}

func (microsoftTestArtifacts) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrGet
}

func (microsoftTestArtifacts) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}

func (microsoftTestArtifacts) ObjectReference(artifactstore.Locator) (string, error) {
	return "", artifactstore.ErrArtifact
}
