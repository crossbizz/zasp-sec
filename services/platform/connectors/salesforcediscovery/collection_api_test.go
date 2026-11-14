package salesforcediscovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const (
	salesforceTestToken    = "salesforce-access-secret-value"
	salesforceTestHost     = "https://acme.my.salesforce.com"
	salesforceTestOrgID    = "00D5g000004XyZaEAK"
	salesforceTestOrgBody  = `{"totalSize":1,"done":true,"records":[{"attributes":{"type":"Organization","url":"/services/data/v62.0/sobjects/Organization/00D5g000004XyZaEAK"},"Id":"00D5g000004XyZaEAK","Name":"Acme Corporation"}]}`
	salesforceTestBotOne   = "0Xx5g0000004C9ACAU"
	salesforceTestBotTwo   = "0Xx5g0000004C9BCAU"
	salesforceTestBotThree = "0Xx5g0000004C9CCAU"
	salesforceTestVersion  = "0X95g0000004D1AAAU"
)

var (
	salesforceTestSubject = collection.SubjectBinding{Kind: "salesforce_org", ID: salesforceTestOrgID}
	salesforceTestNow     = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
)

type salesforceRoundTripper struct {
	mu        sync.Mutex
	requests  []*http.Request
	responses []salesforceHTTPResponse
}

type salesforceHTTPResponse struct {
	status int
	body   string
	header http.Header
}

func (roundTripper *salesforceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	roundTripper.requests = append(roundTripper.requests, request.Clone(request.Context()))
	if len(roundTripper.responses) == 0 {
		return nil, errors.New("salesforce-provider-secret " + salesforceTestToken)
	}
	response := roundTripper.responses[0]
	roundTripper.responses = roundTripper.responses[1:]
	return &http.Response{StatusCode: response.status, Header: response.header, Body: io.NopCloser(strings.NewReader(response.body)), Request: request}, nil
}

func (roundTripper *salesforceRoundTripper) calls() int {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	return len(roundTripper.requests)
}

func salesforceTestCredential(token, instanceURL string) []byte {
	return []byte(`{"access_token":"` + token + `","instance_url":"` + instanceURL + `"}`)
}

func newSalesforceTestAPI(t *testing.T, responses ...salesforceHTTPResponse) (CollectionAPI, *salesforceRoundTripper) {
	t.Helper()
	roundTripper := &salesforceRoundTripper{responses: responses}
	api, err := NewSalesforceCollectionAPI(CollectionAPIConfig{Transport: roundTripper, Timeout: time.Second, Clock: func() time.Time { return salesforceTestNow }})
	if err != nil {
		t.Fatalf("NewSalesforceCollectionAPI() error = %v", err)
	}
	return api, roundTripper
}

func salesforceInitialRequest() CollectionPageRequest {
	return CollectionPageRequest{Provider: collection.ProviderSalesforce, Subject: salesforceTestSubject, Page: 1, RemainingItems: 64, RemainingRelationships: 128, RemainingBytes: 1 << 20}
}

// salesforceAgentsRequest is the request for the first agents page (page 2).
func salesforceAgentsRequest(t *testing.T) CollectionPageRequest {
	t.Helper()
	cursor, ok := nextSalesforceStateCursor(salesforceTestSubject, salesforcePageState{Phase: "agents", Lineage: 2})
	if !ok {
		t.Fatal("agents cursor rejected")
	}
	request := salesforceInitialRequest()
	request.Cursor, request.Page = cursor, 2
	return request
}

func salesforceBotRecord(id, developerName, label, extra string) string {
	return fmt.Sprintf(`{"attributes":{"type":"BotDefinition","url":"/services/data/v62.0/sobjects/BotDefinition/%s"},"Id":%q,"DeveloperName":%q,"MasterLabel":%q%s}`, id, id, developerName, label, extra)
}

func salesforceQueryBody(done bool, next string, records ...string) string {
	if next != "" {
		next = fmt.Sprintf(`,"nextRecordsUrl":%q`, next)
	}
	return fmt.Sprintf(`{"totalSize":%d,"done":%t%s,"records":[%s]}`, len(records), done, next, strings.Join(records, ","))
}

func salesforceErrorBody(code string) string {
	return fmt.Sprintf(`[{"message":"No such column 'AgentType' on entity 'BotDefinition' %s","errorCode":%q}]`, salesforceTestToken, code)
}

const salesforceActiveVersions = `,"BotVersions":{"totalSize":1,"done":true,"records":[{"attributes":{"type":"BotVersion","url":"/services/data/v62.0/sobjects/BotVersion/0X95g0000004D1AAAU"},"Id":"0X95g0000004D1AAAU"}]}`

type salesforceTestEntity struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	SourceNativeID string `json:"source_native_id"`
	DisplayName    string `json:"display_name"`
	StableFields   struct {
		Name       string `json:"name"`
		ObjectType string `json:"object_type"`
		Org        string `json:"org"`
	} `json:"stable_fields"`
	Attributes struct {
		Status    string  `json:"status"`
		AgentType *string `json:"agent_type"`
		Posture   *struct {
			CredentialActive bool `json:"credential_active"`
		} `json:"posture"`
		Discovery *struct {
			Method   string   `json:"method"`
			Platform string   `json:"platform"`
			Signals  []string `json:"signals"`
		} `json:"discovery"`
	} `json:"attributes"`
}

func salesforceTestEntities(t *testing.T, values []json.RawMessage) []salesforceTestEntity {
	t.Helper()
	result := make([]salesforceTestEntity, len(values))
	for index, value := range values {
		if err := json.Unmarshal(value, &result[index]); err != nil {
			t.Fatalf("entity %d: %v", index, err)
		}
	}
	return result
}

func salesforceFailureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}

func mustSalesforceCollectionPage(t *testing.T, page CollectionPage) CollectionPage {
	t.Helper()
	canonical, err := NewSalesforceCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil {
		t.Fatalf("NewSalesforceCollectionPage() error = %v", err)
	}
	return canonical
}

func TestSalesforceCollectionAPICollectsOrganizationAndAgentsCanonically(t *testing.T) {
	t.Parallel()
	api, roundTripper := newSalesforceTestAPI(t,
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody},
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV-2000",
			salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"Type":"Bot","AgentType":"EinsteinServiceAgent"`+salesforceActiveVersions),
			salesforceBotRecord(salesforceTestBotTwo, "Legacy_Bot", "", `,"Type":"Bot","AgentType":null,"BotVersions":null`))},
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(true, "",
			salesforceBotRecord(salesforceTestBotThree, "Sales_Coach", "Sales Coach", `,"Type":null,"AgentType":null,"BotVersions":{"totalSize":0,"done":true,"records":[]}`))},
	)
	credential := salesforceTestCredential(salesforceTestToken, salesforceTestHost)
	request := salesforceInitialRequest()
	pages := make([]CollectionPage, 0, 3)
	for pageNumber := 1; pageNumber <= 3; pageNumber++ {
		request.Page = pageNumber
		page, err := api.FetchCollectionPage(context.Background(), credential, request)
		if err != nil {
			t.Fatalf("FetchCollectionPage(%d) error = %v", pageNumber, err)
		}
		if bytes.Contains(page.Raw, []byte(salesforceTestToken)) || bytes.Contains(page.Raw, credential) || !bytes.Equal(page.Raw, mustSalesforceCollectionPage(t, page).Raw) || page.Subject != salesforceTestSubject {
			t.Fatalf("page %d leaked or noncanonical: %s", pageNumber, page.Raw)
		}
		for _, item := range append(append([]json.RawMessage(nil), page.Entities...), page.Relationships...) {
			if bytes.Contains(item, []byte(salesforceTestToken)) {
				t.Fatalf("page %d item leaked: %s", pageNumber, item)
			}
		}
		pages = append(pages, page)
		request.Cursor = page.Cursor
		request.RemainingItems -= len(page.Entities)
		request.RemainingRelationships -= len(page.Relationships)
	}
	if pages[0].Complete || !strings.HasPrefix(pages[0].Cursor.Value, "salesforce:agents:2:") || len(pages[0].Entities) != 1 || len(pages[0].Relationships) != 0 ||
		pages[1].Complete || !strings.HasPrefix(pages[1].Cursor.Value, "salesforce:agents:3:") || len(pages[1].Entities) != 2 || len(pages[1].Relationships) != 2 ||
		!pages[2].Complete || !strings.HasPrefix(pages[2].Cursor.Value, "salesforce:complete:") || len(pages[2].Entities) != 1 || len(pages[2].Relationships) != 1 {
		t.Fatalf("pages = %#v", pages)
	}
	organization := salesforceTestEntities(t, pages[0].Entities)[0]
	if organization.Kind != "salesforce_org" || organization.SourceNativeID != "salesforce:org:"+salesforceTestOrgID || organization.DisplayName != "Acme Corporation" || organization.StableFields.Name != "Acme Corporation" || organization.StableFields.Org != salesforceTestOrgID || organization.ID != deterministicSalesforceInventoryID(salesforceTestSubject, "salesforce_org", salesforceTestOrgID) {
		t.Fatalf("organization = %+v", organization)
	}
	agents := append(salesforceTestEntities(t, pages[1].Entities), salesforceTestEntities(t, pages[2].Entities)...)
	want := []struct {
		id, name, status, agentType string
		active                      bool
	}{
		{salesforceTestBotOne, "Support Agent", "ACTIVE", "EinsteinServiceAgent", true},
		{salesforceTestBotTwo, "Legacy_Bot", "INACTIVE", "Bot", false},
		{salesforceTestBotThree, "Sales Coach", "INACTIVE", "", false},
	}
	for index, agent := range agents {
		expected := want[index]
		agentType := ""
		if agent.Attributes.AgentType != nil {
			agentType = *agent.Attributes.AgentType
		}
		if agent.Kind != "salesforce_agent" || agent.SourceNativeID != "salesforce:bot_definition:"+expected.id || agent.DisplayName != expected.name || agent.StableFields.Name != expected.name || agent.StableFields.ObjectType != "bot_definition" || agent.StableFields.Org != salesforceTestOrgID ||
			agent.Attributes.Status != expected.status || agentType != expected.agentType || (agent.Attributes.AgentType != nil) != (expected.agentType != "") || agent.Attributes.Posture == nil || agent.Attributes.Posture.CredentialActive != expected.active ||
			agent.Attributes.Discovery == nil || agent.Attributes.Discovery.Method != "provider_api" || agent.Attributes.Discovery.Platform != "agentforce" || agent.Attributes.Discovery.Signals == nil || len(agent.Attributes.Discovery.Signals) != 0 ||
			agent.ID != deterministicSalesforceInventoryID(salesforceTestSubject, "salesforce_agent", expected.id) {
			t.Fatalf("agent %d = %+v", index, agent)
		}
	}
	var relationship struct {
		Kind           string `json:"kind"`
		SourceNativeID string `json:"source_native_id"`
		FromEntityID   string `json:"from_entity_id"`
		ToEntityID     string `json:"to_entity_id"`
		Attributes     struct {
			Type string `json:"type"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal(pages[1].Relationships[0], &relationship); err != nil || relationship.Kind != "contains" || relationship.SourceNativeID != "salesforce:org:"+salesforceTestOrgID+":"+salesforceTestBotOne || relationship.FromEntityID != organization.ID || relationship.ToEntityID != agents[0].ID || relationship.Attributes.Type != "org_object" {
		t.Fatalf("relationship = %+v / %v", relationship, err)
	}
	if roundTripper.calls() != 3 {
		t.Fatalf("provider calls = %d", roundTripper.calls())
	}
	wantPaths := []string{"/services/data/v62.0/query", "/services/data/v62.0/query", "/services/data/v62.0/query/01g5g00000AbCdEAAV-2000"}
	wantQueries := []string{"SELECT Id,Name FROM Organization", "SELECT Id,DeveloperName,MasterLabel,Type,AgentType,(SELECT Id FROM BotVersions WHERE Status='Active' LIMIT 1) FROM BotDefinition ORDER BY Id", ""}
	for index, providerRequest := range roundTripper.requests {
		if providerRequest.Method != http.MethodGet || providerRequest.URL.Scheme != "https" || providerRequest.URL.Host != "acme.my.salesforce.com" || providerRequest.URL.Path != wantPaths[index] || providerRequest.URL.Query().Get("q") != wantQueries[index] || len(providerRequest.URL.Query()) > 1 ||
			providerRequest.Header.Get("Authorization") != "Bearer "+salesforceTestToken || providerRequest.Header.Get("Accept") != "application/json" {
			t.Fatalf("request %d = %s %s", index, providerRequest.Method, providerRequest.URL)
		}
	}
	// A completed collection restarts from the org on the next run.
	restart := salesforceInitialRequest()
	restart.Cursor = pages[2].Cursor
	again, _ := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
	if page, err := again.FetchCollectionPage(context.Background(), credential, restart); err != nil || len(page.Entities) != 1 || !strings.HasPrefix(page.Cursor.Value, "salesforce:agents:2:") {
		t.Fatalf("restart page/error = %#v / %v", page, err)
	}
}

func TestSalesforceCollectionAPIRefusesAnotherOrganization(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"another org":       `{"totalSize":1,"done":true,"records":[{"Id":"00D5g000004XyZbEAK","Name":"Other"}]}`,
		"15 character id":   `{"totalSize":1,"done":true,"records":[{"Id":"00D5g000004XyZa","Name":"Acme Corporation"}]}`,
		"case folded id":    `{"totalSize":1,"done":true,"records":[{"Id":"00d5g000004xyzaeak","Name":"Acme Corporation"}]}`,
		"no record":         `{"totalSize":0,"done":true,"records":[]}`,
		"two records":       `{"totalSize":2,"done":true,"records":[{"Id":"00D5g000004XyZaEAK","Name":"Acme"},{"Id":"00D5g000004XyZbEAK","Name":"Other"}]}`,
		"unfinished result": `{"totalSize":1,"done":false,"nextRecordsUrl":"/services/data/v62.0/query/01g5g00000AbCdEAAV-1","records":[{"Id":"00D5g000004XyZaEAK","Name":"Acme"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: body})
			_, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceInitialRequest())
			if !salesforceFailureHasCode(err, collection.FailureDenied) || roundTripper.calls() != 1 {
				t.Fatalf("attestation error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	for name, body := range map[string]string{
		"not json":      `<html>`,
		"missing done":  `{"totalSize":1,"records":[{"Id":"00D5g000004XyZaEAK","Name":"Acme"}]}`,
		"no records":    `{"totalSize":1,"done":true}`,
		"trailing data": salesforceTestOrgBody + `{}`,
		"control name":  `{"totalSize":1,"done":true,"records":[{"Id":"00D5g000004XyZaEAK","Name":"Ac\u0007me"}]}`,
		"empty name":    `{"totalSize":1,"done":true,"records":[{"Id":"00D5g000004XyZaEAK","Name":""}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, _ := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: body})
			if _, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceInitialRequest()); !salesforceFailureHasCode(err, collection.FailureMalformed) {
				t.Fatalf("malformed org error = %v", err)
			}
		})
	}
}

func TestSalesforceCollectionAPIAcceptsOnlySameVersionOpaqueNextRecordsURL(t *testing.T) {
	t.Parallel()
	record := salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":null`)
	for name, body := range map[string]string{
		"absolute url":          salesforceQueryBody(false, "https://evil.example/services/data/v62.0/query/01g5g00000AbCdEAAV-2000", record),
		"absolute same host":    salesforceQueryBody(false, salesforceTestHost+"/services/data/v62.0/query/01g5g00000AbCdEAAV-2000", record),
		"scheme relative":       salesforceQueryBody(false, "//evil.example/services/data/v62.0/query/01g5g00000AbCdEAAV-2000", record),
		"another version":       salesforceQueryBody(false, "/services/data/v61.0/query/01g5g00000AbCdEAAV-2000", record),
		"another resource":      salesforceQueryBody(false, "/services/data/v62.0/sobjects/01g5g00000AbCdEAAV-2000", record),
		"path traversal":        salesforceQueryBody(false, "/services/data/v62.0/query/../sobjects", record),
		"nested path":           salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV/2000", record),
		"query string":          salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV-2000?q=x", record),
		"empty locator":         salesforceQueryBody(false, "/services/data/v62.0/query/", record),
		"oversized locator":     salesforceQueryBody(false, "/services/data/v62.0/query/"+strings.Repeat("a", 129), record),
		"unfinished without":    salesforceQueryBody(false, "", record),
		"unfinished and empty":  salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV-2000"),
		"finished with locator": salesforceQueryBody(true, "/services/data/v62.0/query/01g5g00000AbCdEAAV-2000", record),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: body})
			if _, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceAgentsRequest(t)); !salesforceFailureHasCode(err, collection.FailureMalformed) || roundTripper.calls() != 1 {
				t.Fatalf("hostile nextRecordsUrl error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
}

func TestSalesforceCollectionAPIFallsBackThroughQueryVariantsAndLaterPagesReuseTheChoice(t *testing.T) {
	t.Parallel()
	typed := `,"Type":"Bot","AgentType":"AgentforceEmployeeAgent"`
	api, roundTripper := newSalesforceTestAPI(t,
		salesforceHTTPResponse{status: http.StatusBadRequest, body: salesforceErrorBody("INVALID_FIELD")},
		salesforceHTTPResponse{status: http.StatusBadRequest, body: salesforceErrorBody("INVALID_FIELD")},
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV-200", salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", typed))},
		// The provider cannot switch the later page back to the subquery shape.
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(true, "", salesforceBotRecord(salesforceTestBotTwo, "Sales_Coach", "Sales Coach", typed+salesforceActiveVersions))},
	)
	credential := salesforceTestCredential(salesforceTestToken, salesforceTestHost)
	request := salesforceAgentsRequest(t)
	first, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || first.Complete || roundTripper.calls() != 3 {
		t.Fatalf("first agents page/error/calls = %#v / %v / %d", first, err, roundTripper.calls())
	}
	state, ok := validSalesforcePageRequest(CollectionPageRequest{Provider: collection.ProviderSalesforce, Subject: salesforceTestSubject, Cursor: first.Cursor, Page: 3, RemainingItems: 1, RemainingBytes: 4096})
	if !ok || state != (salesforcePageState{Phase: "agents", Lineage: 3, Locator: "01g5g00000AbCdEAAV-200", Variant: 3}) {
		t.Fatalf("cursor state = %+v, %t", state, ok)
	}
	request.Cursor, request.Page = first.Cursor, 3
	second, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || !second.Complete || roundTripper.calls() != 4 {
		t.Fatalf("second agents page/error/calls = %#v / %v / %d", second, err, roundTripper.calls())
	}
	for index, agent := range append(salesforceTestEntities(t, first.Entities), salesforceTestEntities(t, second.Entities)...) {
		if agent.Attributes.Status != "UNKNOWN" || agent.Attributes.Posture == nil || agent.Attributes.Posture.CredentialActive || agent.Attributes.AgentType == nil || *agent.Attributes.AgentType != "AgentforceEmployeeAgent" {
			t.Fatalf("agent %d = %+v", index, agent)
		}
	}
	for index, want := range []string{salesforceAgentQueryVariants[0].soql, salesforceAgentQueryVariants[1].soql, salesforceAgentQueryVariants[2].soql, ""} {
		if got := roundTripper.requests[index].URL.Query().Get("q"); got != want {
			t.Fatalf("request %d query = %q, want %q", index, got, want)
		}
	}
	if roundTripper.requests[3].URL.Path != "/services/data/v62.0/query/01g5g00000AbCdEAAV-200" {
		t.Fatalf("continuation = %s", roundTripper.requests[3].URL)
	}

	for name, test := range map[string]struct {
		codes    []string
		variant  int
		complete bool
		failure  collection.FailureCode
	}{
		"reduced fields keep the subquery":     {codes: []string{"INVALID_FIELD"}, variant: 1},
		"unknown relationship skips to plain":  {codes: []string{"INVALID_TYPE"}, variant: 2},
		"malformed subquery skips to plain":    {codes: []string{"MALFORMED_QUERY"}, variant: 2},
		"reduced subquery then plain":          {codes: []string{"INVALID_FIELD", "MALFORMED_QUERY"}, variant: 2},
		"last variant":                         {codes: []string{"INVALID_FIELD", "INVALID_FIELD", "INVALID_FIELD"}, variant: 3},
		"plain after type then reduced":        {codes: []string{"INVALID_TYPE", "INVALID_FIELD"}, variant: 3},
		"no bots feature":                      {codes: []string{"INVALID_TYPE", "INVALID_TYPE"}, complete: true},
		"no bots feature after reduced fields": {codes: []string{"INVALID_FIELD", "INVALID_TYPE", "INVALID_FIELD", "INVALID_TYPE"}, complete: true},
		"every variant refused":                {codes: []string{"INVALID_FIELD", "INVALID_FIELD", "INVALID_FIELD", "INVALID_FIELD"}, failure: collection.FailureTerminal},
		"plain query malformed":                {codes: []string{"MALFORMED_QUERY", "MALFORMED_QUERY"}, failure: collection.FailureTerminal},
		"another error code":                   {codes: []string{"INSUFFICIENT_ACCESS"}, failure: collection.FailureTerminal},
		"unreadable error":                     {codes: []string{""}, failure: collection.FailureTerminal},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			responses := make([]salesforceHTTPResponse, 0, len(test.codes)+1)
			for _, code := range test.codes {
				body := salesforceErrorBody(code)
				if code == "" {
					body = `<html>` + salesforceTestToken
				}
				responses = append(responses, salesforceHTTPResponse{status: http.StatusBadRequest, body: body})
			}
			extra := `,"Type":"Bot","AgentType":"AgentforceEmployeeAgent"` + salesforceActiveVersions
			responses = append(responses, salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV-200", salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", extra))})
			api, roundTripper := newSalesforceTestAPI(t, responses...)
			page, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceAgentsRequest(t))
			if roundTripper.calls() > len(salesforceAgentQueryVariants) {
				t.Fatalf("provider calls = %d", roundTripper.calls())
			}
			switch {
			case test.failure != "":
				if !salesforceFailureHasCode(err, test.failure) || strings.Contains(err.Error(), salesforceTestToken) || roundTripper.calls() != len(test.codes) {
					t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
				}
			case test.complete:
				if err != nil || !page.Complete || len(page.Entities) != 0 || len(page.Relationships) != 0 || !strings.HasPrefix(page.Cursor.Value, "salesforce:complete:") || roundTripper.calls() != len(test.codes) {
					t.Fatalf("page/error/calls = %#v / %v / %d", page, err, roundTripper.calls())
				}
			default:
				if err != nil || roundTripper.calls() != len(test.codes)+1 || roundTripper.requests[len(test.codes)].URL.Query().Get("q") != salesforceAgentQueryVariants[test.variant].soql {
					t.Fatalf("error/calls = %v / %d", err, roundTripper.calls())
				}
				state, ok := validSalesforcePageRequest(CollectionPageRequest{Provider: collection.ProviderSalesforce, Subject: salesforceTestSubject, Cursor: page.Cursor, Page: 3, RemainingItems: 1, RemainingBytes: 4096})
				agent := salesforceTestEntities(t, page.Entities)[0]
				variant := salesforceAgentQueryVariants[test.variant]
				if !ok || state.Variant != test.variant+1 || (agent.Attributes.Status == "UNKNOWN") == variant.activeVersions || (agent.Attributes.AgentType != nil) != variant.agentTypes {
					t.Fatalf("state/agent = %+v / %+v", state, agent)
				}
			}
		})
	}
}

func TestSalesforceCollectionAPIRefusesHostileCredentialEnvelopes(t *testing.T) {
	t.Parallel()
	valid := string(salesforceTestCredential(salesforceTestToken, salesforceTestHost))
	hostile := map[string]string{
		"unknown member":       `{"access_token":"` + salesforceTestToken + `","instance_url":"` + salesforceTestHost + `","refresh_token":"salesforce-refresh-secret"}`,
		"leading member":       `{"scope":"api","access_token":"` + salesforceTestToken + `","instance_url":"` + salesforceTestHost + `"}`,
		"reordered members":    `{"instance_url":"` + salesforceTestHost + `","access_token":"` + salesforceTestToken + `"}`,
		"duplicate member":     `{"access_token":"` + salesforceTestToken + `","instance_url":"https://evil.example","instance_url":"` + salesforceTestHost + `"}`,
		"spaced":               `{"access_token": "` + salesforceTestToken + `", "instance_url": "` + salesforceTestHost + `"}`,
		"trailing data":        valid + `{}`,
		"bare token":           salesforceTestToken,
		"empty":                ``,
		"http scheme":          string(salesforceTestCredential(salesforceTestToken, "http://acme.my.salesforce.com")),
		"non salesforce host":  string(salesforceTestCredential(salesforceTestToken, "https://acme.my.salesforce.com.evil.example")),
		"lookalike suffix":     string(salesforceTestCredential(salesforceTestToken, "https://acme.evilmy.salesforce.com")),
		"bare domain":          string(salesforceTestCredential(salesforceTestToken, "https://my.salesforce.com")),
		"login host":           string(salesforceTestCredential(salesforceTestToken, "https://login.salesforce.com")),
		"host with path":       string(salesforceTestCredential(salesforceTestToken, "https://acme.my.salesforce.com/services")),
		"host with slash":      string(salesforceTestCredential(salesforceTestToken, "https://acme.my.salesforce.com/")),
		"host with port":       string(salesforceTestCredential(salesforceTestToken, "https://acme.my.salesforce.com:8443")),
		"host with userinfo":   string(salesforceTestCredential(salesforceTestToken, "https://user@acme.my.salesforce.com")),
		"host with query":      string(salesforceTestCredential(salesforceTestToken, "https://acme.my.salesforce.com?x=1")),
		"upper case host":      string(salesforceTestCredential(salesforceTestToken, "https://ACME.my.salesforce.com")),
		"too many labels":      string(salesforceTestCredential(salesforceTestToken, "https://a.b.c.d.e.my.salesforce.com")),
		"short token":          string(salesforceTestCredential("short-token-15b", salesforceTestHost)),
		"long token":           string(salesforceTestCredential(strings.Repeat("a", 8193), salesforceTestHost)),
		"token with space":     string(salesforceTestCredential("salesforce access secret", salesforceTestHost)),
		"token with newline":   string(salesforceTestCredential("salesforce-access\\nsecret-value", salesforceTestHost)),
		"token with control":   string(salesforceTestCredential("salesforce-access\x07secret-value", salesforceTestHost)),
		"token with non ascii": string(salesforceTestCredential("salesforce-access-sécret-value", salesforceTestHost)),
	}
	for name, credential := range hostile {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
			_, err := api.FetchCollectionPage(context.Background(), []byte(credential), salesforceInitialRequest())
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "secret") || roundTripper.calls() != 0 {
				t.Fatalf("hostile envelope error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
	for name, instanceURL := range map[string]string{"sandbox": "https://acme--uat.sandbox.my.salesforce.com", "single label": "https://a.my.salesforce.com"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
			if _, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(strings.Repeat("a", 8192), instanceURL), salesforceInitialRequest()); err != nil || roundTripper.calls() != 1 || "https://"+roundTripper.requests[0].URL.Host != instanceURL {
				t.Fatalf("accepted envelope error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
}

func TestSalesforceCollectionAPINeverReturnsTheToken(t *testing.T) {
	t.Parallel()
	credential := salesforceTestCredential(salesforceTestToken, salesforceTestHost)
	// A provider that echoes the token into inventory data is refused.
	echoed, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(true, "", salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Agent "+salesforceTestToken, `,"BotVersions":null`))})
	if _, err := echoed.FetchCollectionPage(context.Background(), credential, salesforceAgentsRequest(t)); !salesforceFailureHasCode(err, collection.FailureMalformed) || strings.Contains(err.Error(), salesforceTestToken) || roundTripper.calls() != 1 {
		t.Fatalf("credential echo error/calls = %v / %d", err, roundTripper.calls())
	}
	echoedOrg, _ := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: `{"totalSize":1,"done":true,"records":[{"Id":"00D5g000004XyZaEAK","Name":"` + salesforceTestToken + `"}]}`})
	if _, err := echoedOrg.FetchCollectionPage(context.Background(), credential, salesforceInitialRequest()); !salesforceFailureHasCode(err, collection.FailureMalformed) || strings.Contains(err.Error(), salesforceTestToken) {
		t.Fatalf("org credential echo error = %v", err)
	}
	// A transport error that carries the token is reduced to a stable failure.
	broken, _ := newSalesforceTestAPI(t)
	for _, request := range []CollectionPageRequest{salesforceInitialRequest(), salesforceAgentsRequest(t)} {
		_, err := broken.FetchCollectionPage(context.Background(), credential, request)
		if !salesforceFailureHasCode(err, collection.FailureRetryable) || strings.Contains(err.Error(), "secret") || strings.Contains(fmt.Sprintf("%#v %+v", err, err), salesforceTestToken) {
			t.Fatalf("transport error = %v", err)
		}
	}
	// The caller's credential is borrowed, not rewritten.
	if !bytes.Equal(credential, salesforceTestCredential(salesforceTestToken, salesforceTestHost)) {
		t.Fatal("credential mutated")
	}
}

func TestSalesforceCollectionAPIClassifiesProviderFailuresLikeOkta(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		response salesforceHTTPResponse
		code     collection.FailureCode
		retryAt  time.Time
	}{
		"unauthorized":           {salesforceHTTPResponse{status: http.StatusUnauthorized, body: `[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]`}, collection.FailureDenied, time.Time{}},
		"forbidden":              {salesforceHTTPResponse{status: http.StatusForbidden, body: `[{"message":"denied","errorCode":"API_DISABLED_FOR_ORG"}]`}, collection.FailureDenied, time.Time{}},
		"rate limited":           {salesforceHTTPResponse{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"3"}}, body: `{}`}, collection.FailureRateLimited, salesforceTestNow.Add(3 * time.Second)},
		"rate limited unbounded": {salesforceHTTPResponse{status: http.StatusTooManyRequests, body: `{}`}, collection.FailureMalformed, time.Time{}},
		"server error":           {salesforceHTTPResponse{status: http.StatusInternalServerError, body: `{}`}, collection.FailureRetryable, time.Time{}},
		"unavailable":            {salesforceHTTPResponse{status: http.StatusServiceUnavailable, body: `{}`}, collection.FailureRetryable, time.Time{}},
		"not found":              {salesforceHTTPResponse{status: http.StatusNotFound, body: `[{"message":"missing","errorCode":"NOT_FOUND"}]`}, collection.FailureTerminal, time.Time{}},
		"bad request":            {salesforceHTTPResponse{status: http.StatusBadRequest, body: `[{"message":"expired","errorCode":"INVALID_QUERY_LOCATOR"}]`}, collection.FailureTerminal, time.Time{}},
		"redirect":               {salesforceHTTPResponse{status: http.StatusFound, header: http.Header{"Location": []string{"https://evil.example/steal"}}, body: `{}`}, collection.FailureMalformed, time.Time{}},
		"no content":             {salesforceHTTPResponse{status: http.StatusNoContent}, collection.FailureMalformed, time.Time{}},
		"empty body":             {salesforceHTTPResponse{status: http.StatusOK}, collection.FailureMalformed, time.Time{}},
	}
	continuation, ok := nextSalesforceStateCursor(salesforceTestSubject, salesforcePageState{Phase: "agents", Lineage: 3, Locator: "01g5g00000AbCdEAAV-2000", Variant: 1})
	if !ok {
		t.Fatal("continuation cursor rejected")
	}
	later := salesforceInitialRequest()
	later.Cursor, later.Page = continuation, 3
	for name, test := range tests {
		for phase, request := range map[string]CollectionPageRequest{"org": salesforceInitialRequest(), "agents": salesforceAgentsRequest(t), "continuation": later} {
			t.Run(name+"/"+phase, func(t *testing.T) {
				t.Parallel()
				api, roundTripper := newSalesforceTestAPI(t, test.response)
				_, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), request)
				var failure *collection.Failure
				if !errors.As(err, &failure) || failure.Code() != test.code || !failure.RetryAt().Equal(test.retryAt) || roundTripper.calls() != 1 {
					t.Fatalf("failure/calls = %v / %d", err, roundTripper.calls())
				}
				// The same status has the same stable failure as the shared
				// classifier every other collector, Okta included, uses.
				want := providercollection.ClassifyProviderHTTPFailure(context.Background(), nil, test.response.status, test.response.header.Get("Retry-After"), salesforceTestNow)
				if test.response.status != http.StatusOK && !salesforceFailureHasCode(want, test.code) {
					t.Fatalf("shared classification = %v", want)
				}
			})
		}
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
	if _, err := api.FetchCollectionPage(cancelled, salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceInitialRequest()); !salesforceFailureHasCode(err, collection.FailureCancelled) || roundTripper.calls() != 0 {
		t.Fatalf("cancelled error/calls = %v / %d", err, roundTripper.calls())
	}
}

func TestSalesforceCollectionAPIHonoursPageBudgets(t *testing.T) {
	t.Parallel()
	credential := salesforceTestCredential(salesforceTestToken, salesforceTestHost)
	two := salesforceQueryBody(true, "", salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":null`), salesforceBotRecord(salesforceTestBotTwo, "Sales_Coach", "Sales Coach", `,"BotVersions":null`))

	request := salesforceAgentsRequest(t)
	request.RemainingItems, request.RemainingRelationships = 700, 500
	api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: two})
	if page, err := api.FetchCollectionPage(context.Background(), credential, request); err != nil || len(page.Entities) != 2 || roundTripper.requests[0].Header.Get("Sforce-Query-Options") != "batchSize=500" {
		t.Fatalf("bounded batch page/error = %#v / %v", page, err)
	}
	request.RemainingItems, request.RemainingRelationships = 100_000, 200_000
	api, roundTripper = newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: two})
	if _, err := api.FetchCollectionPage(context.Background(), credential, request); err != nil || roundTripper.requests[0].Header.Get("Sforce-Query-Options") != "batchSize=2000" {
		t.Fatalf("maximum batch error = %v", err)
	}

	for name, budget := range map[string][2]int{"items": {1, 8}, "relationships": {8, 1}} {
		request.RemainingItems, request.RemainingRelationships = budget[0], budget[1]
		api, roundTripper = newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: two})
		if _, err := api.FetchCollectionPage(context.Background(), credential, request); !errors.Is(err, providercollection.ErrPageCapacity) || roundTripper.calls() != 1 || roundTripper.requests[0].Header.Get("Sforce-Query-Options") != "batchSize=200" {
			t.Fatalf("%s budget error/calls = %v / %d", name, err, roundTripper.calls())
		}
	}
	request.RemainingItems, request.RemainingRelationships = 8, 0
	api, roundTripper = newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: two})
	if _, err := api.FetchCollectionPage(context.Background(), credential, request); !errors.Is(err, providercollection.ErrPageCapacity) || roundTripper.calls() != 0 {
		t.Fatalf("exhausted relationships error/calls = %v / %d", err, roundTripper.calls())
	}
	request.RemainingItems, request.RemainingRelationships = 0, 8
	if _, err := api.FetchCollectionPage(context.Background(), credential, request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
		t.Fatalf("exhausted items error/calls = %v / %d", err, roundTripper.calls())
	}
	request.RemainingItems, request.RemainingBytes = 8, 4095
	if _, err := api.FetchCollectionPage(context.Background(), credential, request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
		t.Fatalf("byte floor error/calls = %v / %d", err, roundTripper.calls())
	}
	// A provider response larger than the remaining bytes is not read past
	// the budget.
	request.RemainingRelationships, request.RemainingBytes = 8, 4096
	oversized := salesforceQueryBody(true, "", salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":null,"Description":"`+strings.Repeat("x", 4096)+`"`))
	api, _ = newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: oversized})
	if _, err := api.FetchCollectionPage(context.Background(), credential, request); !salesforceFailureHasCode(err, collection.FailureMalformed) {
		t.Fatalf("oversized response error = %v", err)
	}
	// The org page needs no relationship budget.
	initial := salesforceInitialRequest()
	initial.RemainingItems, initial.RemainingRelationships = 1, 0
	api, _ = newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
	if page, err := api.FetchCollectionPage(context.Background(), credential, initial); err != nil || len(page.Entities) != 1 {
		t.Fatalf("org page/error = %#v / %v", page, err)
	}
}

func TestSalesforceCollectionAPIRejectsCursorTransplantAndForgery(t *testing.T) {
	t.Parallel()
	other := collection.SubjectBinding{Kind: "salesforce_org", ID: "00D5g000004XyZbEAK"}
	foreign, _ := nextSalesforceStateCursor(other, salesforcePageState{Phase: "agents", Lineage: 2})
	foreignContinuation, _ := nextSalesforceStateCursor(other, salesforcePageState{Phase: "agents", Lineage: 2, Locator: "01g5g00000AbCdEAAV-2000", Variant: 1})
	own, _ := nextSalesforceStateCursor(salesforceTestSubject, salesforcePageState{Phase: "agents", Lineage: 2, Locator: "01g5g00000AbCdEAAV-2000", Variant: 1})
	if foreign.Value == "" || foreignContinuation.Value == "" || own.Value == "" {
		t.Fatal("test cursors rejected")
	}
	parts := strings.Split(own.Value, ":")
	forgedLocator := salesforceForgedCursor(t, `{"p":"agents","l":2,"n":"../../sobjects/User","v":1}`, 2)
	requests := map[string]CollectionPageRequest{}
	add := func(name string, mutate func(*CollectionPageRequest)) {
		request := salesforceInitialRequest()
		request.Cursor, request.Page = own, 2
		mutate(&request)
		requests[name] = request
	}
	add("another org", func(request *CollectionPageRequest) { request.Cursor = foreign })
	add("another org continuation", func(request *CollectionPageRequest) { request.Cursor = foreignContinuation })
	add("another org complete", func(request *CollectionPageRequest) {
		request.Cursor, request.Page = nextSalesforceCompleteCursor(collection.Cursor{}, other), 1
	})
	add("another page", func(request *CollectionPageRequest) { request.Page = 3 })
	add("tampered binding", func(request *CollectionPageRequest) {
		request.Cursor.Value = strings.Join(parts[:4], ":") + ":0000000000000000"
	})
	add("unbound traversal locator", func(request *CollectionPageRequest) { request.Cursor = forgedLocator })
	add("variant without locator", func(request *CollectionPageRequest) {
		request.Cursor = salesforceForgedCursor(t, `{"p":"agents","l":2,"v":1}`, 2)
	})
	add("locator without variant", func(request *CollectionPageRequest) {
		request.Cursor = salesforceForgedCursor(t, `{"p":"agents","l":2,"n":"01g5g00000AbCdEAAV-2000"}`, 2)
	})
	add("unknown variant", func(request *CollectionPageRequest) {
		request.Cursor = salesforceForgedCursor(t, `{"p":"agents","l":2,"n":"01g5g00000AbCdEAAV-2000","v":5}`, 2)
	})
	add("unknown member", func(request *CollectionPageRequest) {
		request.Cursor = salesforceForgedCursor(t, `{"p":"agents","l":2,"u":"https://evil.example"}`, 2)
	})
	add("okta cursor", func(request *CollectionPageRequest) { request.Cursor.Provider = collection.ProviderOkta })
	add("another cursor version", func(request *CollectionPageRequest) { request.Cursor.Version = "cursor_v2" })
	add("unknown value", func(request *CollectionPageRequest) { request.Cursor.Value = "salesforce:org:1:e30:0000000000000000" })
	add("initial on a later page", func(request *CollectionPageRequest) { request.Cursor = collection.Cursor{} })
	add("another provider", func(request *CollectionPageRequest) { request.Provider = collection.ProviderOkta })
	add("another subject kind", func(request *CollectionPageRequest) { request.Subject.Kind = "okta_tenant" })
	add("15 character subject", func(request *CollectionPageRequest) { request.Subject.ID = salesforceTestOrgID[:15] })
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, roundTripper := newSalesforceTestAPI(t, salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody})
			if _, err := api.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), request); !errors.Is(err, ErrInvalid) || roundTripper.calls() != 0 {
				t.Fatalf("cursor error/calls = %v / %d", err, roundTripper.calls())
			}
		})
	}
}

// salesforceForgedCursor binds an arbitrary payload to the test subject the
// way an attacker who could compute the (unkeyed) binding would.
func salesforceForgedCursor(t *testing.T, payload string, lineage int) collection.Cursor {
	t.Helper()
	valid, ok := nextSalesforceStateCursor(salesforceTestSubject, salesforcePageState{Phase: "agents", Lineage: lineage})
	if !ok {
		t.Fatal("cursor rejected")
	}
	parts := strings.Split(valid.Value, ":")
	encoded := salesforceTestBase64(payload)
	parts[3], parts[4] = encoded, providercollection.CursorBinding(collection.ProviderSalesforce, salesforceTestSubject, "agents", lineage, encoded)
	valid.Value = strings.Join(parts, ":")
	return valid
}

func salesforceTestBase64(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func TestSalesforceNormalizationRefusesUnboundedDisplayTextAndHostileRecords(t *testing.T) {
	t.Parallel()
	subquery, plain := salesforceAgentQueryVariants[0], salesforceAgentQueryVariants[3]
	record := func(body string) []json.RawMessage { return []json.RawMessage{json.RawMessage(body)} }
	for name, body := range map[string]string{
		"label too long":         salesforceBotRecord(salesforceTestBotOne, "Support_Agent", strings.Repeat("a", 257), ""),
		"label control":          `{"Id":"0Xx5g0000004C9ACAU","DeveloperName":"Support_Agent","MasterLabel":"Support\u0000Agent"}`,
		"label newline":          `{"Id":"0Xx5g0000004C9ACAU","DeveloperName":"Support_Agent","MasterLabel":"Support\nAgent"}`,
		"label padded":           salesforceBotRecord(salesforceTestBotOne, "Support_Agent", " Support Agent ", ""),
		"label blank":            salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "   ", ""),
		"missing developer name": `{"Id":"0Xx5g0000004C9ACAU","MasterLabel":"Support Agent"}`,
		"15 character id":        salesforceBotRecord(salesforceTestBotOne[:15], "Support_Agent", "Support Agent", ""),
		"id with separator":      salesforceBotRecord("0Xx5g0000004C9:CAU", "Support_Agent", "Support Agent", ""),
		"agent type control":     `{"Id":"0Xx5g0000004C9ACAU","DeveloperName":"Support_Agent","MasterLabel":"Support Agent","AgentType":"Agent\u0007"}`,
		"type not text":          `{"Id":"0Xx5g0000004C9ACAU","DeveloperName":"Support_Agent","MasterLabel":"Support Agent","Type":7}`,
		"versions not object":    salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":[]`),
		"versions unfinished":    salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":{"totalSize":1,"done":false,"records":[{"Id":"0X95g0000004D1AAAU"}]}`),
		"versions beyond limit":  salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":{"totalSize":2,"done":true,"records":[{"Id":"0X95g0000004D1AAAU"},{"Id":"0X95g0000004D1BAAU"}]}`),
		"version without id":     salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"BotVersions":{"totalSize":1,"done":true,"records":[{}]}`),
		"not an object":          `"0Xx5g0000004C9ACAU"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, ok := normalizeSalesforceAgents(salesforceTestSubject, subquery, record(body)); ok {
				t.Fatal("hostile record accepted")
			}
		})
	}
	duplicate := json.RawMessage(salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", ""))
	if _, _, ok := normalizeSalesforceAgents(salesforceTestSubject, plain, []json.RawMessage{duplicate, duplicate}); ok {
		t.Fatal("duplicate record accepted")
	}
	// The label bound is exact, a missing or null label falls back to the
	// developer name, and a variant that did not select a member ignores it.
	for name, test := range map[string]struct {
		variant salesforceAgentQueryVariant
		body    string
		want    string
	}{
		"label at bound":       {plain, salesforceBotRecord(salesforceTestBotOne, "Support_Agent", strings.Repeat("a", 256), ""), strings.Repeat("a", 256)},
		"null label":           {plain, `{"Id":"0Xx5g0000004C9ACAU","DeveloperName":"Support_Agent","MasterLabel":null}`, "Support_Agent"},
		"absent label":         {plain, `{"Id":"0Xx5g0000004C9ACAU","DeveloperName":"Support_Agent"}`, "Support_Agent"},
		"unselected members":   {plain, salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"AgentType":"Agent\u0007","BotVersions":[]`), "Support Agent"},
		"international label":  {subquery, salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Agente de soporte ✓", `,"BotVersions":null`), "Agente de soporte ✓"},
		"absent subquery data": {subquery, salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", ""), "Support Agent"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entities, relationships, ok := normalizeSalesforceAgents(salesforceTestSubject, test.variant, record(test.body))
			if !ok || len(entities) != 1 || len(relationships) != 1 {
				t.Fatalf("record = %d/%d/%t", len(entities), len(relationships), ok)
			}
			if agent := salesforceTestEntities(t, entities)[0]; agent.DisplayName != test.want || agent.StableFields.Name != test.want {
				t.Fatalf("agent = %+v", agent)
			}
			if _, err := NewSalesforceCollectionPage(salesforceTestSubject, nextSalesforceCompleteCursor(collection.Cursor{}, salesforceTestSubject), true, entities, relationships); err != nil {
				t.Fatalf("NewSalesforceCollectionPage() error = %v", err)
			}
		})
	}
}

func TestSalesforceCollectionAPIConstructionAndReadiness(t *testing.T) {
	t.Parallel()
	local := time.FixedZone("local", 3600)
	for name, config := range map[string]CollectionAPIConfig{
		"no timeout":    {},
		"short timeout": {Timeout: 99 * time.Millisecond},
		"long timeout":  {Timeout: 31 * time.Second},
		"zero clock":    {Timeout: time.Second, Clock: func() time.Time { return time.Time{} }},
		"local clock":   {Timeout: time.Second, Clock: func() time.Time { return salesforceTestNow.In(local) }},
	} {
		if api, err := NewSalesforceCollectionAPI(config); !errors.Is(err, ErrInvalid) || api != nil {
			t.Fatalf("%s: api/error = %v / %v", name, api, err)
		}
	}
	production, err := NewSalesforceCollectionAPI(CollectionAPIConfig{Timeout: time.Second})
	if err != nil || production == nil {
		t.Fatalf("default transport error = %v", err)
	}
	api, roundTripper := newSalesforceTestAPI(t)
	if err := api.CheckCollectionReadiness(context.Background()); err != nil || roundTripper.calls() != 0 {
		t.Fatalf("CheckCollectionReadiness() error/calls = %v / %d", err, roundTripper.calls())
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	var missing *SalesforceCollectionAPI
	if err := api.CheckCollectionReadiness(cancelled); !errors.Is(err, ErrProvider) {
		t.Fatalf("cancelled readiness error = %v", err)
	}
	if err := missing.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrProvider) {
		t.Fatalf("nil readiness error = %v", err)
	}
	if _, err := missing.FetchCollectionPage(context.Background(), salesforceTestCredential(salesforceTestToken, salesforceTestHost), salesforceInitialRequest()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil fetch error = %v", err)
	}
	if _, err := NewSalesforceCollectionClient(api, nil, CollectionClientConfig{CollectorVersion: "salesforce_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return salesforceTestNow }}); err == nil {
		t.Fatal("client without artifact authority accepted")
	}
}
