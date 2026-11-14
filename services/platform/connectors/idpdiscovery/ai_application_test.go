package idpdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

const (
	oktaTestChatGPTID = "0oa1234567890ABCDE1"
	oktaTestCursorID  = "0oa1234567890ABCDE2"
	oktaTestWorkdayID = "0oa1234567890ABCDE3"
	oktaTestUserID    = "00u1234567890ABCDE1"
	oktaTestGroupID   = "00g1234567890ABCDE1"
	oktaTestClientID  = "client1234567890ABCDE1"
)

type oktaTestItem struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	DisplayName    string          `json:"display_name"`
	StableFields   json.RawMessage `json:"stable_fields"`
	Attributes     json.RawMessage `json:"attributes"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
}

func oktaTestItems(t *testing.T, values []json.RawMessage) []oktaTestItem {
	t.Helper()
	items := make([]oktaTestItem, 0, len(values))
	for _, raw := range values {
		var item oktaTestItem
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatalf("item %s: %v", raw, err)
		}
		items = append(items, item)
	}
	return items
}

func oktaTestPosture(credentialActive string) string {
	return `{"cicd_write":false,"credential_active":` + credentialActive + `,"credential_fingerprint":"","destructive_tool":false,"host_filesystem":false,"human_credential":false,"privileged":false,"production_agent":false,"production_credential":false,"production_secret_reach":false,"production_write":false,"runtime_control":false,"runtime_policy_supported":false,"sensitive_data_reach":false,"shell_execution":false,"unapproved_remote_tool":false,"unrestricted_egress":false,"untrusted_input":false}`
}

func oktaAITenantResponses() []oktaHTTPResponse {
	next := func(after string) http.Header {
		return http.Header{"Link": []string{`<https://acme.okta.com/api/v1/apps?after=` + after + `&limit=1>; rel="next"`}}
	}
	return []oktaHTTPResponse{
		{status: http.StatusOK, header: next("app2"), body: `[{"id":"` + oktaTestChatGPTID + `","name":"chatgpt_saml","label":"ChatGPT Enterprise","status":"ACTIVE","signOnMode":"SAML_2_0"}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestUserID + `","scope":"USER"}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestGroupID + `"}]`},
		{status: http.StatusOK, header: next("app3"), body: `[{"id":"` + oktaTestCursorID + `","name":"oidc_client","label":"Cursor","status":"INACTIVE","signOnMode":"OPENID_CONNECT","credentials":{"oauthClient":{"client_id":"` + oktaTestClientID + `"}}}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestUserID + `","scope":"USER"}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestGroupID + `"}]`},
		{status: http.StatusOK, body: `[]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestWorkdayID + `","name":"workday","label":"Workday","status":"ACTIVE","signOnMode":"SAML_2_0"}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestUserID + `","scope":"USER"}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestGroupID + `"}]`},
	}
}

func TestOktaCollectionAPIEmitsAIApplicationsAsAgents(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	roundTripper := &oktaRoundTripper{responses: oktaAITenantResponses()}
	api, err := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("okta-access-secret-value")
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: subject, Cursor: nextOktaPageCursor(subject, "applications", 7, "start"), Page: 7, RemainingItems: 32, RemainingRelationships: 32, RemainingBytes: 1 << 20}
	var entities, relationships []oktaTestItem
	for index := 0; index < 10; index++ {
		page, fetchErr := api.FetchCollectionPage(context.Background(), credential, request)
		if fetchErr != nil {
			t.Fatalf("page %d error = %v", request.Page, fetchErr)
		}
		if !bytes.Equal(page.Raw, mustOktaCollectionPage(t, page).Raw) || page.Complete != (index == 9) {
			t.Fatalf("page %d noncanonical or complete=%t: %s", request.Page, page.Complete, page.Raw)
		}
		entities = append(entities, oktaTestItems(t, page.Entities)...)
		relationships = append(relationships, oktaTestItems(t, page.Relationships)...)
		request.Cursor, request.Page = page.Cursor, request.Page+1
	}
	tenantID := deterministicOktaInventoryID(subject, "okta_tenant", subject.ID)
	chatGPT := deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestChatGPTID)
	cursor := deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestCursorID)
	workday := deterministicOktaInventoryID(subject, "okta_application", oktaTestWorkdayID)
	user := deterministicOktaInventoryID(subject, "okta_user", oktaTestUserID)
	group := deterministicOktaInventoryID(subject, "okta_group", oktaTestGroupID)
	servicePrincipal := deterministicOktaInventoryID(subject, "okta_service_principal", oktaTestClientID)

	wantEntities := map[string]oktaTestItem{
		chatGPT: {Kind: "okta_ai_application", SourceNativeID: "okta:application:" + oktaTestChatGPTID, DisplayName: "ChatGPT Enterprise",
			StableFields: json.RawMessage(`{"name":"ChatGPT Enterprise","object_type":"application","tenant":"acme.okta.com"}`),
			Attributes:   json.RawMessage(`{"discovery":{"method":"inferred","platform":"saas_assistant","signals":["app:chatgpt"]},"posture":` + oktaTestPosture("true") + `,"status":"ACTIVE"}`)},
		cursor: {Kind: "okta_ai_application", SourceNativeID: "okta:application:" + oktaTestCursorID, DisplayName: "Cursor",
			StableFields: json.RawMessage(`{"name":"Cursor","object_type":"application","tenant":"acme.okta.com"}`),
			Attributes:   json.RawMessage(`{"discovery":{"method":"inferred","platform":"saas_coding_agent","signals":["app:cursor"]},"posture":` + oktaTestPosture("false") + `,"status":"INACTIVE"}`)},
		workday: {Kind: "okta_application", SourceNativeID: "okta:application:" + oktaTestWorkdayID, DisplayName: "Workday",
			StableFields: json.RawMessage(`{"name":"Workday","object_type":"application","tenant":"acme.okta.com"}`),
			Attributes:   json.RawMessage(`{"status":"ACTIVE"}`)},
		servicePrincipal: {Kind: "okta_service_principal", SourceNativeID: "okta:service_principal:" + oktaTestClientID, DisplayName: "Cursor service principal",
			StableFields: json.RawMessage(`{"name":"` + oktaTestClientID + `","object_type":"service_principal","tenant":"acme.okta.com"}`),
			Attributes:   json.RawMessage(`{"status":"INACTIVE"}`)},
	}
	if len(entities) != len(wantEntities) {
		t.Fatalf("entities = %d, want %d: %#v", len(entities), len(wantEntities), entities)
	}
	for _, entity := range entities {
		want, ok := wantEntities[entity.ID]
		if !ok || entity.Kind != want.Kind || entity.SourceNativeID != want.SourceNativeID || entity.DisplayName != want.DisplayName || string(entity.StableFields) != string(want.StableFields) || string(entity.Attributes) != string(want.Attributes) {
			t.Fatalf("entity = %+v\nstable %s\nattributes %s\nwant %+v", entity, entity.StableFields, entity.Attributes, want)
		}
	}
	type edge struct{ kind, from, to, relationshipType string }
	wantEdges := map[edge]bool{
		{"contains", tenantID, chatGPT, "tenant_object"}:                           true,
		{"assigned_to", user, chatGPT, "user_application_assignment"}:              true,
		{"assigned_to", group, chatGPT, "group_application_assignment"}:            true,
		{"contains", tenantID, cursor, "tenant_object"}:                            true,
		{"contains", tenantID, servicePrincipal, "tenant_service_principal"}:       true,
		{"assigned_to", servicePrincipal, cursor, "service_principal_application"}: true,
		{"assigned_to", user, cursor, "user_application_assignment"}:               true,
		{"assigned_to", group, cursor, "group_application_assignment"}:             true,
		{"contains", tenantID, workday, "tenant_object"}:                           true,
		{"assigned_to", user, workday, "user_application_assignment"}:              true,
		{"assigned_to", group, workday, "group_application_assignment"}:            true,
	}
	if len(relationships) != len(wantEdges) {
		t.Fatalf("relationships = %d, want %d", len(relationships), len(wantEdges))
	}
	for _, relationship := range relationships {
		var attributes struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(relationship.Attributes, &attributes)
		key := edge{relationship.Kind, relationship.FromEntityID, relationship.ToEntityID, attributes.Type}
		if !wantEdges[key] {
			t.Fatalf("unexpected relationship %+v (%s)", relationship, relationship.Attributes)
		}
		delete(wantEdges, key)
	}
	if len(roundTripper.requests) != 10 {
		t.Fatalf("provider calls = %d, want 10 (no extra call per application)", len(roundTripper.requests))
	}
}

// The application page is the only page that sees the label. Every later page
// of the same application must point at the entity that page emitted, also
// when another process resumes from the stored cursor.
func TestOktaCollectionAPIKeepsApplicationKindAcrossResume(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	credential := []byte("okta-access-secret-value")
	responses := oktaAITenantResponses()
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: subject, Cursor: nextOktaPageCursor(subject, "applications", 7, "start"), Page: 7, RemainingItems: 32, RemainingRelationships: 32, RemainingBytes: 1 << 20}
	wantTargets := []string{
		"", deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestChatGPTID), deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestChatGPTID),
		"", deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestCursorID), deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestCursorID), "",
		"", deterministicOktaInventoryID(subject, "okta_application", oktaTestWorkdayID), deterministicOktaInventoryID(subject, "okta_application", oktaTestWorkdayID),
	}
	for index, response := range responses {
		// A new collector per page: nothing but the cursor survives.
		var pages [2]CollectionPage
		for attempt := range pages {
			api, err := newOktaCollectionAPI("https://acme.okta.com", &oktaRoundTripper{responses: []oktaHTTPResponse{response}}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if pages[attempt], err = api.FetchCollectionPage(context.Background(), credential, request); err != nil {
				t.Fatalf("page %d attempt %d error = %v", request.Page, attempt, err)
			}
		}
		if !bytes.Equal(pages[0].Raw, pages[1].Raw) || pages[0].Cursor != pages[1].Cursor {
			t.Fatalf("page %d is not deterministic on retry", request.Page)
		}
		if want := wantTargets[index]; want != "" {
			relationships := oktaTestItems(t, pages[0].Relationships)
			if len(relationships) != 1 || relationships[0].Kind != "assigned_to" || relationships[0].ToEntityID != want {
				t.Fatalf("page %d relationships = %+v, want target %s", request.Page, relationships, want)
			}
		}
		request.Cursor, request.Page = pages[0].Cursor, request.Page+1
	}
	if !strings.HasPrefix(request.Cursor.Value, "okta:complete:") {
		t.Fatalf("final cursor = %s", request.Cursor.Value)
	}
}

func TestOktaPageStateCarriesAIApplicationOnlyOnAssignmentPhases(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	for _, phase := range []string{"appusers", "appgroups"} {
		if _, _, ok := nextOktaStateCursor(subject, oktaPageState{Phase: phase, Lineage: 3, AppID: oktaTestChatGPTID, AIApplication: true}); !ok {
			t.Fatalf("%s cursor with AI application rejected", phase)
		}
	}
	for _, state := range []oktaPageState{
		{Phase: "users", Lineage: 3, AIApplication: true},
		{Phase: "applications", Lineage: 3, AIApplication: true},
		{Phase: "userroles", Lineage: 3, PrincipalID: oktaTestUserID, AIApplication: true},
		{Phase: "clientroles", Lineage: 3, AppID: oktaTestChatGPTID, ClientID: oktaTestClientID, AIApplication: true},
	} {
		if _, _, ok := nextOktaStateCursor(subject, state); ok {
			t.Fatalf("%s cursor accepted an AI application flag", state.Phase)
		}
	}
	// The flag is part of the bound cursor payload.
	plain, _, _ := nextOktaStateCursor(subject, oktaPageState{Phase: "appusers", Lineage: 3, AppID: oktaTestWorkdayID})
	flagged, _, _ := nextOktaStateCursor(subject, oktaPageState{Phase: "appusers", Lineage: 3, AppID: oktaTestWorkdayID, AIApplication: true})
	if plain == flagged {
		t.Fatalf("cursors do not distinguish the kind: %s", plain.Value)
	}
}
