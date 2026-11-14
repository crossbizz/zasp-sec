package idpdiscovery

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// The whole collection of a tenant, driven by the shared collection client
// exactly as the worker drives it, ends in a typed snapshot holding every
// Okta kind, the AI applications as agents.
func TestOktaCollectionClientCompletesATypedSnapshot(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	roundTripper := &oktaRoundTripper{responses: append([]oktaHTTPResponse{
		{status: http.StatusOK, body: `[{"id":"` + oktaTestUserID + `","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`},
		{status: http.StatusOK, body: `[{"id":"ra1234567890ABCDE1","label":"Organization administrator","type":"ORG_ADMIN","status":"ACTIVE","assignmentType":"USER"}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestGroupID + `","type":"OKTA_GROUP","profile":{"name":"Administrators"}}]`},
		{status: http.StatusOK, body: `[{"id":"` + oktaTestUserID + `","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`},
		{status: http.StatusOK, body: `[{"id":"gra1234567890ABCDE1","label":"Application administrator","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"GROUP"}]`},
	}, oktaAITenantResponses()...)}
	api, err := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driver, artifacts := newTypedSnapshotArtifacts(t)
	client, err := NewOktaCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	request := typedSnapshotRequest(t, collection.ProviderOkta, collection.CredentialOktaRefresh, "ref:okta/connection/customer-0001", subject)
	credential := []byte("okta-access-secret-value")
	outcome, err := client.CollectWithCredential(context.Background(), request, bytes.Clone(credential))
	byKind, relationships := requireTypedSnapshot(t, request, outcome, err, map[string]typedSnapshotEnvelope{
		"okta_tenant":            {"asset", 9500},
		"okta_user":              {"identity", 9500},
		"okta_group":             {"identity", 9500},
		"okta_role":              {"asset", 9500},
		"okta_application":       {"tool", 9500},
		"okta_service_principal": {"identity", 9500},
		"okta_ai_application":    {"agent", 7000},
	})
	if len(roundTripper.requests) != 15 || len(driver.objects) != 16 {
		t.Fatalf("provider calls = %d, artifacts = %d", len(roundTripper.requests), len(driver.objects))
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, credential) {
			t.Fatalf("artifact %s stores the credential", key)
		}
	}
	tenant := deterministicOktaInventoryID(subject, "okta_tenant", subject.ID)
	user := deterministicOktaInventoryID(subject, "okta_user", oktaTestUserID)
	group := deterministicOktaInventoryID(subject, "okta_group", oktaTestGroupID)
	servicePrincipal := deterministicOktaInventoryID(subject, "okta_service_principal", oktaTestClientID)
	chatGPT := deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestChatGPTID)
	cursor := deterministicOktaInventoryID(subject, "okta_ai_application", oktaTestCursorID)
	if len(byKind["okta_ai_application"]) != 2 || len(byKind["okta_role"]) != 2 || len(byKind["okta_application"]) != 1 || len(relationships) != 16 {
		t.Fatalf("kinds = %v, relationships = %d", byKind, len(relationships))
	}
	want := map[string][2]string{
		chatGPT: {`{"name":"ChatGPT Enterprise","object_type":"application","tenant":"acme.okta.com"}`, `{"discovery":{"method":"inferred","platform":"saas_assistant","signals":["app:chatgpt"]},"posture":{"cicd_write":false,"credential_active":true,`},
		cursor:  {`{"name":"Cursor","object_type":"application","tenant":"acme.okta.com"}`, `{"discovery":{"method":"inferred","platform":"saas_coding_agent","signals":["app:cursor"]},"posture":{"cicd_write":false,"credential_active":false,`},
	}
	for _, agent := range byKind["okta_ai_application"] {
		expected, ok := want[agent.ID]
		if !ok || string(agent.StableFields) != expected[0] || !bytes.HasPrefix(agent.Attributes, []byte(expected[1])) || !bytes.HasSuffix(agent.Attributes, []byte(`},"status":"`+map[bool]string{true: "ACTIVE", false: "INACTIVE"}[agent.ID == chatGPT]+`"}`)) {
			t.Fatalf("AI application = %+v\nstable %s\nattributes %s", agent, agent.StableFields, agent.Attributes)
		}
		if !typedSnapshotEdge(relationships, "contains", tenant, agent.ID) || !typedSnapshotEdge(relationships, "assigned_to", user, agent.ID) || !typedSnapshotEdge(relationships, "assigned_to", group, agent.ID) {
			t.Fatalf("AI application %s lacks its tenant or assignment relationships", agent.ID)
		}
	}
	if !typedSnapshotEdge(relationships, "assigned_to", servicePrincipal, cursor) || !typedSnapshotEdge(relationships, "member_of", user, group) {
		t.Fatal("service principal or membership relationship missing")
	}
}
