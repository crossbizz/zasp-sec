package main

import (
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// With ZASP_DISCOVERY_MICROSOFT_AZURE=enabled a Microsoft credential also
// carries a Resource Manager token for the same application, first in the
// envelope, and is good only while every token is.
func TestMicrosoftCredentialAddsAResourceManagerTokenWhenAzureIsEnabled(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	endpoint := healthySaaSTokenEndpoint()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret)}}
	resolver := saasCredentialResolver(t, endpoint, secrets, now, true, false)
	resolver.config.MicrosoftAzure = true
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, microsoftCredentialInput(scope, testMicrosoftConfig, now)))
	defer envelope.Destroy()

	// The stand-in endpoint answers every scope but Graph with its second token.
	want := `{"arm_token":"` + testMicrosoftDataverseTok + `","graph_token":"` + testMicrosoftGraphToken + `"}`
	if envelope.Provider != collection.ProviderMicrosoft || string(envelope.BearerToken) != want || !validDiscoveryMicrosoftCollectorCredential(envelope.BearerToken) {
		t.Fatalf("bearer = %s", envelope.BearerToken)
	}
	if len(endpoint.requests) != 2 || endpoint.requests[0].Form.Get("scope") != "https://graph.microsoft.com/.default" || endpoint.requests[1].Form.Get("scope") != "https://management.azure.com/.default" ||
		endpoint.requests[1].URL != "https://login.microsoftonline.com/"+testMicrosoftTenant+"/oauth2/v2.0/token" {
		t.Fatalf("requests = %#v", endpoint.requests)
	}
	// The Resource Manager token (1800 seconds here) expires first.
	if latest := now.Add(1800 * time.Second); envelope.ExpiresAt.After(latest) {
		t.Fatalf("expiry = %s, after the shorter token's %s", envelope.ExpiresAt, latest)
	}
}

func TestMicrosoftCollectorCredentialShapes(t *testing.T) {
	graph, dataverse, arm := []byte(testMicrosoftGraphToken), []byte(testMicrosoftDataverseTok), []byte("arm-access-token-value-0001")
	const dataverseURL = "https://org1.crm4.dynamics.com"
	for name, test := range map[string]struct {
		arm, dataverse []byte
		url, want      string
	}{
		"graph":                 {nil, nil, "", `{"graph_token":"graph-access-token-value-0001"}`},
		"arm and graph":         {arm, nil, "", `{"arm_token":"arm-access-token-value-0001","graph_token":"graph-access-token-value-0001"}`},
		"arm, dataverse, graph": {arm, dataverse, dataverseURL, `{"arm_token":"arm-access-token-value-0001","dataverse_token":"dataverse-access-token-value-0001","dataverse_url":"https://org1.crm4.dynamics.com","graph_token":"graph-access-token-value-0001"}`},
	} {
		encoded, ok := encodeDiscoveryMicrosoftCollectorCredentialWithARM(test.arm, graph, test.dataverse, test.url)
		if !ok || string(encoded) != test.want || !validDiscoveryMicrosoftCollectorCredential(encoded) {
			t.Errorf("%s: %s (%t)", name, encoded, ok)
		}
	}
	if _, ok := encodeDiscoveryMicrosoftCollectorCredentialWithARM([]byte(`a"b-token-with-a-quote`), graph, nil, ""); ok {
		t.Error("a token with a quote was written")
	}
	for name, hostile := range map[string]string{
		"two arm tokens":  `{"arm_token":"arm-access-token-value-0001","arm_token":"arm-access-token-value-0002","graph_token":"graph-access-token-value-0001"}`,
		"arm alone":       `{"arm_token":"arm-access-token-value-0001"}`,
		"arm after graph": `{"graph_token":"graph-access-token-value-0001","arm_token":"arm-access-token-value-0001"}`,
		"short arm token": `{"arm_token":"short","graph_token":"graph-access-token-value-0001"}`,
	} {
		if validDiscoveryMicrosoftCollectorCredential([]byte(hostile)) {
			t.Errorf("%s: accepted", name)
		}
	}
}
