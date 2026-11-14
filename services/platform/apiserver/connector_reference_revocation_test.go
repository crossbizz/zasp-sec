package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// A reference connector (AWS, Kubernetes) has no grant at a provider to
// withdraw: its revocation is the local transition. The reconciler used to
// look the connector up in the OAuth provider registry, never found it, and
// left the integration in "revoking" until the effect was quarantined.
func TestConnectorReconcilerCompletesReferenceConnectorRevocation(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70003001-0000-4000-8000-000000000001"
	reference := "ref:aws/external-id/customer-0001"
	body := func(status, key, externalID string) WorkflowValue {
		raw, _ := json.Marshal(map[string]any{"id": integrationID, "connector_key": key, "name": "AWS", "status": status,
			"configuration": map[string]string{"role_arn": "arn:aws:iam::000000000001:role/zasp/read", "external_id_reference": externalID, "region": "us-east-1"}})
		return WorkflowValue{Body: raw, Version: 3}
	}
	lease := func(attempt int) ConnectorEffectLease {
		return ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(),
			ID: "pid_70003003-0000-4000-8000-000000000003", IntegrationID: integrationID, Provider: "aws", Operation: "revoke", IdempotencyKey: "delete-integration-0001",
			RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), ConnectionReference: reference, Attempt: attempt, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	}
	// The OAuth registry does not know reference connectors, as in production.
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"okta": {Provider: &connectorRecoveryProvider{}, RequestedScopes: []string{"offline_access"}, CredentialClass: "okta_refresh_reference"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	run := func(workflow WorkflowValue, attempt int) (*connectorReconciliationRepositoryStub, error) {
		repository := &connectorReconciliationRepositoryStub{lease: lease(attempt)}
		reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return repository, reconciler.reconcileOnce(context.Background())
	}
	if repository, err := run(body("revoking", "aws", reference), 1); err != nil || !repository.revoked || repository.quarantined != "" || repository.failedCode != "" {
		t.Fatalf("reference revocation err=%v repository=%#v", err, repository)
	}
	for name, workflow := range map[string]WorkflowValue{
		"not revoking":        body("active", "aws", reference),
		"another connector":   body("revoking", "kubernetes", reference),
		"another reference":   body("revoking", "aws", "ref:aws/external-id/customer-0002"),
		"invalid integration": {Body: json.RawMessage(`{}`), Version: 1},
	} {
		if repository, err := run(workflow, 1); err == nil || repository.revoked || repository.quarantined != "" {
			t.Fatalf("%s: err=%v repository=%#v", name, err, repository)
		}
		if repository, err := run(workflow, 100); err != nil || repository.revoked || repository.quarantined != "provider_revocation_ambiguous" {
			t.Fatalf("%s final attempt: err=%v repository=%#v", name, err, repository)
		}
	}
}
