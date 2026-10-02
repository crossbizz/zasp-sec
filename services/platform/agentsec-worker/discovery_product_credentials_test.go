package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type productSecretReader func(context.Context, string) ([]byte, error)

func (f productSecretReader) ResolveDiscoverySecret(ctx context.Context, ref string) ([]byte, error) {
	return f(ctx, ref)
}

// Exercise the actual credential resolver with controlled secret/STS IO. Product
// authority must not borrow a synthetic worker lease or old retry attempt.
func TestProductDiscoveryCredentialEffectAndCurrentAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	scope := discoveryCredentialScope(t)
	input := apiserver.DiscoveryCollectionInput{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		JobID: discoveryCredentialID(6).String(), SyncID: discoveryCredentialID(7).String(), IntegrationID: discoveryCredentialID(4).String(), ConnectionID: discoveryCredentialID(5).String(), SnapshotID: discoveryCredentialID(8).String(), Generation: 1, ObservationTime: now,
		Provider: collection.ProviderAWS, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialAWSAssumeRole, CredentialReference: "ref:aws/external-id/customer-0001", SubjectKind: "aws_account", SubjectID: "123456789012", ParserVersion: "parser_v1", ToolVersion: "tool_v1",
		Configuration: []byte(`{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`), EffectID: strings.Repeat("a", 64), Deadline: now.Add(time.Hour),
	}
	revoked := false
	secrets := 0
	assume := &discoveryAssumeRoleStub{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 32)), Expiration: aws.Time(now.Add(15 * time.Minute))}}}
	resolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: productSecretReader(func(ctx context.Context, _ string) ([]byte, error) {
		secrets++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(input.Deadline) {
			t.Fatal("credential IO has no original budget")
		}
		return []byte("external-id-customer-0001"), nil
	}), AssumeRole: assume, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bound := discoveryCredentialMaterialRequest{Scope: scope, Product: &input, CheckCurrent: func(context.Context) error {
		if revoked {
			return errors.New("revoked")
		}
		return nil
	}}
	refresh := func() {
		r, err := input.CollectionRequest(scope)
		if err != nil {
			t.Fatal(err)
		}
		bound.Credential = credentialRequestForJob(r)
	}
	refresh()
	material, err := resolver.ResolveDiscoveryCredential(context.Background(), bound)
	if err != nil {
		t.Fatal("lease-free credential", err)
	}
	material.Destroy()
	first := aws.ToString(assume.input.RoleSessionName)
	material, err = resolver.ResolveDiscoveryCredential(context.Background(), bound)
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
	if aws.ToString(assume.input.RoleSessionName) != first {
		t.Fatal("replayed effect changed STS identity")
	}
	input.EffectID = strings.Repeat("b", 64)
	refresh()
	material, err = resolver.ResolveDiscoveryCredential(context.Background(), bound)
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
	if aws.ToString(assume.input.RoleSessionName) == first {
		t.Fatal("new product effect reused legacy attempt identity")
	}
	before := secrets
	revoked = true
	if material, err := resolver.ResolveDiscoveryCredential(context.Background(), bound); err == nil {
		material.Destroy()
		t.Fatal("revoked credential allowed")
	}
	if secrets != before {
		t.Fatal("revocation sent secret IO")
	}
	revoked = false
	resolver.config.Secrets = productSecretReader(func(context.Context, string) ([]byte, error) {
		revoked = true
		return []byte("external-id-customer-0001"), nil
	})
	assume.input = nil
	if material, err := resolver.ResolveDiscoveryCredential(context.Background(), bound); err == nil {
		material.Destroy()
		t.Fatal("revocation between secret and STS ignored")
	}
	if assume.input != nil {
		t.Fatal("STS called after revocation")
	}
	for _, c := range []struct {
		provider                                collection.Provider
		class                                   collection.CredentialClass
		reference, kind, subject, config, first string
	}{
		{collection.ProviderGitHub, collection.CredentialGitHubInstallation, "ref:github/installation/123456", "github_installation", "123456", `{"authorization_mode":"github_app"}`, "private-key-material"},
		{collection.ProviderOkta, collection.CredentialOktaRefresh, "ref:okta/refresh/customer-0001", "okta_tenant", "acme.okta.com", `{"issuer":"https://acme.okta.com"}`, "okta-client-secret-value"},
		{collection.ProviderKubernetes, collection.CredentialKubernetesCluster, "ref:kubernetes/connection/customer-0001", "kubernetes_cluster", "cluster.example.test/customer", `{"connection_reference":"ref:kubernetes/connection/customer-0001"}`, `{"endpoint":"https://cluster.example.test","context":"customer","ca_reference":"ref:kubernetes/ca/customer-0001","credential_reference":"ref:kubernetes/credential/customer-0001"}`},
	} {
		t.Run(string(c.provider)+"-revoked-between-IO", func(t *testing.T) {
			input.Provider, input.CredentialClass, input.CredentialReference, input.SubjectKind, input.SubjectID, input.Configuration = c.provider, c.class, c.reference, c.kind, c.subject, []byte(c.config)
			refresh()
			revoked = false
			calls := 0
			resolver.config.Secrets = productSecretReader(func(context.Context, string) ([]byte, error) { calls++; revoked = true; return []byte(c.first), nil })
			github := &discoveryGitHubMintStub{}
			okta := &discoveryOktaExchangeStub{}
			resolver.config.GitHub, resolver.config.Okta = github, okta
			if material, err := resolver.ResolveDiscoveryCredential(context.Background(), bound); err == nil {
				material.Destroy()
				t.Fatal("revocation ignored")
			}
			if calls != 1 || github.installationID != 0 || okta.issuer != "" {
				t.Fatal("outbound credential IO after revocation", calls, github.installationID, okta.issuer)
			}
		})
	}
	revoked = false
	input.Deadline = now.Add(-time.Second)
	if material, err := resolver.ResolveDiscoveryCredential(context.Background(), bound); err == nil {
		material.Destroy()
		t.Fatal("expired original budget allowed")
	}
}
