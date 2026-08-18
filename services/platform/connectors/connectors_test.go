package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestAWSCredentialAdapterValidatesIdentityAndDenial(t *testing.T) {
	config := AWSConfig{RoleARN: "arn:aws:iam::000000000000:role/zasp-read", ExternalID: "external-fixture", Region: "us-east-1"}
	client := &fakeAWSClient{identity: AWSIdentity{AccountID: "000000000000", PrincipalARN: "arn:aws:sts::000000000000:assumed-role/zasp-read/zasp"}}
	adapter, err := NewAWSCredentialAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Check(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	client.err = errors.New("access denied")
	if _, err := adapter.Check(context.Background(), config); !errors.Is(err, ErrCredentialDenied) {
		t.Fatalf("got %v", err)
	}
	if _, err := adapter.Check(context.Background(), AWSConfig{RoleARN: "arn:aws:iam::other:role/nope"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	client.panic = true
	if _, err := adapter.Check(context.Background(), config); !errors.Is(err, ErrCredentialDenied) {
		t.Fatalf("panic escaped: %v", err)
	}
}

func TestSourceRunnersAndNormalizersAreStableAndScoped(t *testing.T) {
	scopeA, scopeB := fixtureScope(1), fixtureScope(4)
	cart, err := RunCartography(context.Background(), scopeA, []CartographyNode{{Kind: "aws_role", ExternalID: "arn:aws:iam::000000000000:role/shared", Name: "shared"}})
	if err != nil || len(cart.Entities) != 1 {
		t.Fatalf("%+v %v", cart, err)
	}
	other, err := RunCartography(context.Background(), scopeB, []CartographyNode{{Kind: "aws_role", ExternalID: "arn:aws:iam::000000000000:role/shared", Name: "shared"}})
	if err != nil || cart.Entities[0].ID == other.Entities[0].ID {
		t.Fatal("organization scope did not affect source ID")
	}
	prowler, err := RunProwler(context.Background(), scopeA, []ProwlerFinding{{CheckID: "iam_role_cross_service_confused_deputy_prevention", ResourceARN: "arn:aws:iam::000000000000:role/shared", Severity: "high", Status: "FAIL"}})
	if err != nil || len(prowler.Entities) != 1 || len(prowler.Evidence) != 1 {
		t.Fatalf("%+v %v", prowler, err)
	}

	for name, outcome := range map[string]normalizeOutcome{
		"aws":        captureNormalization(NormalizeAWS(scopeA, AWSFixture{AccountID: "000000000000", RoleARN: "arn:aws:iam::000000000000:role/shared", PolicyARN: "arn:aws:iam::000000000000:policy/read"})),
		"kubernetes": captureNormalization(NormalizeKubernetes(scopeA, KubernetesFixture{Cluster: "cluster-a", Namespace: "default", ServiceAccount: "agent", Workload: "worker"})),
		"github":     captureNormalization(NormalizeGitHub(scopeA, GitHubFixture{Organization: "acme", Repository: "security", App: "zasp", Workflow: "scan.yml", Permission: "contents:read"})),
		"idp":        captureNormalization(NormalizeIdP(scopeA, IdPFixture{Provider: "okta", User: "user-1", Group: "security", Application: "zasp", ServicePrincipal: "svc-zasp"})),
	} {
		batch, err := outcome.batch, outcome.err
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := batch.Validate(); err != nil || len(batch.Entities) == 0 || len(batch.Relationships) == 0 {
			t.Fatalf("%s: %+v %v", name, batch, err)
		}
	}
	if _, err := NormalizeAWS(scopeA, AWSFixture{}); !errors.Is(err, ErrNormalization) {
		t.Fatalf("malformed AWS fixture: %v", err)
	}
}

type normalizeOutcome struct {
	batch Batch
	err   error
}

func captureNormalization(batch Batch, err error) normalizeOutcome {
	return normalizeOutcome{batch: batch, err: err}
}

func TestFreshnessRetainsLastKnownInventory(t *testing.T) {
	store := NewFreshnessStore()
	id := fixtureID(7)
	scope := fixtureScope(1)
	now := time.Date(2026, 8, 18, 8, 0, 0, 0, time.UTC)
	entity := Entity{ID: "src_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "aws_role", Name: "shared", ExternalID: "role/shared"}
	if err := store.RecordSuccess(scope, id, now, []Entity{entity}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordFailure(scope, id, now.Add(time.Minute), "rate_limited", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err := store.Get(scope, id, now.Add(25*time.Hour))
	if err != nil || !state.Stale || len(state.Inventory) != 1 || state.Inventory[0] != entity {
		t.Fatalf("%+v %v", state, err)
	}
	if _, err := store.Get(fixtureScope(4), id, now.Add(25*time.Hour)); !errors.Is(err, ErrFreshness) {
		t.Fatalf("cross scope: %v", err)
	}
}

func TestNangoBoundaryStoresReferencesAndRejectsHostAndStateDrift(t *testing.T) {
	store := NewConnectionStore()
	scope := fixtureScope(1)
	record, err := store.Put(scope, "generic", "connection_ref_fixture", "raw-provider-secret")
	if err != nil || record.Reference != "connection_ref_fixture" {
		t.Fatalf("%+v %v", record, err)
	}
	if record.RawCredential != "" {
		t.Fatal("raw credential escaped")
	}
	otherScope, err := domain.NewScope(scope.OrganizationID(), fixtureID(7), fixtureID(8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(otherScope, "generic", "connection_ref_other", "other-secret"); err != nil {
		t.Fatal(err)
	}
	original, err := store.Get(scope, "generic")
	if err != nil || original.Reference != "connection_ref_fixture" {
		t.Fatalf("scope collision: %+v %v", original, err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcd"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	code, err := ValidateOAuthCallback(OAuthCallback{State: "expected", ExpectedState: "expected", Code: "fixture-code", CodeVerifier: verifier, ExpectedChallenge: challenge})
	if err != nil || code != "fixture-code" {
		t.Fatalf("valid callback: %q %v", code, err)
	}
	if _, err := ValidateOAuthCallback(OAuthCallback{State: "wrong", ExpectedState: "expected", Code: "fixture-code", CodeVerifier: verifier, ExpectedChallenge: challenge}); !errors.Is(err, ErrOAuth) {
		t.Fatalf("got %v", err)
	}
	proxy := NewProxyPolicy([]string{"api.example.com"})
	if err := proxy.Validate("GET", "https://api.example.com/v1/items"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"http://api.example.com/v1", "https://api.example.com:8443/v1", "https://127.0.0.1/", "https://metadata.google.internal/", "https://evil.example/v1"} {
		if err := proxy.Validate("GET", target); !errors.Is(err, ErrProxy) {
			t.Fatalf("accepted %s: %v", target, err)
		}
	}
}

type fakeAWSClient struct {
	identity AWSIdentity
	err      error
	panic    bool
}

func (client *fakeAWSClient) AssumeRoleIdentity(context.Context, AWSConfig) (AWSIdentity, error) {
	if client.panic {
		panic("provider panic")
	}
	return client.identity, client.err
}

func fixtureID(seed byte) domain.ProductID {
	text := "pid_00000000-0000-4000-8000-00000000000" + string('0'+seed)
	id, err := domain.ParseProductID(text)
	if err != nil {
		panic(err)
	}
	return id
}
func fixtureScope(seed byte) domain.Scope {
	scope, err := domain.NewScope(fixtureID(seed), fixtureID(seed+1), fixtureID(seed+2))
	if err != nil {
		panic(err)
	}
	return scope
}
