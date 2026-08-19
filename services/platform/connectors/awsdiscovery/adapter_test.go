package awsdiscovery

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]byte, error)

func (function resolverFunc) Resolve(ctx context.Context, reference string) ([]byte, error) {
	return function(ctx, reference)
}

type identityFunc func(context.Context, AssumeRoleRequest) (Identity, error)

func (function identityFunc) GetCallerIdentity(ctx context.Context, request AssumeRoleRequest) (Identity, error) {
	return function(ctx, request)
}

func TestAdapterRequiresExplicitReferenceResolutionAndVerifiesExactAWSIdentity(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-must-not-be-read")
	t.Setenv("AWS_PROFILE", "ambient-must-not-be-read")
	config := Config{RoleARN: "arn:aws:iam::123456789012:role/zasp-read", ExternalIDReference: "ref:aws/external-id-0001", Region: "us-east-1"}
	resolver := resolverFunc(func(_ context.Context, reference string) ([]byte, error) {
		if reference != config.ExternalIDReference {
			t.Fatalf("resolved reference %q", reference)
		}
		return []byte("customer-external-id"), nil
	})
	client := identityFunc(func(_ context.Context, request AssumeRoleRequest) (Identity, error) {
		if request.RoleARN != config.RoleARN || request.Region != config.Region || string(request.ExternalID) != "customer-external-id" || request.Duration != 15*time.Minute {
			t.Fatalf("assume role request %#v", request)
		}
		return Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/zasp-read/check"}, nil
	})
	adapter, err := NewAdapter(client, resolver, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := adapter.TestConnection(context.Background(), config)
	if err != nil || identity.AccountID != "123456789012" {
		t.Fatalf("identity=%#v err=%v", identity, err)
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "ambient-must-not-be-read" {
		t.Fatal("test environment changed")
	}
	if _, err := adapter.TestConnection(context.Background(), Config{RoleARN: config.RoleARN, ExternalIDReference: "plaintext", Region: config.Region}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("plaintext external ID error=%v", err)
	}
}

func TestAdapterRedactsProviderFailuresAndRejectsIdentityDrift(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]byte, error) { return []byte("super-secret-value"), nil })
	for _, client := range []IdentityClient{
		identityFunc(func(context.Context, AssumeRoleRequest) (Identity, error) {
			return Identity{}, errors.New("provider leaked super-secret-value")
		}),
		identityFunc(func(context.Context, AssumeRoleRequest) (Identity, error) {
			return Identity{AccountID: "999999999999", PrincipalARN: "arn:aws:sts::999999999999:assumed-role/other/x"}, nil
		}),
	} {
		adapter, _ := NewAdapter(client, resolver, time.Second)
		_, err := adapter.TestConnection(context.Background(), Config{RoleARN: "arn:aws:iam::123456789012:role/zasp-read", ExternalIDReference: "ref:aws/external-id-0001", Region: "us-east-1"})
		if !errors.Is(err, ErrDenied) || err.Error() != ErrDenied.Error() {
			t.Fatalf("provider failure=%q", err)
		}
	}
}
