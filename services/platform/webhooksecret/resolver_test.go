package webhooksecret

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type versionedSecretStub struct {
	call  func(context.Context, *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
	calls int
}

func (s *versionedSecretStub) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	s.calls++
	return s.call(ctx, in)
}

const secretOrg = "pid_00000000-0000-4000-8000-000000000002"
const secretWorkspace = "pid_00000000-0000-4000-8000-000000000003"
const secretEnvironment = "pid_00000000-0000-4000-8000-000000000004"
const approvedVersion = "11111111-1111-4111-8111-111111111111"

// Removing VersionId pinning or tenant qualification must return the wrong key.
func TestSecurityAgentWebhookVersionedSecret(t *testing.T) {
	secondOrg := "pid_00000000-0000-4000-8000-000000000099"
	secondVersion := "22222222-2222-4222-8222-222222222222"
	firstPath := "zasp/webhook/" + secretOrg + "/" + secretWorkspace + "/" + secretEnvironment + "/receiver/key"
	secondPath := "zasp/webhook/" + secondOrg + "/" + secretWorkspace + "/" + secretEnvironment + "/receiver/key"
	keys := map[string]string{firstPath + approvedVersion: strings.Repeat("a", 32), firstPath + secondVersion: strings.Repeat("b", 32), secondPath + approvedVersion: strings.Repeat("c", 32)}
	stub := &versionedSecretStub{call: func(ctx context.Context, captured *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		if captured.VersionStage != nil {
			t.Fatal("stage lookup forbidden")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Fatal("unbounded provider call")
		}
		key, ok := keys[aws.ToString(captured.SecretId)+aws.ToString(captured.VersionId)]
		if !ok {
			return nil, errors.New("wrong tenant/version path")
		}
		return &secretsmanager.GetSecretValueOutput{VersionId: captured.VersionId, SecretString: aws.String(key)}, nil
	}}
	resolver, err := NewResolver(stub, "zasp/webhook", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ org, version, want string }{{secretOrg, approvedVersion, strings.Repeat("a", 32)}, {secretOrg, secondVersion, strings.Repeat("b", 32)}, {secondOrg, approvedVersion, strings.Repeat("c", 32)}} {
		key, err := resolver.ResolveVersion(context.Background(), tc.org, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", tc.version)
		if err != nil || string(key) != tc.want {
			t.Errorf("tenant/version key mismatch: %v", err)
		}
		clear(key)
	}
	t.Run("exact-version-input", func(t *testing.T) {
		stub.call = func(_ context.Context, captured *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			if aws.ToString(captured.VersionId) != approvedVersion || captured.VersionStage != nil {
				t.Fatalf("secret version is not pinned: %#v", captured)
			}
			return &secretsmanager.GetSecretValueOutput{VersionId: aws.String(approvedVersion), SecretBinary: bytes.Repeat([]byte{'x'}, 32)}, nil
		}
		if _, err := resolver.ResolveVersion(context.Background(), secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", approvedVersion); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct{ name, org, workspace, environment, ref, version string }{
		{"organization", "../tenant", secretWorkspace, secretEnvironment, "secret_ref_receiver/key", approvedVersion},
		{"workspace", secretOrg, "", secretEnvironment, "secret_ref_receiver/key", approvedVersion},
		{"environment", secretOrg, secretWorkspace, "bad", "secret_ref_receiver/key", approvedVersion},
		{"traversal", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/../key", approvedVersion},
		{"double-slash", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver//key", approvedVersion},
		{"dot-segment", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/./key", approvedVersion},
		{"trailing-slash", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/", approvedVersion},
		{"reference", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_", approvedVersion},
		{"missing-version", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", ""},
		{"short-version", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", "AWSCURRENT"},
		{"long-version", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", strings.Repeat("a", 65)},
		{"version-character", secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", strings.Repeat("a", 31) + "_"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := stub.calls
			key, err := resolver.ResolveVersion(context.Background(), tc.org, tc.workspace, tc.environment, tc.ref, tc.version)
			if err == nil || key != nil || stub.calls != before {
				t.Fatal("malformed local input reached provider or yielded key")
			}
		})
	}
	for _, tc := range []struct {
		name, version               string
		size                        int
		both, providerError, cancel bool
	}{
		{name: "mismatch", version: secondVersion, size: 32}, {name: "missing-provider-version", size: 32}, {name: "short-key", version: approvedVersion, size: 31}, {name: "long-key", version: approvedVersion, size: 4097}, {name: "empty-key", version: approvedVersion}, {name: "ambiguous-key", version: approvedVersion, size: 32, both: true}, {name: "provider-error", version: approvedVersion, size: 32, providerError: true}, {name: "cancel-during-provider", version: approvedVersion, size: 32, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Repeat([]byte{'x'}, tc.size)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stub.call = func(context.Context, *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
				out := &secretsmanager.GetSecretValueOutput{VersionId: aws.String(tc.version), SecretBinary: raw}
				if tc.both {
					out.SecretString = aws.String(strings.Repeat("s", 32))
				}
				if tc.cancel {
					cancel()
				}
				if tc.providerError {
					return out, errors.New("PROVIDER_SECRET_SENTINEL")
				}
				return out, nil
			}
			key, err := resolver.ResolveVersion(ctx, secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", approvedVersion)
			if err == nil || key != nil || strings.Contains(err.Error(), "SENTINEL") || !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("rejected provider material was returned, leaked, or not cleared")
			}
		})
	}
	t.Run("cancel-before-provider", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		before := stub.calls
		if key, err := resolver.ResolveVersion(ctx, secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", approvedVersion); err == nil || key != nil || stub.calls != before {
			t.Fatal("cancelled call reached provider")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		stub.call = func(ctx context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		r, _ := NewResolver(stub, "zasp/webhook", 100*time.Millisecond)
		if key, err := r.ResolveVersion(context.Background(), secretOrg, secretWorkspace, secretEnvironment, "secret_ref_receiver/key", approvedVersion); err == nil || key != nil {
			t.Fatal("timeout accepted")
		}
	})
	for _, prefix := range []string{"", "zasp/oauth", "zasp//webhook", "../webhook", "zasp/webhook/"} {
		if _, err := NewResolver(stub, prefix, time.Second); err == nil {
			t.Fatalf("bad prefix accepted: %q", prefix)
		}
	}
	for _, timeout := range []time.Duration{0, 99 * time.Millisecond, 11 * time.Second} {
		if _, err := NewResolver(stub, "zasp/webhook", timeout); err == nil {
			t.Fatal("bad timeout accepted")
		}
	}
	if _, err := NewResolver(nil, "zasp/webhook", time.Second); err == nil {
		t.Fatal("nil client accepted")
	}
}
