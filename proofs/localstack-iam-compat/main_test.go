package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMainWritesOnlyFixedSuccessForExactProof(t *testing.T) {
	withMainSeams(t,
		func(context.Context, string, string, string) (IAMBoundary, error) { return &fakeBoundary{}, nil },
		func(context.Context, ProofOptions) (ProofResult, error) {
			return ProofResult{Namespaces: true, Assumed: true, AllowedRead: true, ExplicitDeny: true, Cleanup: true, Audit: true}, nil
		},
	)
	var output bytes.Buffer
	if code := runMain(context.Background(), &output, lookupMain(map[string]string{"AWS_ENDPOINT_URL": "http://127.0.0.1:4566", "PATH": "/fixed/bin"})); code != 0 {
		t.Fatalf("runMain() code = %d, want 0", code)
	}
	const want = "LocalStack IAM compatibility proof passed: namespaces=true assumed=true allowed_read=true explicit_deny=true cleanup=true audit=true container_cleanup=true.\n"
	if got := output.String(); got != want {
		t.Fatalf("runMain() output = %q, want %q", got, want)
	}
}

func TestMainRedactsProviderDetailsIntoFixedFailureCategories(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "configuration", err: errConfiguration, want: "configuration"},
		{name: "authorization", err: errAuthorization, want: "authorization"},
		{name: "provider", err: errProvider, want: "provider"},
		{name: "unknown provider detail", err: errors.New("provider secret=token"), want: "operation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withMainSeams(t,
				func(context.Context, string, string, string) (IAMBoundary, error) { return &fakeBoundary{}, nil },
				func(context.Context, ProofOptions) (ProofResult, error) { return ProofResult{}, test.err },
			)
			var output bytes.Buffer
			code := runMain(context.Background(), &output, lookupMain(map[string]string{"AWS_ENDPOINT_URL": "http://127.0.0.1:4566", "PATH": "/fixed/bin"}))
			want := "LocalStack IAM compatibility proof failed: " + test.want + " rejected.\n"
			if code != 1 || output.String() != want || strings.Contains(output.String(), "secret") {
				t.Fatalf("runMain() = (%d, %q), want (1, %q)", code, output.String(), want)
			}
		})
	}
}

func TestMainRejectsIncompleteResultsAndUnexpectedEnvironment(t *testing.T) {
	withMainSeams(t,
		func(context.Context, string, string, string) (IAMBoundary, error) { return &fakeBoundary{}, nil },
		func(context.Context, ProofOptions) (ProofResult, error) { return ProofResult{Namespaces: true}, nil },
	)
	for name, environment := range map[string]map[string]string{
		"incomplete result": {"AWS_ENDPOINT_URL": "http://127.0.0.1:4566", "PATH": "/fixed/bin"},
		"missing endpoint":  {"PATH": "/fixed/bin"},
		"missing path":      {"AWS_ENDPOINT_URL": "http://127.0.0.1:4566"},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			code := runMain(context.Background(), &output, lookupMain(environment))
			const want = "LocalStack IAM compatibility proof failed: configuration rejected.\n"
			if name == "incomplete result" {
				if got := output.String(); got != "LocalStack IAM compatibility proof failed: operation rejected.\n" || code != 1 {
					t.Fatalf("runMain() = (%d, %q)", code, got)
				}
				return
			}
			if code != 1 || output.String() != want {
				t.Fatalf("runMain() = (%d, %q), want (1, %q)", code, output.String(), want)
			}
		})
	}
}

func withMainSeams(t *testing.T, boundary mainBoundaryFactory, proof mainProofRunner) {
	t.Helper()
	previousBoundary, previousProof := newMainBoundary, runMainProof
	newMainBoundary, runMainProof = boundary, proof
	t.Cleanup(func() { newMainBoundary, runMainProof = previousBoundary, previousProof })
}

func lookupMain(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}
