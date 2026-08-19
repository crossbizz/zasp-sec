package kubernetesdiscovery

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type probeFunc func(context.Context, ProbeRequest) (ProbeResult, error)

func (function probeFunc) Probe(ctx context.Context, request ProbeRequest) (ProbeResult, error) {
	return function(ctx, request)
}

func TestAdapterUsesOnlyExplicitClusterReferencesAndRequiresReadCapabilities(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/ambient-must-not-be-read")
	config := Config{Endpoint: "https://api.customer.example", CAReference: "ref:kubernetes/ca-0001", CredentialReference: "ref:kubernetes/credential-0001", Context: "production"}
	client := probeFunc(func(_ context.Context, request ProbeRequest) (ProbeResult, error) {
		if request.Endpoint != config.Endpoint || request.CAReference != config.CAReference || request.CredentialReference != config.CredentialReference || request.Context != config.Context {
			t.Fatalf("probe request %#v", request)
		}
		return ProbeResult{ClusterID: "cluster-01", ServerVersion: "v1.31.2", AllowedVerbs: []string{"get", "list", "watch"}}, nil
	})
	adapter, err := NewAdapter(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.TestConnection(context.Background(), config)
	if err != nil || result.ClusterID != "cluster-01" {
		t.Fatalf("probe=%#v err=%v", result, err)
	}
	if os.Getenv("KUBECONFIG") != "/tmp/ambient-must-not-be-read" {
		t.Fatal("ambient kubeconfig changed")
	}
	for _, hostile := range []Config{
		{Endpoint: "http://api.customer.example", CAReference: config.CAReference, CredentialReference: config.CredentialReference, Context: config.Context},
		{Endpoint: "https://127.0.0.1", CAReference: config.CAReference, CredentialReference: config.CredentialReference, Context: config.Context},
		{Endpoint: config.Endpoint, CAReference: "-----BEGIN CERTIFICATE-----", CredentialReference: config.CredentialReference, Context: config.Context},
		{Endpoint: config.Endpoint, CAReference: config.CAReference, CredentialReference: "raw-token", Context: config.Context},
	} {
		if _, err := adapter.TestConnection(context.Background(), hostile); !errors.Is(err, ErrInvalid) {
			t.Fatalf("hostile config %#v error=%v", hostile, err)
		}
	}
}

func TestAdapterRejectsCapabilityGapsWithRedactedError(t *testing.T) {
	client := probeFunc(func(context.Context, ProbeRequest) (ProbeResult, error) {
		return ProbeResult{ClusterID: "cluster-01", ServerVersion: "v1.31.2", AllowedVerbs: []string{"get", "list"}}, nil
	})
	adapter, _ := NewAdapter(client, time.Second)
	_, err := adapter.TestConnection(context.Background(), Config{Endpoint: "https://api.customer.example", CAReference: "ref:kubernetes/ca-0001", CredentialReference: "ref:kubernetes/credential-0001", Context: "production"})
	if !errors.Is(err, ErrDenied) || err.Error() != ErrDenied.Error() {
		t.Fatalf("capability error=%v", err)
	}
}
