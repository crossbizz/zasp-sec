package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/auth"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore/neo4jstore"
)

func newRuntimePipelineGraphFixture(t *testing.T, ctx context.Context) *graphstore.Store {
	t.Helper()
	uri, password := os.Getenv("ZASP_COMBINED_E2E_RUNTIME_GRAPH_URI"), os.Getenv("ZASP_COMBINED_E2E_RUNTIME_GRAPH_PASSWORD")
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "bolt+s" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(password) || os.Getenv("GODEBUG") != "x509usefallbackroots=1" {
		t.Fatal("owned TLS graph configuration rejected")
	}
	block, rest := pem.Decode([]byte(os.Getenv("ZASP_COMBINED_E2E_RUNTIME_GRAPH_CA_PEM")))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("owned graph certificate rejected")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil || certificate.VerifyHostname("127.0.0.1") != nil {
		t.Fatal("owned graph trust rejected")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	// Isolated harness test process only. Production trust and constructors are
	// unchanged; Community cannot attest the production publisher role.
	x509.SetFallbackRoots(roots)
	adapter, err := neo4jstore.NewProduction(ctx, neo4jstore.ProductionConfig{Endpoint: uri, AuthenticationReference: "ref:neo4j/auth/runtime-combined-proof", ReadinessTimeout: 10 * time.Second}, runtimePipelineGraphAuthentication{neo4j.BasicAuth("neo4j", password, "")})
	if err != nil {
		t.Fatal("actual TLS graph adapter unavailable", err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(context.Background()); err != nil {
			t.Error("actual graph cleanup", err)
		}
	})
	if err := adapter.EnsureSchema(ctx); err != nil {
		t.Fatal("actual graph schema", err)
	}
	if err := adapter.Ready(ctx); err != nil {
		t.Fatal("actual graph readiness", err)
	}
	store, err := graphstore.New(adapter, graphstore.Config{OperationTimeout: 10 * time.Second, MaximumNodes: 3000, MaximumEdges: 2000, MaximumDepth: 8})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type runtimePipelineGraphAuthentication struct{ manager auth.TokenManager }

func (value runtimePipelineGraphAuthentication) ResolveNeo4jAuthentication(context.Context, string) (auth.TokenManager, error) {
	return value.manager, nil
}

type runtimePipelineGraphObserver struct {
	delegate runtimeCorrelationGraphStore
	calls    int
}

func (value *runtimePipelineGraphObserver) ApplySnapshot(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
	value.calls++
	return value.delegate.ApplySnapshot(ctx, snapshot)
}
