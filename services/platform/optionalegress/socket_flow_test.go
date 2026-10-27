package optionalegress

// This is an owned synthetic provider over a real TCP/TLS socket, not a live
// OpenRouter request, approved backend, pricing receipt or deployed auth proof.
// Store/Authorizer are component doubles; production SQL/API/browser acceptance
// remains separate. The existing hostile response cases use cheap RoundTrippers.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func socketFlowCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("owned CA key unavailable")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned optional egress component CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal("owned CA certificate unavailable")
	}
	parsedCA, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal("owned CA decode failed")
	}
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("owned provider key unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Owned synthetic provider"}, DNSNames: []string{"openrouter.ai"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, parsedCA, &serverKey.PublicKey, caKey)
	if e != nil {
		t.Fatal("owned provider certificate unavailable")
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsedCA)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: serverKey}, roots
}

func TestOwnedTLSSocketExplanationFlow(t *testing.T) {
	certificate, roots := socketFlowCertificate(t)
	var requests, verifiedTLS atomic.Int64
	var missingIdentity atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Host != "openrouter.ai" || r.URL.Path != "/api/v1/chat/completions" || r.URL.RawQuery != "" || r.TLS == nil || r.TLS.ServerName != "openrouter.ai" {
			t.Error("owned socket received wrong method, host, path or TLS identity")
			http.Error(w, "invalid owned request", 400)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+string(testToken()) || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-OpenRouter-Metadata") != "enabled" {
			t.Error("owned socket missing bound credential or wire headers")
			http.Error(w, "invalid owned request", 400)
			return
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, maximumBodyBytes+1))
		if e != nil || len(raw) > maximumBodyBytes {
			t.Error("owned socket request exceeds bound")
			http.Error(w, "invalid owned request", 400)
			return
		}
		var body map[string]json.RawMessage
		if json.Unmarshal(raw, &body) != nil || len(body) != 6 || string(body["model"]) != `"openai/gpt-5-mini"` || string(body["max_tokens"]) != "512" || string(body["stream"]) != "false" {
			t.Error("owned socket body does not match governed selection")
			http.Error(w, "invalid owned request", 400)
			return
		}
		var provider map[string]json.RawMessage
		if json.Unmarshal(body["provider"], &provider) != nil || string(provider["only"]) != `["OpenAI"]` || string(provider["zdr"]) != "true" || string(provider["allow_fallbacks"]) != "false" || string(provider["require_parameters"]) != "true" || string(provider["data_collection"]) != `"deny"` {
			t.Error("owned socket lost privacy/backend constraints")
			http.Error(w, "invalid owned request", 400)
			return
		}
		var messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		if json.Unmarshal(body["messages"], &messages) != nil || len(messages) != 2 || messages[0].Role != "system" || messages[1].Role != "user" {
			t.Error("owned socket message contract differs")
			http.Error(w, "invalid owned request", 400)
			return
		}
		var summary map[string]json.RawMessage
		if json.Unmarshal([]byte(messages[1].Content), &summary) != nil || len(summary) != 3 || string(summary["rule"]) != `"ownerless_agent"` || string(summary["severity"]) != `"high"` || string(summary["evidence_count"]) != "3" || bytes.Contains(raw, []byte(testIntent().FindingID)) || bytes.Contains(raw, []byte(testIntent().OrganizationID)) {
			t.Error("owned socket received noncanonical or private source data")
			http.Error(w, "invalid owned request", 400)
			return
		}
		reply := responseJSON(t)
		if missingIdentity.Load() {
			var v map[string]json.RawMessage
			_ = json.Unmarshal(reply, &v)
			delete(v, "openrouter_metadata")
			reply, _ = json.Marshal(v)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(reply)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("default transport unavailable")
	}
	transport := base.Clone()
	// Test-only loopback mapping: production URL/Host/TLS DNS remain exact. No
	// external socket or session proxy is contacted, and certificate verification
	// uses an owned CA without InsecureSkipVerify. Injected transport is test-owned.
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "openrouter.ai", RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].VerifyHostname("openrouter.ai") != nil {
			return errors.New("owned TLS peer refused")
		}
		verifiedTLS.Add(1)
		return nil
	}}
	dialer := &net.Dialer{Timeout: time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "openrouter.ai:443" {
			return nil, errors.New("nonowned socket refused")
		}
		return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	resolver := &testResolver{token: testToken()}
	sender, e := NewOpenRouterSender(SenderConfig{Resolver: resolver, Transport: transport, Now: testClock})
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	store := &testStore{source: testSource(t)}
	auth := &testAuthorizer{}
	service := testService(t, store, auth, sender)
	result, e := service.Generate(context.Background(), testIntent())
	if e != nil || result.Explanation == nil || result.Receipt.State != Complete || requests.Load() != 1 || verifiedTLS.Load() < 1 || len(store.settlements) != 1 {
		t.Fatal("owned TLS service flow did not complete", e)
	}
	replay, e := service.Generate(context.Background(), testIntent())
	if e != nil || !replay.Replayed || replay.Explanation != nil || requests.Load() != 1 {
		t.Fatal("same-key metadata replay repeated socket request", e)
	}
	auth.deny = ReplayPhase
	if _, e := service.Generate(context.Background(), testIntent()); e == nil || requests.Load() != 1 {
		t.Fatal("revoked replay reached socket")
	}
	denied := testService(t, &testStore{source: testSource(t)}, &testAuthorizer{deny: DispatchPhase}, sender)
	if _, e := denied.Generate(context.Background(), testIntent()); e == nil || requests.Load() != 1 {
		t.Fatal("revoked dispatch reached socket")
	}
	missingIdentity.Store(true)
	unknownStore := &testStore{source: testSource(t)}
	unknown := testService(t, unknownStore, &testAuthorizer{}, sender)
	unknownIntent := testIntent()
	unknownIntent.IdempotencyKey = "finding-explanation-intent-unknown-0002"
	uncertain, e := unknown.Generate(context.Background(), unknownIntent)
	if !errors.Is(e, ErrUnknown) || uncertain.Explanation != nil || uncertain.Receipt.State != Unknown || uncertain.Receipt.Usage != nil || uncertain.Receipt.Binding.CostCeilingNanoCredits != result.Receipt.Binding.CostCeilingNanoCredits || uncertain.Receipt.Binding.CostCeilingNanoCredits <= 0 || requests.Load() != 2 {
		t.Fatal("missing socket routing evidence did not retain unknown cost ceiling", e)
	}
	replay, e = unknown.Generate(context.Background(), unknownIntent)
	if e != nil || !replay.Replayed || replay.Receipt.State != Unknown || replay.Receipt.Usage != nil || requests.Load() != 2 {
		t.Fatal("unknown socket effect resent", e)
	}
}
