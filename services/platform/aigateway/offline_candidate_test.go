package aigateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const batchTestToken = "local-qualification-only-fixture"

func offlineCandidateFixture(t *testing.T) (offlineManifest, [3]string, ed25519.PrivateKey, time.Time) {
	t.Helper()
	scope := [3]string{"pid_11111111-1111-4111-8111-111111111111", "pid_22222222-2222-4222-8222-222222222222", "pid_33333333-3333-4333-8333-333333333333"}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return offlineManifest{
		Mode: offlineQualificationMode, Purpose: PurposeHeuristicVerify,
		Deployment: Deployment{Provider: ModeBYOC, OrganizationID: scope[0], WorkspaceID: scope[1], EnvironmentID: scope[2],
			Model: offlineSafeguardModel, PrivateIP: "10.4.3.2", Endpoint: "https://batch.customer.internal/v1/chat/completions", Region: "us",
			WeightsSHA256: strings.Repeat("a", 64), MaximumNanoCredits: 10},
		CredentialSHA256: candidateDigest([]byte(batchTestToken)), CorpusSHA256: candidateDigest([]byte("signed fixtures")),
		ZeroRetention: true, BaseWeightOrigin: "us", ExpiresAt: now.Add(time.Hour),
	}, scope, private, now
}

func TestOfflineCandidateAuthority(t *testing.T) {
	m, scope, private, now := offlineCandidateFixture(t)
	pub := private.Public().(ed25519.PublicKey)
	raw, _ := json.Marshal(m)
	sig := ed25519.Sign(private, raw)
	if _, err := verifiedOfflineManifest(raw, sig, pub, scope, batchTestToken, now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestation(raw, sig, pub, now); err == nil {
		t.Fatal("offline signature authorized runtime qualification")
	}
	other := scope
	other[1] = scope[2]
	if _, err := verifiedOfflineManifest(raw, sig, pub, other, batchTestToken, now); err == nil {
		t.Fatal("authorized another tenant scope")
	}
	if _, err := verifiedOfflineManifest(raw, sig, pub, scope, batchTestToken+"-rotated", now); err == nil {
		t.Fatal("accepted a different credential")
	}
	if _, err := verifiedOfflineManifest(append(raw, ' '), sig, pub, scope, batchTestToken, now); err == nil {
		t.Fatal("accepted modified signed bytes")
	}
	for name, mutate := range map[string]func(*offlineManifest){
		"runtime":             func(m *offlineManifest) { m.Mode = "online" },
		"another purpose":     func(m *offlineManifest) { m.Purpose = PurposeAlignment },
		"unscoped deployment": func(m *offlineManifest) { m.Deployment.Provider = ModeVPC },
		"different model":     func(m *offlineManifest) { m.Deployment.Model = ModelShieldstral },
		"unattested corpus":   func(m *offlineManifest) { m.CorpusSHA256 = "" },
		"unattested base":     func(m *offlineManifest) { m.BaseWeightOrigin = "" },
		"retention":           func(m *offlineManifest) { m.ZeroRetention = false },
		"expired":             func(m *offlineManifest) { m.ExpiresAt = now },
	} {
		t.Run(name, func(t *testing.T) {
			bad := m
			mutate(&bad)
			data, _ := json.Marshal(bad)
			if _, err := verifiedOfflineManifest(data, ed25519.Sign(private, data), pub, scope, batchTestToken, now); err == nil {
				t.Fatal("accepted invalid candidate")
			}
		})
	}
	changed := []byte("unsigned fixtures")
	if _, err := MeasureOfflineCandidate(t.Context(), raw, sig, pub, scope, batchTestToken, changed); err != ErrInvalidRequest {
		t.Fatalf("changed corpus: %v", err)
	}
	m.Deployment.PrivateIP = "203.0.113.12"
	raw, _ = json.Marshal(m)
	if _, err := MeasureOfflineCandidate(t.Context(), raw, ed25519.Sign(private, raw), pub, scope, batchTestToken, changed); err != ErrInvalidConfiguration {
		t.Fatalf("public endpoint: %v", err)
	}
}

func TestOfflineCandidateRejectedByEveryRuntime(t *testing.T) {
	m, _, _, _ := offlineCandidateFixture(t)
	for p := range purposes {
		for _, mode := range []string{ModeVPC, ModeBYOC, ModeDev, ModeBedrock, ModeVertex} {
			if EligibleModel(p, mode, m.Deployment.Model) {
				t.Fatalf("eligible for %s/%s", mode, p)
			}
		}
	}
	if _, err := m.Deployment.Driver(); err == nil {
		t.Fatal("production constructor accepted offline model")
	}
	a := DeploymentAttestation{Deployment: m.Deployment, Purpose: PurposeHeuristicVerify}
	if _, _, err := a.MeasuredDriver(batchTestToken); err == nil {
		t.Fatal("tenant qualification worker accepted offline model")
	}
	noClient := &VLLMDriver{model: offlineSafeguardModel}
	if _, err := noClient.Evaluate(t.Context(), PurposeHeuristicVerify, json.RawMessage("{}")); err == nil {
		t.Fatal("synchronous driver accepted offline model")
	}
}

func TestOfflineCandidateMeasuresBoundedTypedBatch(t *testing.T) {
	m, _, _, _ := offlineCandidateFixture(t)
	var calls int
	client := &http.Client{Transport: semanticTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		var body struct {
			Model     string         `json:"model"`
			Messages  []modelMessage `json:"messages"`
			MaxTokens int            `json:"max_tokens"`
		}
		if json.NewDecoder(req.Body).Decode(&body) != nil || body.Model != m.Deployment.Model || body.MaxTokens != 512 || len(body.Messages) != 2 ||
			body.Messages[0].Content != systemMessages[PurposeHeuristicVerify] || body.Messages[1].Role != "user" || req.Header.Get("Authorization") != "Bearer "+batchTestToken {
			t.Fatal("unexpected offline model request")
		}
		var sample struct {
			Data struct {
				FixtureID int `json:"fixture_id"`
			} `json:"untrusted_data"`
		}
		if err := json.Unmarshal([]byte(body.Messages[1].Content), &sample); err != nil {
			t.Fatal(err)
		}
		verdict := "benign_context"
		if sample.Data.FixtureID >= 60 {
			verdict = "true_positive"
		}
		response, _ := json.Marshal(map[string]any{"model": m.Deployment.Model, "choices": []any{map[string]any{"finish_reason": "stop", "message": modelMessage{"assistant", fmt.Sprintf(`{"verdict":%q,"confidence":0.98,"reason_code":"test_fixture"}`, verdict)}}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	driver := offlineSafeguard{&VLLMDriver{client: client, endpoint: m.Deployment.Endpoint, model: m.Deployment.Model}, batchTestToken}
	if _, err := driver.Evaluate(t.Context(), PurposeAlignment, []byte("{}")); err == nil || calls != 0 {
		t.Fatal("offline driver sent an alignment request")
	}
	var corpus bytes.Buffer
	for i := 0; i < 110; i++ {
		fmt.Fprintf(&corpus, "{\"input\":{\"fixture_id\":%d},\"positive\":%t,\"counterfeit_policy\":%t}\n", i, i >= 60, i == 0)
	}
	a := DeploymentAttestation{Deployment: m.Deployment, Purpose: m.Purpose, CorpusSHA256: candidateDigest(corpus.Bytes())}
	result, err := MeasureCorpus(t.Context(), driver, a, corpus.Bytes())
	if err != nil || calls != 110 || result.Total != 110 || result.Valid != 110 || !result.Qualified {
		t.Fatal(calls, result, err)
	}
}
