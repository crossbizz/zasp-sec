package aigateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type semanticTransport func(*http.Request) (*http.Response, error)

func (r semanticTransport) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }

func TestPinnedPrivateDriver(t *testing.T) {
	endpoint := PrivateEndpoint{"https://inference.internal/v1/chat/completions", netip.MustParseAddr("10.0.0.3")}
	driver, err := NewVLLMDriver(endpoint, ModelShieldstral)
	if err != nil {
		t.Fatal(err)
	}
	real := driver.client.Transport.(*http.Transport)
	if real.Proxy != nil || real.TLSClientConfig.ServerName != "inference.internal" || !errors.Is(driver.client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("unexpected egress policy")
	}
	for _, ip := range []string{"192.0.2.1", "0.0.0.0", "127.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "::1"} {
		bad := endpoint
		bad.IP = netip.MustParseAddr(ip)
		if _, err := NewVLLMDriver(bad, ModelShieldstral); err == nil {
			t.Fatal(ip)
		}
	}
	var returned string
	driver.client.Transport = semanticTransport(func(req *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(req.Body)
		var body struct {
			Messages []modelMessage `json:"messages"`
		}
		_ = json.Unmarshal(raw, &body)
		if req.URL.String() != endpoint.URL || len(body.Messages) != 2 || body.Messages[1].Role != "user" || body.Messages[1].Content != `{"untrusted_data":{"flag":true}}` || strings.Contains(body.Messages[0].Content, `"flag"`) {
			t.Fatal("untrusted input crossed boundary")
		}
		out, _ := json.Marshal(map[string]any{"model": ModelShieldstral, "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": returned}}}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(out))}, nil
	})
	returned = `{"verdict":"aligned","violated_clause":"none","confidence":0.99}`
	if _, err := driver.Evaluate(t.Context(), PurposeAlignment, json.RawMessage(`{"flag":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, returned + `{}`, strings.Replace(returned, "0.99", "2", 1), strings.Replace(returned, "0.99", "null", 1), strings.Replace(returned, "0.99", `0.99,"confidence":0.5`, 1)} {
		returned = bad
		if _, err := driver.Evaluate(t.Context(), PurposeAlignment, json.RawMessage(`{"flag":true}`)); err == nil {
			t.Fatal("accepted malformed output", bad)
		}
	}
}

func TestSignedDeployment(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := Deployment{Endpoint: "https://inference.internal/v1/chat/completions", PrivateIP: "10.0.2.3", WeightsSHA256: strings.Repeat("b", 64), Model: ModelShieldstral, Region: "eu", MaximumNanoCredits: 10}
	now := time.Now()
	a := DeploymentAttestation{Deployment: d, Purpose: PurposeAlignment, BaseWeightOrigin: "eu", ZeroRetention: true, ExpiresAt: now.Add(time.Hour)}
	verify := func(a DeploymentAttestation, valid bool) {
		t.Helper()
		raw, _ := json.Marshal(a)
		sig := ed25519.Sign(priv, raw)
		_, err := VerifyAttestation(raw, sig, priv.Public().(ed25519.PublicKey), now)
		if (err == nil) != valid {
			t.Fatal(err)
		}
	}
	verify(a, true)
	a.ZeroRetention = false
	verify(a, false)
	a.ZeroRetention = true
	a.BaseWeightOrigin = "unknown"
	verify(a, false)
	a.BaseWeightOrigin = "eu"
	a.ExpiresAt = now
	verify(a, false)
	if EligibleModel(PurposeInjectionScreen, ModeVPC, "Horizon-Labs/prompt-injection-guard-large") || EligibleModel(PurposeDiscoveryVerify, ModeVPC, modelSonnet) {
		t.Fatal("unapproved model or plane")
	}
}

type alignedOnly struct{}

func (alignedOnly) Evaluate(context.Context, Purpose, json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{"verdict":"aligned","violated_clause":"none","confidence":1}`), nil
}
func TestPerfectSchemaCannotQualifyWrongAnswers(t *testing.T) {
	r, err := MeasureAlignment(t.Context(), alignedOnly{}, Deployment{})
	if err != nil || r.Valid != 128 || r.Total != 128 || r.CounterfeitFailures == 0 || r.Qualified {
		t.Fatal(r, err)
	}
}

func TestONNXBinaryLabelMapAndOutputBounds(t *testing.T) {
	d, err := NewONNXDriver(PrivateEndpoint{"https://inference.internal/predict", netip.MustParseAddr("10.1.2.3")}, modelGuardBase, "SAFE", "INJECTION")
	if err != nil {
		t.Fatal(err)
	}
	var response string
	d.client.Transport = semanticTransport(func(req *http.Request) (*http.Response, error) {
		var in struct {
			Inputs   string `json:"inputs"`
			Truncate bool   `json:"truncate"`
		}
		if json.NewDecoder(req.Body).Decode(&in) != nil || !strings.Contains(in.Inputs, `"untrusted_data"`) || in.Truncate {
			t.Fatal("bad TEI request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	response = `[{"label":"INJECTION","score":0.01},{"label":"SAFE","score":0.99}]`
	if out, err := d.Evaluate(t.Context(), PurposeInjectionScreen, json.RawMessage(`{"snippet":"test"}`)); err != nil || !ValidateSemanticOutput(PurposeInjectionScreen, out) {
		t.Fatal(err, string(out))
	}
	for _, bad := range []string{`[]`, `[{"label":"SAFE","score":1},{"label":"SAFE","score":0}]`, `[{"label":"INJECTION","score":0.95},{"label":"SAFE","score":0.95}]`} {
		response = bad
		if _, err = d.Evaluate(t.Context(), PurposeInjectionScreen, json.RawMessage(`{}`)); err == nil {
			t.Fatal("invalid TEI score accepted")
		}
	}
}
