package aigateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestVertexPSCPinsScopeAndValidatesResponse(t *testing.T) {
	const reference = "secret_ref_planner/org/workspace/environment/vertex"
	const token = "controlled-test-token-material"
	ip := netip.MustParseAddr("10.2.0.4")
	d, b, err := NewVertexForPurpose(PurposeTriage, "europe-west4", "tenant-stage", ip, modelGemini, reference, token, 100)
	if err != nil || b.Provider != ModeVertex || b.Region != "eu" || b.CredentialDigest != digest(token) {
		t.Fatalf("binding %+v: %v", b, err)
	}
	for _, x := range []struct{ location, project, ip, model string }{
		{"global", "tenant-stage", "10.2.0.4", modelGemini}, {"europe-west2", "tenant-stage", "10.2.0.4", modelGemini}, {"europe-west6", "tenant-stage", "10.2.0.4", modelGemini},
		{"us-central1", "tenant-stage", "8.8.8.8", modelGemini}, {"us-central1", "other/tenant", "10.2.0.4", modelGemini}, {"us-central1", "tenant-stage", "10.2.0.4", modelHaiku},
	} {
		if _, _, err := NewVertexForPurpose(PurposeTriage, x.location, x.project, netip.MustParseAddr(x.ip), x.model, reference, token, 100); err == nil {
			t.Fatal("accepted unsafe binding", x)
		}
	}
	reqs := 0
	d.client.Transport = semanticTransport(func(r *http.Request) (*http.Response, error) {
		reqs++
		if r.URL.String() != "https://europe-west4-aiplatform.googleapis.com/v1/projects/tenant-stage/locations/europe-west4/publishers/google/models/gemini-2.5-pro:generateContent" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("unexpected Vertex request")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), "untrusted_data") || !strings.Contains(string(body), "systemInstruction") {
			t.Fatalf("missing fixed data barrier: %s", body)
		}
		content := map[string]any{"modelVersion": modelGemini, "candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"role": "model", "parts": []any{map[string]string{"text": `{"summary":"Reviewed the receipt","evidence_ids":["receipt-1"]}`}}}}}}
		raw, _ := json.Marshal(content)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	if _, err := d.Evaluate(context.Background(), PurposeDraft, json.RawMessage(`{}`)); err == nil || reqs != 0 {
		t.Fatal("mismatched job reached transport")
	}
	if _, err := d.Evaluate(context.Background(), PurposeTriage, json.RawMessage(`{"evidence":"receipt-1"}`)); err != nil || reqs != 1 {
		t.Fatalf("private evaluation %d: %v", reqs, err)
	}
	for _, raw := range []string{`{"modelVersion":"other"}`, `{"modelVersion":"gemini-2.5-pro","candidates":[{"finishReason":"SAFETY"}]}`} {
		if _, err := d.response([]byte(raw), PurposeTriage); err == nil {
			t.Fatal("accepted incomplete response")
		}
	}
}
