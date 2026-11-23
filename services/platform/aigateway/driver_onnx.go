package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// ONNXDriver speaks the TEI /predict sequence-classification API. The exact
// label map is part of the measured model deployment's digest.
type ONNXDriver struct {
	client          *http.Client
	url             string
	safe, malicious string
}

func NewONNXDriver(endpoint PrivateEndpoint, model, safe, malicious string) (*ONNXDriver, error) {
	if !EligibleModel(PurposeInjectionScreen, ModeVPC, model) || !validLabel(safe) || !validLabel(malicious) || safe == malicious {
		return nil, ErrInvalidConfiguration
	}
	client, err := pinnedPrivateClient(endpoint, "/predict")
	if err != nil {
		return nil, err
	}
	return &ONNXDriver{client: client, url: endpoint.URL, safe: safe, malicious: malicious}, nil
}
func validLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// Tier: 2 | Purpose: indirect injection screening.
// Model: qualified US/EU binary ONNX sequence classifier.
// Authority: private, pinned endpoint and the current scoped grant.
// Fallback: missing or invalid scores leave deterministic enforcement intact.
func (d *ONNXDriver) Evaluate(ctx context.Context, p Purpose, snippet json.RawMessage) (json.RawMessage, error) {
	def, _ := LookupPurpose(PurposeInjectionScreen)
	if d == nil || ctx == nil || p != PurposeInjectionScreen || len(snippet) > def.MaxInputBytes || !json.Valid(snippet) {
		return nil, ErrInvalidRequest
	}
	envelope, _ := json.Marshal(map[string]json.RawMessage{"untrusted_data": snippet})
	input, _ := json.Marshal(map[string]any{"inputs": string(envelope), "raw_scores": false, "truncate": false})
	bounded, cancel := context.WithTimeout(ctx, def.MaxLatency)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, http.MethodPost, d.url, bytes.NewReader(input))
	if err != nil {
		return nil, ErrGeneration
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, ErrGeneration
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrGeneration
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 || bounded.Err() != nil {
		return nil, ErrGeneration
	}
	var labels []struct {
		Label string   `json:"label"`
		Score *float64 `json:"score"`
	}
	if json.Unmarshal(raw, &labels) != nil || len(labels) != 2 {
		return nil, ErrGeneration
	}
	scores := map[string]float64{}
	for _, l := range labels {
		if l.Score == nil || *l.Score < 0 || *l.Score > 1 || (l.Label != d.safe && l.Label != d.malicious) {
			return nil, ErrGeneration
		}
		scores[l.Label] = *l.Score
	}
	if len(scores) != 2 || scores[d.safe]+scores[d.malicious] < 0.999 || scores[d.safe]+scores[d.malicious] > 1.001 {
		return nil, ErrGeneration
	}
	return json.Marshal(map[string]any{"malicious_probability": scores[d.malicious], "confidence": max(scores[d.safe], scores[d.malicious]), "attack_family": "indirect_injection"})
}
