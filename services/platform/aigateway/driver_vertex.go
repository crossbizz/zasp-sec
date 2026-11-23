package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
)

var gcpProject = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

type VertexDriver struct {
	purpose                Purpose
	client                 *http.Client
	endpoint, model, token string
}

func vertexResidency(location string) string {
	switch location {
	case "us-central1", "us-east1", "us-east4", "us-east5", "us-west1", "us-west2", "us-west3", "us-west4", "us-south1":
		return "us"
	case "europe-west1", "europe-west3", "europe-west4", "europe-west8", "europe-west9", "europe-west10", "europe-west12", "europe-central2", "europe-north1", "europe-north2", "europe-southwest1":
		return "eu"
	}
	return ""
}

func NewVertexForPurpose(p Purpose, location, project string, ip netip.Addr, model, reference, token string, upperCost int64) (*VertexDriver, BedrockBinding, error) {
	var b BedrockBinding
	region := vertexResidency(location)
	if region == "" || !gcpProject.MatchString(project) || bedrockInstructions[p] == "" || !EligibleModel(p, ModeVertex, model) || !validPrivateCredential(reference, token, upperCost) {
		return nil, b, ErrInvalidConfiguration
	}
	path := fmt.Sprintf("/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent", project, location, model)
	endpoint := "https://" + location + "-aiplatform.googleapis.com" + path
	client, err := pinnedPrivateClient(PrivateEndpoint{URL: endpoint, IP: ip}, path)
	if err != nil {
		return nil, b, err
	}
	b = BedrockBinding{Provider: ModeVertex, Model: model, Region: region, CredentialReference: reference, CredentialDigest: digest(token), DeploymentDigest: digest("vertex-generate-v1\n" + endpoint + "\n" + ip.String() + "\n" + model), Cost: upperCost}
	return &VertexDriver{p, client, endpoint, model, token}, b, nil
}

// Tier: 3 | Purpose: bounded advisory analysis and investigation.
// Model: qualified Gemini deployment on a pinned regional PSC endpoint.
// Authority: the caller holds a matching per-job qualification and budget.
// Fallback: an incomplete or blocked response preserves deterministic coverage.
func (d *VertexDriver) Evaluate(ctx context.Context, p Purpose, input json.RawMessage) (json.RawMessage, error) {
	rule, ok := LookupPurpose(p)
	if ctx == nil || d == nil || !ok || p != d.purpose || !json.Valid(input) || len(input) > rule.MaxInputBytes {
		return nil, ErrInvalidRequest
	}
	data, _ := json.Marshal(map[string]json.RawMessage{"untrusted_data": input})
	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Role  string `json:"role,omitempty"`
		Parts []part `json:"parts"`
	}
	body, _ := json.Marshal(map[string]any{
		"systemInstruction": content{Parts: []part{{bedrockInstructions[p]}}},
		"contents":          []content{{Role: "user", Parts: []part{{string(data)}}}},
		"generationConfig":  map[string]any{"temperature": 0, "candidateCount": 1, "maxOutputTokens": 1024, "responseMimeType": "application/json"},
	})
	limited, cancel := context.WithTimeout(ctx, rule.MaxLatency)
	defer cancel()
	req, err := http.NewRequestWithContext(limited, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrGeneration
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := d.client.Do(req)
	if err != nil {
		return nil, ErrGeneration
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, ErrGeneration
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32769))
	if err != nil || len(raw) > 32768 || limited.Err() != nil {
		return nil, ErrGeneration
	}
	return d.response(raw, p)
}

func (d *VertexDriver) response(raw []byte, p Purpose) (json.RawMessage, error) {
	var reply struct {
		ModelVersion string
		Candidates   []struct {
			FinishReason string
			Content      struct {
				Role  string
				Parts []struct {
					Text    string
					Thought bool
				}
			}
		}
	}
	if json.Unmarshal(raw, &reply) != nil || reply.ModelVersion != d.model || len(reply.Candidates) != 1 {
		return nil, ErrGeneration
	}
	choice := reply.Candidates[0]
	if choice.FinishReason != "STOP" || choice.Content.Role != "model" || len(choice.Content.Parts) != 1 || choice.Content.Parts[0].Thought {
		return nil, ErrGeneration
	}
	answer := json.RawMessage(choice.Content.Parts[0].Text)
	if !ValidateSemanticOutput(p, answer) {
		return nil, ErrGeneration
	}
	return answer, nil
}
