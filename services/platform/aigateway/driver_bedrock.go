package aigateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var bedrockHost = regexp.MustCompile(`^vpce-[a-z0-9-]+\.bedrock-runtime\.((?:us|eu)-[a-z]+-[1-9])\.vpce\.amazonaws\.com$`)

type BedrockDriver struct {
	purpose         Purpose
	client          *http.Client
	endpoint, token string
}

type BedrockBinding struct {
	Provider            string `json:"provider"`
	Model               string `json:"model"`
	Region              string `json:"region"`
	CredentialReference string `json:"credential_reference"`
	CredentialDigest    string `json:"credential_digest"`
	DeploymentDigest    string `json:"deployment_digest"`
	Cost                int64  `json:"cost"`
}

func NewBedrockTriage(host string, ip netip.Addr, model, reference, token string, upperCost int64) (*BedrockDriver, BedrockBinding, error) {
	return NewBedrockForPurpose(PurposeTriage, host, ip, model, reference, token, upperCost)
}

func NewBedrockForPurpose(p Purpose, host string, ip netip.Addr, model, reference, token string, upperCost int64) (*BedrockDriver, BedrockBinding, error) {
	b := BedrockBinding{}
	match := bedrockHost.FindStringSubmatch(host)
	if len(match) != 2 || awsResidency(match[1]) == "" || bedrockInstructions[p] == "" || !EligibleModel(p, ModeBedrock, model) || !validPrivateCredential(reference, token, upperCost) {
		return nil, b, ErrInvalidConfiguration
	}
	path := "/model/" + url.PathEscape(model) + "/converse"
	endpoint := "https://" + host + path
	client, err := pinnedPrivateClient(PrivateEndpoint{URL: endpoint, IP: ip}, path)
	if err != nil {
		return nil, b, err
	}

	b = BedrockBinding{Provider: ModeBedrock, Model: model, Region: awsResidency(match[1]), CredentialReference: reference, CredentialDigest: digest(token), DeploymentDigest: digest(fmt.Sprintf("bedrock-converse-v1\n%s\n%s\n%s", endpoint, ip.String(), model)), Cost: upperCost}
	return &BedrockDriver{p, client, endpoint, token}, b, nil
}

func digest(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func validPrivateCredential(reference, token string, cost int64) bool {
	return strings.HasPrefix(reference, "secret_ref_planner/") && len(reference) <= 240 &&
		len(token) >= 16 && len(token) <= 8192 && strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) < 0 &&
		cost > 0 && cost <= 9_007_199_254_740_991
}

func awsResidency(region string) string {
	switch region {
	case "us-east-1", "us-east-2", "us-west-1", "us-west-2":
		return "us"
	case "eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2":
		return "eu"
	}
	return ""
}

// Tier: 3 | Purpose: security_agent_triage using qualified regional Haiku.
// Model: operator-pinned Bedrock model, VPCE TLS host, private IP and token.
// Authority: one pre-budgeted, authorized, redacted investigation. No tools.
// Fallback: a failed request or invalid structured result degrades coverage.
func (d *BedrockDriver) Evaluate(ctx context.Context, p Purpose, input json.RawMessage) (json.RawMessage, error) {
	rule, ok := LookupPurpose(p)
	if ctx == nil || d == nil || !ok || p != d.purpose || !json.Valid(input) || len(input) > rule.MaxInputBytes {
		return nil, ErrInvalidRequest
	}
	data, _ := json.Marshal(map[string]json.RawMessage{"untrusted_data": input})
	body, _ := json.Marshal(map[string]any{"system": []map[string]string{{"text": bedrockInstructions[p]}}, "messages": []any{map[string]any{"role": "user", "content": []map[string]string{{"text": string(data)}}}}, "inferenceConfig": map[string]any{"temperature": 0, "maxTokens": 512}})
	limited, cancel := context.WithTimeout(ctx, rule.MaxLatency)
	defer cancel()
	req, err := http.NewRequestWithContext(limited, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrGeneration
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, ErrGeneration
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrGeneration
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(data) > 32768 {
		return nil, ErrGeneration
	}
	var output struct {
		StopReason string
		Output     struct {
			Message struct {
				Role    string
				Content []struct{ Text string }
			}
		}
	}
	if json.Unmarshal(data, &output) != nil || output.StopReason != "end_turn" || output.Output.Message.Role != "assistant" || len(output.Output.Message.Content) != 1 {
		return nil, ErrGeneration
	}
	answer := json.RawMessage(output.Output.Message.Content[0].Text)
	if !ValidateSemanticOutput(p, answer) {
		return nil, ErrGeneration
	}
	return answer, nil
}
