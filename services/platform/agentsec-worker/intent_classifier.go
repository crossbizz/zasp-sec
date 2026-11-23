package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// The provider interface cannot accept tenant identifiers, user-controlled
// labels, model input/output, or action arguments.
type intentFeatures struct {
	Destination            string `json:"destination"`
	HasPrevious            bool   `json:"has_previous"`
	OperationMismatch      bool   `json:"operation_mismatch"`
	ClassificationMismatch bool   `json:"classification_mismatch"`
	DestinationMismatch    bool   `json:"destination_mismatch"`
	SequenceMismatch       bool   `json:"sequence_mismatch"`
}
type IntentClassifier interface {
	Classify(context.Context, intentFeatures) (string, error)
}
type intentClaim struct {
	Lease    string         `json:"lease"`
	Features intentFeatures `json:"features"`
}

var intentCodes = []string{"none", "review_purpose", "review_destination", "review_sequence", "review_data_access"}

const intentModel = "openai/gpt-5-mini"
const intentEndpoint = "https://openrouter.ai/api/v1/chat/completions"

type openRouterIntentClassifier struct {
	tokenPath string
	client    *http.Client
}

// The deployment switch and independently managed per-agent consent must
// both be enabled. A missing optional provider never blocks worker startup.
func configuredIntentClassifier() IntentClassifier {
	path := os.Getenv("ZASP_INTENT_CLASSIFIER_KEY_FILE")
	if os.Getenv("ZASP_INTENT_CLASSIFIER_ENABLED") != "true" || path == "" {
		return nil
	}
	return &openRouterIntentClassifier{tokenPath: path, client: &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 2 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 1},
		Timeout:   4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *openRouterIntentClassifier) Classify(ctx context.Context, features intentFeatures) (string, error) {
	if !slices.Contains([]string{"internal", "approved_partner", "external", "public", "unknown"}, features.Destination) {
		return "", errWorkerExecution
	}
	token, ok := readPinnedFile(c.tokenPath, 24, 512, 0400)
	if !ok {
		return "", errWorkerExecution
	}
	defer clear(token)
	if !validSecurityAgentPlannerCredential(token) {
		return "", errWorkerExecution
	}
	payload, _ := json.Marshal(features)
	req := securityAgentOpenRouterRequest{
		Model: intentModel, MaximumTokens: 128,
		Provider: securityAgentOpenRouterProvider{DataCollection: "deny", RequireParameters: true},
		Messages: []securityAgentOpenRouterMessage{
			{Role: "system", Content: "Choose one advisory review for these declared-purpose comparison flags. Return none if no review is warranted. The response is a draft for a human."},
			{Role: "user", Content: string(payload)},
		},
		ResponseFormat: securityAgentOpenRouterResponseFormat{Type: "json_schema", JSONSchema: securityAgentOpenRouterJSONSchema{Name: "intent_draft", Strict: true, Schema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"recommendation"}, "properties": map[string]any{"recommendation": map[string]any{"type": "string", "enum": intentCodes}}}}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", errWorkerExecution
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, intentEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", errWorkerExecution
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	r.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(r)
	if err != nil {
		return "", errWorkerExecution
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errWorkerExecution
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(raw) > 8192 {
		return "", errWorkerExecution
	}
	content, ok := validSecurityAgentOpenRouterResponse(raw, intentModel)
	var compact bytes.Buffer
	if !ok || len(content) > 128 || json.Compact(&compact, []byte(content)) != nil {
		return "", errWorkerExecution
	}
	for _, code := range intentCodes {
		if compact.String() == `{"recommendation":"`+code+`"}` {
			return code, nil
		}
	}
	return "", errWorkerExecution
}

func (s *temporalDiscoveryScheduleSource) claimIntent(ctx context.Context) (job *intentClaim, err error) {
	err = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		if err := c.QueryRow(ctx, `SELECT public.zasp_claim_intent_draft()`).Scan(&raw); err != nil {
			return errWorkerExecution
		}
		if json.Unmarshal(raw, &job) != nil {
			return errWorkerExecution
		}
		return nil
	})
	return
}
func (s *temporalDiscoveryScheduleSource) finishIntent(ctx context.Context, lease string, result *string) error {
	return s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var saved bool
		return c.QueryRow(ctx, `SELECT public.zasp_finish_intent_draft($1::text::uuid,$2)`, lease, result).Scan(&saved)
	})
}

func (p *temporalDiscoveryScheduleProcessor) classifyDue(ctx context.Context) {
	if p.classifier == nil {
		return
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	at := now()
	if !p.lastIntent.IsZero() && at.Sub(p.lastIntent) < time.Minute {
		return
	}
	p.lastIntent = at
	job, err := p.source.claimIntent(ctx)
	if err != nil || job == nil {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	code, err := p.classifier.Classify(bounded, job.Features)
	var recommendation *string
	if err == nil && slices.Contains(intentCodes, code) {
		recommendation = &code
	}
	// A failed attempt leaves the local deterministic findings intact.
	// The database lease supplies bounded retries after an outage or crash.
	_ = p.source.finishIntent(ctx, job.Lease, recommendation)
}
