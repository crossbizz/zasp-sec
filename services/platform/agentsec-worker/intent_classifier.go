package main

import (
	"context"
	"encoding/json"

	"os"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

// Only bounded flags are sent. Tenant identifiers, prompts, arguments, and
// user-controlled operation names are absent from this wire type.
type intentFeatures struct {
	Destination            string `json:"destination"`
	HasPrevious            bool   `json:"has_previous"`
	OperationMismatch      bool   `json:"operation_mismatch"`
	ClassificationMismatch bool   `json:"classification_mismatch"`
	DestinationMismatch    bool   `json:"destination_mismatch"`
	SequenceMismatch       bool   `json:"sequence_mismatch"`
}
type intentClaim struct {
	Lease    string         `json:"lease"`
	Features intentFeatures `json:"features"`
}

var intentCodes = []string{"none", "review_purpose", "review_destination", "review_sequence", "review_data_access"}

type privateIntentClassifier struct {
	driver           aigateway.ProviderDriver
	model, residency string
	maximumCost      int64
	deployment       string
}

// Tier: 2 | Purpose: purpose alignment on a bound workload.
// Model: pinned private vLLM, deployed in US/EU.
// Authority: the scheduler leases only qualified jobs under both policy scopes.
// Fallback: the deterministic analysis and findings stay available.
func configuredIntentClassifier() *privateIntentClassifier {
	if os.Getenv("ZASP_INTENT_CLASSIFIER_ENABLED") != "true" {
		return nil
	}
	model := os.Getenv("ZASP_INTENT_CLASSIFIER_MODEL")
	residency := os.Getenv("ZASP_INTENT_CLASSIFIER_RESIDENCY")
	cost, err := strconv.ParseInt(os.Getenv("ZASP_INTENT_CLASSIFIER_MAX_NANO_CREDITS"), 10, 64)
	if err != nil || cost < 1 || cost > 1000000000000 || !slices.Contains([]string{"us", "eu"}, residency) {
		return nil
	}
	deployment := aigateway.Deployment{
		Provider: os.Getenv("ZASP_INTENT_CLASSIFIER_PROVIDER"), OrganizationID: os.Getenv("ZASP_INTENT_CLASSIFIER_ORGANIZATION_ID"),
		WorkspaceID: os.Getenv("ZASP_INTENT_CLASSIFIER_WORKSPACE_ID"), EnvironmentID: os.Getenv("ZASP_INTENT_CLASSIFIER_ENVIRONMENT_ID"),
		Endpoint: os.Getenv("ZASP_INTENT_CLASSIFIER_ENDPOINT"), PrivateIP: os.Getenv("ZASP_INTENT_CLASSIFIER_PRIVATE_IP"),
		WeightsSHA256: os.Getenv("ZASP_INTENT_CLASSIFIER_WEIGHTS_SHA256"), Model: model, Region: residency, MaximumNanoCredits: cost,
	}
	driver, err := deployment.Driver()
	if err != nil {
		return nil
	}
	return &privateIntentClassifier{driver: driver, model: model, residency: residency, maximumCost: cost, deployment: deployment.Digest()}
}

func (c *privateIntentClassifier) Classify(ctx context.Context, features intentFeatures) (string, error) {
	if !slices.Contains([]string{"internal", "approved_partner", "external", "public", "unknown"}, features.Destination) {
		return "", errWorkerExecution
	}
	input, _ := json.Marshal(features)
	raw, err := c.driver.Evaluate(ctx, aigateway.PurposeAlignment, input)
	if err != nil || !aigateway.ValidateSemanticOutput(aigateway.PurposeAlignment, raw) {
		return "", errWorkerExecution
	}
	var result struct {
		Verdict string `json:"verdict"`
		Clause  string `json:"violated_clause"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return "", errWorkerExecution
	}
	if result.Verdict == "aligned" && result.Clause == "none" {
		return "none", nil
	}
	code := "review_" + result.Clause
	if result.Verdict == "drift" && slices.Contains(intentCodes, code) {
		return code, nil
	}
	return "", errWorkerExecution
}

func (s *temporalDiscoveryScheduleSource) claimIntent(ctx context.Context, cfg *privateIntentClassifier) (job *intentClaim, err error) {
	err = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		if err := c.QueryRow(ctx, `SELECT public.zasp_claim_qualified_intent($1,$2,$3,$4)`, cfg.model, cfg.residency, cfg.maximumCost, cfg.deployment).Scan(&raw); err != nil {
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
	job, err := p.source.claimIntent(ctx, p.classifier)
	if err != nil || job == nil {
		return
	}
	code, err := p.classifier.Classify(ctx, job.Features)
	var recommendation *string
	if err == nil && slices.Contains(intentCodes, code) {
		recommendation = &code
	}
	_ = p.source.finishIntent(ctx, job.Lease, recommendation)
}
