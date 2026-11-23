package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type syncReviewClaim struct {
	Lease   string          `json:"lease"`
	Summary json.RawMessage `json:"summary"`
}

type syncReviewStore interface {
	claimSyncReview(context.Context, aigateway.Purpose, aigateway.BedrockBinding) (*syncReviewClaim, error)
	finishSyncReview(context.Context, string, json.RawMessage) error
}

func (s *temporalDiscoveryScheduleSource) claimSyncReview(ctx context.Context, p aigateway.Purpose, b aigateway.BedrockBinding) (job *syncReviewClaim, err error) {
	cfg, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	err = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		if err := c.QueryRow(ctx, "SELECT public.zasp_claim_discovery_sync_review($1,$2::jsonb)", string(p), cfg).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &job)
	})
	return
}
func (s *temporalDiscoveryScheduleSource) finishSyncReview(ctx context.Context, lease string, answer json.RawMessage) error {
	return s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var ok bool
		return c.QueryRow(ctx, "SELECT public.zasp_finish_discovery_sync_review($1::text::uuid,$2::jsonb)", lease, answer).Scan(&ok)
	})
}

// Tier: 3 | Purpose: verify one inferred repository and prepare a reviewable declaration.
// Model: purpose-qualified private Bedrock or Vertex deployment.
// Authority: the scheduler's database lease bounds scope, monthly cost and source facts.
// Fallback: missing or expired evidence leaves the deterministic record in place.
func reviewSyncedCandidate(ctx context.Context, store syncReviewStore, p aigateway.Purpose, model *aigateway.BoundModel) {
	if model == nil {
		return
	}
	job, err := store.claimSyncReview(ctx, p, model.Binding)
	if err != nil || job == nil || job.Lease == "" {
		return
	}
	var response json.RawMessage
	if len(job.Summary) > 0 && len(job.Summary) <= 8192 {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := model.Driver.Evaluate(bounded, p, job.Summary)
		cancel()
		if err == nil && aigateway.ValidateSemanticOutput(p, out) {
			response = out
		}
	}
	// The database checks the citations, current source evidence, consent and
	// qualification again, also after a failed inference.
	_ = store.finishSyncReview(ctx, job.Lease, response)
}

func startDiscoverySyncReviews(source *temporalDiscoveryScheduleSource) func() {
	verify := aigateway.ConfiguredPrivateModel(aigateway.PurposeDiscoveryVerify, "ZASP_BEDROCK_INVENTORY_")
	draft := aigateway.ConfiguredPrivateModel(aigateway.PurposeDraft, "ZASP_BEDROCK_INVENTORY_")
	if verify == nil && draft == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			reviewSyncedCandidate(ctx, source, aigateway.PurposeDiscoveryVerify, verify)
			reviewSyncedCandidate(ctx, source, aigateway.PurposeDraft, draft)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
