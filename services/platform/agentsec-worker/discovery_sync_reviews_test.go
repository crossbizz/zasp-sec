package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
	"testing"
)

type syncReviewFixture struct {
	job                     *syncReviewClaim
	output                  json.RawMessage
	calls, claims, finishes int
	result                  json.RawMessage
}

func (x *syncReviewFixture) claimSyncReview(context.Context, aigateway.Purpose, aigateway.BedrockBinding) (*syncReviewClaim, error) {
	x.claims++
	return x.job, nil
}
func (x *syncReviewFixture) finishSyncReview(_ context.Context, _ string, r json.RawMessage) error {
	x.finishes++
	x.result = r
	return nil
}
func (x *syncReviewFixture) Evaluate(context.Context, aigateway.Purpose, json.RawMessage) (json.RawMessage, error) {
	x.calls++
	return x.output, nil
}
func TestSyncReviewDispatchRequiresLeaseAndValidatesModelSchema(t *testing.T) {
	x := &syncReviewFixture{}
	ctx := context.Background()
	p := aigateway.PurposeDiscoveryVerify
	reviewSyncedCandidate(ctx, x, p, nil)
	if x.claims != 0 {
		t.Fatal("unconfigured worker leased data")
	}
	model := &aigateway.BoundModel{Driver: x}
	reviewSyncedCandidate(ctx, x, p, model)
	if x.calls != 0 || x.finishes != 0 {
		t.Fatal("unleased data dispatched")
	}
	x.job = &syncReviewClaim{"lease", json.RawMessage(`{"evidence_refs":["record"]}`)}
	x.output = json.RawMessage(`{"kind":"autonomous_agent","evidence_refs":["record"]}`)
	reviewSyncedCandidate(ctx, x, p, model)
	if x.calls != 1 || x.finishes != 1 || string(x.result) != string(x.output) {
		t.Fatal("missing validated settlement")
	}
	x.output = json.RawMessage(`{"kind":"unsupported","evidence_refs":[]}`)
	reviewSyncedCandidate(ctx, x, p, model)
	if x.finishes != 2 || x.result != nil {
		t.Fatal("invalid result accepted")
	}
}
