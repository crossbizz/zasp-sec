package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/riskprojection"
)

func TestRiskProjectionAdapterBindsLeaseAndDurableReceipt(t *testing.T) {
	scope := projectionTestScope(t)
	integrationID, _ := domain.ParseProductID("pid_94100001-0000-4000-8000-000000000001")
	snapshotID, _ := domain.ParseProductID("pid_94100002-0000-4000-8000-000000000002")
	inputDigest := sha256.Sum256([]byte("candidate"))
	contentDigest := sha256.Sum256([]byte("risk-input"))
	store := &riskProjectionStoreStub{result: riskprojection.ApplyResult{
		SnapshotID: snapshotID, IntegrationID: integrationID, Source: "github", Generation: 3, InputDigest: inputDigest,
		ContentDigest: contentDigest, Receipt: "postgres:risk-input:" + snapshotID.String() + ":sha256:" + resultDigestHex(contentDigest),
	}}
	projector, err := newRiskProjectionProjector(store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := projector.Apply(context.Background(), projectionCandidate{
		Scope: scope, IntegrationID: integrationID.String(), SnapshotID: snapshotID.String(), Source: "github", Kind: "risk", Version: "v1", Generation: 3,
		Worker: "projection-risk-01", LeaseToken: "projection-risk-token-0001", InputDigest: inputDigest,
		Entities: []json.RawMessage{json.RawMessage(`{"id":"pid_94100003-0000-4000-8000-000000000003","kind":"repository","source_native_id":"repo-1","display_name":"Repository","stable_fields":{},"attributes":{}}`)}, Relationships: []json.RawMessage{}, Evidence: []json.RawMessage{},
	})
	if err != nil || result.Digest != contentDigest || result.Receipt != store.result.Receipt {
		t.Fatalf("Apply() = %#v, %v", result, err)
	}
	if store.input.Worker != "projection-risk-01" || store.input.LeaseToken != "projection-risk-token-0001" || store.input.IntegrationID != integrationID || store.input.SnapshotID != snapshotID {
		t.Fatalf("durable input = %#v", store.input)
	}
}

type riskProjectionStoreStub struct {
	input  riskprojection.CompleteInput
	result riskprojection.ApplyResult
	err    error
}

func (store *riskProjectionStoreStub) ApplyComplete(_ context.Context, input riskprojection.CompleteInput) (riskprojection.ApplyResult, error) {
	store.input = input
	return store.result, store.err
}
