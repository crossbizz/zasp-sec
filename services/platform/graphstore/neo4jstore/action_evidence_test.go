package neo4jstore

import (
	"context"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

func TestActionEvidenceMetadataIsPartOfGraphTransaction(t *testing.T) {
	id, err := domain.ParseProductID(nodeAID)
	if err != nil {
		t.Fatal(err)
	}
	fact := graphstore.ActionEvidence{EvidenceID: id, Source: "signed_endpoint", EventType: "hook_decision", Verdict: "deny", ObservedAt: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
	p := validDriverProjection()
	p.Nodes[0].Kind = fact.EventType
	for _, matched := range []int64{0, 1} {
		session := validUpsertSession()
		original := session.tx.results[2]
		node := original.records[0].Values[0].([]any)[0].(map[string]any)
		node["kind"] = fact.EventType
		proof := &fakeResult{keys: []string{"matched"}, records: []graphRecord{{Keys: []string{"matched"}, Values: []any{matched}}}}
		session.tx.results = append(session.tx.results[:2], proof, original)
		adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
		_, err := adapter.UpsertActionEvidence(context.Background(), p, fact)
		if matched == 0 && (err == nil || session.tx.rollbackCalls != 1 || session.tx.commitCalls != 0) {
			t.Fatal("metadata mismatch committed topology")
		}
		if matched == 1 && (err != nil || session.tx.commitCalls != 1) {
			t.Fatal("matching evidence rejected", err)
		}
	}
}
