package graphstore

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// ActionEvidence describes an admitted receipt. Verdict is the hook's or
// workload's report. It never describes a target-side effect.
type ActionEvidence struct {
	EvidenceID                 domain.ProductID
	Source, EventType, Verdict string
	ObservedAt                 time.Time
}

func (fact ActionEvidence) Valid() bool {
	if fact.EvidenceID.IsZero() || fact.ObservedAt.IsZero() || fact.ObservedAt.Year() < 1 || fact.ObservedAt.Year() > 9999 {
		return false
	}
	switch fact.Source {
	case "signed_endpoint":
		return fact.EventType == "hook_decision" && (fact.Verdict == "deny" || fact.Verdict == "continue" || fact.Verdict == "unavailable")
	case "authenticated_workload":
		switch fact.EventType {
		case "action_decision":
			return fact.Verdict == "allow" || fact.Verdict == "block"
		case "action_outcome":
			return fact.Verdict == "not_dispatched" || fact.Verdict == "returned" || fact.Verdict == "raised" || fact.Verdict == "cancelled"
		}
	}
	return false
}

type actionEvidenceDriver interface {
	UpsertActionEvidence(context.Context, DriverProjection, ActionEvidence) (DriverUpserted, error)
}

// UpsertActionEvidence writes the topology and its proof in one transaction.
// Replaying an immutable evidence ID must verify the original observations.
func (store *Store) UpsertActionEvidence(ctx context.Context, scope domain.Scope, projection Projection, fact ActionEvidence) error {
	if !store.usable() || ctx == nil || !fact.Valid() {
		return ErrProjection
	}
	driver, ok := store.driver.(actionEvidenceDriver)
	if !ok {
		return ErrUpsert
	}
	input, nodes, edges, ok := buildDriverProjection(scope, projection, store.config)
	if !ok {
		return ErrProjection
	}
	bounded, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	ack, err := driver.UpsertActionEvidence(bounded, input, fact)
	if err != nil || bounded.Err() != nil || !exactStrings(ack.NodeIDs, nodes) || !exactStrings(ack.EdgeIDs, edges) {
		return ErrUpsert
	}
	return nil
}
