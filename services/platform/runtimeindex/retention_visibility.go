package runtimeindex

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// EventVisibility is bound by the caller to the original authenticated request
// or actual worker lease. Scope and event IDs alone never confer authority.
// False means a durable expiry tombstone; true means authoritative known-live.
// An unknown event must be omitted or return an error, never default to true.
// Implementations must recheck current permission and the full supplied scope.
type EventVisibility interface {
	VisibleEvents(context.Context, domain.Scope, []string) (map[string]bool, error)
}

// CheckEventVisibility checks one bounded search response after provider I/O.
// Each authority call receives at most 1000 unique IDs. Missing/extra keys and
// uncertain results are unavailable, so a failed check cannot fabricate empty
// history. No source digest is inferred from mutable index content.
func CheckEventVisibility(ctx context.Context, gate EventVisibility, scope domain.Scope, ids []string) (map[string]bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if nilInterface(gate) || scope.Validate() != nil || len(ids) > 4096 {
		return nil, ErrRejected
	}
	unique := make([]string, 0, len(ids))
	requested := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, err := domain.ParseProductID(id); err != nil {
			return nil, ErrDrift
		}
		if !requested[id] {
			unique = append(unique, id)
			requested[id] = true
		}
	}
	result := make(map[string]bool, len(unique))
	for start := 0; start < len(unique); start += 1000 {
		end := start + 1000
		if end > len(unique) {
			end = len(unique)
		}
		batch := append([]string(nil), unique[start:end]...)
		states, err := gate.VisibleEvents(ctx, scope, batch)
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		if err != nil || len(states) != len(batch) {
			return nil, ErrRetryable
		}
		for _, id := range unique[start:end] {
			state, ok := states[id]
			if !ok {
				return nil, ErrRetryable
			}
			result[id] = state
		}
	}
	return result, nil
}
