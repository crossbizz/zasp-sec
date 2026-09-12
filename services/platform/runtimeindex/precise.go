package runtimeindex

import "context"

// ApplyPrecise indexes a validated V2 runtime archive without promoting lineage
// into semantic agent or session identity.
func (store *Store) ApplyPrecise(ctx context.Context, input Batch) (ApplyResult, error) {
	return store.applyProfile(ctx, input, true)
}
