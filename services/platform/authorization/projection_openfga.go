package authorization

import (
	"context"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"strings"
	"time"
)

// OpenFGATupleWriter borrows the same pinned, authenticated SDK client as Check.
// Each organization must remain pending until every bounded write is acknowledged.
type OpenFGATupleWriter struct {
	client           *fga.OpenFgaClient
	storeID, modelID string
	timeout          time.Duration
}

func NewOpenFGATupleWriter(client *fga.OpenFgaClient, config runtimeservices.Config) (*OpenFGATupleWriter, error) {
	if client == nil || !config.Enabled || config.Validate() != nil {
		return nil, ErrInvalid
	}
	return &OpenFGATupleWriter{client, config.StoreID, config.ModelID, config.Timeout}, nil
}
func (w *OpenFGATupleWriter) Replace(ctx context.Context, r Revision, previous, desired []fga.ClientTupleKey) error {
	if w == nil || ctx == nil || r.validate() != nil || r.StoreID != w.storeID || r.ModelID != w.modelID {
		return ErrInvalid
	}
	// A corrupt ledger must not delete tuples belonging to another tenant.
	for _, batch := range [][]fga.ClientTupleKey{previous, desired} {
		for _, tuple := range batch {
			parts := strings.SplitN(tuple.Object, ":", 2)
			if len(parts) != 2 || (parts[1] != r.OrganizationID && !strings.HasPrefix(parts[1], r.OrganizationID+"/")) {
				return ErrInvalid
			}
		}
	}
	options := fga.ClientWriteOptions{StoreId: &w.storeID, AuthorizationModelId: &w.modelID, Conflict: fga.ClientWriteConflictOptions{OnDuplicateWrites: fga.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE, OnMissingDeletes: fga.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE}}
	write := func(body fga.ClientWriteRequest) error {
		call, cancel := context.WithTimeout(ctx, w.timeout)
		defer cancel()
		if _, err := w.client.Write(call).Options(options).Body(body).Execute(); err != nil {
			return ErrUnavailable
		}
		return nil
	}
	// Delete-before-write repairs removed grants and changed task conditions even
	// after a crash between batches. Stage persisted every candidate key first.
	keys := make([]fga.ClientTupleKeyWithoutCondition, 0, len(previous))
	seen := map[fga.ClientTupleKeyWithoutCondition]bool{}
	for _, v := range previous {
		key := fga.ClientTupleKeyWithoutCondition{User: v.User, Relation: v.Relation, Object: v.Object}
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	for start := 0; start < len(keys); start += 100 {
		if err := write(fga.ClientWriteRequest{Deletes: keys[start:min(start+100, len(keys))]}); err != nil {
			return err
		}
	}
	for start := 0; start < len(desired); start += 100 {
		if err := write(fga.ClientWriteRequest{Writes: desired[start:min(start+100, len(desired))]}); err != nil {
			return err
		}
	}
	return nil
}
