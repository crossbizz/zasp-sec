package neo4jstore

import "context"

// The published graph writer has WRITE on the graph. Creating label, type,
// and property tokens is the responsibility of the one-shot schema identity.
func (adapter *Adapter) EnsureActionEvidenceTokens(ctx context.Context) error {
	if adapter == nil || nilInterface(adapter.provider) || adapter.database != databaseName || ctx == nil || ctx.Err() != nil {
		return ErrSchema
	}
	queries := []struct {
		query string
		names []string
	}{
		{"UNWIND $names AS name CALL db.createLabel(name) RETURN count(*) AS matched", []string{"ZaspActionEvidence"}},
		{"UNWIND $names AS name CALL db.createRelationshipType(name) RETURN count(*) AS matched", []string{"ZASP_HAS_ACTION_EVIDENCE"}},
		{"UNWIND $names AS name CALL db.createProperty(name) RETURN count(*) AS matched", []string{"kind", "schema_version", "evidence_id", "source", "event_type", "observed_at", "verdict"}},
	}
	return executeTransaction(ctx, adapter.provider, sessionConfig{Database: adapter.database, Access: accessWrite}, ErrSchema, func(tx graphTransaction) error {
		for _, q := range queries {
			if !runMatched(ctx, tx, q.query, map[string]any{"names": q.names}, int64(len(q.names))) {
				return ErrSchema
			}
		}
		return nil
	})
}
