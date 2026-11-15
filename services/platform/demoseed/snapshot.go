package demoseed

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// applySnapshot applies one typed snapshot and returns its entity count and
// its failed checks. A passed check is evidence, not a finding.
func applySnapshot(ctx context.Context, tx pgx.Tx, scope domain.Scope, id domain.ProductID, principal string, observed time.Time, snapshot demodata.Snapshot) (entities int, failed []finding, err error) {
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	syncID, err := newID()
	if err != nil {
		return 0, nil, err
	}
	snapshotID, err := newID()
	if err != nil {
		return 0, nil, err
	}
	digest := sha256.Sum256([]byte("zasp-demo-sync\x1f" + syncID))
	if _, err := tx.Exec(ctx, insertSyncSQL, o, w, e, syncID, id.String(), "demo-seed-"+syncID[4:], digest[:], principal, demodata.ParserVersion, demodata.ToolVersion); err != nil {
		return 0, nil, fmt.Errorf("record the collection: %w", err)
	}
	var generation int64
	if err := tx.QueryRow(ctx, nextGenerationSQL, o, w, e, id.String()).Scan(&generation); err != nil {
		return 0, nil, err
	}
	var result []byte
	if err := tx.QueryRow(ctx, applySnapshotSQL, o, w, e, id.String(), syncID, snapshotID, generation, snapshot.Provider, snapshot.ManifestReference, snapshot.ManifestChecksum[:],
		observed, snapshot.Provider, snapshot.CursorValue, string(snapshot.Entities), string(snapshot.Relationships), string(snapshot.Evidence)).Scan(&result); err != nil {
		return 0, nil, fmt.Errorf("apply the snapshot: %w", err)
	}
	// Applying a snapshot queues the three projections of it for the
	// projection workers, who read the snapshot's stored input. A demo
	// snapshot has none (it did not come from a leased job), so a worker
	// that claimed the work would fail and retry. The seeder does the risk
	// projection itself (projectFindings) and withdraws the work; the graph
	// and search projections are not made, and the demo is not in them.
	if _, err := tx.Exec(ctx, cancelProjectionSQL, o, w, e, snapshotID); err != nil {
		return 0, nil, fmt.Errorf("withdraw the projection work: %w", err)
	}
	var evidence []struct {
		ID        string `json:"id"`
		EntityID  string `json:"entity_id"`
		FindingID string `json:"finding_id"`
		CheckID   string `json:"check_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(snapshot.Evidence, &evidence); err != nil {
		return 0, nil, err
	}
	for _, item := range evidence {
		if item.FindingID != "" && item.Status == "FAIL" {
			failed = append(failed, finding{FindingID: item.FindingID, EntityID: item.EntityID, CheckID: item.CheckID, EvidenceID: item.ID, Source: snapshot.Provider})
		}
	}
	var listed []json.RawMessage
	if err := json.Unmarshal(snapshot.Entities, &listed); err != nil {
		return 0, nil, err
	}
	return len(listed), failed, nil
}

// projectFindings gives the Environment its discovery findings (the failed
// checks of every integration's newest snapshot, which is the set the risk
// projection keeps) and refreshes the posture findings and the attack paths
// that are computed from the inventory.
func projectFindings(ctx context.Context, tx pgx.Tx, scope domain.Scope, failed []finding) error {
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	if failed == nil {
		failed = []finding{}
	}
	encoded, err := json.Marshal(failed)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, applyFindingsSQL, o, w, e, string(encoded)); err != nil {
		return fmt.Errorf("apply the discovery findings: %w", err)
	}
	if _, err := tx.Exec(ctx, refreshPostureSQL, o, w, e); err != nil {
		return fmt.Errorf("refresh the posture findings: %w", err)
	}
	return nil
}
