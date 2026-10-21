package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type retentionStageContextKey struct{}
type retentionSessionContextKey struct{}
type retentionAdmissionsKey struct{}
type retentionAdmissions struct {
	mu  sync.Mutex
	ids []string
}

func retentionAdmissionContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, retentionAdmissionsKey{}, &retentionAdmissions{})
}

type retentionSessionExecution struct {
	lease           runtimeSessionSearchLease
	workerID, token string
}
type retentionPartitionDatabase interface {
	recoveryJSONDatabase
	CommitRetainedJSON(context.Context, string, []byte, string) (json.RawMessage, error)
}

// This wrapper borrows the original owned worker pool. Only fixed write
// admission and immutable partition operations use this transaction boundary.
type retentionWorkerDatabase struct {
	apiserver.JSONDatabase
	pool *pgxpool.Pool
}

func (d *retentionWorkerDatabase) CommitRetainedJSON(ctx context.Context, q string, body []byte, pin string) (json.RawMessage, error) {
	if d == nil || d.pool == nil || ctx == nil || ctx.Err() != nil || len(body) > 1<<20 || !migrations.IsRetentionProfileChecksum(pin) {
		return nil, errRuntimeUnavailable
	}
	switch q {
	case `SELECT zasp_retention_v1.record_index_partition($1::jsonb)`, `SELECT zasp_retention_v1.record_session_index_partition($1::jsonb)`, `SELECT zasp_retention_v1.index_visibility($1::jsonb)`, `SELECT zasp_retention_v1.session_index_visibility($1::jsonb)`:
	default:
		return nil, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := d.pool.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var ready bool
	if tx.QueryRow(bounded, `SELECT zasp_authorization80_runtime.ready($1,$2) AND zasp_retention_v1.caller_ready('runtime-index',$3)`, migrations.AuthorizationRuntimeProfileChecksum(), "zasp_runtime_index_worker", pin).Scan(&ready) != nil || !ready {
		return nil, errRuntimeUnavailable
	}
	var raw []byte
	if tx.QueryRow(bounded, q, body).Scan(&raw) != nil {
		return nil, errRuntimeUnavailable
	}
	if q == `SELECT zasp_retention_v1.index_visibility($1::jsonb)` || q == `SELECT zasp_retention_v1.session_index_visibility($1::jsonb)` {
		var result struct {
			AdmissionID string `json:"admission_id"`
			Items       []struct {
				EventID string `json:"event_id"`
				Visible *bool  `json:"visible"`
			} `json:"items"`
		}
		var request struct {
			IDs []string `json:"event_ids"`
		}
		if len(raw) > 128<<10 || json.Unmarshal(body, &request) != nil || decodeStrictWorkerJSON(raw, &result) != nil || !retentionCycleKeyPattern.MatchString(result.AdmissionID) || len(result.Items) != len(request.IDs) || len(result.Items) < 1 || len(result.Items) > 1000 {
			return nil, errRuntimeUnavailable
		}
		for i, item := range result.Items {
			if item.EventID != request.IDs[i] || item.Visible == nil {
				return nil, errRuntimeUnavailable
			}
		}
	} else {
		var result struct {
			Digest string `json:"partition_digest"`
		}
		if decodeStrictWorkerJSON(raw, &result) != nil || !retentionCycleKeyPattern.MatchString(result.Digest) {
			return nil, errRuntimeUnavailable
		}
	}
	if tx.Commit(bounded) != nil {
		return nil, errRuntimeUnavailable
	}
	return append(json.RawMessage(nil), raw...), nil
}

type retentionIndexVisibility struct {
	database retentionPartitionDatabase
	pin      string
}

func newRetentionIndexVisibility(database recoveryJSONDatabase, pin string) (*retentionIndexVisibility, error) {
	db, ok := database.(retentionPartitionDatabase)
	if !ok || nilWorkerDependency(db) || !migrations.IsRetentionProfileChecksum(pin) {
		return nil, errRuntimeUnavailable
	}
	return &retentionIndexVisibility{database: db, pin: pin}, nil
}
func hexRetentionDigest(v [sha256.Size]byte) string { return hex.EncodeToString(v[:]) }
func (g *retentionIndexVisibility) request(ctx context.Context, scope domain.Scope, ids []string) (map[string]any, bool, error) {
	if g == nil || nilWorkerDependency(g.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || len(ids) < 1 || len(ids) > 1000 || ctx.Value(retentionAdmissionsKey{}) == nil {
		return nil, false, errRuntimeUnavailable
	}
	q := map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "class": "runtime_event", "event_ids": append([]string(nil), ids...)}
	if x, ok := ctx.Value(retentionStageContextKey{}).(runtimeStageExecution); ok {
		l := x.currentLease()
		if l.Scope != scope || !exactRuntimeStageLease(l, "index") || !workerIdentityPattern.MatchString(x.workerID) || !runtimeLeaseToken(x.leaseToken) {
			return nil, false, errRuntimeUnavailable
		}
		var predecessor any
		if l.PredecessorDigest != nil {
			predecessor = hexRetentionDigest(*l.PredecessorDigest)
		}
		q["batch_id"], q["generation"], q["stage"], q["attempt"], q["implementation_version"] = l.BatchID.String(), l.Generation, "index", l.Attempt, l.ImplementationVersion
		q["predecessor_digest"], q["input_digest"], q["input_reference"], q["input_version_id"] = predecessor, hexRetentionDigest(l.InputDigest), l.InputReference, l.InputVersionID
		q["lease_expires_at"], q["worker_id"], q["lease_token"] = l.LeaseExpiresAt.UTC().Format(time.RFC3339Nano), x.workerID, x.leaseToken
		return q, false, nil
	}
	if x, ok := ctx.Value(retentionSessionContextKey{}).(retentionSessionExecution); ok {
		l := x.lease
		if l.Binding.Scope != scope || !validRuntimeSessionSearchLease(l) || !l.currentDeadline().After(time.Now()) || !workerIdentityPattern.MatchString(x.workerID) || !runtimeLeaseToken(x.token) {
			return nil, false, errRuntimeUnavailable
		}
		q["batch_id"], q["generation"], q["receipt_digest"], q["receipt_reference"], q["receipt_version"] = l.Binding.BatchID.String(), l.Binding.Generation, hexRetentionDigest(l.Binding.ReceiptDigest), l.ReceiptReference, l.ReceiptVersion
		q["document_ids"], q["attempt"], q["lease_until"] = append([]string(nil), l.DocumentIDs...), l.Attempt, l.currentDeadline().UTC().Format(time.RFC3339Nano)
		q["worker_id"], q["lease_token"], q["projection_implementation_version"] = x.workerID, x.token, l.projectionImplementationVersion
		family := "session-v1"
		if l.indexName == "zasp-runtime-sessions-v2" {
			family = "sandbox-v2"
		}
		q["index_family"] = family
		return q, true, nil
	}
	return nil, false, errRuntimeUnavailable
}
func (g *retentionIndexVisibility) VisibleEvents(ctx context.Context, scope domain.Scope, ids []string) (map[string]bool, error) {
	q, session, err := g.request(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	sql := `SELECT zasp_retention_v1.index_visibility($1::jsonb)`
	if session {
		sql = `SELECT zasp_retention_v1.session_index_visibility($1::jsonb)`
	}
	body, _ := json.Marshal(q)
	raw, err := g.database.CommitRetainedJSON(ctx, sql, body, g.pin)
	var response struct {
		AdmissionID string `json:"admission_id"`
		Items       []struct {
			EventID string `json:"event_id"`
			Visible *bool  `json:"visible"`
		} `json:"items"`
	}
	if err != nil || len(raw) > 128<<10 || decodeStrictWorkerJSON(raw, &response) != nil || len(response.Items) != len(ids) || !retentionCycleKeyPattern.MatchString(response.AdmissionID) {
		return nil, errRuntimeUnavailable
	}
	out := make(map[string]bool, len(ids))
	for i, item := range response.Items {
		if item.EventID != ids[i] || item.Visible == nil {
			return nil, errRuntimeUnavailable
		}
		out[item.EventID] = *item.Visible
	}
	collector, ok := ctx.Value(retentionAdmissionsKey{}).(*retentionAdmissions)
	if !ok || collector == nil {
		return nil, errRuntimeUnavailable
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(collector.ids) >= 1000 {
		return nil, errRuntimeUnavailable
	}
	for _, id := range collector.ids {
		if id == response.AdmissionID {
			return nil, errRuntimeUnavailable
		}
	}
	collector.ids = append(collector.ids, response.AdmissionID)
	return out, nil
}
func (g *retentionIndexVisibility) RecordRetainedWrite(ctx context.Context, r runtimeindex.RetainedWriteReceipt) error {
	q, session, err := g.request(ctx, r.Scope, r.EventIDs)
	if err != nil {
		return err
	}
	if q["batch_id"] != r.BatchID || q["generation"] != r.Generation || r.OriginalContentDigest == ([sha256.Size]byte{}) || r.Partition.ProviderContentDigest == ([sha256.Size]byte{}) {
		return errRuntimeUnavailable
	}
	digestKey := "input_digest"
	if session {
		digestKey = "receipt_digest"
	}
	if q[digestKey] != hexRetentionDigest(r.InputDigest) {
		return errRuntimeUnavailable
	}
	collector, ok := ctx.Value(retentionAdmissionsKey{}).(*retentionAdmissions)
	if !ok || collector == nil {
		return errRuntimeUnavailable
	}
	collector.mu.Lock()
	admissions := append([]string(nil), collector.ids...)
	collector.mu.Unlock()
	if len(admissions) < 1 || len(admissions) > 1000 {
		return errRuntimeUnavailable
	}
	q["admission_ids"] = admissions
	q["full_document_ids"], q["written_document_ids"], q["suppressed_document_ids"] = r.DocumentIDs, r.Partition.WrittenDocumentIDs, r.Partition.SuppressedDocumentIDs
	q["original_content_digest"], q["provider_content_digest"] = hexRetentionDigest(r.OriginalContentDigest), hexRetentionDigest(r.Partition.ProviderContentDigest)
	sql := `SELECT zasp_retention_v1.record_index_partition($1::jsonb)`
	if session {
		sql = `SELECT zasp_retention_v1.record_session_index_partition($1::jsonb)`
	}
	body, _ := json.Marshal(q)
	_, err = g.database.CommitRetainedJSON(ctx, sql, body, g.pin)
	return err
}

func (retentionSessionExecution) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "retention-session-execution[redacted]")
}

// Cleanup borrows the same original index pool. Its separately reviewed drainer
// owns transaction joins and uses only its closed cleanup claim protocol.
func (d *retentionWorkerDatabase) BeginRetentionCleanup(ctx context.Context) (pgx.Tx, error) {
	if d == nil || d.pool == nil || ctx == nil || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	return d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}
