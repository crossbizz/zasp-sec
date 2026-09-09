package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type runtimeSessionSearchAuthority interface {
	Ready(context.Context) error
	Claim(context.Context, string, string, int) (*runtimeSessionSearchLease, error)
	Heartbeat(context.Context, runtimeSessionSearchLease, string, string, int) (time.Time, error)
	Finish(context.Context, runtimeSessionSearchLease, string, string, string, []string, int) error
}

type postgresRuntimeSessionSearchAuthority struct{ database recoveryJSONDatabase }

func newPostgresRuntimeSessionSearchAuthority(database recoveryJSONDatabase) (*postgresRuntimeSessionSearchAuthority, error) {
	if nilWorkerDependency(database) {
		return nil, errRuntimeUnavailable
	}
	return &postgresRuntimeSessionSearchAuthority{database: database}, nil
}
func (authority *postgresRuntimeSessionSearchAuthority) query(ctx context.Context, sql string, args ...any) (body json.RawMessage, resultErr error) {
	defer func() {
		if recover() != nil {
			body = nil
			resultErr = errWorkerExecution
		}
	}()
	if authority == nil || nilWorkerDependency(authority.database) || ctx == nil || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	body, err := authority.database.QueryJSON(ctx, sql, args...)
	if err != nil || ctx.Err() != nil || len(body) > 128<<10 || !utf8.Valid(body) {
		return nil, errWorkerExecution
	}
	return body, nil
}
func (authority *postgresRuntimeSessionSearchAuthority) Ready(ctx context.Context) error {
	metadata := migrations.ProductionRuntimeSessionSearch()
	body, err := authority.query(ctx, `SELECT to_jsonb(zasp_production_runtime_session_search_readiness($1,$2) AND zasp_runtime_session_search_worker_ready())`, metadata.Checksum(), migrations.ProductionRuntimeSessionSearchSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictWorkerJSON(body, &ready) != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}
func validSessionSearchWorkerCall(worker, token string, seconds int) bool {
	return workerIdentityPattern.MatchString(worker) && runtimeLeaseToken(token) && seconds >= 5 && seconds <= 900
}

func (authority *postgresRuntimeSessionSearchAuthority) Claim(ctx context.Context, worker, token string, seconds int) (*runtimeSessionSearchLease, error) {
	if !validSessionSearchWorkerCall(worker, token, seconds) {
		return nil, errWorkerExecution
	}
	body, err := authority.query(ctx, `SELECT COALESCE(zasp_runtime_session_search_claim($1,$2,$3),'null'::jsonb)`, worker, token, seconds)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil, nil
	}
	var wire struct {
		Organization string    `json:"organization_id"`
		Workspace    string    `json:"workspace_id"`
		Environment  string    `json:"environment_id"`
		Batch        string    `json:"batch_id"`
		Generation   int64     `json:"generation"`
		Digest       string    `json:"receipt_digest"`
		Reference    string    `json:"receipt_reference"`
		Version      string    `json:"receipt_version"`
		IDs          []string  `json:"document_ids"`
		Attempt      int       `json:"attempt"`
		Until        time.Time `json:"lease_until"`
	}
	if decodeStrictWorkerJSON(body, &wire) != nil {
		return nil, errWorkerExecution
	}
	org, orgErr := domain.ParseProductID(wire.Organization)
	workspace, workspaceErr := domain.ParseProductID(wire.Workspace)
	environment, environmentErr := domain.ParseProductID(wire.Environment)
	batch, batchErr := domain.ParseProductID(wire.Batch)
	scope, scopeErr := domain.NewScope(org, workspace, environment)
	digest, digestErr := hex.DecodeString(wire.Digest)
	if orgErr != nil || workspaceErr != nil || environmentErr != nil || batchErr != nil || scopeErr != nil || digestErr != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != wire.Digest {
		return nil, errWorkerExecution
	}
	lease := runtimeSessionSearchLease{Binding: sessionsearch.ReceiptBinding{Scope: scope, BatchID: batch, Generation: wire.Generation}, ReceiptReference: wire.Reference, ReceiptVersion: wire.Version, DocumentIDs: wire.IDs, Attempt: wire.Attempt, LeaseUntil: wire.Until.UTC()}
	copy(lease.Binding.ReceiptDigest[:], digest)
	if !validRuntimeSessionSearchLease(lease) || !validSessionSearchDeadline(lease.LeaseUntil, seconds) {
		return nil, errWorkerExecution
	}
	return &lease, nil
}
func validSessionSearchDeadline(deadline time.Time, seconds int) bool {
	now := time.Now()
	return deadline.After(now) && !deadline.After(now.Add(time.Duration(seconds)*time.Second+2*time.Second))
}
func sessionSearchLeaseArguments(lease runtimeSessionSearchLease, worker, token string) []any {
	return []any{lease.Binding.Scope.OrganizationID().String(), lease.Binding.Scope.WorkspaceID().String(), lease.Binding.Scope.EnvironmentID().String(), lease.Binding.BatchID.String(), lease.Binding.Generation, worker, token, lease.Attempt}
}
func (authority *postgresRuntimeSessionSearchAuthority) Heartbeat(ctx context.Context, lease runtimeSessionSearchLease, worker, token string, seconds int) (time.Time, error) {
	if !validRuntimeSessionSearchLease(lease) || !validSessionSearchWorkerCall(worker, token, seconds) {
		return time.Time{}, errWorkerExecution
	}
	body, err := authority.query(ctx, `SELECT zasp_runtime_session_search_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)`, append(sessionSearchLeaseArguments(lease, worker, token), seconds)...)
	var result struct {
		Until time.Time `json:"lease_until"`
	}
	if err != nil || decodeStrictWorkerJSON(body, &result) != nil || !validSessionSearchDeadline(result.Until, seconds) {
		return time.Time{}, errWorkerExecution
	}
	return result.Until.UTC(), nil
}
func (authority *postgresRuntimeSessionSearchAuthority) Finish(ctx context.Context, lease runtimeSessionSearchLease, worker, token, outcome string, ids []string, retrySeconds int) error {
	if !validRuntimeSessionSearchLease(lease) || !validSessionSearchWorkerCall(worker, token, 5) || ids == nil {
		return errWorkerExecution
	}
	state := outcome
	switch outcome {
	case "indexed":
		if retrySeconds != 0 || !slices.Equal(ids, lease.DocumentIDs) {
			return errWorkerExecution
		}
	case "retryable":
		if len(ids) != 0 || retrySeconds < 1 || retrySeconds > 3600 {
			return errWorkerExecution
		}
		state = "pending"
	case "quarantined":
		if len(ids) != 0 || retrySeconds != 0 {
			return errWorkerExecution
		}
	default:
		return errWorkerExecution
	}
	args := append(sessionSearchLeaseArguments(lease, worker, token), lease.Binding.ReceiptDigest[:], outcome, ids, retrySeconds)
	body, err := authority.query(ctx, `SELECT zasp_runtime_session_search_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, args...)
	var result struct {
		State      string     `json:"state"`
		Batch      string     `json:"batch_id"`
		Generation int64      `json:"generation"`
		Attempt    int        `json:"attempt"`
		Digest     string     `json:"receipt_digest"`
		At         *time.Time `json:"indexed_at"`
	}
	if err != nil || decodeStrictWorkerJSON(body, &result) != nil || result.State != state || result.Batch != lease.Binding.BatchID.String() || result.Generation != lease.Binding.Generation || result.Attempt != lease.Attempt || result.Digest != hex.EncodeToString(lease.Binding.ReceiptDigest[:]) || (outcome == "indexed") != (result.At != nil) {
		return errWorkerExecution
	}
	if result.At != nil && (result.At.IsZero() || result.At.After(time.Now().Add(2*time.Second))) {
		return errWorkerExecution
	}
	return nil
}

var _ runtimeSessionSearchAuthority = (*postgresRuntimeSessionSearchAuthority)(nil)
