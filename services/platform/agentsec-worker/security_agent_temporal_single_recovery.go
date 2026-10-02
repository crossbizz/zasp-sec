package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"time"
)

const singleRecoveryLoadSQL = `SELECT zasp_temporal_single_recovery.load($1::jsonb)`
const singleRecoveryObserveSQL = `SELECT to_jsonb(zasp_temporal_single_recovery.observe($1::jsonb,$2))`
const singleRecoveryFinishSQL = `SELECT zasp_temporal_single_recovery.finish($1::jsonb)`

func singleRecoveryRuntimeAvailable(ctx context.Context, db apiserver.JSONDatabase) (bool, error) {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(db) {
		return false, errRuntimeUnavailable
	}
	metadata := migrations.ProductionTemporalSingleRecoveryMetadata()
	if ctx.Err() != nil {
		return false, errRuntimeUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := db.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal_single_recovery') IS NOT NULL)`)
	if err != nil {
		return false, errRuntimeUnavailable
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return false, nil
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	raw, err = db.QueryJSON(ctx, "SELECT to_jsonb(("+strings.TrimPrefix(migrations.TemporalSingleRecoveryReadySourceSQL, "SELECT ")+"))", metadata.ReadyBodyDigest)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	raw, err = db.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal_single_recovery.ready($1))`, metadata.Checksum)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	return true, nil
}

type singleTestRecoveryProduct struct {
	database apiserver.JSONDatabase
	cleanup  interface {
		Cleanup(context.Context, orchestration.CleanupRequest) error
	}
}

func (p *temporalSecurityAgentProduct) SingleTestRecoveryProduct() (orchestration.SingleTestRecoveryProduct, error) {
	if p == nil || p.workerForward == nil || p.workerCompensation == nil || nilWorkerDependency(p.compensation) {
		return nil, orchestration.ErrInvalid
	}
	// Construction is composed only after profile readiness. This retains the
	// actual captured product and cannot fall back to its legacy SQL branch.
	return &singleTestRecoveryProduct{database: p.compensation, cleanup: p.SingleTestProduct()}, nil
}
func recoveryWorkerError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, orchestration.ErrConflict) || errors.Is(err, orchestration.ErrInvalid) {
		return orchestration.ErrConflict
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "40001" || pg.Code == "22023" || pg.Code == "42501") {
		return orchestration.ErrConflict
	}
	return orchestration.ErrUnavailable
}
func (p *singleTestRecoveryProduct) observe(ctx context.Context, q orchestration.SingleTestRecoveryRef, reason string) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	wire, _ := json.Marshal(q)
	raw, err := p.database.QueryJSON(bounded, singleRecoveryObserveSQL, json.RawMessage(wire), reason)
	if err != nil {
		return recoveryWorkerError(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return orchestration.ErrConflict
	}
	return nil
}

func (p *singleTestRecoveryProduct) failed(ctx context.Context, q orchestration.SingleTestRecoveryRef, err error) error {
	safe := recoveryWorkerError(err)
	reason := "dependency_unavailable"
	if safe == orchestration.ErrConflict {
		reason = "evidence_conflict"
	}
	// This SQL entry authenticates the immutable reference before any UPDATE.
	// Unknown references cannot write even if load failed before returning facts.
	_ = p.observe(ctx, q, reason)
	return safe
}
func (p *singleTestRecoveryProduct) Step(ctx context.Context, q orchestration.SingleTestRecoveryRef) error {
	if p == nil || ctx == nil || nilWorkerDependency(p.database) || nilWorkerDependency(p.cleanup) {
		return orchestration.ErrInvalid
	}
	if _, err := orchestration.SingleTestRecoveryWorkflowID(q); err != nil {
		return err
	}
	raw, err := temporalQuery(ctx, p.database, singleRecoveryLoadSQL, q)
	if err != nil {
		return p.failed(ctx, q, err)
	}
	var loaded orchestration.SingleTestRecoveryRef
	if len(raw) > 4096 || decodeStrictWorkerJSON(raw, &loaded) != nil || loaded != q {
		return p.failed(ctx, q, orchestration.ErrConflict)
	}
	if err = p.cleanup.Cleanup(ctx, orchestration.CleanupRequest{Start: q.Start, Reason: "workflow_cancelled"}); err != nil {
		reason := "dependency_unavailable"
		safe := recoveryWorkerError(err)
		if errors.Is(err, orchestration.ErrCleanupPending) {
			reason = "cleanup_pending"
			safe = orchestration.ErrCleanupPending
		} else if safe == orchestration.ErrConflict {
			reason = "evidence_conflict"
		}
		// A status-write outage must not turn a permanent primary conflict into
		// a retryable error. SQL authenticates this known command independently.
		_ = p.observe(ctx, q, reason)
		return safe
	}
	raw, err = temporalQuery(ctx, p.database, singleRecoveryFinishSQL, q)
	if err != nil {
		return p.failed(ctx, q, err)
	}
	var result struct {
		Complete  bool                                `json:"complete"`
		Reference orchestration.SingleTestRecoveryRef `json:"reference"`
	}
	if len(raw) > 4096 || decodeStrictWorkerJSON(raw, &result) != nil || result.Reference != q {
		_ = p.observe(ctx, q, "evidence_conflict")
		return orchestration.ErrConflict
	}
	if !result.Complete {
		_ = p.observe(ctx, q, "cleanup_pending")
		return orchestration.ErrCleanupPending
	}
	return nil
}
