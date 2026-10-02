package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"time"
)

const singleRecoveryPendingSQL = `SELECT zasp_temporal_single_recovery.pending()`
const singleRecoveryAttemptSQL = `SELECT to_jsonb(zasp_temporal_single_recovery.attempt($1::jsonb))`
const singleRecoveryAckSQL = `SELECT to_jsonb(zasp_temporal_single_recovery.ack($1::jsonb))`

type singleTestRecoveryRelay struct {
	database apiserver.JSONDatabase
	start    func(context.Context, orchestration.SingleTestRecoveryRef) error
}

func (r *singleTestRecoveryRelay) Pending(ctx context.Context) ([]orchestration.SingleTestRecoveryRef, error) {
	if r == nil || ctx == nil || nilWorkerDependency(r.database) {
		return nil, orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(bounded, singleRecoveryPendingSQL)
	if err != nil {
		return nil, recoveryWorkerError(err)
	}
	var items []orchestration.SingleTestRecoveryRef
	if len(raw) > 65536 || decodeStrictWorkerJSON(raw, &items) != nil || items == nil || len(items) > 100 {
		return nil, orchestration.ErrConflict
	}
	seen := map[string]bool{}
	for _, q := range items {
		id, err := orchestration.SingleTestRecoveryWorkflowID(q)
		if err != nil || seen[id] {
			return nil, orchestration.ErrConflict
		}
		seen[id] = true
	}
	return items, nil
}
func (r *singleTestRecoveryRelay) change(ctx context.Context, sql string, q orchestration.SingleTestRecoveryRef) error {
	if r == nil {
		return orchestration.ErrInvalid
	}
	if _, err := orchestration.SingleTestRecoveryWorkflowID(q); err != nil {
		return err
	}
	raw, err := temporalQuery(ctx, r.database, sql, q)
	if err != nil {
		return recoveryWorkerError(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return orchestration.ErrConflict
	}
	return nil
}
func (r *singleTestRecoveryRelay) Attempt(ctx context.Context, q orchestration.SingleTestRecoveryRef) error {
	return r.change(ctx, singleRecoveryAttemptSQL, q)
}
func (r *singleTestRecoveryRelay) Ack(ctx context.Context, q orchestration.SingleTestRecoveryRef) error {
	return r.change(ctx, singleRecoveryAckSQL, q)
}
func (r *singleTestRecoveryRelay) RunOnce(ctx context.Context) error {
	if r == nil || ctx == nil || r.start == nil {
		return orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	items, err := r.Pending(bounded)
	if err != nil {
		return err
	}
	var failures error
	for _, q := range items {
		if err = r.Attempt(bounded, q); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		if err = r.start(bounded, q); err != nil {
			failures = errors.Join(failures, recoveryWorkerError(err))
			continue
		}
		failures = errors.Join(failures, r.Ack(bounded, q))
	}
	return failures
}
