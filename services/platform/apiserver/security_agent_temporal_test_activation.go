package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The installed74 authority positively selects single-test definitions. An
// absent release preserves legacy behavior; a present invalid release fails
// closed, including on a warmed database connection.
func (d *PostgresJSONDatabase) ActivateTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, args...)
}

func (d *PostgresJSONDatabase) ReadTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.definition($1,$2,$3,$4,$5)`, args...)
}

func (d *PostgresJSONDatabase) MutateTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.configuration_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`, args...)
}

func (d *PostgresJSONDatabase) ReplayTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.configuration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`, args...)
}

func (d *PostgresJSONDatabase) DecideTemporalTestApproval(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, args...)
}

func (d *PostgresJSONDatabase) CancelTemporalTestRun(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.cancel($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, args...)
}

func (d *PostgresJSONDatabase) ReadTemporalTestApproval(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.approval($1,$2,$3,$4,$5)`, args...)
}

func (d *PostgresJSONDatabase) PageTemporalTestApprovals(ctx context.Context, args ...any) (json.RawMessage, bool, error) {
	return d.queryTemporalTestDefinition(ctx, `SELECT zasp_temporal74.approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8,$9)`, args...)
}

func (d *PostgresJSONDatabase) queryTemporalTestDefinition(ctx context.Context, statement string, args ...any) (json.RawMessage, bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return nil, false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return nil, false, ErrRepositoryUnavailable
	}
	var present, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal74') IS NOT NULL`).Scan(&present); err != nil {
		return nil, false, ErrRepositoryUnavailable
	}
	if !present {
		return nil, false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal74.api_ready($1,$2)`, migrations.TemporalTestExecutorChecksum(), migrations.TemporalTestExecutorFingerprint()).Scan(&ready); err != nil || !ready {
		return nil, true, ErrRepositoryUnavailable
	}
	var raw []byte
	if err := d.driver.QueryRow(ctx, statement, args...).Scan(&raw); err != nil {
		return nil, true, classifyPostgresError(err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	if !json.Valid(raw) {
		return nil, true, ErrRepositoryUnavailable
	}
	return raw, true, nil
}
