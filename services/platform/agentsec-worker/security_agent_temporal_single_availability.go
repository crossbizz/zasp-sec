package main

import (
	"bytes"
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"time"
)

// Absent74 keeps the established path. Present-but-invalid never falls back.
func singleTestRuntimeAvailable(ctx context.Context, db apiserver.JSONDatabase, delivery bool) (bool, error) {
	if ctx == nil || nilWorkerDependency(db) {
		return false, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := db.QueryJSON(bounded, `SELECT to_jsonb(to_regnamespace('zasp_temporal74') IS NOT NULL)`)
	if err != nil {
		return false, errRuntimeUnavailable
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return false, nil
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	sql := `SELECT to_jsonb(zasp_temporal74.client_ready($1,$2))`
	if delivery {
		sql = `SELECT to_jsonb(zasp_temporal74.delivery_ready($1,$2))`
	}
	raw, err = db.QueryJSON(bounded, sql, migrations.TemporalTestExecutorChecksum(), migrations.TemporalTestExecutorFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	return true, nil
}
