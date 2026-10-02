package main

import (
	"bytes"
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func findingResponseRuntimeAvailable(ctx context.Context, db apiserver.JSONDatabase) (bool, error) {
	if ctx == nil || nilWorkerDependency(db) {
		return false, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := db.QueryJSON(bounded, `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`)
	if err != nil {
		return false, errRuntimeUnavailable
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return false, nil
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	raw, err = db.QueryJSON(bounded, `SELECT to_jsonb(zasp_temporal78.client_ready($1,$2))`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errRuntimeUnavailable
	}
	return true, nil
}
