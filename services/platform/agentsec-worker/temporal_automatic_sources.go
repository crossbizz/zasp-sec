package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func automaticSourcesAvailable(ctx context.Context, db orchestration.JSONDatabase) (bool, error) {
	if ctx == nil || db == nil {
		return false, errWorkerExecution
	}
	raw, err := db.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal77') IS NOT NULL)`)
	if err != nil {
		return false, errWorkerExecution
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return false, nil
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errWorkerExecution
	}
	raw, err = db.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal77.executor_ready($1,$2))`, migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return false, errWorkerExecution
	}
	return true, nil
}

type automaticSelectorDatabase struct{ conn *pgx.Conn }

func (d automaticSelectorDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.conn.QueryRow(ctx, sql, args...).Scan(&raw)
	return raw, err
}

func (p *temporalSecurityAgentProduct) AutomaticSourcePage(ctx context.Context, q orchestration.AutomaticSourceStart) (orchestration.AutomaticPage, error) {
	if !q.Ref.Valid() {
		return orchestration.AutomaticPage{}, orchestration.ErrInvalid
	}
	body := map[string]any{"organization_id": q.Ref.OrganizationID, "workspace_id": q.Ref.WorkspaceID, "environment_id": q.Ref.EnvironmentID, "event_id": q.Ref.EventID, "after": q.After}
	return p.automaticPage(ctx, `SELECT zasp_temporal77.dispatch_page($1::jsonb)`, body, q.After)
}
func (p *temporalSecurityAgentProduct) AutomaticCatchupPage(ctx context.Context, q orchestration.AutomaticCatchupStart) (orchestration.AutomaticPage, error) {
	if !q.Ref.Valid() || q.Revision < 1 || q.Revision > 1000000 {
		return orchestration.AutomaticPage{}, orchestration.ErrInvalid
	}
	body := map[string]any{"ref": q.Ref, "revision": q.Revision, "after": q.After}
	return p.automaticPage(ctx, `SELECT zasp_temporal77.catchup_definition($1::jsonb)`, body, q.After)
}
func (p *temporalSecurityAgentProduct) automaticPage(ctx context.Context, sql string, body any, after string) (orchestration.AutomaticPage, error) {
	var result orchestration.AutomaticPage
	if p == nil || !p.automaticSourcesEnabled || p.executor == nil || ctx == nil {
		return result, orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	encoded, err := json.Marshal(body)
	if err != nil {
		return result, orchestration.ErrInvalid
	}
	raw, err := p.executor.QueryJSON(bounded, sql, string(encoded))
	if err != nil || bounded.Err() != nil {
		return result, orchestration.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 5 || decodeStrictWorkerJSON(raw, &result) != nil || !result.Valid(after) {
		return result, orchestration.ErrUnavailable
	}
	return result, nil
}

type temporalAutomaticSourceProcessor struct {
	mu       sync.Mutex
	database orchestration.JSONDatabase
	relay    workerProcessor
}

func (p *temporalAutomaticSourceProcessor) RunOnce(ctx context.Context) error {
	if p == nil || ctx == nil || p.database == nil || p.relay == nil {
		return errWorkerExecution
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	raw, err := p.database.QueryJSON(bounded, `SELECT zasp_temporal77.scan_sources($1)`, 100)
	if bounded.Err() != nil {
		err = orchestration.ErrUnavailable
	}
	cancel()
	var result struct {
		Scanned  int  `json:"scanned"`
		Captured int  `json:"captured"`
		Wrapped  bool `json:"wrapped"`
	}
	if err == nil && (decodeStrictWorkerJSON(raw, &result) != nil || result.Scanned < 0 || result.Scanned > 100 || result.Captured < 0 || result.Captured > result.Scanned) {
		err = orchestration.ErrUnavailable
	}
	// A failed catch-up scan must not prevent committed event delivery.
	return errors.Join(err, p.relay.RunOnce(ctx))
}
