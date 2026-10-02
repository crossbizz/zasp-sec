package redteamadapter

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// TestEffectRouter selects exactly one persisted owner. An unknown or unhealthy
// owner is an error; a failed74 invocation never retries against68 or public71.
type TestEffectRouter struct {
	database        JSONDatabase
	single, ordered *TemporalPostgresJournal
}

func NewTestEffectRouter(ctx context.Context, db JSONDatabase) (*TestEffectRouter, error) {
	single, err := NewSingleTestPostgresJournal(db, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint())
	if err != nil {
		return nil, err
	}
	ordered, err := NewTemporalPostgresJournal(db, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint())
	if err != nil {
		return nil, err
	}
	r := &TestEffectRouter{db, single, ordered}
	if r.Ready(ctx) != nil {
		return nil, ErrAdapter
	}
	return r, nil
}
func (r *TestEffectRouter) Ready(ctx context.Context) error {
	if r == nil || r.single == nil || r.ordered == nil || r.single.Ready(ctx) != nil || r.ordered.Ready(ctx) != nil {
		return ErrAdapter
	}
	return nil
}
func (r *TestEffectRouter) selectJournal(ctx context.Context, scope domain.Scope, run, key string) (*TemporalPostgresJournal, error) {
	if r == nil || nilJSONDatabase(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !ValidEffectKey(key) {
		return nil, ErrAdapter
	}
	if _, err := domain.ParseProductID(run); err != nil {
		return nil, ErrAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(ctx, `SELECT zasp_temporal74.adapter_protocol($1,$2,$3,$4,$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), run, key)
	if err != nil || len(raw) > 256 {
		return nil, ErrAdapter
	}
	fields, err := exactJournalObject(raw, "protocol")
	if err != nil || len(fields) != 1 {
		return nil, ErrAdapter
	}
	var protocol string
	if json.Unmarshal(fields["protocol"], &protocol) != nil {
		return nil, ErrAdapter
	}
	switch protocol {
	case "single_test74":
		return r.single, nil
	case "ordered68":
		return r.ordered, nil
	default:
		return nil, ErrAdapter
	}
}
func (r *TestEffectRouter) ResolveTarget(ctx context.Context, q TargetResolution) (TargetBinding, error) {
	j, err := r.selectJournal(ctx, q.Scope, q.RunID, q.EffectKey)
	if err != nil {
		return TargetBinding{}, err
	}
	return j.ResolveTarget(ctx, q)
}
func (r *TestEffectRouter) Start(ctx context.Context, q JournalRequest) (InvocationReceipt, error) {
	j, err := r.selectJournal(ctx, q.Invocation.Scope, q.Invocation.RunID, q.EffectKey)
	if err != nil {
		return InvocationReceipt{}, err
	}
	return j.Start(ctx, q)
}
func (r *TestEffectRouter) Complete(ctx context.Context, q JournalRequest, attempt int, observation InvocationObservation) error {
	j, err := r.selectJournal(ctx, q.Invocation.Scope, q.Invocation.RunID, q.EffectKey)
	if err != nil {
		return err
	}
	return j.Complete(ctx, q, attempt, observation)
}
