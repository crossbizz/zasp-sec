package redteamadapter

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/legacytests"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"time"
)

const legacyJournalProtocolSQL = `SELECT zasp_temporal71.adapter_protocol($1,$2,$3,$4)`

// LegacyJournalRouter retains both leased linked protocols. Effect-key routes
// use their separate68 handler. Database classification never grants a send.
type LegacyJournalRouter struct {
	database         JSONDatabase
	single, retained *PostgresInvocationJournal
}

func NewLegacyJournalRouter(ctx context.Context, db JSONDatabase) (*LegacyJournalRouter, error) {
	if nilJSONDatabase(db) || ctx == nil || ctx.Err() != nil {
		return nil, ErrAdapter
	}
	single, err := NewPostgresInvocationJournal(legacytests.Database{DB: db, Role: "zasp_red_team_adapter"}, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil {
		return nil, ErrAdapter
	}
	retained, err := NewPostgresInvocationJournal(db, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
	if err != nil {
		return nil, ErrAdapter
	}
	retained, err = retained.Release61(ctx)
	if err != nil {
		return nil, ErrAdapter
	}
	router := &LegacyJournalRouter{db, single, retained}
	if router.Ready(ctx) != nil {
		return nil, ErrAdapter
	}
	return router, nil
}
func (r *LegacyJournalRouter) Ready(ctx context.Context) error {
	if r == nil || r.single == nil || r.retained == nil || r.single.Ready(ctx) != nil || r.retained.Ready(ctx) != nil {
		return ErrAdapter
	}
	return nil
}
func (r *LegacyJournalRouter) selectJournal(ctx context.Context, scope domain.Scope, run string) (*PostgresInvocationJournal, error) {
	if r == nil || nilJSONDatabase(r.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil {
		return nil, ErrAdapter
	}
	if _, err := domain.ParseProductID(run); err != nil {
		return nil, ErrAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(ctx, legacyJournalProtocolSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), run)
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
	case "legacy_single_test":
		return r.single, nil
	case "retained_ordered":
		return r.retained, nil
	default:
		return nil, ErrAdapter
	}
}
func (r *LegacyJournalRouter) ResolveTarget(ctx context.Context, q TargetResolution) (TargetBinding, error) {
	j, err := r.selectJournal(ctx, q.Scope, q.RunID)
	if err != nil {
		return TargetBinding{}, err
	}
	return j.ResolveTarget(ctx, q)
}
func (r *LegacyJournalRouter) Start(ctx context.Context, q JournalRequest) (InvocationReceipt, error) {
	j, err := r.selectJournal(ctx, q.Invocation.Scope, q.Invocation.RunID)
	if err != nil {
		return InvocationReceipt{}, err
	}
	return j.Start(ctx, q)
}
func (r *LegacyJournalRouter) Complete(ctx context.Context, q JournalRequest, attempt int, observation InvocationObservation) error {
	j, err := r.selectJournal(ctx, q.Invocation.Scope, q.Invocation.RunID)
	if err != nil {
		return err
	}
	return j.Complete(ctx, q, attempt, observation)
}
