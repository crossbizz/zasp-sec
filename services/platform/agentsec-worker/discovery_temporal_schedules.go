package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Each reconciliation owns a bounded dedicated session. No SQL transaction
// spans the Schedule RPC; a new desired revision remains durably pending.
type temporalDiscoveryScheduleSource struct {
	dsn     string
	timeout time.Duration
}

func newTemporalDiscoveryScheduleSource(ctx context.Context, dsn string, timeout time.Duration) (*temporalDiscoveryScheduleSource, error) {
	if ctx == nil || dsn == "" || timeout <= 0 || timeout > 30*time.Second {
		return nil, errWorkerExecution
	}
	s := &temporalDiscoveryScheduleSource{dsn, timeout}
	if err := s.Ready(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *temporalDiscoveryScheduleSource) withConnection(ctx context.Context, fn func(context.Context, *pgx.Conn) error) (result error) {
	if s == nil || ctx == nil || ctx.Err() != nil || fn == nil {
		return errWorkerExecution
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := pgx.Connect(bounded, s.dsn)
	if err != nil {
		return errWorkerExecution
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer closeCancel()
		if conn.Close(closeCtx) != nil {
			result = errWorkerExecution
		}
	}()
	return fn(bounded, conn)
}
func (s *temporalDiscoveryScheduleSource) Ready(ctx context.Context) error {
	return s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var ready bool
		if c.QueryRow(ctx, `SELECT zasp_temporal72.principal_ready('zasp_discovery_scheduler')`).Scan(&ready) != nil || !ready {
			return errWorkerExecution
		}
		return nil
	})
}
func discoveryScheduleArgs(r orchestration.DiscoveryScheduleRef) []any {
	return []any{r.OrganizationID, r.WorkspaceID, r.EnvironmentID, r.ScheduleID, r.IntegrationID}
}

func (s *temporalDiscoveryScheduleSource) WithCurrentSchedule(ctx context.Context, ref orchestration.DiscoveryScheduleRef, fn func(orchestration.DiscoveryScheduleDesired) error) error {
	id, err := orchestration.DiscoveryScheduleID(ref)
	if err != nil || fn == nil {
		return errWorkerExecution
	}
	return s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		if _, err := c.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, id); err != nil {
			return errWorkerExecution
		}
		var raw []byte
		if c.QueryRow(ctx, `SELECT zasp_temporal72.schedule_current($1,$2,$3,$4,$5)`, discoveryScheduleArgs(ref)...).Scan(&raw) != nil {
			return errWorkerExecution
		}
		var wire struct {
			Ref      orchestration.DiscoveryScheduleRef `json:"ref"`
			Revision int64                              `json:"revision"`
			Cadence  int                                `json:"cadence_seconds"`
			Anchor   time.Time                          `json:"anchor"`
			Enabled  bool                               `json:"enabled"`
		}
		if json.Unmarshal(raw, &wire) != nil || wire.Ref != ref || wire.Revision < 1 || wire.Anchor.IsZero() {
			return errWorkerExecution
		}
		d := orchestration.DiscoveryScheduleDesired{Ref: wire.Ref, Revision: wire.Revision, CadenceSeconds: wire.Cadence, Anchor: wire.Anchor.UTC(), Enabled: wire.Enabled}
		if err := fn(d); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return orchestration.ErrScheduleOutcomeUnknown
		}
		if c.QueryRow(ctx, `SELECT zasp_temporal72.schedule_ack($1,$2,$3,$4,$5,$6)`, append(discoveryScheduleArgs(ref), wire.Revision)...).Scan(&raw) != nil {
			return errWorkerExecution
		}
		return nil
	})
}
func (s *temporalDiscoveryScheduleSource) ReconcileDiscoveryDue(ctx context.Context, ref orchestration.DiscoveryScheduleRef) error {
	if _, err := orchestration.DiscoveryScheduleID(ref); err != nil {
		return errWorkerExecution
	}
	return s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		if c.QueryRow(ctx, `SELECT zasp_temporal72.reconcile_due($1,$2,$3,$4,$5)`, discoveryScheduleArgs(ref)...).Scan(&raw) != nil {
			return errWorkerExecution
		}
		return nil
	})
}

func (s *temporalDiscoveryScheduleSource) pending(ctx context.Context, after string, all bool, limit int) (refs []orchestration.DiscoveryScheduleRef, result error) {
	result = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		if c.QueryRow(ctx, `SELECT zasp_temporal72.pending_schedules($1,$2,$3)`, after, all, limit).Scan(&raw) != nil || json.Unmarshal(raw, &refs) != nil {
			return errWorkerExecution
		}
		for _, r := range refs {
			if _, err := orchestration.DiscoveryScheduleID(r); err != nil {
				return errWorkerExecution
			}
		}
		return nil
	})
	return
}

// This scans desired changes, never due work. One startup pass also repairs
// deleted or missing Temporal Schedules through the same reconciliation path.
type temporalDiscoveryScheduleProcessor struct {
	mu         sync.Mutex
	source     *temporalDiscoveryScheduleSource
	reconciler *orchestration.DiscoveryScheduleReconciler
	limit      int
	startup    bool
	after      string
}

func (p *temporalDiscoveryScheduleProcessor) RunOnce(ctx context.Context) error {
	if p == nil || p.source == nil || p.reconciler == nil || p.limit < 1 || p.limit > 100 {
		return errWorkerExecution
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	refs, err := p.source.pending(ctx, p.after, p.startup, p.limit)
	if err != nil {
		return err
	}
	var result error
	for _, ref := range refs {
		result = errors.Join(result, p.reconciler.Reconcile(ctx, ref))
		p.after = strings.Join([]string{ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, ref.ScheduleID, ref.IntegrationID}, "/")
	}
	if len(refs) < p.limit {
		p.after = ""
		p.startup = false
	}
	return result
}
