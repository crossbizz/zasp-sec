package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	conn, err := runtimepostgres.Connect(bounded, s.dsn)
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

// discoveryReleaseInterval is how often the scheduler asks the database to
// release abandoned discovery runs. The database decides which runs are
// abandoned (quiet for ten or thirty-five minutes, nothing committed), so the
// interval only bounds how long after that a run is released.
const discoveryReleaseInterval = time.Minute

// releaseAbandoned releases abandoned discovery runs of integrations that no
// later sync would release (completion.sql, section V4). It returns how many
// runs were released.
func (s *temporalDiscoveryScheduleSource) releaseAbandoned(ctx context.Context, limit int) (released int, result error) {
	result = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		var wire struct {
			Examined *int `json:"examined"`
			Released *int `json:"released"`
		}
		if c.QueryRow(ctx, `SELECT zasp_temporal72.release_abandoned_due($1)`, limit).Scan(&raw) != nil || json.Unmarshal(raw, &wire) != nil || wire.Examined == nil || wire.Released == nil || *wire.Released < 0 || *wire.Examined < 0 {
			return errWorkerExecution
		}
		released = *wire.Released
		return nil
	})
	return
}

// redTeamRetestInterval is how often the scheduler asks the database to queue
// the due red team re-tests. The database decides what is due: a cadence that
// has elapsed, or a target whose inventory record changed.
const redTeamRetestInterval = time.Minute

// fireRedTeamSchedules queues a run for each due red team schedule
// (completion.sql, section WS2c) and returns how many runs were queued. The
// database applies the non-production rule to every one. A database that does
// not hold the section yet has no schedules, so that is not a failure.
func (s *temporalDiscoveryScheduleSource) fireRedTeamSchedules(ctx context.Context, limit int) (queued int, result error) {
	result = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		var raw []byte
		var wire struct {
			Examined *int `json:"examined"`
			Queued   *int `json:"queued"`
		}
		if err := c.QueryRow(ctx, `SELECT zasp_red_team_fire_due_schedules('discovery-scheduler',$1)`, min(limit, 50)).Scan(&raw); err != nil {
			var provider *pgconn.PgError
			if errors.As(err, &provider) && provider.Code == "42883" {
				return nil
			}
			return errWorkerExecution
		}
		if json.Unmarshal(raw, &wire) != nil || wire.Examined == nil || wire.Queued == nil || *wire.Queued < 0 || *wire.Queued > *wire.Examined {
			return errWorkerExecution
		}
		queued = *wire.Queued
		return nil
	})
	return
}

// This scans desired changes, never due work. One startup pass also repairs
// deleted or missing Temporal Schedules through the same reconciliation path.
// On a timer it also releases abandoned discovery runs.
type temporalDiscoveryScheduleProcessor struct {
	mu         sync.Mutex
	source     *temporalDiscoveryScheduleSource
	reconciler *orchestration.DiscoveryScheduleReconciler
	limit      int
	startup    bool
	after      string
	// release and now are replaced in tests; nil means the source and the
	// wall clock.
	release     func(context.Context, int) (int, error)
	now         func() time.Time
	lastRelease time.Time
	// retest is replaced in tests; nil means the source.
	retest     func(context.Context, int) (int, error)
	lastRetest time.Time
}

// retestDue queues the due red team re-tests when its interval has elapsed. A
// failed pass is retried on the next one.
func (p *temporalDiscoveryScheduleProcessor) retestDue(ctx context.Context) error {
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	at := now()
	if !p.lastRetest.IsZero() && at.Sub(p.lastRetest) < redTeamRetestInterval {
		return nil
	}
	retest := p.retest
	if retest == nil {
		retest = p.source.fireRedTeamSchedules
	}
	if _, err := retest(ctx, p.limit); err != nil {
		return err
	}
	p.lastRetest = at
	return nil
}

// releaseDue runs the release sweep when its interval has elapsed. A failed
// sweep is retried on the next pass.
func (p *temporalDiscoveryScheduleProcessor) releaseDue(ctx context.Context) error {
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	at := now()
	if !p.lastRelease.IsZero() && at.Sub(p.lastRelease) < discoveryReleaseInterval {
		return nil
	}
	release := p.release
	if release == nil {
		release = p.source.releaseAbandoned
	}
	if _, err := release(ctx, p.limit); err != nil {
		return err
	}
	p.lastRelease = at
	return nil
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
	result := errors.Join(p.releaseDue(ctx), p.retestDue(ctx))
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
