package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"time"
)

func (s *temporalDiscoveryScheduleSource) analyzeBoundActions(ctx context.Context, limit int) (n int, result error) {
	result = s.withConnection(ctx, func(ctx context.Context, c *pgx.Conn) error {
		if err := c.QueryRow(ctx, `SELECT zasp_analyze_bound_actions($1)`, limit).Scan(&n); err != nil {
			var db *pgconn.PgError
			if errors.As(err, &db) && db.Code == "42883" {
				return nil
			}
			return errWorkerExecution
		}
		if n < 0 || n > limit {
			return errWorkerExecution
		}
		return nil
	})
	return
}
func (p *temporalDiscoveryScheduleProcessor) analyzeDue(ctx context.Context) error {
	if p.analyze == nil && p.source == nil {
		return nil
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	at := now()
	if !p.lastAnalysis.IsZero() && at.Sub(p.lastAnalysis) < time.Minute {
		return nil
	}
	run := p.analyze
	if run == nil {
		run = p.source.analyzeBoundActions
	}
	limit := min(max(p.limit, 1), 250)
	n, err := run(ctx, limit)
	if err == nil && n < limit {
		p.lastAnalysis = at
	}
	return err
}
