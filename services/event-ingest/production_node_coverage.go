package main

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type productionNodeCoveragePool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	Close()
}

// Borrow the original pool through commit/rollback. Close cannot race this lease.
func (d *productionJSONDatabase) CommitNodeCoverage(ctx context.Context, locator, secret, raw []byte) (nodecoveragewire.Receipt, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || len(locator) != 16 || len(secret) != 32 {
		return nodecoveragewire.Receipt{}, errRuntimeUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || d.pool == nil {
		return nodecoveragewire.Receipt{}, errRuntimeUnavailable
	}
	receipt, err := runtimeevent.CommitProductionNodeCoverage(ctx, d.pool, locator, secret, raw)
	if err != nil {
		return nodecoveragewire.Receipt{}, errRuntimeUnavailable
	}
	return receipt, nil
}
func (r cachedProductionIngestRepository) AuthenticateNodeCoverage(ctx context.Context, c *sensor.TokenCredential) error {
	a, ok := r.productionIngestRepository.(sensor.PrivateNodeCoverageHeartbeatAuthority)
	if !ok || invalidRuntimeValue(a) {
		return sensor.ErrUnavailable
	}
	return a.AuthenticateNodeCoverage(ctx, c)
}
func (r cachedProductionIngestRepository) RecordAuthenticatedNodeCoverage(ctx context.Context, c *sensor.TokenCredential, b []byte) (nodecoveragewire.Receipt, error) {
	a, ok := r.productionIngestRepository.(sensor.PrivateNodeCoverageHeartbeatAuthority)
	if !ok || invalidRuntimeValue(a) {
		return nodecoveragewire.Receipt{}, sensor.ErrUnavailable
	}
	return a.RecordAuthenticatedNodeCoverage(ctx, c, b)
}
func mountNodeCoverageHeartbeat(router http.Handler, repository productionIngestRepository, clock func() time.Time, timeout time.Duration) (http.Handler, error) {
	a, ok := repository.(sensor.PrivateNodeCoverageHeartbeatAuthority)
	if !ok || invalidRuntimeValue(a) {
		return nil, errRuntimeUnavailable
	}
	retained, e := sensor.NewPrivateNodeCoverageHeartbeatHandler(a, clock, timeout)
	if e != nil {
		return nil, errRuntimeUnavailable
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL != nil && r.URL.Path == sensor.PrivateHeartbeatPath && r.Header.Get(sensor.PrivateHeartbeatSchemaHeader) == nodecoveragewire.HeartbeatSchema {
			retained.ServeHTTP(w, r)
			return
		}
		router.ServeHTTP(w, r)
	}), nil
}
