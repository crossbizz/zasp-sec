package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// ProductionNodeCoverageCommitter returns only after a confirmed transaction.
// The original pool owns the transaction and its Close/borrower lifetime.
type ProductionNodeCoverageCommitter interface {
	CommitNodeCoverage(context.Context, []byte, []byte, []byte) (nodecoveragewire.Receipt, error)
}
type productionNodeCoverageBinding struct {
	database ProductionIngestDatabase
	commit   ProductionNodeCoverageCommitter
	pin      string
}

func NewPostgresNodeCoverageIngestRepository(database ProductionIngestDatabase, pin string) (*PostgresProductionIngestRepository, error) {
	if nilProductionDatabase(database) || !migrations.IsSensorNodeCoverageProfileChecksum(pin) {
		return nil, ErrProductionIngestUnavailable
	}
	commit, ok := database.(ProductionNodeCoverageCommitter)
	if !ok || nilProductionDatabase(commit) {
		return nil, ErrProductionIngestUnavailable
	}
	repository, e := NewPostgresCurrentRuntimeIngestRepository(database)
	if e != nil {
		return nil, e
	}
	repository.nodeCoverage = &productionNodeCoverageBinding{database: database, commit: commit, pin: pin}
	return repository, nil
}
func (r *PostgresProductionIngestRepository) ReadyNodeCoverage(ctx context.Context) error {
	if !validProductionRepository(r, ctx) || r.nodeCoverage == nil || !migrations.IsSensorNodeCoverageProfileChecksum(r.nodeCoverage.pin) {
		return sensor.ErrUnavailable
	}
	raw, e := safeProductionQuery(r.nodeCoverage.database, ctx, `SELECT jsonb_build_object('ready',zasp_sensor_coverage_v1.caller_ready('ingest',$1))`, r.nodeCoverage.pin)
	var value struct {
		Ready bool `json:"ready"`
	}
	if e != nil || !closedCandidateJSON(raw, 16384, &value, "ready") || !value.Ready || ctx.Err() != nil {
		return sensor.ErrUnavailable
	}
	return nil
}
func (r *PostgresProductionIngestRepository) nodeCoverageAuthority(ctx context.Context, c *sensor.TokenCredential) (IngestAuthority, error) {
	if c == nil || r.ReadyNodeCoverage(ctx) != nil {
		return IngestAuthority{}, sensor.ErrUnavailable
	}
	a, e := r.Authenticate(ctx, c)
	if e != nil || !validIngestAuthority(a) || a.Source != "tetragon" {
		return IngestAuthority{}, sensor.ErrForbidden
	}
	return a, nil
}
func (r *PostgresProductionIngestRepository) AuthenticateNodeCoverage(ctx context.Context, c *sensor.TokenCredential) error {
	_, e := r.nodeCoverageAuthority(ctx, c)
	return e
}
func (r *PostgresProductionIngestRepository) RecordAuthenticatedNodeCoverage(ctx context.Context, c *sensor.TokenCredential, raw []byte) (nodecoveragewire.Receipt, error) {
	v, e := nodecoveragewire.ParseEnvelope(raw)
	if e != nil {
		return nodecoveragewire.Receipt{}, sensor.ErrInvalid
	}
	a, e := r.nodeCoverageAuthority(ctx, c)
	if e != nil {
		return nodecoveragewire.Receipt{}, e
	}
	binding, e := sensor.EnrollmentBinding(a.Scope, a.SensorID)
	if e != nil || binding != v.Selection.EnrollmentBinding {
		return nodecoveragewire.Receipt{}, sensor.ErrForbidden
	}
	locator, secret, e := c.Parts()
	if e != nil {
		return nodecoveragewire.Receipt{}, sensor.ErrForbidden
	}
	defer clear(locator)
	defer clear(secret)
	receipt, e := safeCommitNodeCoverage(ctx, r.nodeCoverage.commit, locator, secret, raw)
	if e != nil || ctx.Err() != nil {
		return nodecoveragewire.Receipt{}, sensor.ErrUnavailable
	}
	sum := sha256.Sum256(raw)
	if _, e = nodecoveragewire.MarshalReceipt(receipt); e != nil || receipt.SensorID != a.SensorID.String() || receipt.Sequence != v.Sequence || receipt.RequestDigest != hex.EncodeToString(sum[:]) || !receipt.SourceObservedAt.Equal(v.SourceObservedAt) || !receipt.ExpiresAt.Equal(v.SourceObservedAt.Add(time.Duration(v.TTLSeconds)*time.Second)) {
		return nodecoveragewire.Receipt{}, sensor.ErrUnavailable
	}
	return receipt, nil
}
func safeCommitNodeCoverage(ctx context.Context, c ProductionNodeCoverageCommitter, l, s, b []byte) (result nodecoveragewire.Receipt, err error) {
	defer func() {
		if recover() != nil {
			result = nodecoveragewire.Receipt{}
			err = sensor.ErrUnavailable
		}
	}()
	return c.CommitNodeCoverage(ctx, l, s, b)
}
