package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"time"
)

// NodeCoverageTransactionPool borrows a transaction from an existing principal's
// pool. It cannot open/close pools, select roles, or choose caller SQL.
type NodeCoverageTransactionPool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

const nodeCoverageRecordSQL = `SELECT zasp_sensor_coverage_v1.record_heartbeat($1,$2,'event-ingest',$3)`
const nodeCoverageConfirmSQL = `SELECT zasp_sensor_coverage_v1.confirm_receipt($1,$2,'event-ingest',$3,$4)`

// CommitProductionNodeCoverage is the shared production transaction boundary.
// The caller retains pool ownership and joins borrowers before closing it.
func CommitProductionNodeCoverage(ctx context.Context, pool NodeCoverageTransactionPool, locator, secret, raw []byte) (nodecoveragewire.Receipt, error) {
	if ctx == nil || ctx.Err() != nil || nilProductionDatabase(pool) || len(locator) != 16 || len(secret) != 32 {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	envelope, e := nodecoveragewire.ParseEnvelope(raw)
	if e != nil {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	sum := sha256.Sum256(raw)
	tx, e := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	defer func() {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollback)
	}()
	var recorded []byte
	if tx.QueryRow(ctx, nodeCoverageRecordSQL, locator, secret, raw).Scan(&recorded) != nil {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	receipt, e := nodecoveragewire.ParseReceipt(recorded)
	clear(recorded)
	if e != nil || receipt.Sequence != envelope.Sequence || receipt.RequestDigest != hex.EncodeToString(sum[:]) || !receipt.SourceObservedAt.Equal(envelope.SourceObservedAt) || !receipt.ExpiresAt.Equal(envelope.SourceObservedAt.Add(time.Duration(envelope.TTLSeconds)*time.Second)) {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	var confirmed []byte
	if tx.QueryRow(ctx, nodeCoverageConfirmSQL, locator, secret, receipt.Sequence, sum[:]).Scan(&confirmed) != nil {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	confirmation, e := nodecoveragewire.ParseReceipt(confirmed)
	clear(confirmed)
	// Replayed describes lookup presentation. Preserve the actual record's flag.
	stable := confirmation
	stable.Replayed = receipt.Replayed
	if e != nil || stable != receipt || ctx.Err() != nil {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return nodecoveragewire.Receipt{}, ErrProductionIngestUnavailable
	}
	return receipt, nil
}
