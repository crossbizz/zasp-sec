package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
)

// Expectations only: executable production SQL lives in runtimeevent's fixed helper.
const nodeCoverageRecordSQL = `SELECT zasp_sensor_coverage_v1.record_heartbeat($1,$2,'event-ingest',$3)`
const nodeCoverageConfirmSQL = `SELECT zasp_sensor_coverage_v1.confirm_receipt($1,$2,'event-ingest',$3,$4)`

// Exercises our transaction boundary/lifetime against the pgx transaction
// interface; no PostgreSQL engine, provider or pgx internals are tested.
func TestProductionNodeCoverageSamePoolTransaction(t *testing.T) {
	for _, mode := range []string{"confirmed", "expired_terminal", "commit_unknown", "begin_error", "record_error", "malformed_record", "confirm_changed_fact", "confirm_error", "close_joins_commit"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			raw := nodeCoverageCompositionWire(t, now, mode == "expired_terminal", false)
			v, e := nodecoveragewire.ParseEnvelope(raw)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(raw)
			kind := "accepted"
			if mode == "expired_terminal" {
				kind = "expired_not_committed"
			}
			receipt := nodecoveragewire.Receipt{SensorID: "pid_10000004-0000-4000-8000-000000000004", Sequence: v.Sequence, RequestDigest: hex.EncodeToString(sum[:]), Disposition: kind, ResolvedAt: now, SourceObservedAt: v.SourceObservedAt, ExpiresAt: v.SourceObservedAt.Add(time.Duration(v.TTLSeconds) * time.Second)}
			tx := &nodeCoverageTxFixture{mode: mode, receipt: receipt, raw: raw, commitEntered: make(chan struct{}), releaseCommit: make(chan struct{})}
			pool := &nodeCoveragePoolFixture{tx: tx}
			db := &productionJSONDatabase{pool: pool}
			run := func() (nodecoveragewire.Receipt, error) {
				return db.CommitNodeCoverage(context.Background(), bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32), raw)
			}
			if mode == "close_joins_commit" {
				done := make(chan error, 1)
				go func() { _, e := run(); done <- e }()
				<-tx.commitEntered
				closed := make(chan struct{})
				go func() { db.Close(); close(closed) }()
				select {
				case <-closed:
					t.Fatal("pool closed before borrowed commit joined")
				case <-time.After(10 * time.Millisecond):
				}
				close(tx.releaseCommit)
				if <-done != nil {
					t.Fatal("confirmed joined commit failed")
				}
				<-closed
				if !pool.closed.Load() {
					t.Fatal("original owned pool did not close")
				}
				return
			}
			got, e := run()
			success := mode == "confirmed" || mode == "expired_terminal"
			if success {
				if e != nil || got != receipt || got.Replayed {
					t.Fatal("confirmed stable original receipt lost", e)
				}
			} else if e == nil || got != (nodecoveragewire.Receipt{}) {
				t.Fatal("unconfirmed transaction published receipt")
			}
			if mode == "begin_error" {
				if tx.rollbacks != 0 || len(tx.queries) != 0 {
					t.Fatal("failed Begin used transaction")
				}
				return
			}
			if !pool.readCommitted || tx.rollbacks != 1 {
				t.Fatal("original isolation/rollback lifetime changed")
			}
			if success && (len(tx.queries) != 2 || tx.queries[0] != nodeCoverageRecordSQL || tx.queries[1] != nodeCoverageConfirmSQL || tx.commits != 1) {
				t.Fatal("fixed record/confirm/commit protocol not used")
			}
		})
	}
}

type nodeCoveragePoolFixture struct {
	tx            *nodeCoverageTxFixture
	readCommitted bool
	closed        atomic.Bool
}

func (p *nodeCoveragePoolFixture) QueryRow(context.Context, string, ...any) pgx.Row {
	return nodeCoverageRowFixture{err: errors.New("implicit query forbidden")}
}
func (p *nodeCoveragePoolFixture) BeginTx(_ context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	p.readCommitted = o.IsoLevel == pgx.ReadCommitted
	if p.tx.mode == "begin_error" {
		return nil, errors.New("begin unavailable")
	}
	return p.tx, nil
}
func (p *nodeCoveragePoolFixture) Close() { p.closed.Store(true) }

type nodeCoverageTxFixture struct {
	pgx.Tx
	mode                         string
	receipt                      nodecoveragewire.Receipt
	raw                          []byte
	queries                      []string
	commits, rollbacks           int
	commitEntered, releaseCommit chan struct{}
}

func (t *nodeCoverageTxFixture) QueryRow(_ context.Context, q string, a ...any) pgx.Row {
	t.queries = append(t.queries, q)
	if len(a) < 3 {
		return nodeCoverageRowFixture{err: errors.New("missing authority")}
	}
	if q == nodeCoverageRecordSQL {
		if !bytes.Equal(a[2].([]byte), t.raw) {
			return nodeCoverageRowFixture{err: errors.New("wire changed")}
		}
		if t.mode == "record_error" {
			return nodeCoverageRowFixture{err: errors.New("record refused")}
		}
		if t.mode == "malformed_record" {
			return nodeCoverageRowFixture{raw: []byte(`{"sequence":7}`)}
		}
		b, _ := json.Marshal(t.receipt)
		return nodeCoverageRowFixture{raw: b}
	}
	if q == nodeCoverageConfirmSQL {
		if a[2].(int64) != t.receipt.Sequence || hex.EncodeToString(a[3].([]byte)) != t.receipt.RequestDigest {
			return nodeCoverageRowFixture{err: errors.New("confirm identity changed")}
		}
		if t.mode == "confirm_error" {
			return nodeCoverageRowFixture{err: errors.New("live token refused")}
		}
		r := t.receipt
		r.Replayed = true
		if t.mode == "confirm_changed_fact" {
			r.ResolvedAt = r.ResolvedAt.Add(time.Second)
		}
		b, _ := json.Marshal(r)
		return nodeCoverageRowFixture{raw: b}
	}
	return nodeCoverageRowFixture{err: errors.New("unknown query")}
}
func (t *nodeCoverageTxFixture) Commit(context.Context) error {
	t.commits++
	if t.mode == "commit_unknown" {
		return errors.New("commit outcome unknown")
	}
	if t.mode == "close_joins_commit" {
		close(t.commitEntered)
		<-t.releaseCommit
	}
	return nil
}
func (t *nodeCoverageTxFixture) Rollback(context.Context) error { t.rollbacks++; return nil }

type nodeCoverageRowFixture struct {
	raw []byte
	err error
}

func (r nodeCoverageRowFixture) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dst) != 1 {
		return errors.New("unexpected projection")
	}
	p, ok := dst[0].(*[]byte)
	if !ok {
		return errors.New("unexpected type")
	}
	*p = append([]byte(nil), r.raw...)
	return nil
}
