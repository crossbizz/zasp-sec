package approvalmaintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This transport fixture observes our real transaction and dispatch code. It
// cannot validate native receipts, SQL privileges or durable audit insertion.
type settlementAuditTx struct {
	pgx.Tx
	queries            []string
	args               [][]any
	ready, auditReady  bool
	failure            error
	commits, rollbacks int
}
type settlementAuditDB struct {
	tx     *settlementAuditTx
	begins int
}

func (d *settlementAuditDB) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if options.IsoLevel != pgx.ReadCommitted {
		return nil, ErrUnavailable
	}
	d.begins++
	return d.tx, nil
}
func (tx *settlementAuditTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if sql != "SET LOCAL ROLE zasp_approval_maintenance_worker" {
		return pgconn.CommandTag{}, ErrUnavailable
	}
	return pgconn.CommandTag{}, nil
}

type settlementAuditRow func(...any) error

func (row settlementAuditRow) Scan(out ...any) error { return row(out...) }
func (tx *settlementAuditTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	tx.queries = append(tx.queries, sql)
	tx.args = append(tx.args, args)
	return settlementAuditRow(func(out ...any) error {
		if tx.failure != nil {
			return tx.failure
		}
		if strings.Contains(sql, "caller_ready") {
			*out[0].(*bool) = tx.ready
			return nil
		}
		if strings.Contains(sql, "catalog_ready") {
			*out[0].(*bool) = tx.auditReady
			return nil
		}
		transition := "retryable"
		if len(args) > 2 && args[2] == true {
			transition = "delivered"
		}
		*out[0].(*[]byte) = []byte(`{"transition":"` + transition + `"}`)
		return nil
	})
}
func (tx *settlementAuditTx) Commit(context.Context) error   { tx.commits++; return nil }
func (tx *settlementAuditTx) Rollback(context.Context) error { tx.rollbacks++; return nil }

type settlementRevokedChecker struct{ calls int }

func (c *settlementRevokedChecker) Check(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
	c.calls++
	return authorization.Decision{}, ErrDenied
}
func settlementAuditExecutor(t *testing.T) (*Executor, *settlementAuditTx, *settlementAuditDB) {
	t.Helper()
	tx := &settlementAuditTx{ready: true, auditReady: true}
	db := &settlementAuditDB{tx: tx}
	return &Executor{pool: db, key: bytes.Repeat([]byte{7}, 32), profile: migrations.ApprovalMaintenanceProfileChecksum(), version: strings.Repeat("a", 64)}, tx, db
}

func TestSettlementAuditSelectionRequiresOriginalAndAdditiveCatalog(t *testing.T) {
	activation, err := migrations.ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	audit, err := migrations.ApprovalSettlementAuditProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ready", "wrong-activation", "wrong-original", "original-refused", "audit-refused", "catalog-error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			e, tx, db := settlementAuditExecutor(t)
			ctx := context.Background()
			pin := activation
			switch mode {
			case "wrong-activation":
				pin = strings.Repeat("0", 64)
			case "wrong-original":
				e.profile = strings.Repeat("0", 64)
			case "original-refused":
				tx.ready = false
			case "audit-refused":
				tx.auditReady = false
			case "catalog-error":
				tx.failure = errors.New("native catalog refused")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := e.bindSettlementAudit(ctx, pin)
			if mode == "ready" {
				if err != nil || e.settlementAuditPin != audit || len(tx.queries) != 2 || tx.queries[1] != `SELECT zasp_approval_settlement_v1.catalog_ready($1)` || tx.args[1][0] != audit || tx.commits != 1 {
					t.Fatalf("complete catalog admission changed: %v", err)
				}
			} else if err == nil {
				t.Fatal("partial authority admitted")
			}
			if mode == "wrong-activation" || mode == "wrong-original" || mode == "canceled" {
				if db.begins != 0 || !errors.Is(err, ErrConfiguration) {
					t.Fatal("invalid selection reached database", err)
				}
			}
			if mode == "original-refused" && len(tx.queries) != 1 {
				t.Fatal("original caller gate bypassed")
			}
			if mode == "audit-refused" && tx.commits != 0 {
				t.Fatal("refused catalog committed")
			}
			for _, q := range tx.queries {
				if strings.Contains(q, "zasp_approval_activation_v1") {
					t.Fatal("immutable predecessor ACL expanded")
				}
			}
		})
	}
}

func TestSettlementAuditCapturedDispatchNeverReauthorizesOrFallsBack(t *testing.T) {
	for _, selected := range []bool{false, true} {
		for _, op := range []Operation{NativeComplete, NativeFail} {
			e, tx, _ := settlementAuditExecutor(t)
			checker := &settlementRevokedChecker{}
			e.checker = checker
			if selected {
				e.settlementAuditPin = strings.Repeat("b", 64)
			}
			q := json.RawMessage(`{"opaque_native_reference":true}`)
			proof := []byte(`{"opaque_captured_receipt":true}`)
			raw, err := e.Invoke(context.Background(), op, q, proof)
			if err != nil || len(raw) == 0 || checker.calls != 0 || len(tx.queries) != 1 || tx.commits != 1 {
				t.Fatal("captured settlement changed or reauthorized", err)
			}
			want := `SELECT zasp_approval_maintenance.settle($1::jsonb,$2::json,$3)`
			count := 3
			if selected {
				want = `SELECT zasp_approval_settlement_v1.settle($1::jsonb,$2::json,$3,$4)`
				count = 4
			}
			if tx.queries[0] != want || len(tx.args[0]) != count || !bytes.Equal(tx.args[0][0].(json.RawMessage), q) || !bytes.Equal(tx.args[0][1].(json.RawMessage), proof) || tx.args[0][2] != (op == NativeComplete) {
				t.Fatal("native reference/receipt or outcome changed")
			}
			tx.queries = nil
			tx.args = nil
			tx.commits = 0
			tx.failure = &pgconn.PgError{Code: "42501"}
			if raw, err = e.Invoke(context.Background(), op, q, proof); raw != nil || !errors.Is(err, ErrDenied) || len(tx.queries) != 1 || tx.queries[0] != want || tx.commits != 0 {
				t.Fatal("refusal fell back or committed", err)
			}
		}
	}
}

// A zero pool makes any constructor I/O invalid. The transport substituted only
// after construction observes live gate/dispatch behavior, not native authority.
func TestConfiguredActivatedExecutorDefersLiveReadinessWithoutDroppingAudit(t *testing.T) {
	activation, err := migrations.ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal("compiled activation profile unavailable")
	}
	audit, err := migrations.ApprovalSettlementAuditProfileChecksum()
	if err != nil {
		t.Fatal("compiled settlement audit profile unavailable")
	}
	original := migrations.ApprovalMaintenanceProfileChecksum()
	construct := func(t *testing.T, profile, pin string, key []byte) (*Executor, error) {
		t.Helper()
		e, err := NewConfiguredActivatedExecutor(&pgxpool.Pool{}, executorChecker{}, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", profile, key, pin)
		if e != nil {
			t.Cleanup(e.Close)
		}
		return e, err
	}
	t.Run("compiled-selection", func(t *testing.T) {
		for _, bad := range []struct{ name, profile, activation string }{
			{"missing-activation", original, ""},
			{"wrong-activation", original, strings.Repeat("0", 64)},
			{"wrong-original", strings.Repeat("0", 64), activation},
		} {
			t.Run(bad.name, func(t *testing.T) {
				key := bytes.Repeat([]byte{7}, 32)
				e, err := construct(t, bad.profile, bad.activation, key)
				if e != nil || !errors.Is(err, ErrConfiguration) {
					t.Fatal("invalid compiled selection admitted")
				}
				if !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
					t.Fatal("selection failure erased caller-owned key")
				}
			})
		}
		e, err := construct(t, original, activation, bytes.Repeat([]byte{7}, 32))
		if err != nil || e == nil || e.settlementAuditPin != audit {
			t.Fatal("pure construction omitted compiled audit selection")
		}
	})
	for _, mode := range []string{"ready", "original-refused", "audit-refused", "catalog-error"} {
		t.Run(mode, func(t *testing.T) {
			e, err := construct(t, original, activation, bytes.Repeat([]byte{7}, 32))
			if err != nil || e == nil {
				t.Fatal("pure construction failed before live readiness")
			}
			tx := &settlementAuditTx{ready: true, auditReady: true}
			db := &settlementAuditDB{tx: tx}
			e.pool = db
			switch mode {
			case "original-refused":
				tx.ready = false
			case "audit-refused":
				tx.auditReady = false
			case "catalog-error":
				tx.failure = errors.New("controlled native catalog failure")
			}
			err = e.Ready(context.Background())
			if mode == "ready" {
				if err != nil || db.begins != 1 || tx.commits != 1 || len(tx.queries) != 2 || tx.queries[0] != `SELECT zasp_approval_maintenance.caller_ready($1,$2)` || tx.queries[1] != `SELECT zasp_approval_settlement_v1.catalog_ready($1)` || tx.args[0][0] != original || tx.args[0][1] != e.version || tx.args[1][0] != audit {
					t.Fatal("mandatory live readiness omitted caller or audit catalog gate")
				}
			} else if !errors.Is(err, ErrUnavailable) || tx.commits != 0 {
				t.Fatal("live native refusal admitted after pure construction")
			}
			if mode == "original-refused" && len(tx.queries) != 1 {
				t.Fatal("audit gate ran after original caller refusal")
			}
		})
	}
	for _, op := range []Operation{NativeComplete, NativeFail} {
		name := "captured-fail"
		if op == NativeComplete {
			name = "captured-complete"
		}
		t.Run(name, func(t *testing.T) {
			e, err := construct(t, original, activation, bytes.Repeat([]byte{7}, 32))
			if err != nil || e == nil {
				t.Fatal("pure construction failed")
			}
			tx := &settlementAuditTx{}
			e.pool = &settlementAuditDB{tx: tx}
			checker := &settlementRevokedChecker{}
			e.checker = checker
			q := json.RawMessage(`{"opaque_native_reference":true}`)
			proof := []byte(`{"opaque_captured_receipt":true}`)
			_, err = e.Invoke(context.Background(), op, q, proof)
			if err != nil || checker.calls != 0 || len(tx.queries) != 1 || tx.queries[0] != `SELECT zasp_approval_settlement_v1.settle($1::jsonb,$2::json,$3,$4)` || len(tx.args[0]) != 4 || tx.args[0][3] != audit || tx.args[0][2] != (op == NativeComplete) {
				t.Fatal("configured captured settlement lost audit routing or reauthorized")
			}
		})
	}
	t.Run("owned-key", func(t *testing.T) {
		key := bytes.Repeat([]byte{7}, 32)
		e, err := construct(t, original, activation, key)
		if err != nil || e == nil {
			t.Fatal("pure construction failed")
		}
		clear(key)
		if !bytes.Equal(e.key, bytes.Repeat([]byte{7}, 32)) {
			t.Fatal("configured executor aliased caller signing key")
		}
		owned := e.key
		e.Close()
		if !bytes.Equal(owned, make([]byte, 32)) || e.key != nil {
			t.Fatal("configured executor retained owned signing key")
		}
	})
}
