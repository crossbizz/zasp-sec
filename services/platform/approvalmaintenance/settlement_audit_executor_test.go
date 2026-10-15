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
