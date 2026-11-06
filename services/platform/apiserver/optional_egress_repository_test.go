package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

type optionalBoundaryTx struct {
	pgx.Tx
	steps       []string
	ready       bool
	fenceError  error
	commitError error
	payload     []byte
}

func (t *optionalBoundaryTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.HasPrefix(sql, "SET TRANSACTION"):
		t.steps = append(t.steps, "read-committed")
	case strings.HasPrefix(sql, "SET LOCAL ROLE"):
		t.steps = append(t.steps, sql)
	case sql == `SELECT zasp_authorization80.fence($1::text)`:
		t.steps = append(t.steps, "fence")
		return pgconn.CommandTag{}, t.fenceError
	default:
		return pgconn.CommandTag{}, errors.New("unexpected statement")
	}
	return pgconn.CommandTag{}, nil
}
func (t *optionalBoundaryTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if sql == `SELECT zasp_optional_egress_v1.caller_ready($1,$2)` {
		t.steps = append(t.steps, "purpose-and-pin")
		return optionalBoundaryRow{ready: t.ready}
	}
	if sql != `SELECT zasp_optional_egress_v1.dispatch($1::jsonb)` {
		return optionalBoundaryRow{err: errors.New("unexpected effect")}
	}
	t.steps = append(t.steps, "dispatch")
	return optionalBoundaryRow{payload: t.payload}
}
func (t *optionalBoundaryTx) Commit(context.Context) error {
	t.steps = append(t.steps, "commit")
	return t.commitError
}
func (t *optionalBoundaryTx) Rollback(context.Context) error {
	t.steps = append(t.steps, "rollback")
	return nil
}

type optionalBoundaryRow struct {
	ready   bool
	payload []byte
	err     error
}

func (r optionalBoundaryRow) Scan(values ...any) error {
	if r.err != nil {
		return r.err
	}
	switch value := values[0].(type) {
	case *bool:
		*value = r.ready
	case *[]byte:
		*value = append([]byte(nil), r.payload...)
	default:
		return errors.New("unexpected destination")
	}
	return nil
}

type optionalBoundaryDriver struct {
	PostgresDriver
	tx *optionalBoundaryTx
}

func (d *optionalBoundaryDriver) Begin(context.Context) (pgx.Tx, error) {
	d.tx.steps = append(d.tx.steps, "begin")
	return d.tx, nil
}

// Transaction boundary controls are component evidence. The native profile
// group separately verifies real SQL roles, attestation and row isolation.
func TestOptionalEgressTypedSQLCommitAndPermissionBoundary(t *testing.T) {
	for _, scenario := range []string{"committed", "commit-unknown", "role-refused", "fence-refused", "unsigned"} {
		t.Run(scenario, func(t *testing.T) {
			claim := optionalegress.DispatchResult{Receipt: optionalegress.Receipt{State: optionalegress.Started}, NewlyStarted: true, Nonce: strings.Repeat("a", 64)}
			payload, _ := json.Marshal(claim)
			tx := &optionalBoundaryTx{ready: true, payload: payload}
			if scenario == "commit-unknown" {
				tx.commitError = errors.New("commit response unavailable")
			}
			if scenario == "role-refused" {
				tx.ready = false
			}
			if scenario == "fence-refused" {
				tx.fenceError = &pgconn.PgError{Code: "42501"}
			}
			forward := &PostgresJSONDatabase{driver: &optionalBoundaryDriver{tx: tx}}
			captured := &PostgresJSONDatabase{driver: &optionalBoundaryDriver{tx: &optionalBoundaryTx{ready: true}}}
			r, err := NewOptionalEgressRepository(forward, captured)
			if err != nil {
				t.Fatal(err)
			}
			proof := optionalegress.Proof(`{"component-proof":"SQL verification exercised separately"}`)
			if scenario == "unsigned" {
				proof = nil
			}
			got, err := r.Dispatch(context.Background(), optionalegress.Binding{}, proof)
			if scenario == "committed" {
				if err != nil || !got.NewlyStarted || got.Nonce != claim.Nonce {
					t.Fatalf("committed claim unavailable: %v", err)
				}
				want := []string{"begin", "read-committed", "SET LOCAL ROLE zasp_security_agent_api", "purpose-and-pin", "fence", "dispatch", "commit", "rollback"}
				if !reflect.DeepEqual(tx.steps, want) {
					t.Fatalf("authority/commit ordering changed: %v", tx.steps)
				}
			} else {
				if err == nil || got.NewlyStarted || got.Nonce != "" {
					t.Fatal("uncommitted or refused dispatch returned a send claim")
				}
				if scenario != "commit-unknown" && strings.Contains(strings.Join(tx.steps, ","), "dispatch") {
					t.Fatal("refused authority reached dispatch")
				}
			}
		})
	}
}
