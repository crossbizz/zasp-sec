package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type orderedConvergenceReader func(context.Context, string) (Revision, error)

func (f orderedConvergenceReader) Revision(ctx context.Context, organization string) (Revision, error) {
	return f(ctx, organization)
}

func orderedConvergenceRevision() Revision {
	return Revision{OrganizationID: org, Desired: 3, Applied: 2, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
}

func TestOrderedPolicyConvergenceTransientAndFreshCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	value, reads := orderedConvergenceRevision(), 0
	reader := orderedConvergenceReader(func(got context.Context, organization string) (Revision, error) {
		deadline, ok := got.Deadline()
		if !ok || deadline != wantDeadline || got != ctx || organization != org {
			t.Fatal("wait changed scope or original context/deadline")
		}
		reads++
		if reads == 2 {
			value.Applied = value.Desired
		}
		return value, nil
	})
	if err := waitOrderedPolicyProjection(ctx, reader, org, value.StoreID, value.ModelID); err != nil || reads != 2 {
		t.Fatal("transient projection did not converge", err, reads)
	}
	value.Desired++
	value.Applied++
	if err := waitOrderedPolicyProjection(ctx, reader, org, value.StoreID, value.ModelID); err != nil || reads != 3 {
		t.Fatal("wait reused a previous positive revision", err, reads)
	}
}

func TestOrderedPolicyConvergenceRejectsInvalidOrRegressingRevision(t *testing.T) {
	for _, name := range []string{"organization", "store", "model", "desired-zero", "applied-negative", "applied-ahead", "generation-zero", "desired-regression", "applied-regression", "generation-regression", "regression-after-advance", "pins-change", "reader-error"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			base, reads, wantReads := orderedConvergenceRevision(), 0, 1
			want := ErrPending
			if name == "desired-regression" || name == "applied-regression" || name == "generation-regression" || name == "pins-change" {
				wantReads = 2
			}
			if name == "regression-after-advance" {
				wantReads = 3
			}
			reader := orderedConvergenceReader(func(context.Context, string) (Revision, error) {
				reads++
				r := base
				if name == "regression-after-advance" && reads == 2 {
					r.Desired, r.Applied, r.Generation = 5, 4, 3
					return r, nil
				}
				if reads < wantReads {
					return r, nil
				}
				switch name {
				case "organization":
					r.OrganizationID = principal
				case "store", "pins-change":
					r.StoreID = "01K00000000000000000000009"
				case "model":
					r.ModelID = "01K00000000000000000000009"
				case "desired-zero":
					r.Desired, r.Applied = 0, 0
				case "applied-negative":
					r.Applied = -1
				case "applied-ahead":
					r.Applied = 4
				case "generation-zero":
					r.Generation = 0
				case "desired-regression":
					r.Desired, r.Applied = 2, 2
					want = ErrConflict
				case "applied-regression":
					r.Applied = 1
					want = ErrConflict
				case "generation-regression":
					r.Generation = 1
					want = ErrConflict
				case "regression-after-advance":
					r.Desired, r.Applied, r.Generation = 4, 4, 2
					want = ErrConflict
				case "reader-error":
					want = ErrDenied
					return Revision{}, ErrDenied
				}
				return r, nil
			})
			if name == "generation-regression" {
				base.Generation = 2
			}
			err := waitOrderedPolicyProjection(ctx, reader, org, base.StoreID, base.ModelID)
			if !errors.Is(err, want) || reads != wantReads {
				t.Fatal("invalid revision was polled or accepted", err, reads, wantReads)
			}
		})
	}
}

func TestOrderedPolicyConvergenceContextBounds(t *testing.T) {
	for _, name := range []string{"no-deadline", "already-cancelled", "pending-deadline", "cancel-current-read", "cancel-pending-read"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if name == "no-deadline" {
				ctx = context.Background()
			}
			if name == "already-cancelled" {
				cancel()
			}
			reads, value := 0, orderedConvergenceRevision()
			reader := orderedConvergenceReader(func(context.Context, string) (Revision, error) {
				reads++
				if name == "cancel-current-read" {
					value.Applied = value.Desired
					cancel()
				}
				if name == "cancel-pending-read" {
					cancel()
				}
				return value, nil
			})
			err := waitOrderedPolicyProjection(ctx, reader, org, value.StoreID, value.ModelID)
			want, wantReads := error(context.Canceled), 1
			switch name {
			case "no-deadline":
				want, wantReads = ErrInvalid, 0
			case "already-cancelled":
				wantReads = 0
			case "pending-deadline":
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || reads != wantReads {
				t.Fatal("wait ignored original context", err, reads)
			}
		})
	}
}

type orderedCaptureExec func(context.Context, string, ...any) (pgconn.CommandTag, error)

func (f orderedCaptureExec) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return f(ctx, sql, args...)
}

func TestOrderedPreparationPolicyCaptureThenConvergence(t *testing.T) {
	for _, op := range []WorkerOperation{"ordered68.application.source", "ordered68.delivery.apply.prepare", "ordered68.delivery.apply.store", "ordered68.effect.reserve"} {
		t.Run(string(op), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			key, _ := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{63}, 32))
			value := orderedConvergenceRevision()
			e := &WorkerExecutor{key: key, pool: &pgxpool.Pool{}, storeID: value.StoreID, modelID: value.ModelID}
			raw := json.RawMessage(`{"organization_id":"pid_10000000-0000-4000-8000-000000000001"}`)
			captures, reads := 0, 0
			capture := orderedCaptureExec(func(got context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				captures++
				if got != ctx || reads != 0 {
					t.Fatal("capture context/order changed")
				}
				if op == "ordered68.effect.reserve" {
					if sql != `SELECT zasp_authorization80_worker.prepare_ordered68_effect($1::jsonb)` || len(args) != 1 || !bytes.Equal(args[0].(json.RawMessage), raw) {
						t.Fatal("effect capture request changed")
					}
				} else if sql != `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)` || len(args) != 2 || args[0] != string(op) || !bytes.Equal(args[1].(json.RawMessage), raw) {
					t.Fatal("policy capture request changed")
				}
				return pgconn.CommandTag{}, nil
			})
			reader := orderedConvergenceReader(func(got context.Context, organization string) (Revision, error) {
				reads++
				if captures != 1 || got != ctx || organization != org {
					t.Fatal("projection before capture or wrong scope")
				}
				if reads == 2 {
					value.Applied = value.Desired
				}
				return value, nil
			})
			if err := e.prepareOrdered68Operation(ctx, op, raw, capture, reader); err != nil {
				t.Fatal("capture/convergence failed", err)
			}
			wantReads := 2
			if op == "ordered68.effect.reserve" {
				wantReads = 0
			}
			if captures != 1 || reads != wantReads {
				t.Fatal("wrong preparation side effects", captures, reads)
			}
		})
	}
}

func TestOrderedPreparationCaptureFailureAndMissingDeadline(t *testing.T) {
	for _, missingDeadline := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if missingDeadline {
			ctx = context.Background()
		}
		key, _ := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{63}, 32))
		value := orderedConvergenceRevision()
		e := &WorkerExecutor{key: key, pool: &pgxpool.Pool{}, storeID: value.StoreID, modelID: value.ModelID}
		captures := 0
		capture := orderedCaptureExec(func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			captures++
			return pgconn.CommandTag{}, ErrDenied
		})
		reader := orderedConvergenceReader(func(context.Context, string) (Revision, error) {
			t.Fatal("failed capture reached projection wait")
			return Revision{}, nil
		})
		err := e.prepareOrdered68Operation(ctx, "ordered68.application.source", json.RawMessage(`{"organization_id":"pid_10000000-0000-4000-8000-000000000001"}`), capture, reader)
		if missingDeadline {
			if err != ErrInvalid || captures != 0 {
				t.Fatal("missing deadline reached capture", err, captures)
			}
		} else if err == nil || captures != 1 {
			t.Fatal("capture failure accepted", err, captures)
		}
	}
}
