package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type orderedPolicyProjectionAttempt func(context.Context) (authorization.ProjectionReceipt, error)

// Only capture's concurrent projector uses this loop. Every conflict restarts
// the entire Reconcile with a fresh snapshot; no receipt or authority is cached.
func orderedPolicyProjectUntilApplied(ctx context.Context, attempt orderedPolicyProjectionAttempt) error {
	if ctx == nil || attempt == nil {
		return authorization.ErrInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return authorization.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := attempt(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			if !r.Applied {
				return authorization.ErrPending
			}
			return nil
		}
		if !errors.Is(err, authorization.ErrConflict) {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// This in-memory repository is only a deterministic conflict injector. The
// consuming algorithm is the real authorization.Reconcile and real Project.
// An acknowledgement rejects the first stale revision after the writer changes
// the current membership, so a successful second attempt must read fresh facts.
type orderedProjectionRace struct {
	snapshot                            authorization.ProjectionSnapshot
	snapshots, writes, acknowledgements int
	stageRevision                       int64
	desired                             [][]fga.ClientTupleKey
	fail                                error
	change                              bool
	changeAtStage                       bool
	cancel                              context.CancelFunc
	deadline                            time.Time
}

func (r *orderedProjectionRace) WithOrganization(ctx context.Context, _ string, consume func(authorization.ProjectionSession) error) error {
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(r.deadline) {
		return authorization.ErrInvalid
	}
	return consume(r)
}
func (r *orderedProjectionRace) Snapshot(context.Context) (authorization.ProjectionSnapshot, error) {
	r.snapshots++
	return r.snapshot, nil
}
func (r *orderedProjectionRace) Stage(_ context.Context, v authorization.Revision, tuples []fga.ClientTupleKey) error {
	if r.changeAtStage && r.snapshots == 1 {
		r.snapshot.Revision.Desired++
		r.snapshot.Members = nil
		return authorization.ErrConflict
	}
	r.stageRevision = v.Desired
	r.snapshot.Known = append([]fga.ClientTupleKey(nil), tuples...)
	return nil
}
func (r *orderedProjectionRace) Replace(_ context.Context, v authorization.Revision, _, desired []fga.ClientTupleKey) error {
	r.writes++
	if r.stageRevision != v.Desired {
		return authorization.ErrInvalid
	}
	r.desired = append(r.desired, append([]fga.ClientTupleKey(nil), desired...))
	if r.fail != nil {
		return r.fail
	}
	if r.change && r.writes == 1 {
		r.snapshot.Revision.Desired++
		r.snapshot.Members = nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	return nil
}
func (r *orderedProjectionRace) Acknowledge(_ context.Context, v authorization.Revision, _ []fga.ClientTupleKey) error {
	if v.Desired != r.snapshot.Revision.Desired {
		return authorization.ErrConflict
	}
	r.acknowledgements++
	r.snapshot.Revision.Applied = v.Desired
	return nil
}
func orderedProjectionRaceFixture(ctx context.Context) *orderedProjectionRace {
	d, _ := ctx.Deadline()
	return &orderedProjectionRace{deadline: d, snapshot: authorization.ProjectionSnapshot{
		Revision: authorization.Revision{OrganizationID: "pid_10000000-0000-4000-8000-000000000001", Desired: 2, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"},
		Members:  []authorization.ProjectionMember{{Kind: "user", ID: "pid_40000000-0000-4000-8000-000000000001"}},
	}}
}
func (r *orderedProjectionRace) attempt(ctx context.Context) (authorization.ProjectionReceipt, error) {
	v := r.snapshot.Revision
	return authorization.Reconcile(ctx, r, r, v.OrganizationID, v.StoreID, v.ModelID)
}

func TestOrderedPolicyProjectionFreshConflict(t *testing.T) {
	for _, stage := range []bool{false, true} {
		t.Run(map[bool]string{false: "ack", true: "stage"}[stage], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := orderedProjectionRaceFixture(ctx)
			r.change, r.changeAtStage = !stage, stage
			if err := orderedPolicyProjectUntilApplied(ctx, r.attempt); err != nil {
				t.Fatal("capture projector failed instead of re-snapshotting conflict", err)
			}
			wantWrites := 2
			if stage {
				wantWrites = 1
			}
			if r.snapshots != 2 || r.writes != wantWrites || r.acknowledgements != 1 || r.snapshot.Revision.Applied != 3 || len(r.desired[len(r.desired)-1]) != 0 || !stage && len(r.desired[0]) != 1 {
				t.Fatal("fresh projection did not remove revoked membership before acknowledging", r.snapshots, r.writes, r.acknowledgements)
			}
		})
	}
}

func TestOrderedPolicyProjectionRefusals(t *testing.T) {
	for _, failure := range []error{authorization.ErrUnavailable, authorization.ErrInvalid, authorization.ErrBusy, authorization.ErrPending} {
		t.Run(failure.Error(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := orderedProjectionRaceFixture(ctx)
			r.fail = failure
			if err := orderedPolicyProjectUntilApplied(ctx, r.attempt); !errors.Is(err, failure) || r.snapshots != 1 || r.writes != 1 || r.acknowledgements != 0 {
				t.Fatal("non-conflict failure retried or acknowledged", err)
			}
		})
	}
	t.Run("cancelled-conflict", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r := orderedProjectionRaceFixture(ctx)
		r.change = true
		r.cancel = cancel
		if err := orderedPolicyProjectUntilApplied(ctx, r.attempt); !errors.Is(err, context.Canceled) || r.snapshots != 1 || r.acknowledgements != 0 {
			t.Fatal("cancelled capture retried or acknowledged", err)
		}
	})
	t.Run("original-deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		calls := 0
		err := orderedPolicyProjectUntilApplied(ctx, func(c context.Context) (authorization.ProjectionReceipt, error) {
			calls++
			if c != ctx {
				t.Fatal("retry replaced original context")
			}
			return authorization.ProjectionReceipt{}, authorization.ErrConflict
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls < 1 {
			t.Fatal("persistent conflict did not end at original deadline", err, calls)
		}
	})
	t.Run("no-deadline", func(t *testing.T) {
		calls := 0
		err := orderedPolicyProjectUntilApplied(context.Background(), func(context.Context) (authorization.ProjectionReceipt, error) {
			calls++
			return authorization.ProjectionReceipt{Applied: true}, nil
		})
		if !errors.Is(err, authorization.ErrInvalid) || calls != 0 {
			t.Fatal("unbounded projector allowed", err)
		}
	})
	t.Run("already-expired", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		calls := 0
		err := orderedPolicyProjectUntilApplied(ctx, func(context.Context) (authorization.ProjectionReceipt, error) {
			calls++
			return authorization.ProjectionReceipt{Applied: true}, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
			t.Fatal("expired capture attempted projection", err, calls)
		}
	})
	t.Run("unapplied-success", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		err := orderedPolicyProjectUntilApplied(ctx, func(context.Context) (authorization.ProjectionReceipt, error) {
			calls++
			return authorization.ProjectionReceipt{}, nil
		})
		if !errors.Is(err, authorization.ErrPending) || calls != 1 {
			t.Fatal("unapplied receipt accepted or retried", err)
		}
	})
}
