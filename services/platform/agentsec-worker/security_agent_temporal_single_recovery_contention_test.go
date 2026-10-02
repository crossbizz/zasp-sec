package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type recoveryContentionBoundary struct {
	wait, release, join, elapsed string
	joinObserved                 chan struct{}
}

func newRecoveryContentionBoundary() recoveryContentionBoundary {
	return recoveryContentionBoundary{wait: "ready", release: "ok", join: "complete", elapsed: "lt5s"}
}

func (b recoveryContentionBoundary) line(phase string) string {
	return fmt.Sprintf("recovery-contention phase=%s wait=%s release=%s join=%s elapsed=%s", phase, b.wait, b.release, b.join, b.elapsed)
}

func recoveryContentionBoundaryError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case err != nil:
		return "error"
	default:
		return "ok"
	}
}

func recoveryContentionBoundaryElapsed(elapsed time.Duration) string {
	switch {
	case elapsed < 5*time.Second:
		return "lt5s"
	case elapsed < 45*time.Second:
		return "lt45s"
	default:
		return "ge45s"
	}
}

func continueSingleRecoverySettleAfterContention(pending bool, parent context.Context, boundary recoveryContentionBoundary, results [3]error, contentionErr error) bool {
	if pending || parent == nil || parent.Err() != nil || !errors.Is(contentionErr, context.DeadlineExceeded) {
		return false
	}
	if boundary.wait != "ready" || boundary.release != "ok" || boundary.join != "outer-deadline" || boundary.elapsed != "ge45s" {
		return false
	}
	for _, result := range results {
		if result != nil && !errors.Is(result, orchestration.ErrCleanupPending) && !errors.Is(result, orchestration.ErrUnavailable) && !errors.Is(result, context.DeadlineExceeded) {
			return false
		}
	}
	return true
}

// This helper coordinates callers only. The native wait callback must observe
// the actual database lock wait and prove the first receipt is still absent.
func runRecoveryContention(ctx context.Context, calls [3]func(context.Context) error, wait, release func(context.Context) error, observation *recoveryContentionBoundary) ([3]error, error) {
	started := time.Now()
	boundary := newRecoveryContentionBoundary()
	if observation != nil {
		boundary.joinObserved = observation.joinObserved
	}
	defer func() {
		boundary.elapsed = recoveryContentionBoundaryElapsed(time.Since(started))
		if observation != nil {
			*observation = boundary
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	type result struct {
		index int
		err   error
	}
	completed := make(chan result, 3)
	for i, call := range calls {
		go func(i int, call func(context.Context) error) { completed <- result{i, call(ctx)} }(i, call)
	}
	waitCtx, stopWait := context.WithTimeout(ctx, 5*time.Second)
	err := wait(waitCtx)
	if err != nil {
		boundary.wait = recoveryContentionBoundaryError(err)
	}
	stopWait()
	if err != nil {
		cancel()
	}
	cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	releaseErr := release(cleanup)
	boundary.release = recoveryContentionBoundaryError(releaseErr)
	err = errors.Join(err, releaseErr)
	done()
	if err != nil {
		cancel()
	}
	var results [3]error
	for joined := 0; joined < 3; joined++ {
		select {
		case result := <-completed:
			results[result.index] = result.err
		case <-ctx.Done():
			boundary.join = "outer-" + recoveryContentionBoundaryError(ctx.Err())
			if boundary.joinObserved != nil {
				close(boundary.joinObserved)
			}
			// Cancellation is not a successful join. Give context-aware product
			// calls one bounded cleanup interval and reject any escaped caller.
			cancel()
			joinCtx, stopJoin := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer stopJoin()
			for ; joined < 3; joined++ {
				select {
				case result := <-completed:
					results[result.index] = result.err
				case <-joinCtx.Done():
					boundary.join = "unjoined"
					return results, errors.Join(err, errors.New("contention caller did not join"))
				}
			}
			return results, errors.Join(err, ctx.Err())
		}
	}
	return results, err
}

// Ordinary transaction-scoped lock contention only: no functions, grants,
// readiness values or fixture evidence are replaced to create this barrier.
func singleRecoveryContentionApplication(run string) string {
	return "recovery-contention-" + run
}

func waitRecoverySQLContention(ctx context.Context, owner *pgxpool.Pool, blocker uint32, run, application string) error {
	const query = `WITH held AS(SELECT * FROM pg_catalog.pg_locks WHERE pid=$1 AND locktype='advisory' AND granted)
 SELECT count(DISTINCT w.pid) FROM pg_catalog.pg_locks w JOIN held h ON(w.locktype,w.database,w.classid,w.objid,w.objsubid)=(h.locktype,h.database,h.classid,h.objid,h.objsubid)
 JOIN pg_catalog.pg_stat_activity a ON a.pid=w.pid WHERE NOT w.granted AND a.usename='worker_test_compensation' AND a.application_name=$2`
	for ctx.Err() == nil {
		var waiting int
		if err := owner.QueryRow(ctx, query, blocker, application).Scan(&waiting); err != nil {
			return err
		}
		if waiting > 3 {
			return errors.New("unexpected contention participant")
		}
		if waiting == 3 {
			var absent bool
			if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.child_receipts WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.completion_receipts WHERE run_id=$1)`, run).Scan(&absent); err != nil {
				return err
			}
			if !absent {
				return errors.New("contention began after first settlement")
			}
			return nil
		}
		runtime.Gosched()
	}
	return ctx.Err()
}

func TestSingleRecoveryContentionApplicationName(t *testing.T) {
	runs := []string{"pid_f0807400-0000-4000-8000-000000000001", "pid_f0807400-0000-4000-8000-000000000011"}
	seen := map[string]bool{}
	for _, run := range runs {
		application := singleRecoveryContentionApplication(run)
		if len(application) > 63 {
			t.Fatalf("PostgreSQL truncates contention application name for %q: %d bytes", run, len(application))
		}
		if !strings.HasSuffix(application, run) || seen[application] {
			t.Fatalf("contention application selector lost the distinct full run: %q", application)
		}
		seen[application] = true
	}
}

func TestSingleTestRecoveryContentionJoinsAndReleases(t *testing.T) {
	for _, failedWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "release after all callers block", true: "failed wait cancels and joins"}[failedWait], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{}, 3)
			gate := make(chan struct{})
			var exits, releases atomic.Int32
			pending := errors.New("pending result")
			waitErr := errors.New("observed barrier failed")
			var calls [3]func(context.Context) error
			for i := range calls {
				calls[i] = func(ctx context.Context) error {
					defer exits.Add(1)
					if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 45*time.Second {
						t.Error("caller bound missing")
					}
					entered <- struct{}{}
					select {
					case <-gate:
						return pending
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
			boundary := newRecoveryContentionBoundary()
			results, err := runRecoveryContention(ctx, calls, func(ctx context.Context) error {
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
					t.Error("wait bound missing")
				}
				for i := 0; i < 3; i++ {
					select {
					case <-entered:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if failedWait {
					return waitErr
				}
				return nil
			}, func(ctx context.Context) error {
				if ctx.Err() != nil {
					t.Error("cleanup inherited cancellation")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("cleanup has no bound")
				}
				releases.Add(1)
				close(gate)
				return nil
			}, &boundary)
			if releases.Load() != 1 || exits.Load() != 3 {
				t.Fatalf("release/join = %d/%d, want 1/3", releases.Load(), exits.Load())
			}
			if failedWait {
				if !errors.Is(err, waitErr) {
					t.Fatal("primary wait error lost", err)
				}
				if boundary.wait != "error" || boundary.release != "ok" {
					t.Fatalf("failed wait boundary=%+v", boundary)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				for _, result := range results {
					if !errors.Is(result, pending) {
						t.Fatal("caller result lost", result)
					}
				}
				if boundary != (recoveryContentionBoundary{wait: "ready", release: "ok", join: "complete", elapsed: "lt5s"}) {
					t.Fatalf("normal boundary=%+v", boundary)
				}
			}
		})
	}
}

func TestSingleTestRecoveryContentionReleaseFailureStillJoins(t *testing.T) {
	entered, gate := make(chan struct{}, 3), make(chan struct{})
	var exited atomic.Int32
	var calls [3]func(context.Context) error
	for i := range calls {
		calls[i] = func(ctx context.Context) error {
			defer exited.Add(1)
			entered <- struct{}{}
			select {
			case <-gate:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	releaseErr := errors.New("rollback failed")
	boundary := newRecoveryContentionBoundary()
	_, err := runRecoveryContention(context.Background(), calls, func(ctx context.Context) error {
		for i := 0; i < 3; i++ {
			select {
			case <-entered:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}, func(context.Context) error { close(gate); return releaseErr }, &boundary)
	if !errors.Is(err, releaseErr) || exited.Load() != 3 {
		t.Fatal("release failure lost or callers escaped", err, exited.Load())
	}
	if boundary.wait != "ready" || boundary.release != "error" || boundary.join == "unjoined" {
		t.Fatalf("release boundary=%+v", boundary)
	}
}

func TestSingleTestRecoveryContentionBoundaryDeadlineAndUnjoined(t *testing.T) {
	t.Run("outer deadline after a ready wait", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		joinObserved := make(chan struct{})
		var calls [3]func(context.Context) error
		for i := range calls {
			calls[i] = func(ctx context.Context) error {
				<-ctx.Done()
				<-joinObserved
				return ctx.Err()
			}
		}
		boundary := newRecoveryContentionBoundary()
		boundary.joinObserved = joinObserved
		_, err := runRecoveryContention(ctx, calls, func(context.Context) error { return nil }, func(context.Context) error { return nil }, &boundary)
		if !errors.Is(err, context.DeadlineExceeded) || boundary.wait != "ready" || boundary.release != "ok" || boundary.join != "outer-deadline" {
			t.Fatalf("outer deadline boundary=%+v err=%v", boundary, err)
		}
	})

	t.Run("wait deadline is distinct", func(t *testing.T) {
		var calls [3]func(context.Context) error
		for i := range calls {
			calls[i] = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		}
		boundary := newRecoveryContentionBoundary()
		_, err := runRecoveryContention(context.Background(), calls, func(context.Context) error { return context.DeadlineExceeded }, func(context.Context) error { return nil }, &boundary)
		if !errors.Is(err, context.DeadlineExceeded) || boundary.wait != "deadline" || boundary.join == "unjoined" {
			t.Fatalf("wait deadline boundary=%+v err=%v", boundary, err)
		}
	})

	t.Run("escaped caller is unjoined", func(t *testing.T) {
		gate := make(chan struct{})
		defer close(gate)
		ctx, cancel := context.WithCancel(context.Background())
		var calls [3]func(context.Context) error
		for i := range calls {
			calls[i] = func(context.Context) error { <-gate; return nil }
		}
		boundary := newRecoveryContentionBoundary()
		cancel()
		_, err := runRecoveryContention(ctx, calls, func(context.Context) error { return nil }, func(context.Context) error { return nil }, &boundary)
		if err == nil || boundary.join != "unjoined" {
			t.Fatalf("unjoined boundary=%+v err=%v", boundary, err)
		}
	})
}

func TestSingleTestRecoverySettleContinuationIsExact(t *testing.T) {
	live := context.Background()
	exact := recoveryContentionBoundary{wait: "ready", release: "ok", join: "outer-deadline", elapsed: "ge45s"}
	pending := errors.New("other pending")
	allowed := [][3]error{
		{nil, orchestration.ErrCleanupPending, orchestration.ErrUnavailable},
		{context.DeadlineExceeded, nil, orchestration.ErrCleanupPending},
	}
	for i, results := range allowed {
		if !continueSingleRecoverySettleAfterContention(false, live, exact, results, context.DeadlineExceeded) {
			t.Fatalf("exact settle timeout %d was not handed to the durable workflow", i)
		}
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	refusals := []struct {
		name       string
		pending    bool
		parent     context.Context
		boundary   recoveryContentionBoundary
		results    [3]error
		contention error
	}{
		{"pending phase", true, live, exact, allowed[0], context.DeadlineExceeded},
		{"canceled parent", false, canceled, exact, allowed[0], context.DeadlineExceeded},
		{"wait failure", false, live, recoveryContentionBoundary{wait: "deadline", release: "ok", join: "outer-deadline", elapsed: "ge45s"}, allowed[0], context.DeadlineExceeded},
		{"release failure", false, live, recoveryContentionBoundary{wait: "ready", release: "error", join: "outer-deadline", elapsed: "ge45s"}, allowed[0], context.DeadlineExceeded},
		{"completed join", false, live, recoveryContentionBoundary{wait: "ready", release: "ok", join: "complete", elapsed: "ge45s"}, allowed[0], context.DeadlineExceeded},
		{"canceled join", false, live, recoveryContentionBoundary{wait: "ready", release: "ok", join: "outer-canceled", elapsed: "ge45s"}, allowed[0], context.DeadlineExceeded},
		{"unjoined caller", false, live, recoveryContentionBoundary{wait: "ready", release: "ok", join: "unjoined", elapsed: "ge45s"}, allowed[0], context.DeadlineExceeded},
		{"short elapsed", false, live, recoveryContentionBoundary{wait: "ready", release: "ok", join: "outer-deadline", elapsed: "lt45s"}, allowed[0], context.DeadlineExceeded},
		{"arbitrary contention error", false, live, exact, allowed[0], errors.New("private contention")},
		{"arbitrary result", false, live, exact, [3]error{nil, pending, nil}, context.DeadlineExceeded},
		{"canceled result", false, live, exact, [3]error{context.Canceled, nil, nil}, context.DeadlineExceeded},
		{"orchestration conflict", false, live, exact, [3]error{orchestration.ErrConflict, nil, nil}, context.DeadlineExceeded},
		{"orchestration invalid", false, live, exact, [3]error{orchestration.ErrInvalid, nil, nil}, context.DeadlineExceeded},
		{"authorization conflict", false, live, exact, [3]error{authorization.ErrConflict, nil, nil}, context.DeadlineExceeded},
		{"authorization invalid", false, live, exact, [3]error{authorization.ErrInvalid, nil, nil}, context.DeadlineExceeded},
		{"authorization denied", false, live, exact, [3]error{authorization.ErrDenied, nil, nil}, context.DeadlineExceeded},
		{"deadline result without timeout", false, live, exact, allowed[1], nil},
	}
	for _, refusal := range refusals {
		t.Run(refusal.name, func(t *testing.T) {
			if continueSingleRecoverySettleAfterContention(refusal.pending, refusal.parent, refusal.boundary, refusal.results, refusal.contention) {
				t.Fatal("nonexact contention outcome reached the durable workflow")
			}
		})
	}
}
