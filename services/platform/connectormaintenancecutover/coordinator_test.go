package connectormaintenancecutover

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type prepareStageEvidence struct {
	calls     []string
	failure   string
	cancel    context.CancelFunc
	liveCalls int
}

func (e *prepareStageEvidence) live(ctx context.Context, pid int) (identity, error) {
	e.liveCalls++
	stage := "live-before"
	if e.liveCalls > 1 {
		stage = "live-after"
	}
	e.calls = append(e.calls, stage)
	if e.failure == stage {
		return identity{}, errors.New("private dependency detail")
	}
	if e.failure == "deadline" {
		e.cancel()
		return identity{}, context.Canceled
	}
	return identity{pid: pid, start: "owned-process", sha256: "immutable-executable"}, nil
}
func (e *prepareStageEvidence) oldModel(context.Context) error {
	e.calls = append(e.calls, "model-read")
	if e.failure == "model-read" {
		return errors.New("private model detail")
	}
	return nil
}
func (*prepareStageEvidence) oldUnauthorized(context.Context) error  { return nil }
func (*prepareStageEvidence) newModel(context.Context) error         { return nil }
func (*prepareStageEvidence) absent(context.Context, identity) error { return nil }

type prepareStageActivation struct{}

func (prepareStageActivation) activate(context.Context, string, identity, func(context.Context) error) error {
	return nil
}

func TestControlledPrepareRefusalStages(t *testing.T) {
	for _, tc := range []struct {
		stage string
		calls []string
	}{
		{"invalid", nil}, {"live-before", []string{"live-before"}}, {"model-read", []string{"live-before", "model-read"}}, {"live-after", []string{"live-before", "model-read", "live-after"}}, {"deadline", []string{"live-before"}},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			evidence := &prepareStageEvidence{failure: tc.stage, cancel: cancel}
			c := &Coordinator{observations: evidence, sql: prepareStageActivation{}, ttl: time.Second}
			pid := 123
			if tc.stage == "invalid" {
				pid = 0
			}
			p, err := c.Prepare(ctx, "organization", pid)
			if p != nil || !errors.Is(err, ErrRefused) || err.Error() != ErrRefused.Error() || PrepareRefusalStage(fmt.Errorf("outer private detail: %w", err)) != tc.stage {
				t.Fatalf("closed refusal mismatch: permit=%v error=%v stage=%s", p != nil, err, PrepareRefusalStage(err))
			}
			if !reflect.DeepEqual(evidence.calls, tc.calls) {
				t.Fatalf("guard order changed: %v", evidence.calls)
			}
		})
	}
	t.Run("success retains exact observed writer", func(t *testing.T) {
		evidence := &prepareStageEvidence{}
		c := &Coordinator{observations: evidence, sql: prepareStageActivation{}, ttl: time.Second}
		p, err := c.Prepare(context.Background(), "organization", 123)
		if err != nil || p == nil || p.writer.pid != 123 || !reflect.DeepEqual(evidence.calls, []string{"live-before", "model-read", "live-after"}) || PrepareRefusalStage(err) != "unknown" {
			t.Fatal("successful prepare changed")
		}
	})
	t.Run("arbitrary errors disclose no stage", func(t *testing.T) {
		for _, err := range []error{nil, ErrRefused, errors.New("model-read: secret value")} {
			if PrepareRefusalStage(err) != "unknown" {
				t.Fatal("untyped error became diagnostic authority")
			}
		}
	})
}

// Activation diagnostics disclose fixed guard stages while keeping one-use permits.
func TestControlledActivateRefusalStages(t *testing.T) {
	for _, stage := range []string{"old-credential", "writer-absence", "new-model", "sql-activation", "deadline"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observations := &activationStageEvidence{failure: stage, cancel: cancel}
			operation := &activationStageSQL{failure: stage}
			coordinator := &Coordinator{observations: observations, sql: operation, ttl: time.Second}
			permit, err := coordinator.Prepare(ctx, "organization", 123)
			if err != nil {
				t.Fatal("prepare refused")
			}
			err = coordinator.Activate(ctx, permit)
			if !errors.Is(err, ErrRefused) || err.Error() != ErrRefused.Error() || ActivationRefusalStage(fmt.Errorf("private wrapper: %w", err)) != stage {
				t.Fatalf("closed stage mismatch: %s", ActivationRefusalStage(err))
			}
			if coordinator.Activate(context.Background(), permit) == nil || operation.calls > 1 {
				t.Fatal("spent permit replayed")
			}
		})
	}
	for _, err := range []error{nil, ErrRefused, errors.New("sql-activation: private SQL text")} {
		if ActivationRefusalStage(err) != "unknown" {
			t.Fatal("untyped diagnostic accepted")
		}
	}
}

type activationStageEvidence struct {
	failure string
	cancel  context.CancelFunc
}

func (*activationStageEvidence) live(_ context.Context, pid int) (identity, error) {
	return identity{pid: pid, start: "owned-process"}, nil
}
func (*activationStageEvidence) oldModel(context.Context) error { return nil }
func (e *activationStageEvidence) oldUnauthorized(context.Context) error {
	if e.failure == "deadline" {
		e.cancel()
		return context.Canceled
	}
	if e.failure == "old-credential" {
		return errors.New("private token failure")
	}
	return nil
}
func (e *activationStageEvidence) absent(context.Context, identity) error {
	if e.failure == "writer-absence" {
		return errors.New("private process detail")
	}
	return nil
}
func (e *activationStageEvidence) newModel(context.Context) error {
	if e.failure == "new-model" {
		return errors.New("private model detail")
	}
	return nil
}

type activationStageSQL struct {
	failure string
	calls   int
}

func (s *activationStageSQL) activate(ctx context.Context, _ string, _ identity, verify func(context.Context) error) error {
	s.calls++
	if e := verify(ctx); e != nil {
		return e
	}
	if s.failure == "sql-activation" {
		return activationRefused(ctx, "sql-activation")
	}
	return nil
}
