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
