package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

// One product Activity may run for five minutes. Give its completion and the
// next checkpoint poll a minute before declaring the scale fixture stalled.
const continuationStallLimit = 6 * time.Minute

type continuationProgress struct {
	checkpoint int64
	advanced   time.Time
}

func (p *continuationProgress) observe(now time.Time, version int64) error {
	switch {
	case version < p.checkpoint:
		return fmt.Errorf("durable checkpoint regressed from %d to %d", p.checkpoint, version)
	case version > p.checkpoint:
		p.checkpoint = version
		p.advanced = now
	case now.Sub(p.advanced) >= continuationStallLimit:
		return fmt.Errorf("durable checkpoint %d stalled for %s", version, now.Sub(p.advanced))
	}
	return nil
}

func runDiscoveryContinuation(ctx context.Context, child *exec.Cmd, readCheckpoint func(context.Context) (int64, error)) ([]byte, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	watched := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		progress := continuationProgress{advanced: time.Now()}
		for {
			select {
			case <-childCtx.Done():
				watched <- nil
				return
			case now := <-ticker.C:
				readCtx, stop := context.WithTimeout(childCtx, 5*time.Second)
				checkpoint, err := readCheckpoint(readCtx)
				stop()
				if childCtx.Err() != nil {
					watched <- nil
					return
				}
				if err != nil {
					err = fmt.Errorf("read durable checkpoint: %w", err)
				} else {
					err = progress.observe(now, checkpoint)
				}
				if err != nil {
					cancel()
					watched <- err
					return
				}
			}
		}
	}()
	output, childErr := testprocess.Run(childCtx, child)
	cancel()
	return output, errors.Join(childErr, <-watched)
}

func TestTemporalContinuationDurableProgress(t *testing.T) {
	start := time.Unix(0, 0)
	progress := continuationProgress{advanced: start}
	if err := progress.observe(start.Add(5*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	for version := int64(1); version <= 268; version++ {
		at := start.Add(time.Duration(version)*12*time.Second + 5*time.Minute)
		if err := progress.observe(at, version); err != nil {
			t.Fatalf("continuing checkpoint %d: %v", version, err)
		}
	}
	lastChange := progress.advanced
	if err := progress.observe(lastChange.Add(continuationStallLimit-time.Second), 268); err != nil {
		t.Fatal(err)
	}
	if err := progress.observe(lastChange.Add(continuationStallLimit), 268); err == nil {
		t.Fatal("repeated observations reset the stall timer")
	}
	if err := progress.observe(lastChange.Add(time.Second), 267); err == nil {
		t.Fatal("regressing checkpoint counted as progress")
	}
}
