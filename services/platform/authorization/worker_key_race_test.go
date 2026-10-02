package authorization

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The subprocess bounds a blocking FIFO open without leaving a stuck goroutine
// in the test runner. Every replaced path and FIFO belongs to this fixture.
func TestWorkerKeyPathReplacementDoesNotBlock(t *testing.T) {
	if os.Getenv("ZASP_WORKER_KEY_RACE_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkerKeyPathReplacementDoesNotBlock$", "-test.count=1")
		// Parent owns cleanup even when it must kill a blocked child.
		child.Env = append(os.Environ(), "ZASP_WORKER_KEY_RACE_CHILD=1", "TMPDIR="+t.TempDir())
		output, err := child.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatal("owned key loader child blocked during regular-file/FIFO replacement")
		}
		if err != nil {
			t.Fatalf("owned replacement child failed: %v\n%s", err, output)
		}
		return
	}
	dir := t.TempDir()
	regular, pipe, target, stage := filepath.Join(dir, "regular"), filepath.Join(dir, "fifo"), filepath.Join(dir, "key"), filepath.Join(dir, "stage")
	if err := os.WriteFile(regular, bytes.Repeat([]byte{45}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(pipe, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(regular, target); err != nil {
		t.Fatal(err)
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	failures := make(chan error, 1)
	var replacements atomic.Int64
	go func() {
		defer close(joined)
		for {
			for _, source := range []string{pipe, regular} {
				select {
				case <-stop:
					return
				default:
				}
				if err := os.Link(source, stage); err != nil {
					failures <- err
					return
				}
				if err := os.Rename(stage, target); err != nil {
					failures <- err
					return
				}
				replacements.Add(1)
			}
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		key, err := LoadWorkerKeyFile(WorkerForward, target)
		if err != nil && err != ErrInvalid {
			t.Fatal("replacement leaked an unclassified error")
		}
		if err == nil && key == nil {
			t.Fatal("empty key accepted")
		}
	}
	close(stop)
	<-joined
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	if replacements.Load() < 100 {
		t.Fatal("replacement fixture did not exercise race")
	}
}
