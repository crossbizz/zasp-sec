//go:build darwin || linux

package testprocess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// An early successful pipe EOF must not return while the leader is live.
func TestOwnedOutputEarlyEOFStillObservesProcess(t *testing.T) {
	fixture := startOwnedLiveFixture(t, "closed-pipes", "close-output", Run)
	fixture.waitReady(t)
	select {
	case got := <-fixture.done:
		fixture.returned = true
		t.Fatalf("EOF returned with a live leader: %v", got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "stop"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := fixture.result(t, 4*time.Second)
	if got.err != nil || len(got.body) != 0 {
		t.Fatalf("early EOF result bytes=%d err=%v", len(got.body), got.err)
	}
	fixture.assertJoined(t, got.err)
}

func TestOwnedOutputLimitCancellationJoinsErrors(t *testing.T) {
	fixture := startOwnedLiveFixture(t, "inherited-pipes", "overflow", func(ctx context.Context, command *exec.Cmd) ([]byte, error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		return runOwnedWithSignals(ctx, command, observeSandboxWorkerExit, func(pid int, sig unix.Signal) error {
			// The real overflow handling initiates TERM; arrange concurrent
			// cancellation at this boundary without changing actual signaling.
			cancel()
			return sandboxWorkerGroupSignal(pid, sig)
		})
	})
	fixture.waitReady(t)
	if err := os.WriteFile(filepath.Join(fixture.root, "write"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := fixture.result(t, 4*time.Second)
	if !errors.Is(got.err, ErrOutputLimit) || !errors.Is(got.err, context.Canceled) || len(got.body) > 1048576 {
		t.Fatalf("simultaneous cancellation lost error: bytes=%d err=%v", len(got.body), got.err)
	}
	if ownedListenerReachable(fixture.ready.Address) {
		t.Fatal("listener survived concurrent overflow/cancellation")
	}
	fixture.assertJoined(t, got.err)
}

type finalReadError struct {
	body *bytes.Reader
	err  error
}

func (r finalReadError) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if r.body.Len() == 0 {
		return n, r.err
	}
	return n, err
}

// Dropping data delivered with EOF or swallowing a read failure breaks these
// boundary cases. The reader double changes only the final error convention.
func TestOwnedOutputReaderFinalDataAndError(t *testing.T) {
	failure := errors.New("injected output read failure")
	for _, test := range []struct {
		name     string
		size     int
		readErr  error
		overflow bool
	}{
		{"data-with-EOF", 13, io.EOF, false},
		{"data-with-failure", 13, failure, false},
		{"overflow-with-failure", 1048577, failure, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := readOwnedOutput(finalReadError{bytes.NewReader(bytes.Repeat([]byte{'a'}, test.size)), test.readErr})
			wantSize := test.size
			if test.overflow {
				wantSize = 1048576
			}
			if len(got.body) != wantSize || bytes.Count(got.body, []byte{'a'}) != wantSize {
				t.Fatalf("retained bytes=%d want=%d", len(got.body), wantSize)
			}
			if errors.Is(got.err, ErrOutputLimit) != test.overflow || errors.Is(got.err, failure) != (test.readErr == failure) || (got.err == nil) != (test.readErr == io.EOF && !test.overflow) {
				t.Fatalf("read errors=%v", got.err)
			}
		})
	}
}

// exec's reader copier can make Wait unbounded. Reject it before Start,
// without taking ownership of a caller's valid file.
func TestOwnedStdin(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("file input"); err != nil {
		t.Fatal(err)
	}
	var typedNil *os.File
	for _, test := range []struct {
		name    string
		input   io.Reader
		allowed bool
		want    string
	}{
		{"nil", nil, true, ""},
		{"file", file, true, "file input"},
		{"reader", strings.NewReader("copied input"), false, ""},
		{"typed-nil-file", typedNil, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := file.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.Command("/bin/cat")
			command.Stdin = test.input
			body, err := Run(ctx, command)
			if test.allowed {
				if err != nil || string(body) != test.want {
					t.Fatalf("stdin output=%q err=%v", body, err)
				}
				if _, err := file.Stat(); err != nil {
					t.Fatal("runner closed caller file", err)
				}
			} else if err == nil || command.Process != nil {
				t.Fatalf("unsupported stdin started=%t err=%v", command.Process != nil, err)
			}
		})
	}
}

// A post-EOF length check cannot stop a live writer and its listening child.
func TestOwnedOutputLimitLive(t *testing.T) {
	for _, mode := range []string{"inherited-pipes", "closed-pipes"} {
		t.Run(mode, func(t *testing.T) {
			fixture := startOwnedLiveFixture(t, mode, "overflow", Run)
			fixture.waitReady(t)
			if err := os.WriteFile(filepath.Join(fixture.root, "write"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			got := fixture.result(t, 4*time.Second)
			if fixture.ctx.Err() != nil || !errors.Is(got.err, ErrOutputLimit) || len(got.body) > 1<<20 {
				t.Fatalf("live output admission: bytes=%d err=%v caller=%v", len(got.body), got.err, fixture.ctx.Err())
			}
			if ownedListenerReachable(fixture.ready.Address) {
				t.Fatal("descendant listener survived overflow")
			}
			fixture.assertJoined(t, got.err)
		})
	}
}

// Removing admission on the first excess byte must fail cap-plus-one, while
// killing on merely reaching the cap must fail the exact-cap positive.
func TestOwnedOutputLimit(t *testing.T) {
	for _, mode := range []string{"exact-cap", "cap-plus-one"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.Command(os.Args[0], "-test.run=^TestOwnedOutputChild$")
			command.Env = []string{"ZASP_OWNED_OUTPUT_MODE=" + mode}
			body, err := Run(ctx, command)
			t.Logf("bytes=%d run_error=%v reaped=%t", len(body), err, command.ProcessState != nil)
			if command.ProcessState == nil {
				t.Fatal("direct child was not reaped")
			}
			if groupErr := unix.Kill(-command.Process.Pid, 0); groupErr != unix.ESRCH {
				t.Fatalf("owned group absence not confirmed: %v", groupErr)
			}
			if mode == "cap-plus-one" {
				if !errors.Is(err, ErrOutputLimit) || len(body) > 1<<20 {
					t.Fatalf("output admission: bytes=%d err=%v", len(body), err)
				}
			} else if err != nil || command.ProcessState.ExitCode() != 0 || len(body) != 1<<20 || bytes.Count(body, []byte{'a'}) != 524288 || bytes.Count(body, []byte{'b'}) != 524288 {
				t.Fatalf("exact-cap output changed: bytes=%d err=%v", len(body), err)
			}
		})
	}
}

func TestOwnedOutputChild(t *testing.T) {
	mode := os.Getenv("ZASP_OWNED_OUTPUT_MODE")
	if mode == "" {
		return
	}
	if mode != "exact-cap" && mode != "cap-plus-one" {
		os.Exit(10)
	}
	secondSize := 524288
	if mode == "cap-plus-one" {
		secondSize++
	}
	first, second := bytes.Repeat([]byte{'a'}, 524288), bytes.Repeat([]byte{'b'}, secondSize)
	if n, err := os.Stdout.Write(first); err != nil || n != len(first) {
		os.Exit(11)
	}
	if n, err := os.Stderr.Write(second); err != nil || n != len(second) {
		os.Exit(12)
	}
	os.Exit(0)
}
