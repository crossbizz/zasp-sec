//go:build darwin || linux

package testprocess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Publishing any terminal result must close fault authority without consuming
// that result or disabling the unchanged known-owned final cleanup authority.
func TestOwnedForcePublication(t *testing.T) {
	for _, state := range []string{"pending", "lost", "owned-exit", "owned-error"} {
		t.Run(state, func(t *testing.T) {
			p := newExitPublication()
			failure := errors.New("observer failure")
			observation := exitObservation{owned: state != "lost"}
			if state == "lost" || state == "owned-error" {
				observation.err = failure
			}
			if state != "pending" {
				p.publish(observation)
			}
			calls := 0
			dispatched, err := p.forceKill(12345, func(pid int, sig unix.Signal) error {
				calls++
				if pid != 12345 || sig != unix.SIGKILL {
					t.Errorf("force identity: %d %v", pid, sig)
				}
				return nil
			})
			want := state == "pending"
			if err != nil || dispatched != want || (calls == 1) != want || calls > 1 {
				t.Fatalf("state=%s dispatched=%t calls=%d err=%v", state, dispatched, calls, err)
			}
			if !want && <-p.result != observation {
				t.Fatal("fault attempt changed terminal observation")
			}
		})
	}
}

func TestOwnedForcePreStart(t *testing.T) {
	for _, mode := range []string{"value", "closed"} {
		t.Run(mode, func(t *testing.T) {
			request := make(chan struct{}, 1)
			if mode == "closed" {
				close(request)
			} else {
				request <- struct{}{}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedForceChild$")
			_, err := RunWithForceKill(context.Background(), cmd, request)
			if err == nil || errors.Is(err, ErrForceKilled) || cmd.Process != nil {
				t.Fatalf("prestart request: process=%v err=%v", cmd.Process, err)
			}
		})
	}
}

func TestOwnedForceNaturalAndLate(t *testing.T) {
	for _, mode := range []string{"nil", "late"} {
		t.Run(mode, func(t *testing.T) {
			var request chan struct{}
			if mode == "late" {
				request = make(chan struct{})
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedForceChild$")
			var calls atomic.Int32
			_, err := runOwnedWithForceKill(context.Background(), cmd, observeSandboxWorkerExit, func(pid int, sig unix.Signal) error {
				calls.Add(1)
				return sandboxWorkerGroupSignal(pid, sig)
			}, request)
			if err != nil || cmd.ProcessState == nil || !cmd.ProcessState.Success() {
				t.Fatalf("natural: %v", err)
			}
			before := calls.Load()
			if request != nil {
				close(request)
			}
			if before != 1 || calls.Load() != before {
				t.Fatalf("late signals: %d -> %d", before, calls.Load())
			}
		})
	}
}

func TestOwnedForceOneShot(t *testing.T) {
	request := make(chan struct{}, 2)
	var calls atomic.Int32
	f := startForceFixture(t, "closed-pipes", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		return runOwnedWithForceKill(ctx, cmd, observeSandboxWorkerExit, func(pid int, sig unix.Signal) error {
			if sig != unix.SIGKILL {
				t.Errorf("unexpected signal %v", sig)
			}
			calls.Add(1)
			return sandboxWorkerGroupSignal(pid, sig)
		}, request)
	})
	f.waitReady(t)
	request <- struct{}{}
	request <- struct{}{}
	got := f.result(t, 3*time.Second)
	if got.err != ErrForceKilled || len(request) != 1 || calls.Load() != 2 {
		t.Fatalf("one-shot: pending=%d signals=%d err=%v", len(request), calls.Load(), got.err)
	}
	f.assertJoined(t, got.err)
}

// Removing the clean-error gate would hide the supplied cleanup cause, including
// a joined SIGKILL error. Obtain the ProcessState from this runner's real Wait.
func TestOwnedForceClassification(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedForceChild$")
	cmd.Env = []string{"ZASP_OWNED_FORCE_SELF_KILL=1"}
	_, err := Run(context.Background(), cmd)
	var killed *exec.ExitError
	if !errors.As(err, &killed) || err == ErrForceKilled {
		t.Fatalf("ordinary SIGKILL: %v", err)
	}
	if status := killed.Sys().(syscall.WaitStatus); status.Signal() != syscall.SIGKILL {
		t.Fatalf("wait status: %v", status)
	}
	if got := classifyForceKill(true, killed, nil); got != ErrForceKilled {
		t.Fatalf("clean: %v", got)
	}
	for _, failure := range []error{unix.EPERM, context.Canceled, ErrOutputLimit, io.ErrUnexpectedEOF, ErrGroupRemaining, errors.New("watcher failed"), errors.New("reap incomplete")} {
		t.Run(failure.Error(), func(t *testing.T) {
			got := classifyForceKill(true, killed, failure)
			var preserved *exec.ExitError
			if errors.Is(got, ErrForceKilled) || !errors.Is(got, failure) || !errors.As(got, &preserved) || preserved != killed {
				t.Fatalf("failure lost: %v", got)
			}
		})
	}
	for _, waitErr := range []error{nil, errors.New("wait failed"), errors.Join(killed, unix.EPERM), &exec.ExitError{}} {
		if got := classifyForceKill(true, waitErr, nil); errors.Is(got, ErrForceKilled) || !errors.Is(got, waitErr) {
			t.Fatalf("non-clean wait: %v", got)
		}
	}
	if got := classifyForceKill(false, killed, nil); errors.Is(got, ErrForceKilled) || !errors.Is(got, killed) {
		t.Fatalf("unrequested: %v", got)
	}
	ordinary := exec.Command(os.Args[0], "-test.run=^TestOwnedForceChild$")
	ordinary.Env = []string{"ZASP_OWNED_FORCE_EXIT=7"}
	_, ordinaryErr := Run(context.Background(), ordinary)
	var exited *exec.ExitError
	if !errors.As(ordinaryErr, &exited) || exited.ExitCode() != 7 {
		t.Fatalf("ordinary exit: %v", ordinaryErr)
	}
	if got := classifyForceKill(true, exited, nil); errors.Is(got, ErrForceKilled) || !errors.Is(got, exited) {
		t.Fatalf("non-SIGKILL: %v", got)
	}
}

// Holding Done delays only the owner loop; the real observer and output reader
// keep running. It makes request and cancellation pending before either branch.
type forceGateContext struct {
	context.Context
	gate <-chan struct{}
}

func (c forceGateContext) Done() <-chan struct{} { <-c.gate; return c.Context.Done() }

func TestOwnedForcePendingStop(t *testing.T) {
	for _, cause := range []string{"context", "overflow"} {
		t.Run(cause, func(t *testing.T) {
			request, gate := make(chan struct{}), make(chan struct{})
			var once sync.Once
			open := func() { once.Do(func() { close(gate) }) }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var terms atomic.Int32
			f := startForceFixture(t, "closed-pipes", func(_ context.Context, cmd *exec.Cmd) ([]byte, error) {
				if cause == "overflow" {
					cmd.Env = append(cmd.Env, "ZASP_OWNED_FORCE_OVERFLOW=1")
				}
				return runOwnedWithForceKill(forceGateContext{ctx, gate}, cmd, observeSandboxWorkerExit, func(pid int, sig unix.Signal) error {
					if sig == unix.SIGTERM {
						terms.Add(1)
					}
					return sandboxWorkerGroupSignal(pid, sig)
				}, request)
			})
			t.Cleanup(open)
			f.waitReady(t)
			if cause == "context" {
				cancel()
			} else {
				if !ownedFixtureFileBeforeDeadline(f.root, "wrote") {
					t.Fatal("overflow not written")
				}
			}
			close(request)
			open()
			got := f.result(t, 3*time.Second)
			want := error(context.Canceled)
			if cause == "overflow" {
				want = ErrOutputLimit
			}
			if !errors.Is(got.err, want) || errors.Is(got.err, ErrForceKilled) || terms.Load() != 0 {
				t.Fatalf("pending stop: terms=%d err=%v", terms.Load(), got.err)
			}
			f.assertJoined(t, got.err)
		})
	}
}

func TestOwnedForceFailures(t *testing.T) {
	for _, mode := range []string{"denied", "watcher"} {
		t.Run(mode, func(t *testing.T) {
			request := make(chan struct{})
			failure := errors.New("injected force watcher failure")
			var calls atomic.Int32
			f := startForceFixture(t, "closed-pipes", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				return runOwnedWithForceKill(ctx, cmd, func(pid int) exitObservation {
					observation := observeSandboxWorkerExit(pid)
					if mode == "watcher" {
						observation.err = errors.Join(observation.err, failure)
					}
					return observation
				}, func(pid int, sig unix.Signal) error {
					calls.Add(1)
					if mode == "denied" {
						return unix.EPERM
					}
					return sandboxWorkerGroupSignal(pid, sig)
				}, request)
			})
			f.waitReady(t)
			close(request)
			got := f.result(t, 3*time.Second)
			want := error(failure)
			if mode == "denied" {
				want = unix.EPERM
			}
			if !errors.Is(got.err, want) || errors.Is(got.err, ErrForceKilled) {
				t.Fatalf("failed force: %v", got.err)
			}
			if mode == "denied" {
				if !ownedListenerReachable(f.ready.Address) || calls.Load() != 1 {
					t.Fatalf("denied fixture: signals=%d", calls.Load())
				}
				f.cleanup(t) // The sole background Wait is joined by cooperative exit.
				if calls.Load() != 1 {
					t.Fatal("late signal after denied force")
				}
			} else {
				var exitErr *exec.ExitError
				if !errors.As(got.err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatalf("SIGKILL error lost: %v", got.err)
				}
				f.assertJoined(t, got.err)
			}
		})
	}
}

// The observer withholds publication until the owner receives the late request.
// Removing the killed guard sends a third KILL and incorrectly credits it.
func TestOwnedForceAfterOrdinaryKill(t *testing.T) {
	request, received, quit := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := startForceFixture(t, "closed-pipes", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		return runOwnedWithForceKill(ctx, cmd, func(pid int) exitObservation {
			observation := observeSandboxWorkerExit(pid)
			select {
			case <-received:
			case <-time.After(time.Second):
				observation.err = errors.New("late request not received")
			}
			return observation
		}, func(pid int, sig unix.Signal) error {
			if sig == unix.SIGKILL && calls.Add(1) == 1 {
				go func() {
					defer close(received)
					select {
					case request <- struct{}{}:
					case <-quit:
					}
				}()
			}
			return sandboxWorkerGroupSignal(pid, sig)
		}, request)
	})
	t.Cleanup(func() { close(quit) })
	f.waitReady(t)
	f.cancel()
	got := f.result(t, 3*time.Second)
	if !errors.Is(got.err, context.Canceled) || errors.Is(got.err, ErrForceKilled) || calls.Load() != 2 {
		t.Fatalf("late fault: KILLs=%d err=%v", calls.Load(), got.err)
	}
	f.assertJoined(t, got.err)
}

func TestOwnedForceDuringGrace(t *testing.T) {
	request := make(chan struct{})
	var termAt, killAt time.Time
	f := startForceFixture(t, "closed-pipes", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		return runOwnedWithForceKill(ctx, cmd, observeSandboxWorkerExit, func(pid int, sig unix.Signal) error {
			err := sandboxWorkerGroupSignal(pid, sig)
			if sig == unix.SIGTERM {
				termAt = time.Now()
				close(request)
			}
			if sig == unix.SIGKILL && killAt.IsZero() {
				killAt = time.Now()
			}
			return err
		}, request)
	})
	f.waitReady(t)
	f.cancel()
	got := f.result(t, 3*time.Second)
	if !errors.Is(got.err, context.Canceled) || errors.Is(got.err, ErrForceKilled) || termAt.IsZero() || killAt.IsZero() || killAt.Sub(termAt) >= 200*time.Millisecond {
		t.Fatalf("grace: elapsed=%v err=%v", killAt.Sub(termAt), got.err)
	}
	if !strings.HasPrefix(got.err.Error(), context.Canceled.Error()) {
		t.Fatalf("existing context-first error order changed: %v", got.err)
	}
	f.assertJoined(t, got.err)
}

// Ignoring the request leaves the ready listener alive until cooperative cleanup.
func TestOwnedForceKillLive(t *testing.T) {
	for _, mode := range []string{"inherited-pipes", "closed-pipes"} {
		t.Run(mode, func(t *testing.T) {
			request := make(chan struct{})
			f := startForceFixture(t, mode, func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				return RunWithForceKill(ctx, cmd, request)
			})
			f.waitReady(t)
			close(request)
			got := f.result(t, 3*time.Second)
			if got.err != ErrForceKilled {
				t.Fatalf("force result = %v, want exact ErrForceKilled", got.err)
			}
			f.assertJoined(t, got.err)
			status, ok := f.command.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("leader wait status = %v, want SIGKILL", status)
			}
			if ownedListenerReachable(f.ready.Address) {
				t.Fatal("listener survived force-kill")
			}
			if _, err := os.Stat(filepath.Join(f.root, "term")); !os.IsNotExist(err) {
				t.Fatalf("TERM marker present or unreadable: %v", err)
			}
			t.Log("exact_force_sentinel=true leader_SIGKILL=true TERM_marker=false reaped=true listener_absent=true group_absent=true")
		})
	}
}

func startForceFixture(t *testing.T, mode string, run func(context.Context, *exec.Cmd) ([]byte, error)) *ownedLiveFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	f := &ownedLiveFixture{root: t.TempDir(), ctx: ctx, cancel: cancel, done: make(chan ownedRunResult, 1)}
	f.command = exec.Command(os.Args[0], "-test.run=^TestOwnedForceChild$")
	f.command.Env = []string{"ZASP_OWNED_LIVE_ROLE=leader", "ZASP_OWNED_LIVE_ROOT=" + f.root, "ZASP_OWNED_LIVE_MODE=" + mode}
	go func() { body, err := run(ctx, f.command); f.done <- ownedRunResult{body, err} }()
	t.Cleanup(func() { f.cleanup(t); cancel() })
	return f
}

// Both processes install TERM recording before the descendant publishes ready.
// A private stop file and finite deadline remain the only fixture fallback.
func TestOwnedForceChild(t *testing.T) {
	if os.Getenv("ZASP_OWNED_FORCE_EXIT") == "7" {
		os.Exit(7)
	}
	if os.Getenv("ZASP_OWNED_FORCE_SELF_KILL") == "1" {
		_ = unix.Kill(os.Getpid(), unix.SIGKILL)
		os.Exit(44)
	}
	root, role := os.Getenv("ZASP_OWNED_LIVE_ROOT"), os.Getenv("ZASP_OWNED_LIVE_ROLE")
	if role == "" {
		return
	}
	if !filepath.IsAbs(root) || (role != "leader" && role != "descendant") {
		os.Exit(40)
	}
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, unix.SIGTERM)
	go func() {
		for range terms {
			if err := os.WriteFile(filepath.Join(root, "term"), []byte("TERM"), 0600); err != nil {
				os.Exit(41)
			}
		}
	}()
	if role == "descendant" {
		os.Exit(runOwnedLiveDescendant(root))
	}
	child := exec.Command(os.Args[0], "-test.run=^TestOwnedForceChild$")
	child.Env = append(os.Environ(), "ZASP_OWNED_LIVE_ROLE=descendant")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		os.Exit(42)
	}
	if os.Getenv("ZASP_OWNED_FORCE_OVERFLOW") == "1" {
		if _, err := os.Stdout.Write(bytes.Repeat([]byte{'x'}, outputLimit+1)); err != nil {
			os.Exit(45)
		}
		if err := os.WriteFile(filepath.Join(root, "wrote"), nil, 0600); err != nil {
			os.Exit(46)
		}
	}
	if err := child.Wait(); err != nil {
		os.Exit(42)
	}
	if err := os.WriteFile(filepath.Join(root, "leader-stopped"), []byte("0"), 0600); err != nil {
		os.Exit(43)
	}
	os.Exit(0)
}
