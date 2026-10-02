//go:build darwin || linux

package testprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type ownedFixtureReady struct {
	Leader  int    `json:"leader"`
	Child   int    `json:"child"`
	Group   int    `json:"group"`
	Address string `json:"address"`
}

type ownedRunResult struct {
	body []byte
	err  error
}

// Every owner-loop stop path uses this publication/signal boundary. Publication
// completes synchronously here, and its result stays unread until after the
// signal attempt. A recorder is mandatory: loss is simulated, not OS evidence.
func TestOwnedPublishedLossRefusesSignals(t *testing.T) {
	for _, sig := range []unix.Signal{unix.SIGTERM, unix.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			publication := newExitPublication()
			failure := errors.New("injected published loss of ownership")
			publication.publish(exitObservation{err: failure, owned: false})
			signals := 0
			err := publication.signal(12345, sig, func(pid int, got unix.Signal) error {
				signals++
				if pid != 12345 || got != sig {
					t.Errorf("signal identity changed: pid=%d signal=%v", pid, got)
				}
				return nil
			})
			observed := <-publication.result
			if observed.owned || !errors.Is(observed.err, failure) {
				t.Fatal("lost published observation")
			}
			t.Logf("publication_complete_before_signal=true pending_result_consumed_after_signal=true signals=%d err=%v", signals, err)
			if signals != 0 || !errors.Is(err, failure) {
				t.Fatal("published ownership loss allowed a group signal")
			}
		})
	}
}

// Ordinary cancellation must still be able to signal while observation blocks;
// an already-published owned result must also allow final descendant cleanup.
func TestOwnedPublicationAllowsOwnedSignals(t *testing.T) {
	for _, state := range []string{"observer-pending", "owned-exit", "owned-error"} {
		t.Run(state, func(t *testing.T) {
			publication := newExitPublication()
			if state != "observer-pending" {
				observation := exitObservation{owned: true}
				if state == "owned-error" {
					observation.err = errors.New("injected owned failure")
				}
				publication.publish(observation)
			}
			var signals []unix.Signal
			for _, sig := range []unix.Signal{unix.SIGTERM, unix.SIGKILL} {
				err := publication.signal(12345, sig, func(pid int, got unix.Signal) error {
					if pid != 12345 {
						t.Errorf("signal identity changed: pid=%d", pid)
					}
					signals = append(signals, got)
					return nil
				})
				if err != nil {
					t.Fatal("owned signal refused", err)
				}
			}
			if len(signals) != 2 || signals[0] != unix.SIGTERM || signals[1] != unix.SIGKILL {
				t.Fatalf("owned signals=%v", signals)
			}
		})
	}
}

// Simulated loss exercises the no-signal branch; this isn't an OS reaping test.
func TestOwnedObserverLostOwnershipDoesNotSignal(t *testing.T) {
	failure := errors.New("injected lost ownership")
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	var signals atomic.Int32
	fixture := startOwnedLiveFixture(t, "closed-pipes", "quiet", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		return runOwnedWithSignals(ctx, cmd, func(pid int) exitObservation {
			<-release
			return exitObservation{err: failure, owned: false}
		}, func(int, unix.Signal) error {
			signals.Add(1)
			return errors.New("signal attempted after lost ownership")
		})
	})
	t.Cleanup(open)
	fixture.waitReady(t)
	open()
	got := fixture.result(t, 4*time.Second)
	if !errors.Is(got.err, failure) || signals.Load() != 0 {
		t.Fatalf("lost ownership: signals=%d err=%v", signals.Load(), got.err)
	}
	if !ownedListenerReachable(fixture.ready.Address) {
		t.Fatal("simulated lost-ownership fixture unexpectedly stopped")
	}
	fixture.cleanup(t)
	if signals.Load() != 0 {
		t.Fatal("late signal after reconciliation")
	}
}

// A denied final signal must return incomplete cleanup, with the same Wait
// owner retained and no late retry against the numeric group after reap.
func TestOwnedObserverDeniedTermination(t *testing.T) {
	failure := errors.New("injected owned watcher failure with denied termination")
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	var signals atomic.Int32
	fixture := startOwnedLiveFixture(t, "closed-pipes", "quiet", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		return runOwnedWithSignals(ctx, cmd, func(pid int) exitObservation {
			<-release
			return exitObservation{err: failure, owned: true}
		}, func(int, unix.Signal) error {
			signals.Add(1)
			return unix.EPERM
		})
	})
	t.Cleanup(open)
	fixture.waitReady(t)
	open()
	got := fixture.result(t, 4*time.Second)
	if !errors.Is(got.err, failure) || !errors.Is(got.err, unix.EPERM) || signals.Load() != 1 {
		t.Fatalf("denied termination: signals=%d err=%v", signals.Load(), got.err)
	}
	if !ownedListenerReachable(fixture.ready.Address) {
		t.Fatal("denied-termination fixture unexpectedly stopped")
	}
	fixture.cleanup(t)
	if signals.Load() != 1 {
		t.Fatal("late signal after incomplete reap")
	}
}

// Reverting owned-error termination leaves the proven-live listener reachable.
func TestOwnedObserverFailure(t *testing.T) {
	for _, mode := range []string{"inherited-pipes", "closed-pipes"} {
		t.Run(mode, func(t *testing.T) {
			failure := errors.New("injected owned watcher setup failure")
			release := make(chan struct{})
			var once sync.Once
			open := func() { once.Do(func() { close(release) }) }
			fixture := startOwnedLiveFixture(t, mode, "quiet", func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				return runOwned(ctx, cmd, func(pid int) exitObservation {
					<-release
					return exitObservation{err: failure, owned: true}
				})
			})
			t.Cleanup(open)
			fixture.waitReady(t)
			start := time.Now()
			open()
			got := fixture.result(t, 4*time.Second)
			alive := ownedListenerReachable(fixture.ready.Address)
			t.Logf("observer_error=%t listener_survived=%t bytes=%d return_ms=%d", errors.Is(got.err, failure), alive, len(got.body), time.Since(start).Milliseconds())
			if !errors.Is(got.err, failure) {
				t.Errorf("lost observer error: %v", got.err)
			}
			// The original faulty branch still has background Wait writing
			// ProcessState. Probe first and skip that mutable read on the RED.
			if alive {
				fixture.cleanup(t)
				t.Fatal("owned descendant listener survived watcher-error return")
			}
			fixture.assertJoined(t, got.err)
		})
	}
}

type ownedLiveFixture struct {
	root     string
	ctx      context.Context
	cancel   context.CancelFunc
	command  *exec.Cmd
	done     chan ownedRunResult
	ready    ownedFixtureReady
	returned bool
	cleaned  bool
}

func startOwnedLiveFixture(t *testing.T, mode, activity string, run func(context.Context, *exec.Cmd) ([]byte, error)) *ownedLiveFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	f := &ownedLiveFixture{root: t.TempDir(), ctx: ctx, cancel: cancel, done: make(chan ownedRunResult, 1)}
	f.command = exec.Command(os.Args[0], "-test.run=^TestOwnedLiveChild$")
	f.command.Env = []string{"ZASP_OWNED_LIVE_ROLE=leader", "ZASP_OWNED_LIVE_ROOT=" + f.root, "ZASP_OWNED_LIVE_MODE=" + mode, "ZASP_OWNED_LIVE_ACTIVITY=" + activity}
	go func() { body, err := run(ctx, f.command); f.done <- ownedRunResult{body, err} }()
	t.Cleanup(func() { f.cleanup(t); cancel() })
	return f
}

func (f *ownedLiveFixture) waitReady(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); {
		body, err := os.ReadFile(filepath.Join(f.root, "ready"))
		if err == nil && len(body) > 0 && len(body) < 1024 && json.Unmarshal(body, &f.ready) == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	host, portText, err := net.SplitHostPort(f.ready.Address)
	port, _ := strconv.Atoi(portText)
	if err != nil || host != "127.0.0.1" || port < 1 || port > 65535 || f.ready.Leader <= 1 || f.ready.Group != f.ready.Leader || f.ready.Child <= 1 || f.ready.Child == f.ready.Leader {
		t.Fatal("invalid owned readiness identity")
	}
	if !ownedListenerReachable(f.ready.Address) {
		t.Fatal("descendant never became live")
	}
	t.Logf("READY leader=%d child=%d group=%d listener_reachable=true", f.ready.Leader, f.ready.Child, f.ready.Group)
}

func (f *ownedLiveFixture) result(t *testing.T, bound time.Duration) ownedRunResult {
	t.Helper()
	select {
	case got := <-f.done:
		f.returned = true
		return got
	case <-time.After(bound):
		t.Fatal("owned runner did not return before caller deadline")
		return ownedRunResult{}
	}
}

func (f *ownedLiveFixture) assertJoined(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrGroupRemaining) {
		t.Errorf("group cleanup failure: %v", err)
	}
	if f.command.ProcessState == nil {
		t.Fatal("direct child was not reaped")
	}
	if f.command.Process.Pid != f.ready.Leader {
		t.Fatal("fixture leader does not match owned direct child")
	}
	if groupErr := unix.Kill(-f.ready.Group, 0); groupErr != unix.ESRCH {
		t.Fatalf("owned group absence not confirmed: %v", groupErr)
	}
}

func (f *ownedLiveFixture) cleanup(t *testing.T) {
	t.Helper()
	if f.cleaned {
		return
	}
	f.cleaned = true
	if err := os.WriteFile(filepath.Join(f.root, "stop"), nil, 0600); err != nil {
		t.Error("owned stop file", err)
	}
	if !f.returned {
		select {
		case <-f.done:
			f.returned = true
		case <-time.After(5 * time.Second):
			t.Error("runner return not joined")
		}
	}
	if f.ready.Group <= 1 {
		return
	}
	absent := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if unix.Kill(-f.ready.Group, 0) == unix.ESRCH {
			absent = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	leaderStopped, _ := os.ReadFile(filepath.Join(f.root, "leader-stopped"))
	childStopped, _ := os.ReadFile(filepath.Join(f.root, "child-stopped"))
	t.Logf("CLEANUP group_absent=%t cooperative_leader=%q cooperative_child=%q", absent, leaderStopped, childStopped)
	if !absent {
		t.Error("owned fixture group remained after cooperative cleanup")
	}
}

func ownedListenerReachable(address string) bool {
	connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

// This ports the finite diagnostic listener, atomic readiness and stop file.
func TestOwnedLiveChild(t *testing.T) {
	root, role := os.Getenv("ZASP_OWNED_LIVE_ROOT"), os.Getenv("ZASP_OWNED_LIVE_ROLE")
	if role == "" {
		return
	}
	if !filepath.IsAbs(root) || (role != "leader" && role != "descendant") {
		os.Exit(20)
	}
	if role == "leader" {
		command := exec.Command(os.Args[0], "-test.run=^TestOwnedLiveChild$")
		command.Env = append(os.Environ(), "ZASP_OWNED_LIVE_ROLE=descendant")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Start(); err != nil {
			os.Exit(21)
		}
		if os.Getenv("ZASP_OWNED_LIVE_ACTIVITY") == "close-output" {
			_ = os.Stdout.Close()
			_ = os.Stderr.Close()
		}
		if os.Getenv("ZASP_OWNED_LIVE_ACTIVITY") == "overflow" {
			if !ownedFixtureFileBeforeDeadline(root, "write") {
				os.Exit(23)
			}
			if _, err := os.Stdout.Write(bytes.Repeat([]byte{'a'}, 524288)); err != nil {
				os.Exit(24)
			}
			if _, err := os.Stderr.Write(bytes.Repeat([]byte{'b'}, 524289)); err != nil {
				os.Exit(25)
			}
		}
		if err := command.Wait(); err != nil {
			os.Exit(26)
		}
		if err := os.WriteFile(filepath.Join(root, "leader-stopped"), []byte("0"), 0600); err != nil {
			os.Exit(22)
		}
		os.Exit(0)
	}
	os.Exit(runOwnedLiveDescendant(root))
}

func ownedFixtureFileBeforeDeadline(root, name string) bool {
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return true
		}
		if _, err := os.Stat(filepath.Join(root, "stop")); err == nil {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func runOwnedLiveDescendant(root string) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 31
	}
	defer listener.Close()
	if os.Getenv("ZASP_OWNED_LIVE_MODE") == "closed-pipes" {
		_ = os.Stdout.Close()
		_ = os.Stderr.Close()
	}
	body, err := json.Marshal(ownedFixtureReady{Leader: os.Getppid(), Child: os.Getpid(), Group: unix.Getpgrp(), Address: listener.Addr().String()})
	if err != nil {
		return 32
	}
	readyFile, err := os.CreateTemp(root, "ready-*.tmp")
	if err != nil {
		return 33
	}
	if _, err = readyFile.Write(body); err != nil {
		_ = readyFile.Close()
		return 34
	}
	if err = readyFile.Close(); err != nil {
		return 35
	}
	if err = os.Rename(readyFile.Name(), filepath.Join(root, "ready")); err != nil {
		return 36
	}
	if !ownedFixtureFileBeforeDeadline(root, "stop") {
		return 38
	}
	if err := os.WriteFile(filepath.Join(root, "child-stopped"), []byte("0"), 0600); err != nil {
		return 37
	}
	return 0
}
