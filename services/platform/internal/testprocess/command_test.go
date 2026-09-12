//go:build darwin || linux

package testprocess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Removing process-group cancellation must leave this descendant's listener
// alive even when it closes stdout/stderr. Pipe closure alone is not cleanup.
func TestSandboxWorkerCommandCancellationStopsDescendant(t *testing.T) {
	for _, mode := range []string{"inherited-pipes", "closed-pipes"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := exec.Command(os.Args[0], "-test.run=^TestSandboxWorkerCommandFixture$")
			command.Env = append(os.Environ(), "ZASP_SANDBOX_COMMAND_FIXTURE=leader", "ZASP_SANDBOX_COMMAND_ROOT="+root, "ZASP_SANDBOX_COMMAND_MODE="+mode)
			done := make(chan error, 1)
			go func() { _, err := Run(ctx, command); done <- err }()
			joined := false
			t.Cleanup(func() {
				// The fixture cooperatively exits on its unique stop file even in
				// the RED run, without signaling historical numeric process IDs.
				_ = os.WriteFile(filepath.Join(root, "stop"), nil, 0600)
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(4 * time.Second):
						t.Error("fixture cleanup did not join command")
					}
				}
			})
			address := waitSandboxFixtureAddress(t, root)
			connection, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal("descendant never became live", err)
			}
			_ = connection.Close()
			cancel()
			select {
			case err := <-done:
				joined = true
				if !errors.Is(err, context.Canceled) {
					t.Errorf("cancellation error=%v", err)
				}
				if errors.Is(err, ErrGroupRemaining) {
					t.Errorf("cancellation did not confirm process group disappearance: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("cancelled command remained blocked on descendant output pipes")
			}
			connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				_ = connection.Close()
				t.Fatal("descendant listener survived command cancellation")
			}
		})
	}
}

func TestSandboxWorkerCommandJoinsDescendantAfterLeaderExit(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(root, "stop"), nil, 0600) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.Command(os.Args[0], "-test.run=^TestSandboxWorkerCommandFixture$")
	command.Env = append(os.Environ(), "ZASP_SANDBOX_COMMAND_FIXTURE=leader", "ZASP_SANDBOX_COMMAND_ROOT="+root, "ZASP_SANDBOX_COMMAND_MODE=leader-exit")
	if output, err := Run(ctx, command); err != nil {
		t.Fatalf("leader success did not clean up its descendants: %v %s", err, output)
	}
	address := waitSandboxFixtureAddress(t, root)
	if connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("descendant listener survived normal leader exit")
	}
}

func TestSandboxWorkerCommandPreservesResultAndRejectsCancelledStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, exit := range []string{"0", "7"} {
		command := exec.Command("/bin/sh", "-c", "printf stdout; printf stderr >&2; exit "+exit)
		output, err := Run(ctx, command)
		if string(output) != "stdoutstderr" || (err == nil) != (exit == "0") {
			t.Fatalf("output=%q err=%v exit=%s", output, err, exit)
		}
		if exit == "7" {
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 7 {
				t.Fatal("lost child exit status", err)
			}
		}
	}
	cancel()
	command := exec.Command("/bin/sh", "-c", "exit 0")
	if _, err := Run(ctx, command); !errors.Is(err, context.Canceled) || command.Process != nil {
		t.Fatal("cancelled context started a child", err)
	}
}

func waitSandboxFixtureAddress(t *testing.T, root string) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if body, err := os.ReadFile(filepath.Join(root, "ready")); err == nil && len(body) != 0 {
			return string(body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("descendant fixture did not become ready")
	return ""
}

func TestSandboxWorkerCommandFixture(t *testing.T) {
	role, root := os.Getenv("ZASP_SANDBOX_COMMAND_FIXTURE"), os.Getenv("ZASP_SANDBOX_COMMAND_ROOT")
	if role == "" {
		return
	}
	if !filepath.IsAbs(root) {
		t.Fatal("invalid fixture root")
	}
	signal.Ignore(unix.SIGTERM)
	if role == "leader" {
		command := exec.Command(os.Args[0], "-test.run=^TestSandboxWorkerCommandFixture$")
		command.Env = append(os.Environ(), "ZASP_SANDBOX_COMMAND_FIXTURE=descendant")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if os.Getenv("ZASP_SANDBOX_COMMAND_MODE") == "leader-exit" {
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitSandboxFixtureAddress(t, root)
			return
		}
		if err := command.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if role != "descendant" {
		t.Fatal("invalid fixture role")
	}
	if os.Getenv("ZASP_SANDBOX_COMMAND_MODE") == "closed-pipes" {
		_ = os.Stdout.Close()
		_ = os.Stderr.Close()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(filepath.Join(root, "ready"), []byte(listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(filepath.Join(root, "stop")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "fixture safety deadline reached")
}
