package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The parent must remove an owned container even when no child cleanup ran.
func TestOrderedRunnerParentContainerCleanup(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_ENGINE_PREFLIGHT") != "1" {
		t.Skip("explicit owned local image opt-in required")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "zasp-ordered-engine-" + hex.EncodeToString(nonce[:])
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupOrderedRunnerContainers(t, directory) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "--label", "io.zasp.ordered-engine-owner="+name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "128m", "--entrypoint", "/usr/local/bin/node", "sha256:35693f52bb18536d511ca9ec3bb7f2fa12163fc9d81c066e80e0bf201774a1a5", "-e", "setTimeout(()=>{},60000)")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("owned cleanup control startup", err, "diagnostic_bytes", len(output))
	}
	cleanupOrderedRunnerContainers(t, directory)
	output, err := exec.CommandContext(ctx, "docker", "inspect", name).CombinedOutput()
	if err == nil || !strings.Contains(strings.ToLower(string(output)), "error: no such object: "+name) {
		t.Fatal("parent did not remove its exact owned container")
	}
}

// Default CommandContext SIGKILL must not strand the actual adapter descendant.
func TestOrderedRunnerChildCancellation(t *testing.T) {
	if directory := os.Getenv("ZASP_ORDERED_CHILD_CANCEL_FIXTURE"); directory != "" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		if os.Getenv("ZASP_ORDERED_CHILD_CANCEL_LEAF") == "1" {
			if err := os.WriteFile(filepath.Join(directory, "ready"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			<-signals
			if err := os.WriteFile(filepath.Join(directory, "terminated"), []byte("joined"), 0600); err != nil {
				t.Fatal(err)
			}
			return
		}
		child := exec.Command(os.Args[0], "-test.run=^TestOrderedRunnerChildCancellation$")
		child.Env = append(os.Environ(), "ZASP_ORDERED_CHILD_CANCEL_LEAF=1")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		<-signals
		if err := child.Wait(); err != nil {
			t.Fatal(err)
		}
		return
	}
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOrderedRunnerChildCancellation$")
	child.Env = append(os.Environ(), "ZASP_ORDERED_CHILD_CANCEL_FIXTURE="+directory)
	done := make(chan error, 1)
	go func() { _, err := orderedRunnerChildOutput(child); done <- err }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(directory, "ready")); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatal("child exited before fixture readiness", err)
		case <-ctx.Done():
			t.Fatal("child readiness timeout")
		case <-ticker.C:
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("expected bounded cancellation", err)
	}
	if body, err := os.ReadFile(filepath.Join(directory, "terminated")); err != nil || string(body) != "joined" {
		t.Fatal("owned descendant did not receive cancellation and join", err)
	}
}
