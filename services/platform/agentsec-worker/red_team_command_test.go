//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Real subprocesses reproduce the Go -> Node launcher -> engine ownership tree.
// The descendant writes only inside this test's temporary directory and has a
// hard self-expiry plus a stop-file cleanup, even against the broken launcher.
func TestProductionRedTeamCommandCancellationStopsDescendant(t *testing.T) {
	for _, mode := range []string{"parent", "parent_stubborn"} {
		t.Run(mode, func(t *testing.T) { assertRedTeamCommandCancellation(t, mode) })
	}
}

func TestProductionRedTeamCommandCompletionAndCancellationRace(t *testing.T) {
	for iteration := 0; iteration < 12; iteration++ {
		directory := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- (productionRedTeamCommand{}).Run(ctx, os.Args[0], []string{"-test.run=^TestProductionRedTeamCommandFixture$"}, []string{"ZASP_RED_TEAM_COMMAND_FIXTURE=exit", "ZASP_RED_TEAM_COMMAND_DIRECTORY=" + directory}, directory)
		}()
		if iteration%2 == 0 {
			until := time.Now().Add(3 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(directory, "exiting")); err == nil {
					break
				}
				if time.Now().After(until) {
					cancel()
					t.Fatal("completion fixture did not start")
				}
				time.Sleep(100 * time.Microsecond)
			}
			cancel()
		}
		select {
		case err := <-done:
			if iteration%2 != 0 && err != nil {
				t.Fatal("successful exit was changed", err)
			}
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("completion/cancellation race exceeded bound")
		}
		cancel()
	}
}

func assertRedTeamCommandCancellation(t *testing.T, mode string) {
	t.Helper()
	directory := t.TempDir()
	heartbeat := filepath.Join(directory, "heartbeat")
	stop := filepath.Join(directory, "stop")
	closed := filepath.Join(directory, "closed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (productionRedTeamCommand{}).Run(ctx, os.Args[0], []string{"-test.run=^TestProductionRedTeamCommandFixture$"}, []string{"ZASP_RED_TEAM_COMMAND_FIXTURE=" + mode, "ZASP_RED_TEAM_COMMAND_DIRECTORY=" + directory}, directory)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(heartbeat); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned descendant did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(stop, []byte("stop"), 0o600)
		until := time.Now().Add(time.Second)
		for time.Now().Before(until) {
			if _, err := os.Stat(closed); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled command returned success")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancelled command did not return")
	}
	before, err := os.ReadFile(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	after, err := os.ReadFile(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("engine descendant continued executing after launcher cancellation")
	}
}

func TestProductionRedTeamCommandFixture(t *testing.T) {
	mode := os.Getenv("ZASP_RED_TEAM_COMMAND_FIXTURE")
	if mode == "" {
		t.Skip("owned subprocess fixture")
	}
	directory := os.Getenv("ZASP_RED_TEAM_COMMAND_DIRECTORY")
	if !filepath.IsAbs(directory) {
		t.Fatal("fixture directory rejected")
	}
	if mode == "exit" {
		_ = os.WriteFile(filepath.Join(directory, "exiting"), []byte("exiting"), 0o600)
		return
	}
	if mode == "parent_stubborn" || mode == "child_stubborn" {
		signal.Ignore(syscall.SIGTERM)
	}
	if mode == "parent" || mode == "parent_stubborn" {
		childMode := "child"
		if mode == "parent_stubborn" {
			childMode = "child_stubborn"
		}
		child := exec.Command(os.Args[0], "-test.run=^TestProductionRedTeamCommandFixture$")
		child.Env = []string{"ZASP_RED_TEAM_COMMAND_FIXTURE=" + childMode, "ZASP_RED_TEAM_COMMAND_DIRECTORY=" + directory}
		if err := child.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if mode != "child" && mode != "child_stubborn" {
		t.Fatal("fixture mode rejected")
	}
	defer func() { _ = os.WriteFile(filepath.Join(directory, "closed"), []byte("closed"), 0o600) }()
	until := time.Now().Add(10 * time.Second)
	for count := 0; time.Now().Before(until); count++ {
		if _, err := os.Stat(filepath.Join(directory, "stop")); err == nil {
			return
		}
		if err := os.WriteFile(filepath.Join(directory, "heartbeat"), []byte(strconv.Itoa(count)), 0o600); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
