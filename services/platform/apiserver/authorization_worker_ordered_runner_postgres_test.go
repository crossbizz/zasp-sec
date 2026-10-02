package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This fails if the current product bypasses the named Test boundaries,
// dispatches twice, accepts an unjournaled result, or cannot settle the actual
// pinned engine artifact. The customer response is controlled; the engine,
// TLS adapter, journal, artifact decoder and product callers are real.
func TestP7OrderedActualRunner(t *testing.T) {
	runOrderedActualRunnerConsumer(t, "")
}

func TestP7OrderedTestCheckpointRecovery(t *testing.T) {
	for _, phase := range []string{"test-reserved", "test-started"} {
		t.Run(phase, func(t *testing.T) { runOrderedActualRunnerConsumer(t, phase) })
	}
}

func runOrderedActualRunnerConsumer(t *testing.T, checkpoint string, afterStarted ...func(ordered68ApprovedTestContext)) {
	runOrderedActualRunnerWithSettledConsumer(t, checkpoint, nil, afterStarted...)
}

func runOrderedActualRunnerWithSettledConsumer(t *testing.T, checkpoint string, afterSettled func(ordered68ApprovedTestContext, string), afterStarted ...func(ordered68ApprovedTestContext)) {
	t.Helper()
	if afterSettled != nil && (checkpoint != "" || len(afterStarted) != 0) {
		t.Fatal("settled consumer requires the complete happy producer")
	}
	if len(afterStarted) > 1 || len(afterStarted) == 1 && (checkpoint != "test-started" || afterStarted[0] == nil) {
		t.Fatal("invalid started consumer callback")
	}
	postAdapter := checkpoint == "test-response-revoked" || checkpoint == "test-disconnected"
	if checkpoint != "" && !postAdapter && checkpoint != "test-reserved" && checkpoint != "test-started" {
		t.Fatal("unknown Ordered consumer phase")
	}
	if os.Getenv("ZASP_ORDERED_ENGINE_PREFLIGHT") != "1" {
		t.Skip("explicit owned local engine opt-in required")
	}
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer buildCancel()
	binaries := t.TempDir()
	worker, adapter := filepath.Join(binaries, "worker-test"), filepath.Join(binaries, "adapter-test")
	for _, target := range []struct{ name, pkg string }{{worker, "../agentsec-worker"}, {adapter, "../redteamadapter"}} {
		build := exec.CommandContext(buildCtx, "go", "test", "-c", "-o", target.name, target.pkg)
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("ordered consumer build: %v\n%s", err, output)
		}
	}
	buildCancel()
	containerRecords := t.TempDir()
	t.Cleanup(func() { cleanupOrderedRunnerContainers(t, containerRecords) })
	preflightCtx, preflightCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer preflightCancel()
	preflight := exec.CommandContext(preflightCtx, worker, "-test.run=^TestOrderedNativeEnginePrerequisites$", "-test.v", "-test.timeout=55s")
	preflight.Env = append(orderedRunnerChildEnvironment(t.TempDir()), "ZASP_ORDERED_ENGINE_PREFLIGHT=1", "ZASP_ORDERED_CONTAINER_RECORDS="+containerRecords)
	if output, err := orderedRunnerChildOutput(preflight); err != nil || !bytes.Contains(output, []byte("--- PASS: TestOrderedNativeEnginePrerequisites")) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("owned engine preflight: %v\n%s", err, output)
	}
	preflightCancel()
	consumed := false
	runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{phase: "application-complete", connectedConsumer: true, application: func(c ordered68TestFlowContext) {
		approved := assertOrdered68TestApproval(c)
		settings, err := json.Marshal(c.config)
		if err != nil {
			t.Fatal(err)
		}
		child := exec.CommandContext(c.ctx, worker, "-test.run=^TestP7OrderedActualRunnerNative$", "-test.v", "-test.timeout=5m")
		// The worker fixture resolves its checked-in runner files relative to
		// its package, exactly as the standalone component smoke does.
		child.Dir = "../agentsec-worker"
		artifactDirectory := t.TempDir()
		child.Env = append(orderedRunnerChildEnvironment(t.TempDir()),
			"ZASP_P7_ORDERED_OWNER_DSN="+approved.owner.Config().ConnString(),
			"ZASP_P7_ORDERED_CONFIG="+string(settings),
			"ZASP_P7_ORDERED_START="+string(c.identity),
			"ZASP_P7_ORDERED_EXECUTOR="+c.forwardLogin,
			"ZASP_P7_ORDERED_ADAPTER_BINARY="+adapter,
			"ZASP_ORDERED_CONTAINER_RECORDS="+containerRecords,
			"ZASP_P7_ORDERED_ARTIFACT_DIRECTORY="+artifactDirectory)
		marker := filepath.Join(t.TempDir(), "checkpoint")
		if postAdapter {
			child.Env = append(child.Env, "ZASP_P7_ORDERED_POST_ADAPTER="+checkpoint)
		} else if checkpoint != "" {
			child.Env = append(child.Env, "ZASP_P7_ORDERED_CHECKPOINT="+checkpoint, "ZASP_P7_ORDERED_CHECKPOINT_FILE="+marker)
		}
		output, err := orderedRunnerChildOutput(child)
		if checkpoint != "" && !postAdapter {
			var crashed *exec.ExitError
			body, readErr := os.ReadFile(marker)
			if !errors.As(err, &crashed) || crashed.ExitCode() != 73 || readErr != nil || string(body) != checkpoint {
				t.Fatalf("expected owned producer crash boundary %s: %v; marker_error=%v; diagnostic_bytes=%d", checkpoint, err, readErr, len(output))
			}
			var unsent bool
			if err := approved.owner.QueryRow(c.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1)`, approved.run).Scan(&unsent); err != nil || !unsent {
				t.Fatal("pre-engine producer had an adapter invocation", err)
			}
			if len(afterStarted) == 1 {
				before := orderedPostRecoveryEvidence(approved, artifactDirectory)
				afterStarted[0](approved)
				if !bytes.Equal(before, orderedPostRecoveryEvidence(approved, artifactDirectory)) {
					t.Fatal("native dispatch controls changed checkpoint or durable artifacts")
				}
			}
			assertOrdered69TestStop(approved, checkpoint)
			consumed = true
			return
		}
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestP7OrderedActualRunnerNative")) || bytes.Contains(output, []byte("--- SKIP:")) {
			t.Fatalf("actual Ordered Test consumer: %v\n%s", err, output)
		}
		t.Log(string(output))
		if afterSettled != nil {
			afterSettled(approved, artifactDirectory)
		}
		if postAdapter {
			assertOrdered69PostAdapterStop(approved, checkpoint, artifactDirectory)
			retryEvidence := orderedPostRecoveryEvidence(approved, artifactDirectory)
			retry := exec.CommandContext(c.ctx, worker, "-test.run=^TestP7OrderedActualRunnerNative$", "-test.v", "-test.timeout=60s")
			retry.Dir = child.Dir
			retry.Env = append(append([]string{}, child.Env...), "ZASP_P7_ORDERED_POST_RECOVERY_RETRY=1")
			output, err := orderedRunnerChildOutput(retry)
			if err != nil || !bytes.Contains(output, []byte("--- PASS: TestP7OrderedActualRunnerNative")) || bytes.Contains(output, []byte("--- SKIP:")) {
				t.Fatalf("actual post-recovery Test retry: %v\n%s", err, output)
			}
			t.Log(string(output))
			if !bytes.Equal(retryEvidence, orderedPostRecoveryEvidence(approved, artifactDirectory)) {
				t.Fatal("actual post-recovery Test retry changed child, Block debt, journal or durable artifacts")
			}
		}
		consumed = true
	}})
	if !t.Failed() && !consumed {
		t.Fatal("actual approved Test never reached its consuming child")
	}
}

// Explicit environment only. In particular, earlier artifact fault selectors,
// paid-provider keys and application credentials cannot enter this child.
func orderedRunnerChildEnvironment(ownedTemp string) []string {
	// Parent cleanup also owns the child's temporary keys/workspaces when an
	// expected checkpoint crash intentionally bypasses the child's t.Cleanup.
	result := []string{"TMPDIR=" + ownedTemp}
	for _, key := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT"} {
		if value, present := os.LookupEnv(key); present {
			result = append(result, key+"="+value)
		}
	}
	return result
}
