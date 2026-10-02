package apiserver

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSingleTestRecoveryWorkerFailureDiagnostic(t *testing.T) {
	secret := "postgres" + "://private:secret@host/body request-id-123"
	t.Run("known source and SQLSTATE", func(t *testing.T) {
		output := []byte("--- FAIL: TestSingleTestRecoveryConnectedTemporal (2.00s)\n    security_agent_temporal_single_recovery_live_test.go:267: private " + secret + " (SQLSTATE 40001)\n")
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New(secret)).Error()
		want := "connected worker failed context=live exit=failed test=fail source=security_agent_temporal_single_recovery_live_test.go:267 stage=workflow reason= sqlstate=40001"
		if got != want || strings.Contains(got, secret) {
			t.Fatalf("unsafe or incomplete worker diagnostic: %q", got)
		}
	})

	t.Run("helper attributed call sites", func(t *testing.T) {
		for line, stage := range map[int]string{77: "composition", 191: "contention-pending", 238: "contention-settle"} {
			output := []byte("--- FAIL: TestSingleTestRecoveryConnectedTemporal (1.00s)\n    security_agent_temporal_single_recovery_live_test.go:" + strconv.Itoa(line) + ": " + secret + "\n")
			got := singleRecoveryWorkerFailure(context.Background(), output, errors.New(secret)).Error()
			if !strings.Contains(got, "stage="+stage+" ") || strings.Contains(got, secret) {
				t.Fatalf("helper call site was not classified safely: %q", got)
			}
		}
	})

	t.Run("unknown output stays unknown", func(t *testing.T) {
		output := append([]byte("--- FAIL: TestSingleTestRecoveryConnectedTemporal (1.00s)\n    other_secret_test.go:103: "), 0xff)
		output = append(output, []byte(secret+" SQLSTATE ZZ999\n")...)
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New(secret)).Error()
		want := "connected worker failed context=live exit=failed test=fail source=unknown stage=unknown reason= sqlstate="
		if got != want || strings.Contains(got, secret) || strings.Contains(got, "ZZ999") {
			t.Fatalf("unknown child output escaped: %q", got)
		}
	})

	t.Run("known orchestration reason", func(t *testing.T) {
		output := []byte("--- FAIL: TestSingleTestRecoveryConnectedTemporal (1.00s)\n    orchestration input conflict\n")
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New(secret)).Error()
		if !strings.Contains(got, "reason=conflict ") || strings.Contains(got, secret) {
			t.Fatalf("known orchestration reason was not classified safely: %q", got)
		}
	})

	t.Run("first observation wins", func(t *testing.T) {
		output := []byte("--- FAIL: TestSingleTestRecoveryConnectedTemporal (1.00s)\n    security_agent_temporal_single_recovery_live_test.go:100: first\n    security_agent_temporal_single_recovery_live_test.go:267: cleanup\n")
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New(secret)).Error()
		if !strings.Contains(got, "source=security_agent_temporal_single_recovery_live_test.go:100 stage=debt-baseline") {
			t.Fatalf("primary child observation was replaced: %q", got)
		}
	})

	t.Run("context and test states", func(t *testing.T) {
		deadline, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
		defer stop()
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		for _, test := range []struct {
			name, marker, want string
			ctx                context.Context
		}{
			{"deadline", "--- FAIL: TestSingleTestRecoveryConnectedTemporal (1.00s)", "context=deadline exit=deadline test=fail", deadline},
			{"canceled", "--- FAIL: TestSingleTestRecoveryConnectedTemporal (1.00s)", "context=canceled exit=canceled test=fail", canceled},
			{"skip", "--- SKIP: TestSingleTestRecoveryConnectedTemporal (0.00s)", "context=live exit=failed test=skip", context.Background()},
			{"pass", "--- PASS: TestSingleTestRecoveryConnectedTemporal (1.00s)", "context=live exit=failed test=pass", context.Background()},
		} {
			t.Run(test.name, func(t *testing.T) {
				got := singleRecoveryWorkerFailure(test.ctx, []byte(test.marker), errors.New(secret)).Error()
				if !strings.Contains(got, test.want) || strings.Contains(got, secret) {
					t.Fatalf("worker state classification changed: %q", got)
				}
			})
		}
	})
}

func TestSingleTestRecoveryWorkerFailureSkipsOnlyClosedDiagnosticRecords(t *testing.T) {
	const pendingBoundary = "    security_agent_temporal_single_recovery_live_test.go:191: recovery-contention phase=pending wait=ready release=ok join=complete elapsed=lt5s\n"
	const settleBoundary = "    security_agent_temporal_single_recovery_live_test.go:238: recovery-contention phase=settle wait=ready release=ok join=outer-deadline elapsed=ge45s\n"
	const trace = "    security_agent_temporal_single_recovery_live_test.go:238: recovery-trace phase=settle caller=cleanup operation=source-state error=deadline sqlstate=none ordinal=many source_state=3 state_completed=3 elapsed=lt1s result=deadline\n"
	t.Run("later workflow failure wins", func(t *testing.T) {
		output := []byte(pendingBoundary + settleBoundary + trace + "    security_agent_temporal_single_recovery_live_test.go:267: actual cleanup workflow private-error\n")
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New("private-error")).Error()
		for _, want := range []string{
			"source=security_agent_temporal_single_recovery_live_test.go:267 stage=workflow",
			"boundary[pending]=ready/ok/complete/lt5s",
			"boundary[settle]=ready/ok/outer-deadline/ge45s",
			"trace[settle/cleanup]=source-state/deadline/none/many/3/3/lt1s/deadline",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q: %s", want, got)
			}
		}
		if strings.Contains(got, "private-error") {
			t.Fatalf("raw failure escaped: %s", got)
		}
	})

	t.Run("contention detail uses the same filtered view", func(t *testing.T) {
		output := []byte(settleBoundary + "    security_agent_temporal_single_recovery_live_test.go:238: pre-settlement contention barrier or join context deadline exceeded\n")
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New("private-error")).Error()
		if !strings.Contains(got, "source=security_agent_temporal_single_recovery_live_test.go:238 stage=contention-settle") || !strings.Contains(got, "assertion=wait-join caller=none detail=deadline") {
			t.Fatalf("actual contention failure was hidden by its boundary record: %s", got)
		}
	})

	t.Run("invalid diagnostic is not skipped", func(t *testing.T) {
		invalid := strings.Replace(pendingBoundary, "wait=ready", "wait=private", 1)
		output := []byte(invalid + "    security_agent_temporal_single_recovery_live_test.go:267: actual cleanup workflow private-error\n")
		got := singleRecoveryWorkerFailure(context.Background(), output, errors.New("private-error")).Error()
		if !strings.Contains(got, "source=security_agent_temporal_single_recovery_live_test.go:191 stage=contention-pending") || strings.Contains(got, "boundary[") || strings.Contains(got, "private-error") {
			t.Fatalf("invalid diagnostic was treated as trusted framing: %s", got)
		}
	})
}

func TestSingleTestRecoveryWorkerFailureConsumesClosedRelayObservation(t *testing.T) {
	const relay = "    security_agent_temporal_single_recovery_live_test.go:262: recovery-relay failure=ack completed=start class=deadline sqlstate=none elapsed=lt10s total=ge30s\n"
	output := []byte(relay + "    security_agent_temporal_single_recovery_live_test.go:263: durable command relay private-secret\n")
	got := singleRecoveryWorkerFailure(context.Background(), output, errors.New("postgres" + "://private:secret@host/body")).Error()
	if !strings.Contains(got, "source=security_agent_temporal_single_recovery_live_test.go:263 stage=relay") || !strings.Contains(got, " relay=ack/start/deadline/none/lt10s/ge30s") || strings.Contains(got, "private") {
		t.Fatalf("relay observation not safely consumed: %s", got)
	}
	for _, invalid := range []string{
		strings.Replace(relay, "ack", "SELECT secret", 1),
		strings.Replace(relay, "deadline", "private", 1),
		strings.Replace(relay, "none", "ZZ999", 1),
		relay[:len(relay)-1] + " private\n",
	} {
		classified := singleRecoveryWorkerFailure(context.Background(), []byte(invalid+"    security_agent_temporal_single_recovery_live_test.go:263: durable command relay private-secret\n"), errors.New("private"))
		if strings.Contains(classified.Error(), " relay=") || strings.Contains(classified.Error(), "private") || strings.Contains(classified.Error(), "secret") {
			t.Fatalf("invalid relay record escaped: %s", classified)
		}
	}
}

func TestSingleTestRecoveryWorkerFailureSourceAllowlist(t *testing.T) {
	raw, err := os.ReadFile("../agentsec-worker/security_agent_temporal_single_recovery_live_test.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	for line, binding := range singleRecoveryWorkerSourceBindings {
		if line < 1 || line > len(lines) || !strings.Contains(lines[line-1], binding.contains) {
			t.Fatalf("worker failure source binding changed at %d", line)
		}
	}
}

func TestSingleTestRecoveryWorkerDiagnosticOverlay(t *testing.T) {
	source, err := os.ReadFile("single_test_recovery_native_composition_test.go")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := os.ReadFile("../../../native-overlay/single_test_recovery_native_composition_test.go")
	if err != nil {
		t.Fatal(err)
	}
	sourceLines, overlayLines := strings.Split(string(source), "\n"), strings.Split(string(overlay), "\n")
	if len(sourceLines) != len(overlayLines) {
		t.Fatal("native overlay line count changed")
	}
	pins := map[string]bool{
		"singleRecoveryApprovedWorkerTree":      false,
		"singleRecoveryApprovedRecoverySource":  false,
		"singleRecoveryApprovedCaptureManifest": false,
		"singleRecoveryApprovedContextProof":    false,
		"singleRecoveryApprovedRunnerSource":    false,
		"singleRecoveryCaptureManifestPath":     false,
		"singleRecoveryContextProofPath":        false,
	}
	for i := range sourceLines {
		name := ""
		for candidate := range pins {
			if strings.HasPrefix(sourceLines[i], "const "+candidate+" = ") {
				name = candidate
				break
			}
		}
		if name != "" {
			if sourceLines[i] == overlayLines[i] || !strings.HasSuffix(sourceLines[i], `= ""`) || strings.HasSuffix(overlayLines[i], `= ""`) {
				t.Fatalf("native overlay pin %s is not an explicit fixed replacement", name)
			}
			pins[name] = true
			continue
		}
		if sourceLines[i] != overlayLines[i] {
			t.Fatalf("native overlay contains an unreviewed difference at line %d", i+1)
		}
	}
	for name, seen := range pins {
		if !seen {
			t.Fatalf("native overlay pin %s is missing", name)
		}
	}
}
