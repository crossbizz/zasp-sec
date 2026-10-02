package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// These inputs are the existing child fatal messages. A missing classification
// hides which assertion failed; returning their free-form tails leaks output.
func TestSingleRecoveryContentionFailureLabels(t *testing.T) {
	for _, c := range []struct{ message, want string }{
		{"contention barrier transaction", "assertion=begin caller=none detail=unknown"},
		{"contention lock", "assertion=lock caller=none detail=unknown"},
		{"pre-settlement contention barrier or join context deadline exceeded", "assertion=wait-join caller=none detail=deadline"},
		{"pre-settlement contention barrier or join context canceled", "assertion=wait-join caller=none detail=canceled"},
		{"pre-settlement contention barrier or join contention caller did not join", "assertion=wait-join caller=none detail=unjoined"},
		{"pre-settlement contention barrier or join unexpected contention participant", "assertion=wait-join caller=none detail=participant"},
		{"pre-settlement contention barrier or join contention began after first settlement", "assertion=wait-join caller=none detail=already-settled"},
		{"unknown-evidence caller did not remain pending 0 orchestration input conflict", "assertion=pending-result caller=cleanup detail=conflict"},
		{"first-settlement caller was not complete or retryable 1 orchestration command rejected", "assertion=settlement-result caller=step detail=invalid"},
		{"first-settlement caller was not complete or retryable 2 private-error", "assertion=settlement-result caller=finish detail=unknown"},
		{"first-settlement caller was not complete or retryable 999 private-error", "assertion=settlement-result caller=none detail=unknown"},
		{"contention changed immutable identity", "assertion=identity caller=none detail=unknown"},
		{"contention attempted fresh provider/target authorization", "assertion=fresh-io caller=none detail=unknown"},
	} {
		t.Run(c.want, func(t *testing.T) {
			secret := "postgres" + "://private:secret@host/body"
			output := []byte("    security_agent_temporal_single_recovery_live_test.go:238: " + c.message + " " + secret + "\n")
			got := singleRecoveryWorkerFailure(context.Background(), output, errors.New(secret)).Error()
			if !strings.Contains(got, c.want) || strings.Contains(got, secret) || strings.Contains(got, "private-error") {
				t.Fatalf("wrong safe classification: %s", got)
			}
		})
	}
	for _, output := range []string{
		"other_test.go:238: contention changed immutable identity",
		"security_agent_temporal_single_recovery_live_test.go:238: private contention changed immutable identity",
		"security_agent_temporal_single_recovery_live_test.go:238: contention changed immutable identity-extra",
		"security_agent_temporal_single_recovery_live_test.go:100: first\nsecurity_agent_temporal_single_recovery_live_test.go:238: contention changed immutable identity",
	} {
		if got := singleRecoveryWorkerFailure(context.Background(), []byte(output), errors.New("private")).Error(); strings.Contains(got, "assertion=") {
			t.Fatalf("unbound assertion classified: %s", got)
		}
	}
}
