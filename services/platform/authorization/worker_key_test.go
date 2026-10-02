package authorization

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A key in a diagnostic must not reveal its private verifier, even when the
// caller uses Go-syntax formatting or dereferences it.
func TestWorkerKeyDiagnosticRedaction(t *testing.T) {
	k, err := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{k, *k} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, value); got != "[worker authorization key]" {
				t.Errorf("worker key diagnostic is not redacted for %s", format)
			}
		}
	}
}

func TestWorkerKeyFilePurposeAndBounds(t *testing.T) {
	dir := t.TempDir()
	for _, size := range []int{32, 4096} {
		path := filepath.Join(dir, fmt.Sprint(size))
		seed := bytes.Repeat([]byte{43}, size)
		if err := os.WriteFile(path, seed, 0o400); err != nil {
			t.Fatal(err)
		}
		forward, err := LoadWorkerKeyFile(WorkerForward, path)
		if err != nil {
			t.Fatal(err)
		}
		compensation, err := LoadWorkerKeyFile(CapturedCompensation, path)
		if err != nil {
			t.Fatal(err)
		}
		if forward.Version() == compensation.Version() || bytes.Equal(forward.Verifier(), compensation.Verifier()) {
			t.Fatal("machine purposes alias")
		}
		copy := forward.Verifier()
		clear(copy)
		if bytes.Equal(copy, forward.Verifier()) {
			t.Fatal("verifier accessor exposed key storage")
		}
	}
	for _, purpose := range []WorkerPurpose{"", "session", "human", "webhook", "gateway-policy"} {
		if _, err := LoadWorkerKeyFile(purpose, filepath.Join(dir, "32")); err != ErrInvalid {
			t.Fatal("unsupported key purpose accepted")
		}
	}
}

func TestWorkerDecisionDiagnosticRedaction(t *testing.T) {
	decision := WorkerDecision{operation: FindingApply, request: []byte(`{"run_id":"fixture"}`), envelope: []byte("fixture bearer proof")}
	for _, value := range []any{decision, &decision} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, value); got != "[worker authorization decision]" {
				t.Errorf("worker decision diagnostic is not redacted for %s", format)
			}
		}
	}
}
