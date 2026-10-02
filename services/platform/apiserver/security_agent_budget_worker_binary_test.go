//go:build darwin || linux

package apiserver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func validateSecurityAgentBudgetWorkerBinary(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("budget worker binary must be an absolute path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("budget worker binary must be a regular executable file")
	}
	return nil
}

func securityAgentBudgetWorkerBinary(t *testing.T, ctx context.Context) string {
	t.Helper()
	if binary, present := os.LookupEnv("ZASP_BUDGET_PROVIDER_WORKER_BINARY"); present {
		if err := validateSecurityAgentBudgetWorkerBinary(binary); err != nil {
			t.Fatalf("invalid prebuilt budget worker: %v", err)
		}
		t.Logf("budget worker binary mode=prebuilt path=%s", binary)
		return binary
	}
	binary := filepath.Join(t.TempDir(), "budget-provider-worker.test")
	t.Log("budget worker binary mode=local-compile")
	if output, err := runSandboxWorkerCommand(ctx, exec.Command("go", "test", "-race", "-c", "-o", binary, "../agentsec-worker")); err != nil {
		t.Fatalf("compile owned budget worker: %v\n%s", err, output)
	}
	return binary
}

func TestSecurityAgentBudgetWorkerBinaryRejectsInvalidPaths(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "worker.test")
	if err := os.WriteFile(regular, []byte("test fixture, never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "worker.test", filepath.Join(directory, "missing"), directory, regular} {
		if err := validateSecurityAgentBudgetWorkerBinary(path); err == nil {
			t.Errorf("accepted invalid binary path %q", path)
		}
	}
	if err := os.Chmod(regular, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurityAgentBudgetWorkerBinary(regular); err != nil {
		t.Fatalf("rejected executable regular file: %v", err)
	}
	t.Setenv("ZASP_BUDGET_PROVIDER_WORKER_BINARY", regular)
	if selected := securityAgentBudgetWorkerBinary(t, context.Background()); selected != regular {
		t.Fatalf("prebuilt selection=%q", selected)
	}
}
