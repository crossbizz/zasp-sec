package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

// Invalid names must fail in main before even attempting the supplied DSN.
func TestComplianceRegistrationBinaryPreflight(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if output, err := testprocess.Run(ctx, exec.Command("go", "build", "-o", binary, ".")); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, tc := range []struct {
		name, executor, cleanup string
		extra                   bool
		valid                   bool
	}{
		{"missing-both", "", "", false, false},
		{"missing-worker", "", "cleanup_login", false, false},
		{"missing-cleanup", "worker_login", "", false, false},
		{"duplicate", "same_login", "same_login", false, false},
		{"reserved-worker", "zasp_worker", "cleanup_login", false, false},
		{"reserved-cleanup", "worker_login", "zasp_cleanup", false, false},
		{"uppercase", "PRIVATE_MARKER", "cleanup_login", false, false},
		{"whitespace", "worker_login ", "cleanup_login", false, false},
		{"injection", "worker;private_marker", "cleanup_login", false, false},
		{"short-worker", "ab", "cleanup_login", false, false},
		{"long-cleanup", "worker_login", strings.Repeat("b", 64), false, false},
		{"extra-argument", "worker_login", "cleanup_login", true, false},
		{"valid-boundaries", "abc", strings.Repeat("b", 63), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"register-compliance-workers"}
			if tc.extra {
				args = append(args, "private_marker")
			}
			command := exec.Command(binary, args...)
			command.Env = []string{"ZASP_MIGRATION_TIMEOUT=1s", "ZASP_POSTGRES_DSN=postgres://private_marker@127.0.0.1:1/private_marker?sslmode=disable", "ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL=" + tc.executor, "ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL=" + tc.cleanup}
			output, err := testprocess.Run(ctx, command)
			want := "release migration configuration rejected"
			if tc.valid {
				want = "release migration database unavailable"
			}
			if err == nil || !strings.Contains(string(output), want) || strings.Contains(strings.ToLower(string(output)), "private_marker") || strings.Contains(string(output), "worker_login") || strings.Contains(string(output), "cleanup_login") {
				t.Fatalf("preflight failure: %v %s", err, output)
			}
		})
	}
}
