package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real command dispatch: a missing machine key must fail before
// database connection, and a valid command must read only its matching file.
func TestWorkerVerifierCLIConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "agentsec-migrate")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	seed := bytes.Repeat([]byte("fixture-worker-secret-"), 3)
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, seed, 0o400); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "link")
	if err := os.Symlink(keyFile, symlink); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct {
		name string
		size int
		mode os.FileMode
	}{{"short", 31, 0o400}, {"oversize", 4097, 0o400}, {"writable", 32, 0o600}, {"public", 32, 0o444}} {
		if err := os.WriteFile(filepath.Join(dir, file.name), bytes.Repeat([]byte{42}, file.size), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []struct{ name, input, other string }{
		{"register-worker-authorization-verifier", "ZASP_AUTHORIZATION_WORKER_KEY_FILE", "ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE"},
		{"register-compensation-authorization-verifier", "ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE", "ZASP_AUTHORIZATION_WORKER_KEY_FILE"},
	} {
		for _, tc := range []struct {
			name, path, principal, want string
			extra                       []string
		}{
			{"missing", "", "zasp_e2e", "release migration configuration rejected", nil},
			{"nonexistent", filepath.Join(dir, "missing"), "zasp_e2e", "release migration configuration rejected", nil},
			{"relative", "key", "zasp_e2e", "release migration configuration rejected", nil},
			{"symlink", symlink, "zasp_e2e", "release migration configuration rejected", nil},
			{"directory", dir, "zasp_e2e", "release migration configuration rejected", nil},
			{"short", filepath.Join(dir, "short"), "zasp_e2e", "release migration configuration rejected", nil},
			{"oversize", filepath.Join(dir, "oversize"), "zasp_e2e", "release migration configuration rejected", nil},
			{"writable", filepath.Join(dir, "writable"), "zasp_e2e", "release migration configuration rejected", nil},
			{"public", filepath.Join(dir, "public"), "zasp_e2e", "release migration configuration rejected", nil},
			{"missing_principal", keyFile, "", "release migration configuration rejected", nil},
			{"extra_argument", keyFile, "zasp_e2e", "release migration configuration rejected", []string{"unexpected"}},
			{"matching_file_only", keyFile, "zasp_e2e", "release migration database unavailable", nil},
		} {
			t.Run(command.name+"/"+tc.name, func(t *testing.T) {
				c := exec.CommandContext(ctx, binary, append([]string{command.name}, tc.extra...)...)
				for _, value := range os.Environ() {
					if !strings.HasPrefix(value, "ZASP_") {
						c.Env = append(c.Env, value)
					}
				}
				c.Env = append(c.Env, command.input+"="+tc.path, command.other+"="+filepath.Join(dir, "must-not-read"), "ZASP_WORKFLOW_SIGNING_KEY="+string(seed), "ZASP_MIGRATION_DB_PRINCIPAL="+tc.principal, "ZASP_POSTGRES_DSN=postgres" + "://invalid:invalid@127.0.0.1:1/invalid?sslmode=disable&connect_timeout=1", "ZASP_MIGRATION_TIMEOUT=10s")
				var stdout, stderr bytes.Buffer
				c.Stdout, c.Stderr = &stdout, &stderr
				err := c.Run()
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || stdout.Len() != 0 {
					t.Fatal("command must refuse with exit1 and empty stdout")
				}
				output := strings.TrimSpace(stderr.String())
				if strings.Contains(output, string(seed)) || strings.Contains(output, dir) || strings.Contains(output, "postgres://") {
					t.Fatal("command disclosed private configuration")
				}
				if strings.Contains(output, "\n") || !strings.HasSuffix(output, " "+tc.want) {
					t.Fatalf("wrong fixed error: want %q, got %q", tc.want, output)
				}
			})
		}
	}
}
