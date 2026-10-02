package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Catch configuration accepted until after connection, argument-based secrets,
// or raw connection/key material leaking through public errors.
func TestAuthorizationVerifierCLIConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	secret := hex.EncodeToString(seed)
	for _, tc := range []struct {
		name, key, principal, dsn, timeout string
		args                               []string
		want                               string
	}{
		{"missing_key", "", "zasp_e2e", "postgres://invalid", "10s", nil, "release migration configuration rejected"},
		{"short_key", secret[:31], "zasp_e2e", "postgres://invalid", "10s", nil, "release migration configuration rejected"},
		{"oversize_key", strings.Repeat(secret, 65), "zasp_e2e", "postgres://invalid", "10s", nil, "release migration configuration rejected"},
		{"missing_principal", secret, "", "postgres://invalid", "10s", nil, "release migration configuration rejected"},
		{"invalid_principal", secret, "bad principal", "postgres://invalid", "10s", nil, "release migration configuration rejected"},
		{"missing_dsn", secret, "zasp_e2e", "", "10s", nil, "release migration configuration rejected"},
		{"invalid_timeout", secret, "zasp_e2e", "postgres://invalid", "0s", nil, "release migration configuration rejected"},
		{"extra_argument", secret, "zasp_e2e", "postgres://invalid", "10s", []string{"unexpected"}, "release migration configuration rejected"},
		{"unavailable_database", secret, "zasp_e2e", "postgres" + "://invalid:invalid@127.0.0.1:1/invalid?sslmode=disable&connect_timeout=1", "10s", nil, "release migration database unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := exec.CommandContext(ctx, binary, append([]string{"register-authorization-verifier"}, tc.args...)...)
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "ZASP_") {
					c.Env = append(c.Env, v)
				}
			}
			c.Env = append(c.Env, "ZASP_WORKFLOW_SIGNING_KEY="+tc.key, "ZASP_MIGRATION_DB_PRINCIPAL="+tc.principal, "ZASP_POSTGRES_DSN="+tc.dsn, "ZASP_MIGRATION_TIMEOUT="+tc.timeout)
			var stdout, stderr bytes.Buffer
			c.Stdout = &stdout
			c.Stderr = &stderr
			err := c.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || stdout.Len() != 0 {
				t.Fatal("command must refuse with exit1 and empty stdout")
			}
			output := stderr.String()
			if strings.Contains(output, secret) || tc.key != "" && strings.Contains(output, tc.key) || strings.Contains(output, tc.dsn) && tc.dsn != "" {
				t.Fatal("command disclosed private configuration")
			}
			// log.Fatal prefixes a timestamp; the public message itself is fixed.
			lines := strings.Split(strings.TrimSpace(output), "\n")
			if len(lines) != 1 || !strings.HasSuffix(lines[0], " "+tc.want) {
				t.Fatalf("wrong fixed error for %s", tc.name)
			}
			t.Logf("real command register-authorization-verifier exit=1 stdout=%q stderr=%q", stdout.String(), stderr.String())
		})
	}
}
