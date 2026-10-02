package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentAttackLab(context.Context) error {
	runner.events = append(runner.events, "up-attack-lab")
	runner.version = 57
	return nil
}

func TestAttackLabRegistrationBinaryPreflight(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if out, err := testprocess.Run(ctx, exec.Command("go", "build", "-o", binary, ".")); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for _, principal := range []string{"", "ab", "zasp_reserved", "UPPER_PRIVATE_MARKER", "bad;private_marker", "space login", strings.Repeat("a", 64)} {
		command := exec.Command(binary, "register-security-agent-attack-lab-reconciler")
		command.Env = []string{"ZASP_MIGRATION_TIMEOUT=1s", "ZASP_POSTGRES_DSN=postgres://private_marker@127.0.0.1:1/private_marker?sslmode=disable", "ZASP_SECURITY_AGENT_ATTACK_LAB_RECONCILER_DB_PRINCIPAL=" + principal}
		out, err := testprocess.Run(ctx, command)
		if err == nil || !strings.Contains(string(out), "release migration configuration rejected") || strings.Contains(strings.ToLower(string(out)), "private_marker") {
			t.Fatalf("pre-DB refusal: %v %s", err, out)
		}
	}
}
func (runner *scriptedMigrationRunner) DownProductionSecurityAgentAttackLab(context.Context) error {
	runner.events = append(runner.events, "down-attack-lab")
	runner.version = 56
	return nil
}
func TestAttackLabExplicitReleaseCommands(t *testing.T) {
	for _, start := range []int64{49, 55, 56, 57} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"up-to-57"}); err != nil || runner.version != 57 {
			t.Errorf("up57 from%d: version%d error%v", start, runner.version, err)
		}
	}
	runner := &scriptedMigrationRunner{version: 57}
	if err := runReleaseMigration(context.Background(), runner, []string{"down-from-57"}); err != nil || runner.version != 56 {
		t.Errorf("down57: version%d error%v", runner.version, err)
	}
	if err := runReleaseMigration(context.Background(), runner, []string{"up-to-61"}); err == nil {
		t.Error("unsupported60 accepted")
	}
}
