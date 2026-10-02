//go:build darwin || linux

package apiserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Removing expired-effect reclamation must fail this proof. A successful empty
// poll is not its oracle: the child checks the exact durable signed outcome.
func TestProductionSecurityAgentActionNaturalRecovery(t *testing.T) {
	for _, name := range []string{"initdb", "postgres", "pg_isready", "pg_ctl"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("owned local fixture requires %s; refusing skip", name)
		}
	}
	binary := os.Getenv("ZASP_ACTION_RECOVERY_WORKER_BINARY")
	mode := "prebuilt-worker"
	if binary == "" {
		mode = "local-offline-build"
		binary = filepath.Join(t.TempDir(), "action-recovery-worker.test")
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		command := exec.Command("go", "test", "-c", "-o", binary, "../agentsec-worker")
		command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
		if output, err := runSandboxWorkerCommand(ctx, command); err != nil {
			t.Fatalf("offline worker compile: %v\n%s", err, output)
		}
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("worker binary must be an absolute path")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatal("worker binary must be an executable regular file")
	}
	t.Logf("execution mode=%s; owned synthetic PostgreSQL, registered release55", mode)
	for _, action := range []string{"create_temporary_policy", "isolate_session"} {
		for _, lock := range []string{"work", "fairness"} {
			t.Run(action+"/"+lock, func(t *testing.T) {
				runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
					runner := precisionMigrationRunner(t, owner)
					if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
						t.Fatal(err)
					}
					if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
						t.Fatal(err)
					}
					if version, err := runner.Version(ctx); err != nil || version != 55 {
						t.Fatalf("registered current release=%d err=%v", version, err)
					}
					command := exec.Command(binary, "-test.run=^TestSecurityAgentActionNaturalRecoveryOwnedPostgres$", "-test.v", "-test.count=1", "-test.timeout=75s")
					for _, entry := range os.Environ() {
						if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
							command.Env = append(command.Env, entry)
						}
					}
					command.Env = append(command.Env, "ZASP_ACTION_RECOVERY_DSN="+dsn, "ZASP_ACTION_RECOVERY_ACTION="+action, "ZASP_ACTION_RECOVERY_LOCK="+lock)
					output, err := runSandboxWorkerCommand(ctx, command)
					if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "natural recovery durable proof:") {
						t.Fatalf("owned recovery worker: %v\n%s", err, output)
					}
					t.Logf("%s", output)
				})
			})
		}
	}
}
