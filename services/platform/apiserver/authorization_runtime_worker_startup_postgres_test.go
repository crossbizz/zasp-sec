package apiserver

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func workerRuntimeStartupChild(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "runtime-startup-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "../agentsec-worker")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("runtime startup fixture build: %v\n%s", err, output)
	}
	const name = "TestP7CurrentRuntimeSQLStartupNative"
	child := exec.CommandContext(ctx, binary, "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	child.WaitDelay = 5 * time.Second
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "ZASP_") {
			child.Env = append(child.Env, v)
		}
	}
	child.Env = append(child.Env, "ZASP_P7_RUNTIME_PROFILE_OWNER_DSN="+owner.Config().ConnString())
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("runtime startup child: %v\n%s", err, output)
	}
	t.Logf("registered SQL-only startup fence child passed: %s", output)
}
