package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimepath"
)

// A local stack keeps the fixed key paths beneath a private directory it
// owns. The worker then accepts exactly that path, and still refuses the
// path a pod has and every other path. The resolver reads its setting once
// per process, so the check runs in a second copy of this test.
func TestLocalRuntimeRootMovesTheFixedKeyPaths(t *testing.T) {
	const fixed = "/var/run/secrets/zasp-security-agent/openrouter-api-token"
	if os.Getenv("ZASP_TEST_LOCAL_RUNTIME_ROOT_CHILD") == "1" {
		root := os.Getenv(runtimepath.RootVariable)
		values := map[string]string{
			"ZASP_WORKER_MODE": "security-agent", "ZASP_POSTGRES_DSN": "postgres://security_agent@postgres.internal/zasp?sslmode=verify-full",
			"ZASP_DATABASE_AUTHORITY": "zasp_security_agent_worker", "ZASP_WORKER_ID": "security-agent-worker-01",
			"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
			"ZASP_SECURITY_AGENT_PLANNER_ENDPOINT": "https://openrouter.ai/api/v1/chat/completions", "ZASP_SECURITY_AGENT_PLANNER_MODEL": "openai/gpt-5-mini",
			"ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE": filepath.Join(root, fixed), "ZASP_SECURITY_AGENT_PLANNER_TIMEOUT": "10s",
			"ZASP_SECURITY_AGENT_PLANNER_MAX_TOKENS": "512", "ZASP_SECURITY_AGENT_PLANNER_POLICY_VERSION": "security-agent-planner-v1",
		}
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err != nil {
			t.Fatalf("path beneath the local runtime root rejected: %v", err)
		}
		for _, other := range []string{fixed, filepath.Join(root, "openrouter-api-token"), "/tmp/key"} {
			drift := cloneStringMap(values)
			drift["ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE"] = other
			if _, err := loadWorkerRuntimeConfig(mapLookup(drift)); !errors.Is(err, errWorkerConfiguration) {
				t.Fatalf("%s accepted: %v", other, err)
			}
		}
		return
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, environment := range map[string][]string{
		"local":             {runtimepath.RootVariable + "=" + root},
		"inside kubernetes": {runtimepath.RootVariable + "=" + root, "KUBERNETES_SERVICE_HOST=10.0.0.1"},
	} {
		command := exec.Command(os.Args[0], "-test.run", "^TestLocalRuntimeRootMovesTheFixedKeyPaths$")
		command.Env = append(append(os.Environ(), "ZASP_TEST_LOCAL_RUNTIME_ROOT_CHILD=1"), environment...)
		output, err := command.CombinedOutput()
		// Inside Kubernetes the setting is ignored, so the moved path is refused.
		if accepted := err == nil; accepted != (name == "local") {
			t.Fatalf("%s: accepted=%v\n%s", name, accepted, output)
		}
	}
}
