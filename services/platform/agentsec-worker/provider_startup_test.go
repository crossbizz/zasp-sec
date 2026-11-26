package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInfrastructureProviderRefusalPrecedesModeDispatch(t *testing.T) {
	if os.Getenv("ZASP_TEST_PROVIDER_REFUSAL_CHILD") == "1" {
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInfrastructureProviderRefusalPrecedesModeDispatch$")
	cmd.Env = []string{"ZASP_TEST_PROVIDER_REFUSAL_CHILD=1", "ZASP_QUEUE_PROVIDER=mistakenly-pasted-secret"}
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("expected refusal on startup: %v", err)
	}
	message := string(output)
	if !strings.Contains(message, "ZASP_QUEUE_PROVIDER") || !strings.Contains(message, "sqs") || strings.Contains(message, "mistakenly-pasted-secret") {
		t.Fatalf("worker did not produce a safe provider diagnostic")
	}
}
