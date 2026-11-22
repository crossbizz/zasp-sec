package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvidenceExportRequiresScopedBrowserConfirmation(t *testing.T) {
	t.Setenv("ZASP_API_URL", "https://pilot.example.test")
	env := "pid_30000000-0000-4000-8000-000000000001"
	device := "pid_40000000-0000-4000-8000-000000000001"
	ref := strings.Repeat("a", 64)
	var output bytes.Buffer
	if code := evidenceLink([]string{"--environment", env, "--device", device, "--session", ref, "--no-open"}, &output, &output); code != 0 || !strings.Contains(output.String(), "/compliance/evidence#") || !strings.Contains(output.String(), "endpoint_session_ref="+ref) {
		t.Fatal(output.String())
	}
	for _, bad := range [][]string{{"--environment", env, "--session", ref}, {"--environment", env, "--cohort", "group", "--device", device}, {"--environment", env, "--cohort", "../bad"}} {
		output.Reset()
		if evidenceLink(append(bad, "--no-open"), &output, &output) != 2 || strings.Contains(output.String(), "/compliance/evidence#") {
			t.Fatal(output.String())
		}
	}
}
