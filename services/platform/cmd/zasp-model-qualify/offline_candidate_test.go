package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

func TestOfflineCandidateCannotBecomeTenantQualification(t *testing.T) {
	ids := []string{"pid_11111111-1111-4111-8111-111111111111", "pid_22222222-2222-4222-8222-222222222222", "pid_33333333-3333-4333-8333-333333333333"}
	if err := run("", "", "", "", true, true, ids); err == nil || err.Error() != "invalid qualification scope or mode" {
		t.Fatal("allowed offline candidate on tenant queue", err)
	}
	a := aigateway.DeploymentAttestation{Purpose: aigateway.PurposeHeuristicVerify, Deployment: aigateway.Deployment{Model: "openai/gpt-oss-safeguard-20b", Provider: aigateway.ModeBYOC}}
	if err := record(t.Context(), nil, ids, nil, a, aigateway.QualificationResult{Qualified: true}); err == nil {
		t.Fatal("published an offline report")
	}
}

func TestOfflineCandidateCredentialMount(t *testing.T) {
	p := filepath.Join(t.TempDir(), "candidate-token")
	if err := os.WriteFile(p, []byte("fixture-secret-value"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := candidateInput(p, 8193, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := candidateInput(p, 8193, true); err == nil {
		t.Fatal("credential readable by others")
	}
	if err := os.Symlink(p, p+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := candidateInput(p+".link", 8193, false); err == nil {
		t.Fatal("followed changing mount")
	}
}
