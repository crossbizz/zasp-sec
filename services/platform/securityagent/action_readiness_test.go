package securityagent

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestProductionActionReadinessExposesOnlyVerifiedActions(t *testing.T) {
	values := ProductionActionMetadata()
	if len(values) != 1 || values[0].Key != "update_finding_response" {
		t.Fatalf("production actions=%#v", values)
	}
	if !ProductionActionAvailable("update_finding_response", AutonomySupervised) || !ProductionActionAvailable("update_finding_response", AutonomyAutonomous) {
		t.Fatal("verified finding response action is unavailable")
	}
	for _, key := range []string{"create_temporary_policy", "isolate_session", "run_test", "rerun_test", "start_attack_lab", "create_evidence_export", "send_response_webhook", "revoke_integration_connection"} {
		if ProductionActionAvailable(key, AutonomySupervised) || ProductionActionAvailable(key, AutonomyAutonomous) {
			t.Fatalf("unverified action %q is available", key)
		}
	}
}

func TestProductionActionReadinessManifestMatchesCodeAndCatalog(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source unavailable")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "docs", "product", "security-agent-action-readiness.tsv")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	rows := []string{}
	for scanner.Scan() {
		rows = append(rows, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(ProductionActionReadiness())+1 || rows[0] != "action_key\tproduction_state\tmaximum_autonomy\tprovider\treversible\tapproval_floor\tverification_kind\tcleanup_kind\tcurrent_evidence" {
		t.Fatalf("manifest shape=%#v", rows)
	}
	for index, value := range ProductionActionReadiness() {
		want := strings.Join([]string{value.Key, value.ProductionState, value.MaximumAutonomy, value.Provider, boolText(value.Reversible), value.ApprovalFloor, value.VerificationKind, value.CleanupKind, value.CurrentEvidence}, "\t")
		if rows[index+1] != want {
			t.Fatalf("manifest row %d=%q want=%q", index+2, rows[index+1], want)
		}
	}

	metadataKeys := []string{"create_temporary_policy"}
	for _, value := range BuiltInResponseActionMetadata() {
		metadataKeys = append(metadataKeys, value.Key)
	}
	slices.Sort(metadataKeys)
	readinessKeys := make([]string, 0, len(ProductionActionReadiness()))
	for _, value := range ProductionActionReadiness() {
		readinessKeys = append(readinessKeys, value.Key)
	}
	if !slices.Equal(metadataKeys, readinessKeys) {
		t.Fatalf("metadata=%#v readiness=%#v", metadataKeys, readinessKeys)
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
