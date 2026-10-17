package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func livePreflightContractConfig(t *testing.T, kind string) []byte {
	t.Helper()
	credentials := map[string]any{"kind": kind, "expected_role_arn": "arn:aws:iam::123456789012:role/zasp-preflight-inspector"}
	if kind == "operator_file" {
		credentials["file"] = filepath.Join(t.TempDir(), "missing-credentials.json")
	}
	if kind == "workload_web_identity" {
		credentials["expected_role_arn"] = "arn:aws:iam::123456789012:role/zasp-runtime-index"
		credentials["token_file"] = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
		credentials["namespace"] = "agentsec"
		credentials["service_account"] = "zasp-runtime-index"
	}
	value := map[string]any{
		"schema":      "agentsec-preflight-config-v1",
		"deployment":  map[string]string{"account_id": "123456789012", "region": "us-west-2", "partition": "aws", "profile": "canonical61-temporal78-authorization79-80-worker-v1", "release_version": "test"},
		"scope":       map[string]string{"organization_id": "pid_00000000-0000-4000-8000-000000000001", "workspace_id": "pid_00000000-0000-4000-8000-000000000002", "environment_id": "pid_00000000-0000-4000-8000-000000000003"},
		"credentials": credentials, "features": map[string]string{"attack_lab": "enabled", "sensor_mode": "required"},
		"aws": map[string]any{"buckets": []any{}, "secrets": []any{}, "queues": []any{}},
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("controlled config encoding failed")
	}
	return body
}
func writeLivePreflightContractFile(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "preflight.json")
	// Set the intended fixture permissions explicitly; inherited umask must not
	// turn a public-file rejection case into a private, valid config.
	if os.WriteFile(file, body, mode) != nil || os.Chmod(file, mode) != nil {
		t.Fatal("controlled private config unavailable")
	}
	return file
}
func TestLivePreflightCommandKeepsOriginalUnknownAwareRoster(t *testing.T) {
	for _, mode := range []string{"before-install", "installed"} {
		t.Run(mode, func(t *testing.T) {
			file := writeLivePreflightContractFile(t, livePreflightContractConfig(t, "operator_file"), 0600)
			var output bytes.Buffer
			err := runReleaseCommand(&output, strings.NewReader(""), []string{"preflight", "run", "--mode", mode, "--config-file", file})
			if err == nil {
				t.Fatal("unavailable explicit credentials became readiness")
			}
			var report struct {
				Schema     string `json:"schema"`
				Mode       string `json:"mode"`
				Source     string `json:"source"`
				Ready      bool   `json:"ready"`
				Install    bool   `json:"install_prerequisites_ready"`
				Runtime    bool   `json:"runtime_observations_ready"`
				Production bool   `json:"production_end_to_end_verified"`
				Checks     []struct {
					Name, Status, Hint string
					Required           bool
					Observations       []struct{ Name, Status, Kind, Code string }
				} `json:"checks"`
			}
			if json.Unmarshal(output.Bytes(), &report) != nil || report.Schema != "agentsec-preflight-report-v1" || report.Mode != mode || report.Source != "live-probes" {
				t.Fatal("live command did not emit its bounded prerequisite report")
			}
			if report.Ready || report.Install || report.Runtime || report.Production {
				t.Fatal("unknown dependencies became install/runtime/production readiness")
			}
			sections := []string{"iam_irsa", "s3_kms_secrets", "sqs", "opensearch", "eks_fargate", "neon", "stytch", "sensor"}
			expected := [][]string{{"iam_role", "irsa_trust", "irsa_binding"}, {"s3_evidence", "kms", "secrets"}, {"queues", "dead_letter_queue", "queue_permissions"}, {"opensearch_reachable", "opensearch_index_access"}, {"eks_version_supported", "fargate_profile", "attack_lab_namespace", "private_networking"}, {"neon_migration_compatible", "neon_pool_reachable"}, {"stytch_project_reachable", "stytch_session_reachable"}, {"kernel_supported", "btf_present", "tetragon_supported"}}
			if len(report.Checks) != len(sections) {
				t.Fatal("original preflight sections omitted")
			}
			for i, check := range report.Checks {
				if check.Name != sections[i] || check.Hint == "" || !check.Required || check.Status != "fail" || len(check.Observations) != len(expected[i]) {
					t.Fatal("missing dependency obscured original requirement or remediation")
				}
				for j, observation := range check.Observations {
					if observation.Name != expected[i][j] || observation.Status == "pass" || observation.Code == "" {
						t.Fatal("an unobserved original capability became a passing observation")
					}
				}
			}
			if bytes.Contains(output.Bytes(), []byte(file)) || strings.Contains(output.String(), "missing-credentials.json") {
				t.Fatal("private file path reflected in report")
			}
		})
	}
}
func TestLivePreflightRejectsInputAttestationAndUnsafeConfig(t *testing.T) {
	valid := livePreflightContractConfig(t, "operator_file")
	for _, kind := range []string{"unknown observation", "duplicate key", "trailing input", "public config", "invalid mode"} {
		t.Run(kind, func(t *testing.T) {
			body := append([]byte(nil), valid...)
			mode := os.FileMode(0600)
			selected := "before-install"
			switch kind {
			case "unknown observation":
				body = append(body[:len(body)-1], []byte(`,"iam_role":true}`)...)
			case "duplicate key":
				body = append(body[:len(body)-1], []byte(`,"schema":"agentsec-preflight-config-v1"}`)...)
			case "trailing input":
				body = append(body, []byte(` {}`)...)
			case "public config":
				mode = 0644
			case "invalid mode":
				selected = "automatic"
			}
			file := writeLivePreflightContractFile(t, body, mode)
			var output bytes.Buffer
			if runReleaseCommand(&output, strings.NewReader(""), []string{"preflight", "run", "--mode", selected, "--config-file", file}) == nil || output.Len() != 0 {
				t.Fatal("malformed configuration or attested Boolean entered live observation path")
			}
		})
	}
}
func TestOriginalPreflightEvaluatorIsExplicitlyOffline(t *testing.T) {
	body, err := json.Marshal(validPreflight())
	if err != nil {
		t.Fatal("offline fixture unavailable")
	}
	var output bytes.Buffer
	if runReleaseCommand(&output, bytes.NewReader(body), []string{"preflight", "evaluate", "--offline"}) != nil {
		t.Fatal("original offline evaluator was not retained explicitly")
	}
	var report struct {
		Mode       string `json:"mode"`
		Source     string `json:"source"`
		Ready      bool   `json:"ready"`
		Production bool   `json:"production_end_to_end_verified"`
	}
	if json.Unmarshal(output.Bytes(), &report) != nil || report.Mode != "offline" || report.Source != "offline-evaluation" || report.Ready || report.Production {
		t.Fatal("offline Booleans became deployment or production proof")
	}
}
