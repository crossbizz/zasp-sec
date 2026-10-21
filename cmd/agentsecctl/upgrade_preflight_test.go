package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Existing actual command entry point only: no new product symbol or fake live
// observer is needed to demonstrate that caller strings/booleans cannot prove
// rollback prerequisite existence. Root records the actual initial outcome.
func TestUpgradePreflightRequiresObservedPrerequisites(t *testing.T) {
	input := UpgradeInput{
		CurrentVersion: "1.4.2", TargetVersion: "1.5.0",
		MigrationCompatible: true, BundleFormatCompatible: true,
		RollbackArtifactReference: "oci://registry.example/zasp/release@sha256:" + strings.Repeat("a", 64),
		RecoveryReference:         "s3://nonexistent-recovery/organizations/pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/manifest.json",
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal("controlled upgrade input encoding failed")
	}
	missing := input
	missing.RecoveryReference = ""
	for _, fixture := range []struct {
		name  string
		value UpgradeInput
	}{{"plausible nonexistent references", input}, {"missing rollback prerequisite remains failed", missing}} {
		t.Run(fixture.name, func(t *testing.T) {
			body, _ := json.Marshal(fixture.value)
			var output bytes.Buffer
			err := runReleaseCommand(&output, bytes.NewReader(body), []string{"upgrade-preflight"})
			if !errors.Is(err, errUpgradeRejected) {
				t.Fatal("unobserved prerequisites did not retain upgrade command failure")
			}
			var report map[string]json.RawMessage
			decoder := json.NewDecoder(&output)
			if err := decoder.Decode(&report); err != nil {
				t.Fatal("evaluated unverified prerequisite report missing")
			}
			var ready bool
			if raw, exists := report["ready"]; !exists || string(raw) == "null" || json.Unmarshal(raw, &ready) != nil || ready {
				t.Fatal("caller URI/compatibility claims became observed readiness")
			}
			var trailing any
			if decoder.Decode(&trailing) != io.EOF {
				t.Fatal("unverified report contains extra output")
			}
			if bytes.Contains(output.Bytes(), []byte(input.RollbackArtifactReference)) || bytes.Contains(output.Bytes(), []byte(input.RecoveryReference)) {
				t.Fatal("prerequisite refusal reflected caller artifact locators")
			}
		})
	}
	t.Run("pure compatibility evaluator remains explicitly offline", func(t *testing.T) {
		result, err := EvaluateUpgrade(input)
		if err != nil || !result.Ready || len(result.Checks) != 4 {
			t.Fatal("offline compatibility evaluator changed while fixing live command")
		}
	})
	t.Run("incompatible input remains a reported blocker", func(t *testing.T) {
		incompatible := input
		incompatible.MigrationCompatible = false
		body, _ := json.Marshal(incompatible)
		var output bytes.Buffer
		if err := runReleaseCommand(&output, bytes.NewReader(body), []string{"upgrade-preflight"}); !errors.Is(err, errUpgradeRejected) || output.Len() == 0 {
			t.Fatal("incompatibility lost failure or evaluated report")
		}
		var report struct {
			Ready bool `json:"ready"`
		}
		if json.Unmarshal(output.Bytes(), &report) != nil || report.Ready {
			t.Fatal("incompatible preflight produced readiness")
		}
	})
	t.Run("malformed and unknown input has zero output", func(t *testing.T) {
		for _, raw := range []string{
			`{`,
			string(encoded) + ` {}`,
			strings.Replace(string(encoded), `"migration_compatible":true`, `"migration_compatible":"true"`, 1),
			strings.TrimSuffix(string(encoded), "}") + `,"secret":"not-accepted"}`,
			strings.TrimSuffix(string(encoded), "}") + `,"current_version":"1.4.2"}`,
			strings.Replace(string(encoded), `"current_version"`, `"CURRENT_VERSION"`, 1),
		} {
			var output bytes.Buffer
			if err := runReleaseCommand(&output, strings.NewReader(raw), []string{"upgrade-preflight"}); err == nil || output.Len() != 0 {
				t.Fatal("invalid upgrade input produced report or succeeded")
			}
		}
	})
	t.Run("invalid command arguments have zero output", func(t *testing.T) {
		var output bytes.Buffer
		if err := runReleaseCommand(&output, bytes.NewReader(encoded), []string{"upgrade-preflight", "unexpected"}); !errors.Is(err, errInvalidArguments) || output.Len() != 0 {
			t.Fatal("invalid upgrade command arguments were evaluated")
		}
	})
	t.Run("report write failure propagates", func(t *testing.T) {
		if err := runReleaseCommand(preflightReportFailingWriter{}, bytes.NewReader(encoded), []string{"upgrade-preflight"}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("preflight report output failure was hidden")
		}
	})
}

// Late integration coverage: authored after the concrete command seam. These
// fixtures exercise the existing real TLS/credential client, not a fake success
// artifact observer and not live API/provider acceptance.
func TestUpgradePreflightLiveRecoveryMetadata(t *testing.T) {
	for _, mode := range []string{"bound_completed_metadata", "queued", "failed", "wrong_id", "wrong_scope", "wrong_immutable_version", "wrong_digest", "wrong_size", "wrong_media_type", "wrong_schema", "wrong_signing_key", "wrong_signature", "denied", "redirect", "malformed", "oversized", "missing_local_credential", "canceled_before_client", "canceled_after_response"} {
		t.Run(mode, func(t *testing.T) {
			manifest := recoveryManifestFixture()
			value := liveUpgradeInput{UpgradeInput: UpgradeInput{CurrentVersion: "1.4.2", TargetVersion: "1.5.0", MigrationCompatible: true, BundleFormatCompatible: true, RollbackArtifactReference: "oci://registry.example/zasp@sha256:" + strings.Repeat("b", 64), RecoveryReference: manifest.Reference}, OrganizationID: "pid_7d000010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d000011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d000012-0000-4000-8000-000000000012", BackupID: recoveryBackupID, ExpectedRecoveryManifest: &manifest}
			returned := manifest
			backup := recoveryBackup{ID: recoveryBackupID, Version: 1, State: "succeeded", RetentionDays: 30, Attempt: 1, Manifest: &returned, CreatedAt: "2026-08-25T16:00:00Z", StartedAt: "2026-08-25T16:00:01Z", CompletedAt: "2026-08-25T16:00:02Z"}
			switch mode {
			case "queued":
				backup = mustRecoveryBackupFixture()
			case "failed":
				backup.State = "failed"
				backup.Manifest = nil
				backup.ErrorCode = "dependency_unavailable"
			case "wrong_id":
				backup.ID = recoveryRestoreID
			case "wrong_scope":
				returned.Reference = strings.Replace(returned.Reference, value.OrganizationID, "pid_7d000099-0000-4000-8000-000000000099", 1)
			case "wrong_immutable_version":
				returned.VersionID = "version-2"
			case "wrong_digest":
				returned.SHA256 = strings.Repeat("b", 64)
			case "wrong_size":
				returned.SizeBytes++
			case "wrong_media_type":
				returned.MediaType = "application/json"
			case "wrong_schema":
				returned.Schema = "unaccepted_v1"
			case "wrong_signing_key":
				returned.SigningKeyID = "223e4567-e89b-42d3-a456-426614174000"
			case "wrong_signature":
				returned.Signature = strings.Repeat("A", 43)
			}
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/recovery/backups/"+recoveryBackupID || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 48) {
					t.Error("command widened fixed authenticated read contract")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("ETag", `"1"`)
				switch mode {
				case "denied":
					w.WriteHeader(http.StatusForbidden)
					return
				case "redirect":
					w.Header().Set("Location", "https://unrequested.example/secret")
					w.WriteHeader(http.StatusFound)
					return
				case "malformed":
					_, _ = io.WriteString(w, `{"id":`)
					return
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", maximumRecoveryResponseBytes+1))
					return
				}
				_ = json.NewEncoder(w).Encode(backup)
			}))
			defer server.Close()
			config, dial := recoveryTLSFixture(t, server)
			if mode == "missing_local_credential" {
				if err := os.Remove(config.CredentialFile); err != nil {
					t.Fatal("owned fixture removal failed")
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled_before_client" {
				cancel()
			}
			factoryCalls := 0
			factory := func(c RecoveryClientConfig) (upgradeBackupReader, error) {
				factoryCalls++
				client, err := newRecoveryClientWithDial(c, dial)
				if err != nil {
					return nil, err
				}
				if mode == "canceled_after_response" {
					return &cancelAfterUpgradeRead{upgradeBackupReader: client, cancel: cancel}, nil
				}
				return client, nil
			}
			encoded, _ := json.Marshal(value)
			arguments := []string{"upgrade-preflight", "--endpoint", config.Endpoint, "--credential-file", config.CredentialFile, "--ca-bundle-file", config.CABundleFile, "--timeout", config.Timeout.String()}
			var output bytes.Buffer
			if err := runLiveUpgradePreflightWithFactory(ctx, &output, bytes.NewReader(encoded), arguments, factory); !errors.Is(err, errUpgradeRejected) {
				t.Fatal("unverified artifact did not block upgrade")
			}
			var report liveUpgradeReport
			if json.Unmarshal(output.Bytes(), &report) != nil || report.Ready || report.Mode != "live-upgrade-prerequisites" || report.Compatibility.Kind != "offline-input-evaluation" || !report.Compatibility.Report.Ready || len(report.Checks) != 2 || report.Checks[1].Name != "rollback_artifact_observation" || !report.Checks[1].Required || report.Checks[1].Status != checkFail {
				t.Fatal("live report confused compatibility or metadata with verified rollback readiness")
			}
			wantPass := mode == "bound_completed_metadata"
			if (report.Checks[0].Status == checkPass) != wantPass || (report.BackupObservedAt != "") != wantPass {
				t.Fatal("metadata binding/refusal or observation timestamp differs")
			}
			if wantPass {
				stamp, err := time.Parse(time.RFC3339Nano, report.BackupObservedAt)
				if err != nil || stamp.Location() != time.UTC {
					t.Fatal("observed backup time is not canonical UTC")
				}
			}
			wantRequests := int32(1)
			if mode == "missing_local_credential" || mode == "canceled_before_client" {
				wantRequests = 0
			}
			if requests.Load() != wantRequests || mode == "canceled_before_client" && factoryCalls != 0 {
				t.Fatal("command invented an attempt or made extra requests")
			}
			for _, secret := range []string{strings.Repeat("t", 48), manifest.Reference, config.CredentialFile, returned.Signature, "unrequested.example"} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("report reflected credential/provider material")
				}
			}
		})
	}
}

type cancelAfterUpgradeRead struct {
	upgradeBackupReader
	cancel context.CancelFunc
}

func (r *cancelAfterUpgradeRead) GetBackup(ctx context.Context, id string) (recoveryBackup, error) {
	result, err := r.upgradeBackupReader.GetBackup(ctx, id)
	r.cancel()
	return result, err
}
