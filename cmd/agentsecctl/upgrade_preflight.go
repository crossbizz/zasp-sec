package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"strings"
	"time"
)

type liveUpgradeInput struct {
	UpgradeInput
	OrganizationID           string                   `json:"organization_id"`
	WorkspaceID              string                   `json:"workspace_id"`
	EnvironmentID            string                   `json:"environment_id"`
	BackupID                 string                   `json:"backup_id"`
	ExpectedRecoveryManifest *recoveryManifestLocator `json:"expected_recovery_manifest,omitempty"`
}

type liveUpgradeReport struct {
	Ready         bool   `json:"ready"`
	Mode          string `json:"mode"`
	Compatibility struct {
		Kind   string        `json:"kind"`
		Report UpgradeReport `json:"report"`
	} `json:"compatibility"`
	Checks           []PreflightCheck `json:"checks"`
	BackupObservedAt string           `json:"backup_observed_at,omitempty"`
}

// This read-only command has no artifact observer or readiness override. The
// existing worker ArtifactStore/KMS authority is not implicitly a CLI authority.
// Adding one later requires an explicit immutable release-artifact contract.
type upgradeBackupReader interface {
	GetBackup(context.Context, string) (recoveryBackup, error)
	Close() error
}
type upgradeBackupReaderFactory func(RecoveryClientConfig) (upgradeBackupReader, error)

func runLiveUpgradePreflight(ctx context.Context, output io.Writer, input io.Reader, arguments []string) error {
	return runLiveUpgradePreflightWithFactory(ctx, output, input, arguments, func(c RecoveryClientConfig) (upgradeBackupReader, error) { return NewRecoveryClient(c) })
}

func liveUpgradeConfiguration(arguments []string) (RecoveryClientConfig, error) {
	if len(arguments) == 0 || arguments[0] != "upgrade-preflight" {
		return RecoveryClientConfig{}, errInvalidArguments
	}
	seen := map[string]bool{}
	for n := 1; n < len(arguments); n += 2 {
		if n+1 >= len(arguments) || seen[arguments[n]] || !strings.HasPrefix(arguments[n], "--") {
			return RecoveryClientConfig{}, errInvalidArguments
		}
		seen[arguments[n]] = true
	}
	flags := flag.NewFlagSet("upgrade-preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	endpoint := flags.String("endpoint", "", "")
	credential := flags.String("credential-file", "", "")
	ca := flags.String("ca-bundle-file", "", "")
	timeout := flags.String("timeout", "", "")
	if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 {
		return RecoveryClientConfig{}, errInvalidArguments
	}
	var duration time.Duration
	if *timeout != "" {
		var err error
		duration, err = time.ParseDuration(*timeout)
		if err != nil || duration < 100*time.Millisecond || duration > 30*time.Second {
			return RecoveryClientConfig{}, errInvalidArguments
		}
	}
	return RecoveryClientConfig{Endpoint: *endpoint, CredentialFile: *credential, CABundleFile: *ca, Timeout: duration}, nil
}

func decodeLiveUpgradeInput(input io.Reader) (liveUpgradeInput, error) {
	if input == nil {
		return liveUpgradeInput{}, errUpgradeRejected
	}
	raw, err := io.ReadAll(io.LimitReader(input, maximumRecoveryManifestBytes+1))
	if err != nil || len(raw) > maximumRecoveryManifestBytes || !uniqueReleaseJSON(raw) {
		return liveUpgradeInput{}, errUpgradeRejected
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return liveUpgradeInput{}, errUpgradeRejected
	}
	allowed := map[string]bool{"current_version": true, "target_version": true, "migration_compatible": true, "bundle_format_compatible": true, "rollback_artifact_reference": true, "recovery_reference": true, "organization_id": true, "workspace_id": true, "environment_id": true, "backup_id": true, "expected_recovery_manifest": true}
	for key, value := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return liveUpgradeInput{}, errUpgradeRejected
		}
	}
	if manifest, ok := fields["expected_recovery_manifest"]; ok {
		var parts map[string]json.RawMessage
		if json.Unmarshal(manifest, &parts) != nil || parts == nil {
			return liveUpgradeInput{}, errUpgradeRejected
		}
		keys := map[string]bool{"reference": true, "version_id": true, "sha256": true, "size_bytes": true, "media_type": true, "schema": true, "signing_key_id": true, "signature": true}
		for key, value := range parts {
			if !keys[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return liveUpgradeInput{}, errUpgradeRejected
			}
		}
	}
	var value liveUpgradeInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return liveUpgradeInput{}, errUpgradeRejected
	}
	return value, nil
}

func liveUpgradeSelectorsValid(v liveUpgradeInput) bool {
	if !validRecoveryProductID(v.OrganizationID) || !validRecoveryProductID(v.WorkspaceID) || !validRecoveryProductID(v.EnvironmentID) || !validRecoveryProductID(v.BackupID) || v.ExpectedRecoveryManifest == nil || !validRecoveryManifest(*v.ExpectedRecoveryManifest) || v.RecoveryReference != v.ExpectedRecoveryManifest.Reference {
		return false
	}
	parts := recoveryReferencePattern.FindStringSubmatch(v.ExpectedRecoveryManifest.Reference)
	return len(parts) == 5 && parts[1] == v.OrganizationID && parts[2] == v.WorkspaceID && parts[3] == v.EnvironmentID
}

func runLiveUpgradePreflightWithFactory(ctx context.Context, output io.Writer, input io.Reader, arguments []string, factory upgradeBackupReaderFactory) error {
	if ctx == nil || output == nil || factory == nil {
		return errInvalidArguments
	}
	config, err := liveUpgradeConfiguration(arguments)
	if err != nil {
		return err
	}
	value, err := decodeLiveUpgradeInput(input)
	if err != nil {
		return err
	}
	compatibility, _ := EvaluateUpgrade(value.UpgradeInput)
	report := liveUpgradeReport{Ready: false, Mode: "live-upgrade-prerequisites"}
	report.Compatibility.Kind = "offline-input-evaluation"
	report.Compatibility.Report = compatibility
	metadataOK := false
	configured := config.Endpoint != "" && config.CredentialFile != "" && config.CABundleFile != "" && config.Timeout >= 100*time.Millisecond && config.Timeout <= 30*time.Second
	if ctx.Err() == nil && configured && liveUpgradeSelectorsValid(value) {
		reader, err := factory(config)
		if reader != nil {
			defer reader.Close()
		}
		if err == nil && reader != nil && ctx.Err() == nil {
			observedAt := time.Now().UTC()
			backup, readErr := reader.GetBackup(ctx, value.BackupID)
			completed, completedErr := parseRecoveryTime(backup.CompletedAt)
			if readErr == nil && ctx.Err() == nil && validRecoveryBackup(backup) && backup.ID == value.BackupID && backup.State == "succeeded" && backup.Manifest != nil && *backup.Manifest == *value.ExpectedRecoveryManifest && completedErr == nil && !completed.After(observedAt) {
				metadataOK = true
				report.BackupObservedAt = observedAt.Format(time.RFC3339Nano)
			}
		}
	}
	// Even a successful API record proves only completed backup metadata. Its
	// locator/signature encoding does not prove object bytes, signature validity,
	// manifest expiry, recovery child objects or rollback release existence.
	report.Checks = []PreflightCheck{
		check("completed_backup_metadata", metadataOK, true, "verify the selected completed backup and exact scoped immutable manifest through the authenticated recovery API"),
		check("rollback_artifact_observation", false, true, "rollback artifact remains unverified; configure a reviewed immutable artifact verifier before upgrade"),
	}
	if err := encodeJSON(output, report); err != nil {
		return err
	}
	return errUpgradeRejected
}
