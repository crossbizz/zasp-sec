package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

var (
	errPreflightRejected = errors.New("preflight rejected")
	errManifestRejected  = errors.New("recovery manifest rejected")
	errRestoreRejected   = errors.New("restore rehearsal rejected")
	errUpgradeRejected   = errors.New("upgrade rejected")
)

type CheckStatus string

const (
	checkPass CheckStatus = "pass"
	checkWarn CheckStatus = "warn"
	checkFail CheckStatus = "fail"
)

type PreflightCheck struct {
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Required bool        `json:"required"`
	Hint     string      `json:"hint,omitempty"`
}

type PreflightInput struct {
	IAMRole                 bool   `json:"iam_role"`
	IRSABinding             bool   `json:"irsa_binding"`
	S3Evidence              bool   `json:"s3_evidence"`
	KMS                     bool   `json:"kms"`
	Secrets                 bool   `json:"secrets"`
	Queues                  bool   `json:"queues"`
	DeadLetterQueue         bool   `json:"dead_letter_queue"`
	QueuePermissions        bool   `json:"queue_permissions"`
	OpenSearchReachable     bool   `json:"opensearch_reachable"`
	OpenSearchIndexAccess   bool   `json:"opensearch_index_access"`
	EKSVersionSupported     bool   `json:"eks_version_supported"`
	FargateProfile          bool   `json:"fargate_profile"`
	AttackLabNamespace      bool   `json:"attack_lab_namespace"`
	PrivateNetworking       bool   `json:"private_networking"`
	NeonMigrationCompatible bool   `json:"neon_migration_compatible"`
	NeonPoolReachable       bool   `json:"neon_pool_reachable"`
	StytchProjectReachable  bool   `json:"stytch_project_reachable"`
	StytchSessionReachable  bool   `json:"stytch_session_reachable"`
	SensorMode              string `json:"sensor_mode"`
	KernelSupported         bool   `json:"kernel_supported"`
	BTFPresent              bool   `json:"btf_present"`
	TetragonSupported       bool   `json:"tetragon_supported"`
}

type PreflightReport struct {
	Ready  bool             `json:"ready"`
	Checks []PreflightCheck `json:"checks"`
}

func EvaluatePreflight(input PreflightInput) (PreflightReport, error) {
	if !contains([]string{"disabled", "optional", "required"}, input.SensorMode) {
		return PreflightReport{}, errPreflightRejected
	}
	checks := []PreflightCheck{
		check("iam_irsa", input.IAMRole && input.IRSABinding, true, "allow the product role trust and bind its Kubernetes service account"),
		check("s3_kms_secrets", input.S3Evidence && input.KMS && input.Secrets, true, "grant the product role scoped S3, KMS, and Secrets Manager access"),
		check("sqs", input.Queues && input.DeadLetterQueue && input.QueuePermissions, true, "create the required queue/DLQ pair and grant producer/consumer actions"),
		check("opensearch", input.OpenSearchReachable && input.OpenSearchIndexAccess, true, "allow the private endpoint and required index operations"),
		check("eks_fargate", input.EKSVersionSupported && input.FargateProfile && input.AttackLabNamespace && input.PrivateNetworking, false, "configure the Attack Lab namespace, Fargate selector, and private endpoints"),
		check("neon", input.NeonMigrationCompatible && input.NeonPoolReachable, true, "verify the supported schema and pooled database endpoint"),
		check("stytch", input.StytchProjectReachable && input.StytchSessionReachable, true, "verify the Stytch project and session endpoint"),
	}
	sensorReady := input.SensorMode == "disabled" || input.KernelSupported && input.BTFPresent && input.TetragonSupported
	sensorRequired := input.SensorMode == "required"
	sensor := check("sensor", sensorReady, sensorRequired, "select supported EC2 kernel/BTF nodes or disable the optional sensor")
	if !sensorReady && !sensorRequired {
		sensor.Status = checkWarn
	}
	checks = append(checks, sensor)
	report := PreflightReport{Ready: true, Checks: checks}
	for _, item := range checks {
		if item.Required && item.Status == checkFail {
			report.Ready = false
		}
	}
	if !report.Ready {
		return report, errPreflightRejected
	}
	return report, nil
}

func check(name string, passed, required bool, hint string) PreflightCheck {
	status := checkPass
	if !passed {
		status = checkFail
	}
	return PreflightCheck{Name: name, Status: status, Required: required, Hint: hint}
}

type RecoveryManifest struct {
	SchemaVersion         int               `json:"schema_version"`
	OrganizationID        string            `json:"organization_id"`
	DeploymentMode        string            `json:"deployment_mode"`
	NeonRecoveryPoint     string            `json:"neon_recovery_point"`
	ConfigurationRefs     []string          `json:"configuration_refs"`
	GraphExportReference  string            `json:"graph_export_reference"`
	EvidenceReferences    []string          `json:"evidence_references"`
	ExpectedResourceCount map[string]uint64 `json:"expected_resource_count"`
}

type BackupInput = RecoveryManifest

func BuildBackupManifest(input BackupInput) (RecoveryManifest, error) {
	manifest := RecoveryManifest(input)
	manifest.SchemaVersion = 1
	manifest.ConfigurationRefs = append([]string(nil), input.ConfigurationRefs...)
	manifest.EvidenceReferences = append([]string(nil), input.EvidenceReferences...)
	manifest.ExpectedResourceCount = cloneCounts(input.ExpectedResourceCount)
	sort.Strings(manifest.ConfigurationRefs)
	sort.Strings(manifest.EvidenceReferences)
	if err := validateManifest(manifest); err != nil {
		return RecoveryManifest{}, err
	}
	return manifest, nil
}

func DecodeRecoveryManifest(reader io.Reader) (RecoveryManifest, error) {
	if reader == nil {
		return RecoveryManifest{}, errManifestRejected
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 64*1024+1))
	decoder.DisallowUnknownFields()
	var manifest RecoveryManifest
	if err := decoder.Decode(&manifest); err != nil {
		return RecoveryManifest{}, errManifestRejected
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return RecoveryManifest{}, errManifestRejected
	}
	if err := validateManifest(manifest); err != nil {
		return RecoveryManifest{}, err
	}
	return manifest, nil
}

func validateManifest(manifest RecoveryManifest) error {
	if manifest.SchemaVersion != 1 || !validIdentifier(manifest.OrganizationID) || !contains([]string{"saas", "single_tenant"}, manifest.DeploymentMode) {
		return errManifestRejected
	}
	references := append(append(append([]string{}, manifest.ConfigurationRefs...), manifest.EvidenceReferences...), manifest.NeonRecoveryPoint, manifest.GraphExportReference)
	if len(manifest.ConfigurationRefs) == 0 || len(manifest.EvidenceReferences) == 0 || len(manifest.ExpectedResourceCount) == 0 {
		return errManifestRejected
	}
	for _, reference := range references {
		if !validScopedReference(reference, manifest.OrganizationID) {
			return errManifestRejected
		}
	}
	for name := range manifest.ExpectedResourceCount {
		if !validIdentifier(name) {
			return errManifestRejected
		}
	}
	return nil
}

func validScopedReference(reference, organizationID string) bool {
	return len(reference) <= 512 && strings.HasPrefix(reference, "organizations/"+organizationID+"/") && !strings.ContainsAny(reference, "\r\n\x00")
}

type RestoreRuntime interface {
	Start(context.Context, string, RecoveryManifest) (string, error)
	Poll(context.Context, string) (string, error)
	Validate(context.Context, string, RecoveryManifest) (map[string]uint64, error)
	Cleanup(context.Context, string) error
}

type RestoreRequest struct {
	SourceEnvironment string
	TargetEnvironment string
	DisposableTarget  bool
	Manifest          RecoveryManifest
	PollLimit         int
}

type RestoreResult struct {
	RehearsalID string `json:"rehearsal_id"`
	State       string `json:"state"`
	Validated   bool   `json:"validated"`
	Cleaned     bool   `json:"cleaned"`
}

func RunRestoreRehearsal(ctx context.Context, request RestoreRequest, runtime RestoreRuntime) (result RestoreResult, resultErr error) {
	if ctx == nil || runtime == nil || !request.DisposableTarget || request.TargetEnvironment == "" || request.TargetEnvironment == "production" || request.TargetEnvironment == request.SourceEnvironment || request.PollLimit < 1 || request.PollLimit > 60 {
		return result, errRestoreRejected
	}
	if err := validateManifest(request.Manifest); err != nil {
		return result, err
	}
	id, err := runtime.Start(ctx, request.TargetEnvironment, request.Manifest)
	if err != nil || !validIdentifier(id) {
		return result, errRestoreRejected
	}
	result.RehearsalID = id
	defer func() {
		if cleanupErr := runtime.Cleanup(context.WithoutCancel(ctx), request.TargetEnvironment); cleanupErr != nil {
			resultErr = errRestoreRejected
			return
		}
		result.Cleaned = true
	}()
	for attempt := 0; attempt < request.PollLimit; attempt++ {
		state, pollErr := runtime.Poll(ctx, id)
		if pollErr != nil {
			return result, errRestoreRejected
		}
		if state == "failed" {
			result.State = state
			return result, errRestoreRejected
		}
		if state != "complete" {
			continue
		}
		result.State = state
		counts, validationErr := runtime.Validate(ctx, request.TargetEnvironment, request.Manifest)
		if validationErr != nil || !equalCounts(counts, request.Manifest.ExpectedResourceCount) {
			return result, errRestoreRejected
		}
		result.Validated = true
		return result, nil
	}
	return result, errRestoreRejected
}

type UpgradeInput struct {
	CurrentVersion            string `json:"current_version"`
	TargetVersion             string `json:"target_version"`
	MigrationCompatible       bool   `json:"migration_compatible"`
	BundleFormatCompatible    bool   `json:"bundle_format_compatible"`
	RollbackArtifactReference string `json:"rollback_artifact_reference"`
	RecoveryReference         string `json:"recovery_reference"`
}

type UpgradeReport struct {
	Ready  bool             `json:"ready"`
	Checks []PreflightCheck `json:"checks"`
}

func EvaluateUpgrade(input UpgradeInput) (UpgradeReport, error) {
	checks := []PreflightCheck{
		check("version", compatibleVersion(input.CurrentVersion, input.TargetVersion), true, "upgrade only from the previous supported product version"),
		check("migration", input.MigrationCompatible, true, "resolve incompatible Neon migrations before upgrade"),
		check("bundle", input.BundleFormatCompatible, true, "upgrade policy/content bundles to the supported format"),
		check("rollback", validReference(input.RollbackArtifactReference) && validReference(input.RecoveryReference), true, "provide immutable rollback and recovery references"),
	}
	report := UpgradeReport{Ready: true, Checks: checks}
	for _, item := range checks {
		if item.Status == checkFail {
			report.Ready = false
		}
	}
	if !report.Ready {
		return report, errUpgradeRejected
	}
	return report, nil
}

type UpgradeRuntime interface {
	StartFixture(context.Context, string) (string, error)
	StartUpgrade(context.Context, string, string) (string, string, error)
}

type UpgradeResult struct {
	FixtureID   string `json:"fixture_id"`
	ReleaseID   string `json:"release_id"`
	MigrationID string `json:"migration_id"`
}

func RunUpgradeFixture(ctx context.Context, input UpgradeInput, runtime UpgradeRuntime) (UpgradeResult, error) {
	if ctx == nil || runtime == nil {
		return UpgradeResult{}, errUpgradeRejected
	}
	if _, err := EvaluateUpgrade(input); err != nil {
		return UpgradeResult{}, err
	}
	fixtureID, err := runtime.StartFixture(ctx, input.CurrentVersion)
	if err != nil || !validIdentifier(fixtureID) {
		return UpgradeResult{}, errUpgradeRejected
	}
	releaseID, migrationID, err := runtime.StartUpgrade(ctx, fixtureID, input.TargetVersion)
	if err != nil || !validIdentifier(releaseID) || !validIdentifier(migrationID) {
		return UpgradeResult{}, errUpgradeRejected
	}
	return UpgradeResult{FixtureID: fixtureID, ReleaseID: releaseID, MigrationID: migrationID}, nil
}

func encodeJSON(writer io.Writer, value any) error {
	if writer == nil {
		return errOutputUnavailable
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}

func cloneCounts(input map[string]uint64) map[string]uint64 {
	output := make(map[string]uint64, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func equalCounts(left, right map[string]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-:", character) {
			continue
		}
		return false
	}
	return true
}

func validReference(value string) bool {
	return len(value) >= 8 && len(value) <= 512 && !strings.ContainsAny(value, "\r\n\x00") && (strings.HasPrefix(value, "s3://") || strings.HasPrefix(value, "oci://"))
}

func compatibleVersion(current, target string) bool {
	var currentMajor, currentMinor, currentPatch, targetMajor, targetMinor, targetPatch int
	if _, err := fmt.Sscanf(current, "%d.%d.%d", &currentMajor, &currentMinor, &currentPatch); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(target, "%d.%d.%d", &targetMajor, &targetMinor, &targetPatch); err != nil {
		return false
	}
	if currentMajor < 0 || currentMinor < 0 || currentPatch < 0 || targetMajor < 0 || targetMinor < 0 || targetPatch < 0 {
		return false
	}
	if current != fmt.Sprintf("%d.%d.%d", currentMajor, currentMinor, currentPatch) || target != fmt.Sprintf("%d.%d.%d", targetMajor, targetMinor, targetPatch) {
		return false
	}
	return currentMajor == targetMajor && targetMinor >= currentMinor && targetMinor-currentMinor <= 1 && (targetMinor > currentMinor || targetPatch > currentPatch)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func runReleaseCommand(output io.Writer, input io.Reader, arguments []string) error {
	if output == nil || input == nil || len(arguments) == 0 {
		return errInvalidArguments
	}
	switch arguments[0] {
	case "preflight":
		if len(arguments) != 1 {
			return errInvalidArguments
		}
		var value PreflightInput
		if err := decodeCommandInput(input, &value); err != nil {
			return errPreflightRejected
		}
		report, err := EvaluatePreflight(value)
		if err != nil {
			return err
		}
		return encodeJSON(output, report)
	case "backup":
		if len(arguments) != 1 {
			return errInvalidArguments
		}
		var value BackupInput
		if err := decodeCommandInput(input, &value); err != nil {
			return errManifestRejected
		}
		manifest, err := BuildBackupManifest(value)
		if err != nil {
			return err
		}
		return encodeJSON(output, manifest)
	case "restore-validate":
		if len(arguments) != 3 || arguments[1] == arguments[2] || arguments[2] == "production" || !validIdentifier(arguments[1]) || !validIdentifier(arguments[2]) {
			return errRestoreRejected
		}
		manifest, err := DecodeRecoveryManifest(input)
		if err != nil {
			return err
		}
		return encodeJSON(output, map[string]any{"accepted": true, "organization_id": manifest.OrganizationID, "target": arguments[2]})
	case "upgrade-preflight":
		if len(arguments) != 1 {
			return errInvalidArguments
		}
		var value UpgradeInput
		if err := decodeCommandInput(input, &value); err != nil {
			return errUpgradeRejected
		}
		report, err := EvaluateUpgrade(value)
		if err != nil {
			return err
		}
		return encodeJSON(output, report)
	case "diagnostics":
		if len(arguments) != 1 {
			return errInvalidArguments
		}
		var value DiagnosticsInput
		if err := decodeCommandInput(input, &value); err != nil {
			return errResilienceRejected
		}
		bundle, err := BuildDiagnosticsBundle(value)
		if err != nil {
			return err
		}
		return encodeJSON(output, bundle)
	default:
		return errInvalidArguments
	}
}

func decodeCommandInput(reader io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 64*1024+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errInvalidArguments
	}
	return nil
}
