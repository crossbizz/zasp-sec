package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recoveryJobMode string

const (
	recoveryJobModePostgresValidation recoveryJobMode = "recovery-postgres-validation"
	recoveryJobModeGraphProjection    recoveryJobMode = "recovery-graph-projection"
	recoveryJobModeSearchProjection   recoveryJobMode = "recovery-search-projection"
	recoveryValidateScopeSQL                          = `SELECT zasp_recovery_validate_scope($1,$2,$3)`
)

type recoveryJobConfig struct {
	Mode                 recoveryJobMode
	PostgresDSN          string
	BranchIP             string
	OrganizationID       string
	WorkspaceID          string
	EnvironmentID        string
	TargetEnvironment    string
	ProjectionSHA256     string
	EvidenceSampleSHA256 string
	TargetDirectory      string
}

type recoveryJobDatabase interface {
	ValidateScope(context.Context, string, string, string) (json.RawMessage, error)
}

type postgresRecoveryJobDatabase struct{ pool *pgxpool.Pool }

func (database *postgresRecoveryJobDatabase) ValidateScope(ctx context.Context, organization, workspace, environment string) (json.RawMessage, error) {
	if database == nil || database.pool == nil || ctx == nil || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	var result json.RawMessage
	if err := database.pool.QueryRow(ctx, recoveryValidateScopeSQL, organization, workspace, environment).Scan(&result); err != nil || len(result) < 2 || len(result) > 64<<20 {
		return nil, errWorkerExecution
	}
	return append(json.RawMessage(nil), result...), nil
}

func loadRecoveryJobConfig(getenv func(string) string) (recoveryJobConfig, error) {
	if getenv == nil {
		return recoveryJobConfig{}, errWorkerConfiguration
	}
	config := recoveryJobConfig{
		Mode: recoveryJobMode(getenv("ZASP_WORKER_MODE")), PostgresDSN: getenv("ZASP_POSTGRES_DSN"), BranchIP: getenv("ZASP_RECOVERY_BRANCH_IP"), OrganizationID: getenv("ZASP_RECOVERY_ORGANIZATION_ID"), WorkspaceID: getenv("ZASP_RECOVERY_WORKSPACE_ID"), EnvironmentID: getenv("ZASP_RECOVERY_ENVIRONMENT_ID"), TargetEnvironment: getenv("ZASP_RECOVERY_TARGET_ENVIRONMENT"), ProjectionSHA256: getenv("ZASP_RECOVERY_PROJECTION_SHA256"), EvidenceSampleSHA256: getenv("ZASP_RECOVERY_EVIDENCE_SAMPLE_SHA256"), TargetDirectory: getenv("ZASP_RECOVERY_TARGET_DIRECTORY"),
	}
	if !validRecoveryJobConfig(config) {
		return recoveryJobConfig{}, errWorkerConfiguration
	}
	return config, nil
}

func validRecoveryJobConfig(config recoveryJobConfig) bool {
	if config.Mode != recoveryJobModePostgresValidation && config.Mode != recoveryJobModeGraphProjection && config.Mode != recoveryJobModeSearchProjection {
		return false
	}
	organization, organizationErr := domain.ParseProductID(config.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(config.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(config.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	digest, digestErr := hex.DecodeString(config.ProjectionSHA256)
	evidenceDigest, evidenceDigestErr := hex.DecodeString(config.EvidenceSampleSHA256)
	parsed, dsnErr := url.Parse(config.PostgresDSN)
	branchIP := net.ParseIP(config.BranchIP)
	validTargetPath := len(config.TargetDirectory) >= 2 && len(config.TargetDirectory) <= 256 && filepath.IsAbs(config.TargetDirectory) && filepath.Clean(config.TargetDirectory) == config.TargetDirectory
	validTarget := config.Mode == recoveryJobModePostgresValidation && (config.TargetDirectory == "" || validTargetPath) || config.Mode != recoveryJobModePostgresValidation && validTargetPath
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && scopeErr == nil && validRecoveryTargetEnvironment(config.TargetEnvironment, scope) && digestErr == nil && len(digest) == sha256.Size && !bytes.Equal(digest, make([]byte, sha256.Size)) && evidenceDigestErr == nil && len(evidenceDigest) == sha256.Size && !bytes.Equal(evidenceDigest, make([]byte, sha256.Size)) && dsnErr == nil && parsed.String() == config.PostgresDSN && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") && parsed.User != nil && parsed.Hostname() != "" && parsed.Path != "" && parsed.Query().Get("sslmode") == "verify-full" && branchIP != nil && !branchIP.IsUnspecified() && !branchIP.IsLoopback() && !branchIP.IsMulticast() && !branchIP.IsLinkLocalUnicast() && validTarget
}

func runRecoveryJob(ctx context.Context, config recoveryJobConfig, database recoveryJobDatabase, output io.Writer) error {
	if ctx == nil || ctx.Err() != nil || !validRecoveryJobConfig(config) || database == nil || output == nil {
		return errWorkerExecution
	}
	payload, err := database.ValidateScope(ctx, config.OrganizationID, config.WorkspaceID, config.EnvironmentID)
	var authority struct {
		Counts          apiserver.RecoveryCounts `json:"counts"`
		EvidenceSamples []recoveryEvidenceSample `json:"evidence_samples"`
		Projection      json.RawMessage          `json:"projection"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &authority) != nil {
		return errWorkerExecution
	}
	evidenceDigest, evidenceErr := recoveryEvidenceSampleDigest(authority.EvidenceSamples)
	if !validRecoveryCounts(authority.Counts) || len(authority.Projection) < 2 || len(authority.Projection) > recoveryMaximumCapturedBytes || evidenceErr != nil || hex.EncodeToString(evidenceDigest[:]) != config.EvidenceSampleSHA256 {
		return errWorkerExecution
	}
	var result any
	if config.Mode == recoveryJobModePostgresValidation {
		result = struct {
			SchemaVersion        string                   `json:"schema_version"`
			Counts               apiserver.RecoveryCounts `json:"counts"`
			EvidenceSampleSHA256 string                   `json:"evidence_sample_sha256"`
		}{SchemaVersion: "recovery_validation_job_v1", Counts: authority.Counts, EvidenceSampleSHA256: config.EvidenceSampleSHA256}
	} else {
		var canonical bytes.Buffer
		if json.Compact(&canonical, authority.Projection) != nil {
			return errWorkerExecution
		}
		digest := sha256.Sum256(canonical.Bytes())
		encodedDigest := hex.EncodeToString(digest[:])
		if encodedDigest != config.ProjectionSHA256 {
			return errWorkerExecution
		}
		kind := "graph"
		if config.Mode == recoveryJobModeSearchProjection {
			kind = "search"
		}
		if err := runRecoveryProjectionRebuild(ctx, config, database, authority.Projection, kind); err != nil {
			return errWorkerExecution
		}
		result = struct {
			SchemaVersion        string `json:"schema_version"`
			Kind                 string `json:"kind"`
			ProjectionSHA256     string `json:"projection_sha256"`
			EvidenceSampleSHA256 string `json:"evidence_sample_sha256"`
		}{SchemaVersion: "recovery_projection_job_v1", Kind: kind, ProjectionSHA256: encodedDigest, EvidenceSampleSHA256: config.EvidenceSampleSHA256}
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) < 2 || len(encoded) > 4096 {
		return errWorkerExecution
	}
	if _, err := output.Write(encoded); err != nil {
		return errWorkerExecution
	}
	return nil
}

func runProductionRecoveryJob(ctx context.Context, getenv func(string) string, resultPath string) error {
	config, err := loadRecoveryJobConfig(getenv)
	if err != nil || resultPath != "/dev/termination-log" {
		return errWorkerExecution
	}
	poolConfig, err := pgxpool.ParseConfig(config.PostgresDSN)
	if err != nil {
		return errWorkerExecution
	}
	expectedHost := poolConfig.ConnConfig.Host
	poolConfig.ConnConfig.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
		if ctx == nil || ctx.Err() != nil || host != expectedHost {
			return nil, errWorkerExecution
		}
		return []string{config.BranchIP}, nil
	}
	poolConfig.ConnConfig.ConnectTimeout = 10 * time.Second
	poolConfig.MaxConns, poolConfig.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errWorkerExecution
	}
	defer pool.Close()
	file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return errWorkerExecution
	}
	runErr := runRecoveryJob(ctx, config, &postgresRecoveryJobDatabase{pool: pool}, file)
	closeErr := file.Close()
	if runErr != nil || closeErr != nil {
		return errWorkerExecution
	}
	return nil
}

func recoveryJobModeEnabled(mode workerMode) bool {
	return regexp.MustCompile(`^recovery-(postgres-validation|graph-projection|search-projection)$`).MatchString(string(mode))
}

var _ recoveryJobDatabase = (*postgresRecoveryJobDatabase)(nil)
