package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed sql/0052_production_audit_exports.up.sql
var productionAuditExportsUpSQL string

//go:embed sql/0052_production_audit_exports.down.sql
var productionAuditExportsDownSQL string

const productionAuditExportsReadinessSQL = `SELECT zasp_production_audit_exports_readiness($1,$2)`

type AuditExportConfiguration struct {
	PolicyID, ExpectedCurrentPolicyID        string
	Bucket, ExpectedBucketOwner, KMSKeyARN   string
	MaximumExportBytes, MaximumRetainedBytes int64
	MaximumInflight, CaptureTimeoutSeconds   int
}

var (
	auditExportPolicyIDPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	auditExportBucketPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	auditExportOwnerPattern    = regexp.MustCompile(`^[0-9]{12}$`)
	auditExportKMSPattern      = regexp.MustCompile(`^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// AuditExportPolicyDigest pins an owner-approved configuration revision. The
// canonical wire excludes the digest itself and mutable policy selection state.
func AuditExportPolicyDigest(configuration AuditExportConfiguration) (string, error) {
	if !auditExportPolicyIDPattern.MatchString(configuration.PolicyID) || configuration.ExpectedCurrentPolicyID != "" && (!auditExportPolicyIDPattern.MatchString(configuration.ExpectedCurrentPolicyID) || configuration.ExpectedCurrentPolicyID == configuration.PolicyID) ||
		!auditExportBucketPattern.MatchString(configuration.Bucket) || !auditExportOwnerPattern.MatchString(configuration.ExpectedBucketOwner) || !auditExportKMSPattern.MatchString(configuration.KMSKeyARN) ||
		configuration.MaximumExportBytes < 1 || configuration.MaximumExportBytes > 1<<53-1 || configuration.MaximumRetainedBytes < 1 || configuration.MaximumRetainedBytes > 1<<53-1 || configuration.MaximumInflight < 1 || int64(configuration.MaximumInflight) > 1<<31-1 || configuration.CaptureTimeoutSeconds < 1 || configuration.CaptureTimeoutSeconds > 120 {
		return "", ErrInvalidState
	}
	wire := struct {
		Schema                string `json:"schema"`
		PolicyID              string `json:"policy_id"`
		Bucket                string `json:"bucket"`
		Owner                 string `json:"expected_bucket_owner"`
		KMS                   string `json:"kms_key_arn"`
		MaximumExportBytes    int64  `json:"maximum_export_bytes"`
		MaximumRetainedBytes  int64  `json:"maximum_retained_bytes"`
		MaximumInflight       int    `json:"maximum_inflight"`
		CaptureTimeoutSeconds int    `json:"capture_timeout_seconds"`
	}{"audit-export-policy-v1", configuration.PolicyID, configuration.Bucket, configuration.ExpectedBucketOwner, configuration.KMSKeyARN, configuration.MaximumExportBytes, configuration.MaximumRetainedBytes, configuration.MaximumInflight, configuration.CaptureTimeoutSeconds}
	body, err := json.Marshal(wire)
	if err != nil {
		return "", ErrInvalidState
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (runner *Runner) ConfigureAuditExports(ctx context.Context, configuration AuditExportConfiguration) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	expected, err := AuditExportPolicyDigest(configuration)
	if err != nil {
		return err
	}
	var prior any
	if configuration.ExpectedCurrentPolicyID != "" {
		prior = configuration.ExpectedCurrentPolicyID
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		metadata, err := readAuditExportConfigurationState(ctx, transaction)
		if err != nil {
			return err
		}
		if err := requireAuditExportConfigurationReadiness(ctx, transaction, metadata); err != nil {
			return err
		}
		var actual string
		if err := scanRow(ctx, transaction, `SELECT public.zasp_audit_export_configure($1,$2,$3,$4,$5,$6,$7,$8,$9)->>'policy_digest'`, []any{configuration.PolicyID, prior, configuration.Bucket, configuration.ExpectedBucketOwner, configuration.KMSKeyARN, configuration.MaximumExportBytes, configuration.MaximumRetainedBytes, configuration.MaximumInflight, configuration.CaptureTimeoutSeconds}, &actual); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if actual != expected {
			return ErrInvalidState
		}
		return requireAuditExportConfigurationReadiness(ctx, transaction, metadata)
	})
}

// Operational configuration supports only these compiled release identities.
// Historical upgrade/down readers remain exact to their own predecessor.
func readAuditExportConfigurationState(ctx context.Context, queryer Queryer) (Metadata, error) {
	var count int64
	if err := scanRow(ctx, queryer, countRowsSQL, nil, &count); err != nil {
		return Metadata{}, fixedDatabaseError(ctx, err)
	}
	switch count {
	case 52:
		return ProductionAuditExports(), readProductionAuditExportsState(ctx, queryer)
	case 53:
		return ProductionSecurityAgentBudgets(), readProductionSecurityAgentBudgetsState(ctx, queryer)
	case 54:
		return ProductionSecurityAgentRunContext(), readProductionSecurityAgentRunContextState(ctx, queryer)
	case 55:
		return ProductionSecurityAgentExistingTests(), readProductionSecurityAgentExistingTestsState(ctx, queryer)
	case 56:
		return ProductionCompliance(), readProductionComplianceState(ctx, queryer)
	case 57:
		return ProductionSecurityAgentAttackLab(), readProductionSecurityAgentAttackLabState(ctx, queryer)
	case 58:
		return ProductionSecurityAgentExports(), readProductionSecurityAgentExportsState(ctx, queryer)
	default:
		return Metadata{}, ErrInvalidState
	}
}

func requireAuditExportConfigurationReadiness(ctx context.Context, queryer Queryer, metadata Metadata) error {
	if metadata.Version() == 58 {
		return requireMigrationReadiness(ctx, queryer, productionSecurityAgentExportsReadinessSQL, metadata.Checksum(), SecurityAgentExportsFingerprint())
	}
	if metadata.Version() == 57 {
		return requireMigrationReadiness(ctx, queryer, productionSecurityAgentAttackLabReadinessSQL, metadata.Checksum(), SecurityAgentAttackLabFingerprint())
	}
	if metadata.Version() == 56 {
		return requireMigrationReadiness(ctx, queryer, productionComplianceReadinessSQL, metadata.Checksum(), ComplianceFingerprint())
	}
	if metadata.Version() == 55 {
		return requireMigrationReadiness(ctx, queryer, productionSecurityAgentExistingTestsReadinessSQL, metadata.Checksum(), SecurityAgentExistingTestsFingerprint())
	}
	if metadata.Version() == 54 {
		return requireMigrationReadiness(ctx, queryer, productionSecurityAgentRunContextReadinessSQL, metadata.Checksum(), SecurityAgentRunContextFingerprint())
	}
	if metadata.Version() == 53 {
		return requireMigrationReadiness(ctx, queryer, productionSecurityAgentBudgetsReadinessSQL, metadata.Checksum(), SecurityAgentBudgetCandidateFingerprint())
	}
	return requireMigrationReadiness(ctx, queryer, productionAuditExportsReadinessSQL, metadata.Checksum(), ProductionAuditExportsSemanticFingerprint())
}

func productionAuditExportsPredecessors() []Metadata {
	return []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing(), ProductionReconciliationLanePlan(), ProductionRuntimeCandidateAuthority(), ProductionRuntimeAcceptance(), ProductionRuntimeCorrelationRouting(), ProductionRuntimeSandboxBinding(), ProductionRuntimePrecision()}
}

func ProductionAuditExports() Metadata {
	var rows []string
	for _, prior := range productionAuditExportsPredecessors() {
		rows = append(rows, fmt.Sprintf("(%d::bigint,'%s'::text,'%s'::text)", prior.Version(), prior.Name(), prior.Checksum()))
	}
	up := strings.TrimSpace(strings.Replace(productionAuditExportsUpSQL, "-- predecessor release values", strings.Join(rows, ",\n"), 1))
	down := strings.TrimSpace(productionAuditExportsDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: 52, name: "production_audit_exports", checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}
func ProductionAuditExportsSemanticFingerprint() string {
	return semanticFingerprint(productionAuditExportsUpSQL, "production_audit_exports_fingerprint")
}
func (runner *Runner) UpProductionAuditExports(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionAuditExports(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionRuntimePrecisionState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimePrecision()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimePrecisionReadinessSQL, prior.Checksum(), ProductionRuntimePrecisionSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionAuditExports()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_audit_exports_checksum',$1)`, metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionAuditExportsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionAuditExportsReadinessSQL, metadata.Checksum(), ProductionAuditExportsSemanticFingerprint())
	})
}
func (runner *Runner) DownProductionAuditExports(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionAuditExports(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionAuditExportsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionAuditExports()
		if err := requireMigrationReadiness(ctx, transaction, productionAuditExportsReadinessSQL, metadata.Checksum(), ProductionAuditExportsSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimePrecisionState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimePrecisionReadinessSQL, ProductionRuntimePrecision().Checksum(), ProductionRuntimePrecisionSemanticFingerprint())
	})
}

// RegisterAuditExportAPI opts an already registered discovery API login into
// export operations. It never creates a login, adds a role or changes its DSN.
func (runner *Runner) RegisterAuditExportAPI(ctx context.Context, principal string) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		metadata, err := readAuditExportConfigurationState(ctx, transaction)
		if err != nil {
			return err
		}
		if err := requireAuditExportConfigurationReadiness(ctx, transaction, metadata); err != nil {
			return err
		}
		var registered bool
		if err := scanRow(ctx, transaction, `SELECT public.zasp_audit_export_register_api($1)`, []any{principal}, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !registered {
			return ErrInvalidState
		}
		return requireAuditExportConfigurationReadiness(ctx, transaction, metadata)
	})
}

func (runner *Runner) RegisterAuditExportWorkers(ctx context.Context, executor, outbox string) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		metadata, err := readAuditExportConfigurationState(ctx, transaction)
		if err != nil {
			return err
		}
		if err := requireAuditExportConfigurationReadiness(ctx, transaction, metadata); err != nil {
			return err
		}
		var registered bool
		if err := scanRow(ctx, transaction, `SELECT public.zasp_audit_export_register_workers($1,$2)`, []any{executor, outbox}, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !registered {
			return ErrInvalidState
		}
		return requireAuditExportConfigurationReadiness(ctx, transaction, metadata)
	})
}

func lockProductionAuditExports(ctx context.Context, transaction Transaction) error {
	if err := lockProductionRuntimePrecision(ctx, transaction); err != nil {
		return err
	}
	// Compatibility changes also touch the legacy workflow/risk mutation bodies.
	for _, statement := range []string{`LOCK TABLE public.zasp_workflow_idempotency,public.zasp_workflow_audit,public.zasp_workflow_receipts,public.zasp_risk_findings,public.zasp_admin_audit IN ACCESS EXCLUSIVE MODE NOWAIT`, `DO $lock$ DECLARE relation text;BEGIN FOREACH relation IN ARRAY ARRAY['zasp_audit_export_source_acl','zasp_audit_export_worker_bindings','zasp_audit_export_policies','zasp_audit_export_current_policy','zasp_audit_export_api_bindings','zasp_audit_export_jobs','zasp_audit_export_idempotency','zasp_audit_export_outbox','zasp_audit_export_events','zasp_audit_export_chunks','zasp_audit_export_intents','zasp_audit_export_receipts','zasp_audit_export_retries'] LOOP IF to_regclass('public.'||relation) IS NOT NULL THEN EXECUTE format('LOCK TABLE public.%I IN ACCESS EXCLUSIVE MODE NOWAIT',relation);END IF;END LOOP;END $lock$`} {
		if err := transaction.Exec(ctx, statement); err != nil {
			return fixedDatabaseError(ctx, err)
		}
	}
	return nil
}
func readProductionAuditExportsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, append(productionAuditExportsPredecessors(), ProductionAuditExports()))
}
