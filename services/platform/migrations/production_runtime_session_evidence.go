package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeSessionEvidenceVersion = int64(44)
const productionRuntimeSessionEvidenceName = "production_runtime_session_evidence"
const productionRuntimeSessionEvidenceReadinessSQL = `SELECT zasp_production_runtime_session_evidence_readiness($1,$2)`

//go:embed sql/0044_production_runtime_session_evidence.up.sql
var productionRuntimeSessionEvidenceUpSQL string

//go:embed sql/0044_production_runtime_session_evidence.down.sql
var productionRuntimeSessionEvidenceDownSQL string

func ProductionRuntimeSessionEvidence() Metadata {
	up := strings.TrimSpace(productionRuntimeSessionEvidenceUpSQL)
	down := strings.TrimSpace(productionRuntimeSessionEvidenceDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeSessionEvidenceVersion, name: productionRuntimeSessionEvidenceName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeSessionEvidenceSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeSessionEvidenceUpSQL, "production_runtime_session_evidence_fingerprint")
}

func (runner *Runner) UpProductionRuntimeSessionEvidence(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSessionQueryState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSessionQuery()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionQueryReadinessSQL, prior.Checksum(), ProductionRuntimeSessionQuerySemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionEvidence()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionEvidenceState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionEvidenceReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionEvidenceSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeSessionEvidence(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSessionEvidenceState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionEvidence()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionEvidenceReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionEvidenceSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionQueryState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSessionQuery()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionQueryReadinessSQL, prior.Checksum(), ProductionRuntimeSessionQuerySemanticFingerprint())
	})
}

func readProductionRuntimeSessionEvidenceState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence()})
}
