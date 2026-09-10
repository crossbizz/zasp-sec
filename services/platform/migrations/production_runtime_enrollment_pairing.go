package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeEnrollmentPairingVersion = int64(45)
const productionRuntimeEnrollmentPairingName = "production_runtime_enrollment_pairing"
const productionRuntimeEnrollmentPairingReadinessSQL = `SELECT zasp_production_runtime_enrollment_pairing_readiness($1,$2)`

//go:embed sql/0045_production_runtime_enrollment_pairing.up.sql
var productionRuntimeEnrollmentPairingUpSQL string

//go:embed sql/0045_production_runtime_enrollment_pairing.down.sql
var productionRuntimeEnrollmentPairingDownSQL string

func ProductionRuntimeEnrollmentPairing() Metadata {
	up := strings.TrimSpace(productionRuntimeEnrollmentPairingUpSQL)
	down := strings.TrimSpace(productionRuntimeEnrollmentPairingDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeEnrollmentPairingVersion, name: productionRuntimeEnrollmentPairingName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeEnrollmentPairingSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeEnrollmentPairingUpSQL, "production_runtime_enrollment_pairing_fingerprint")
}

func (runner *Runner) UpProductionRuntimeEnrollmentPairing(ctx context.Context) error {
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
		prior := ProductionRuntimeSessionEvidence()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionEvidenceReadinessSQL, prior.Checksum(), ProductionRuntimeSessionEvidenceSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeEnrollmentPairing()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeEnrollmentPairingState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeEnrollmentPairingReadinessSQL, metadata.Checksum(), ProductionRuntimeEnrollmentPairingSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeEnrollmentPairing(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeEnrollmentPairingState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeEnrollmentPairing()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeEnrollmentPairingReadinessSQL, metadata.Checksum(), ProductionRuntimeEnrollmentPairingSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionEvidenceState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSessionEvidence()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionEvidenceReadinessSQL, prior.Checksum(), ProductionRuntimeSessionEvidenceSemanticFingerprint())
	})
}

func readProductionRuntimeEnrollmentPairingState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing()})
}
