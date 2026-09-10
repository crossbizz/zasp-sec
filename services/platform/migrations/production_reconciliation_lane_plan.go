package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionReconciliationLanePlanVersion = int64(46)
const productionReconciliationLanePlanName = "production_reconciliation_lane_plan"
const productionReconciliationLanePlanReadinessSQL = `SELECT zasp_production_reconciliation_lane_plan_readiness($1,$2)`

//go:embed sql/0046_production_reconciliation_lane_plan.up.sql
var productionReconciliationLanePlanUpSQL string

//go:embed sql/0046_production_reconciliation_lane_plan.down.sql
var productionReconciliationLanePlanDownSQL string

func ProductionReconciliationLanePlan() Metadata {
	up := strings.TrimSpace(productionReconciliationLanePlanUpSQL)
	down := strings.TrimSpace(productionReconciliationLanePlanDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionReconciliationLanePlanVersion, name: productionReconciliationLanePlanName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionReconciliationLanePlanSemanticFingerprint() string {
	return semanticFingerprint(productionReconciliationLanePlanUpSQL, "production_reconciliation_lane_plan_fingerprint")
}

func (runner *Runner) UpProductionReconciliationLanePlan(ctx context.Context) error {
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
		prior := ProductionRuntimeEnrollmentPairing()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeEnrollmentPairingReadinessSQL, prior.Checksum(), ProductionRuntimeEnrollmentPairingSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionReconciliationLanePlan()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionReconciliationLanePlanState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionReconciliationLanePlanReadinessSQL, metadata.Checksum(), ProductionReconciliationLanePlanSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionReconciliationLanePlan(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionReconciliationLanePlanState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionReconciliationLanePlan()
		if err := requireMigrationReadiness(ctx, transaction, productionReconciliationLanePlanReadinessSQL, metadata.Checksum(), ProductionReconciliationLanePlanSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeEnrollmentPairingState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeEnrollmentPairing()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeEnrollmentPairingReadinessSQL, prior.Checksum(), ProductionRuntimeEnrollmentPairingSemanticFingerprint())
	})
}

func readProductionReconciliationLanePlanState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing(), ProductionReconciliationLanePlan()})
}
