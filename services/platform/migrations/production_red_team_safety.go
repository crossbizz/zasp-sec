package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRedTeamSafetyVersion = int64(37)
const productionRedTeamSafetyName = "production_red_team_safety"
const productionRedTeamSafetyReadinessSQL = `SELECT zasp_production_red_team_safety_readiness($1,$2)`

//go:embed sql/0037_production_red_team_safety.up.sql
var productionRedTeamSafetyUpSQL string

//go:embed sql/0037_production_red_team_safety.down.sql
var productionRedTeamSafetyDownSQL string

func ProductionRedTeamSafety() Metadata {
	up := strings.TrimSpace(productionRedTeamSafetyUpSQL)
	down := strings.TrimSpace(productionRedTeamSafetyDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRedTeamSafetyVersion, name: productionRedTeamSafetyName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRedTeamSafetySemanticFingerprint() string {
	return semanticFingerprint(productionRedTeamSafetyUpSQL, "production_red_team_safety_fingerprint")
}

func (runner *Runner) UpProductionRedTeamSafety(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeQueueReplayState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeQueueReplay()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeQueueReplayReadinessSQL, prior.Checksum(), ProductionRuntimeQueueReplaySemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRedTeamSafety()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRedTeamSafetyState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRedTeamSafetyReadinessSQL, metadata.Checksum(), ProductionRedTeamSafetySemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRedTeamSafety(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRedTeamSafetyState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRedTeamSafety()
		if err := requireMigrationReadiness(ctx, transaction, productionRedTeamSafetyReadinessSQL, metadata.Checksum(), ProductionRedTeamSafetySemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeQueueReplayState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeQueueReplay()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeQueueReplayReadinessSQL, prior.Checksum(), ProductionRuntimeQueueReplaySemanticFingerprint())
	})
}

func readProductionRedTeamSafetyState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety()})
}
