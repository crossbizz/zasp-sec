package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeQueueReplayVersion = int64(36)
const productionRuntimeQueueReplayName = "production_runtime_queue_replay"
const productionRuntimeQueueReplayReadinessSQL = `SELECT zasp_production_runtime_queue_replay_readiness($1,$2)`

//go:embed sql/0036_production_runtime_queue_replay.up.sql
var productionRuntimeQueueReplayUpSQL string

//go:embed sql/0036_production_runtime_queue_replay.down.sql
var productionRuntimeQueueReplayDownSQL string

func ProductionRuntimeQueueReplay() Metadata {
	up := strings.TrimSpace(productionRuntimeQueueReplayUpSQL)
	down := strings.TrimSpace(productionRuntimeQueueReplayDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeQueueReplayVersion, name: productionRuntimeQueueReplayName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeQueueReplaySemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeQueueReplayUpSQL, "production_runtime_queue_replay_fingerprint")
}

func (runner *Runner) UpProductionRuntimeQueueReplay(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionIntegrationWebhookState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionIntegrationWebhook()
		if err := requireMigrationReadiness(ctx, transaction, productionIntegrationWebhookReadinessSQL, prior.Checksum(), ProductionIntegrationWebhookSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeQueueReplay()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeQueueReplayState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeQueueReplayReadinessSQL, metadata.Checksum(), ProductionRuntimeQueueReplaySemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeQueueReplay(ctx context.Context) error {
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
		metadata := ProductionRuntimeQueueReplay()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeQueueReplayReadinessSQL, metadata.Checksum(), ProductionRuntimeQueueReplaySemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionIntegrationWebhookState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionIntegrationWebhook()
		return requireMigrationReadiness(ctx, transaction, productionIntegrationWebhookReadinessSQL, prior.Checksum(), ProductionIntegrationWebhookSemanticFingerprint())
	})
}

func readProductionRuntimeQueueReplayState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay()})
}
