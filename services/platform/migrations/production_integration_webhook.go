package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionIntegrationWebhookVersion = int64(35)
const productionIntegrationWebhookName = "production_integration_webhook"
const productionIntegrationWebhookReadinessSQL = `SELECT zasp_production_integration_webhook_readiness($1,$2)`

//go:embed sql/0035_production_integration_webhook.up.sql
var productionIntegrationWebhookUpSQL string

//go:embed sql/0035_production_integration_webhook.down.sql
var productionIntegrationWebhookDownSQL string

func ProductionIntegrationWebhook() Metadata {
	up := strings.TrimSpace(productionIntegrationWebhookUpSQL)
	down := strings.TrimSpace(productionIntegrationWebhookDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionIntegrationWebhookVersion, name: productionIntegrationWebhookName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionIntegrationWebhookSemanticFingerprint() string {
	return semanticFingerprint(productionIntegrationWebhookUpSQL, "production_integration_webhook_fingerprint")
}

func (runner *Runner) UpProductionIntegrationWebhook(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionIntegrationSetupState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionIntegrationSetup()
		if err := requireMigrationReadiness(ctx, transaction, productionIntegrationSetupReadinessSQL, prior.Checksum(), ProductionIntegrationSetupSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionIntegrationWebhook()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionIntegrationWebhookState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionIntegrationWebhookReadinessSQL, metadata.Checksum(), ProductionIntegrationWebhookSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionIntegrationWebhook(ctx context.Context) error {
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
		metadata := ProductionIntegrationWebhook()
		if err := requireMigrationReadiness(ctx, transaction, productionIntegrationWebhookReadinessSQL, metadata.Checksum(), ProductionIntegrationWebhookSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionIntegrationSetupState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionIntegrationSetup()
		return requireMigrationReadiness(ctx, transaction, productionIntegrationSetupReadinessSQL, prior.Checksum(), ProductionIntegrationSetupSemanticFingerprint())
	})
}

func readProductionIntegrationWebhookState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook()})
}
