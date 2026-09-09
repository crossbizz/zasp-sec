package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRedTeamInvocationVersion = int64(38)
const productionRedTeamInvocationName = "production_red_team_invocation"
const productionRedTeamInvocationReadinessSQL = `SELECT zasp_production_red_team_invocation_readiness($1,$2)`

//go:embed sql/0038_production_red_team_invocation.up.sql
var productionRedTeamInvocationUpSQL string

//go:embed sql/0038_production_red_team_invocation.down.sql
var productionRedTeamInvocationDownSQL string

func ProductionRedTeamInvocation() Metadata {
	up := strings.TrimSpace(productionRedTeamInvocationUpSQL)
	down := strings.TrimSpace(productionRedTeamInvocationDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRedTeamInvocationVersion, name: productionRedTeamInvocationName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRedTeamInvocationSemanticFingerprint() string {
	return semanticFingerprint(productionRedTeamInvocationUpSQL, "production_red_team_invocation_fingerprint")
}

func (runner *Runner) UpProductionRedTeamInvocation(ctx context.Context) error {
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
		prior := ProductionRedTeamSafety()
		if err := requireMigrationReadiness(ctx, transaction, productionRedTeamSafetyReadinessSQL, prior.Checksum(), ProductionRedTeamSafetySemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRedTeamInvocation()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRedTeamInvocationState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRedTeamInvocationReadinessSQL, metadata.Checksum(), ProductionRedTeamInvocationSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRedTeamInvocation(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRedTeamInvocationState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRedTeamInvocation()
		if err := requireMigrationReadiness(ctx, transaction, productionRedTeamInvocationReadinessSQL, metadata.Checksum(), ProductionRedTeamInvocationSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRedTeamSafetyState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRedTeamSafety()
		return requireMigrationReadiness(ctx, transaction, productionRedTeamSafetyReadinessSQL, prior.Checksum(), ProductionRedTeamSafetySemanticFingerprint())
	})
}

func readProductionRedTeamInvocationState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation()})
}
