package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRedTeamArtifactsVersion = int64(39)
const productionRedTeamArtifactsName = "production_red_team_artifacts"
const productionRedTeamArtifactsReadinessSQL = `SELECT zasp_production_red_team_artifacts_readiness($1,$2)`

//go:embed sql/0039_production_red_team_artifacts.up.sql
var productionRedTeamArtifactsUpSQL string

//go:embed sql/0039_production_red_team_artifacts.down.sql
var productionRedTeamArtifactsDownSQL string

func ProductionRedTeamArtifacts() Metadata {
	up := strings.TrimSpace(productionRedTeamArtifactsUpSQL)
	down := strings.TrimSpace(productionRedTeamArtifactsDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRedTeamArtifactsVersion, name: productionRedTeamArtifactsName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRedTeamArtifactsSemanticFingerprint() string {
	return semanticFingerprint(productionRedTeamArtifactsUpSQL, "production_red_team_artifacts_fingerprint")
}

func (runner *Runner) UpProductionRedTeamArtifacts(ctx context.Context) error {
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
		prior := ProductionRedTeamInvocation()
		if err := requireMigrationReadiness(ctx, transaction, productionRedTeamInvocationReadinessSQL, prior.Checksum(), ProductionRedTeamInvocationSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRedTeamArtifacts()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRedTeamArtifactsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRedTeamArtifactsReadinessSQL, metadata.Checksum(), ProductionRedTeamArtifactsSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRedTeamArtifacts(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRedTeamArtifactsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRedTeamArtifacts()
		if err := requireMigrationReadiness(ctx, transaction, productionRedTeamArtifactsReadinessSQL, metadata.Checksum(), ProductionRedTeamArtifactsSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRedTeamInvocationState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRedTeamInvocation()
		return requireMigrationReadiness(ctx, transaction, productionRedTeamInvocationReadinessSQL, prior.Checksum(), ProductionRedTeamInvocationSemanticFingerprint())
	})
}

func readProductionRedTeamArtifactsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts()})
}
