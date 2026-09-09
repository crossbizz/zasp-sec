package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeSessionsVersion = int64(40)
const productionRuntimeSessionsName = "production_runtime_sessions"
const productionRuntimeSessionsReadinessSQL = `SELECT zasp_production_runtime_sessions_readiness($1,$2)`

//go:embed sql/0040_production_runtime_sessions.up.sql
var productionRuntimeSessionsUpSQL string

//go:embed sql/0040_production_runtime_sessions.down.sql
var productionRuntimeSessionsDownSQL string

func ProductionRuntimeSessions() Metadata {
	up := strings.TrimSpace(productionRuntimeSessionsUpSQL)
	down := strings.TrimSpace(productionRuntimeSessionsDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeSessionsVersion, name: productionRuntimeSessionsName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeSessionsSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeSessionsUpSQL, "production_runtime_sessions_fingerprint")
}

func (runner *Runner) UpProductionRuntimeSessions(ctx context.Context) error {
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
		prior := ProductionRedTeamArtifacts()
		if err := requireMigrationReadiness(ctx, transaction, productionRedTeamArtifactsReadinessSQL, prior.Checksum(), ProductionRedTeamArtifactsSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessions()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionsReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionsSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeSessions(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSessionsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessions()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionsReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionsSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRedTeamArtifactsState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRedTeamArtifacts()
		return requireMigrationReadiness(ctx, transaction, productionRedTeamArtifactsReadinessSQL, prior.Checksum(), ProductionRedTeamArtifactsSemanticFingerprint())
	})
}

func readProductionRuntimeSessionsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions()})
}
