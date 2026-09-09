package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeSessionReadsVersion = int64(41)
const productionRuntimeSessionReadsName = "production_runtime_session_reads"
const productionRuntimeSessionReadsReadinessSQL = `SELECT zasp_production_runtime_session_reads_readiness($1,$2)`

//go:embed sql/0041_production_runtime_session_reads.up.sql
var productionRuntimeSessionReadsUpSQL string

//go:embed sql/0041_production_runtime_session_reads.down.sql
var productionRuntimeSessionReadsDownSQL string

func ProductionRuntimeSessionReads() Metadata {
	up := strings.TrimSpace(productionRuntimeSessionReadsUpSQL)
	down := strings.TrimSpace(productionRuntimeSessionReadsDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeSessionReadsVersion, name: productionRuntimeSessionReadsName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeSessionReadsSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeSessionReadsUpSQL, "production_runtime_session_reads_fingerprint")
}

func (runner *Runner) UpProductionRuntimeSessionReads(ctx context.Context) error {
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
		prior := ProductionRuntimeSessions()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionsReadinessSQL, prior.Checksum(), ProductionRuntimeSessionsSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionReads()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionReadsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionReadsReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionReadsSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeSessionReads(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSessionReadsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionReads()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionReadsReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionReadsSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionsState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSessions()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionsReadinessSQL, prior.Checksum(), ProductionRuntimeSessionsSemanticFingerprint())
	})
}

func readProductionRuntimeSessionReadsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads()})
}
