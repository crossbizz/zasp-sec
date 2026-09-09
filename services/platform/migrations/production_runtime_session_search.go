package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeSessionSearchVersion = int64(42)
const productionRuntimeSessionSearchName = "production_runtime_session_search"
const productionRuntimeSessionSearchReadinessSQL = `SELECT zasp_production_runtime_session_search_readiness($1,$2)`

//go:embed sql/0042_production_runtime_session_search.up.sql
var productionRuntimeSessionSearchUpSQL string

//go:embed sql/0042_production_runtime_session_search.down.sql
var productionRuntimeSessionSearchDownSQL string

func ProductionRuntimeSessionSearch() Metadata {
	up := strings.TrimSpace(productionRuntimeSessionSearchUpSQL)
	down := strings.TrimSpace(productionRuntimeSessionSearchDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeSessionSearchVersion, name: productionRuntimeSessionSearchName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeSessionSearchSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeSessionSearchUpSQL, "production_runtime_session_search_fingerprint")
}

func (runner *Runner) UpProductionRuntimeSessionSearch(ctx context.Context) error {
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
		prior := ProductionRuntimeSessionReads()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionReadsReadinessSQL, prior.Checksum(), ProductionRuntimeSessionReadsSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionSearch()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionSearchState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionSearchReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionSearchSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeSessionSearch(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSessionSearchState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionSearch()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionSearchReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionSearchSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionReadsState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSessionReads()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionReadsReadinessSQL, prior.Checksum(), ProductionRuntimeSessionReadsSemanticFingerprint())
	})
}

func readProductionRuntimeSessionSearchState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch()})
}
