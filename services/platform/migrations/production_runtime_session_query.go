package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeSessionQueryVersion = int64(43)
const productionRuntimeSessionQueryName = "production_runtime_session_query"
const productionRuntimeSessionQueryReadinessSQL = `SELECT zasp_production_runtime_session_query_readiness($1,$2)`

//go:embed sql/0043_production_runtime_session_query.up.sql
var productionRuntimeSessionQueryUpSQL string

//go:embed sql/0043_production_runtime_session_query.down.sql
var productionRuntimeSessionQueryDownSQL string

func ProductionRuntimeSessionQuery() Metadata {
	up := strings.TrimSpace(productionRuntimeSessionQueryUpSQL)
	down := strings.TrimSpace(productionRuntimeSessionQueryDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: productionRuntimeSessionQueryVersion, name: productionRuntimeSessionQueryName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeSessionQuerySemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeSessionQueryUpSQL, "production_runtime_session_query_fingerprint")
}

func (runner *Runner) UpProductionRuntimeSessionQuery(ctx context.Context) error {
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
		prior := ProductionRuntimeSessionSearch()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionSearchReadinessSQL, prior.Checksum(), ProductionRuntimeSessionSearchSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionQuery()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionQueryState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionQueryReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionQuerySemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeSessionQuery(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSessionQueryState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeSessionQuery()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSessionQueryReadinessSQL, metadata.Checksum(), ProductionRuntimeSessionQuerySemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSessionSearchState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSessionSearch()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSessionSearchReadinessSQL, prior.Checksum(), ProductionRuntimeSessionSearchSemanticFingerprint())
	})
}

func readProductionRuntimeSessionQueryState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery()})
}
