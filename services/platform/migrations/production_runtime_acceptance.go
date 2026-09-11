package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeAcceptanceReadinessSQL = `SELECT zasp_production_runtime_acceptance_readiness($1,$2)`

//go:embed sql/0048_production_runtime_acceptance.up.sql
var productionRuntimeAcceptanceUpSQL string

//go:embed sql/0048_production_runtime_acceptance.down.sql
var productionRuntimeAcceptanceDownSQL string

func ProductionRuntimeAcceptance() Metadata {
	up, down := strings.TrimSpace(productionRuntimeAcceptanceUpSQL), strings.TrimSpace(productionRuntimeAcceptanceDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: 48, name: "production_runtime_acceptance", checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeAcceptanceSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeAcceptanceUpSQL, "production_runtime_acceptance_fingerprint")
}

func (runner *Runner) UpProductionRuntimeAcceptance(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		// Readers can hold catalog locks before requesting sensor authority.
		// Refuse contention and release the entire preflight lock set together.
		for _, statement := range []string{lockIntegrationSetupSQL + " NOWAIT", lockTableSQL + " NOWAIT", `LOCK TABLE public.zasp_schema_metadata IN ACCESS EXCLUSIVE MODE NOWAIT`} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeCandidateAuthorityState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeCandidateAuthority()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeCandidateAuthorityReadinessSQL, prior.Checksum(), ProductionRuntimeCandidateAuthoritySemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeAcceptance()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeAcceptanceState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeAcceptanceReadinessSQL, metadata.Checksum(), ProductionRuntimeAcceptanceSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeAcceptance(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		// Active lookups read version/metadata before authentication locks. Refuse
		// contention instead of waiting with migration locks in the inverse order.
		for _, statement := range []string{lockIntegrationSetupSQL + " NOWAIT", lockTableSQL + " NOWAIT", `LOCK TABLE public.zasp_schema_metadata IN ACCESS EXCLUSIVE MODE NOWAIT`} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeAcceptanceState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeAcceptance()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeAcceptanceReadinessSQL, metadata.Checksum(), ProductionRuntimeAcceptanceSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeCandidateAuthorityState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeCandidateAuthority()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeCandidateAuthorityReadinessSQL, prior.Checksum(), ProductionRuntimeCandidateAuthoritySemanticFingerprint())
	})
}

func readProductionRuntimeAcceptanceState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing(), ProductionReconciliationLanePlan(), ProductionRuntimeCandidateAuthority(), ProductionRuntimeAcceptance()})
}
