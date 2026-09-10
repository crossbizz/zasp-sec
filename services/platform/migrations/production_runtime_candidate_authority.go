package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeCandidateAuthorityReadinessSQL = `SELECT zasp_production_runtime_candidate_authority_readiness($1,$2)`

// Candidate storage and admission authority do not activate a new correlator.
// Existing production jobs remain correlation v1 until v2 consumers are ready.
//
//go:embed sql/0047_production_runtime_candidate_authority.up.sql
var productionRuntimeCandidateAuthorityUpSQL string

//go:embed sql/0047_production_runtime_candidate_authority.down.sql
var productionRuntimeCandidateAuthorityDownSQL string

func ProductionRuntimeCandidateAuthority() Metadata {
	up := strings.TrimSpace(productionRuntimeCandidateAuthorityUpSQL)
	down := strings.TrimSpace(productionRuntimeCandidateAuthorityDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: 47, name: "production_runtime_candidate_authority", checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeCandidateAuthoritySemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeCandidateAuthorityUpSQL, "production_runtime_candidate_authority_fingerprint")
}

func (runner *Runner) UpProductionRuntimeCandidateAuthority(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		for _, statement := range []string{lockIntegrationSetupSQL, lockTableSQL} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionReconciliationLanePlanState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionReconciliationLanePlan()
		if err := requireMigrationReadiness(ctx, transaction, productionReconciliationLanePlanReadinessSQL, prior.Checksum(), ProductionReconciliationLanePlanSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeCandidateAuthority()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeCandidateAuthorityState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeCandidateAuthorityReadinessSQL, metadata.Checksum(), ProductionRuntimeCandidateAuthoritySemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeCandidateAuthority(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		// A worker can hold readiness/catalog or snapshot relation locks before
		// requesting its sensor lock. Never wait while holding the inverse set:
		// refuse contention and roll back every preflight lock together.
		for _, statement := range []string{
			lockIntegrationSetupSQL + " NOWAIT",
			lockTableSQL + " NOWAIT",
			`LOCK TABLE public.zasp_schema_metadata,public.zasp_runtime_candidate_snapshots,public.zasp_runtime_candidate_observations IN ACCESS EXCLUSIVE MODE NOWAIT`,
		} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeCandidateAuthorityState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeCandidateAuthority()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeCandidateAuthorityReadinessSQL, metadata.Checksum(), ProductionRuntimeCandidateAuthoritySemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionReconciliationLanePlanState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionReconciliationLanePlan()
		return requireMigrationReadiness(ctx, transaction, productionReconciliationLanePlanReadinessSQL, prior.Checksum(), ProductionReconciliationLanePlanSemanticFingerprint())
	})
}

func readProductionRuntimeCandidateAuthorityState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing(), ProductionReconciliationLanePlan(), ProductionRuntimeCandidateAuthority()})
}
