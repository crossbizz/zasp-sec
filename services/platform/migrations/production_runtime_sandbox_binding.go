package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimeSandboxBindingReadinessSQL = `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2)`

//go:embed sql/0050_production_runtime_sandbox_binding.up.sql
var productionRuntimeSandboxBindingUpSQL string

//go:embed sql/0050_production_runtime_sandbox_binding.down.sql
var productionRuntimeSandboxBindingDownSQL string

func ProductionRuntimeSandboxBinding() Metadata {
	up, down := strings.TrimSpace(productionRuntimeSandboxBindingUpSQL), strings.TrimSpace(productionRuntimeSandboxBindingDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: 50, name: "production_runtime_sandbox_binding", checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimeSandboxBindingSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimeSandboxBindingUpSQL, "production_runtime_sandbox_binding_fingerprint")
}

func (runner *Runner) UpProductionRuntimeSandboxBinding(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		// Readers can hold catalog locks before requesting sensor authority.
		// Refuse contention and release the entire preflight lock set together.
		for _, statement := range []string{lockIntegrationSetupSQL + " NOWAIT", lockTableSQL + " NOWAIT", `LOCK TABLE public.zasp_schema_metadata IN ACCESS EXCLUSIVE MODE NOWAIT`, `LOCK TABLE public.zasp_runtime_batch_authorities,public.zasp_runtime_stage_work,public.zasp_runtime_candidate_observations,public.zasp_runtime_candidate_snapshots,public.zasp_runtime_session_events,public.zasp_runtime_session_projection_receipts,public.zasp_runtime_session_search_outbox IN ACCESS EXCLUSIVE MODE NOWAIT`} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeCorrelationRoutingState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeCorrelationRouting()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeCorrelationRoutingReadinessSQL, prior.Checksum(), ProductionRuntimeCorrelationRoutingSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimeSandboxBinding()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		// Keep an independent install-time checksum for legacy direct entrypoints
		// whose binaries cannot supply the new release's pinned checksum. Upgraded
		// callers must still supply their own compiled checksum and fingerprint.
		if err := transaction.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_sandbox_binding_checksum',$1)`, metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSandboxBindingState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSandboxBindingReadinessSQL, metadata.Checksum(), ProductionRuntimeSandboxBindingSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimeSandboxBinding(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		// Active lookups read version/metadata before authentication locks. Refuse
		// contention instead of waiting with migration locks in the inverse order.
		for _, statement := range []string{lockIntegrationSetupSQL + " NOWAIT", lockTableSQL + " NOWAIT", `LOCK TABLE public.zasp_schema_metadata IN ACCESS EXCLUSIVE MODE NOWAIT`, `LOCK TABLE public.zasp_runtime_batch_authorities,public.zasp_runtime_stage_work,public.zasp_runtime_candidate_observations,public.zasp_runtime_candidate_snapshots,public.zasp_runtime_session_events,public.zasp_runtime_session_projection_receipts,public.zasp_runtime_session_search_outbox IN ACCESS EXCLUSIVE MODE NOWAIT`} {
			if err := transaction.Exec(ctx, statement); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := readProductionRuntimeSandboxBindingState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimeSandboxBinding()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSandboxBindingReadinessSQL, metadata.Checksum(), ProductionRuntimeSandboxBindingSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeCorrelationRoutingState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeCorrelationRouting()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeCorrelationRoutingReadinessSQL, prior.Checksum(), ProductionRuntimeCorrelationRoutingSemanticFingerprint())
	})
}

func readProductionRuntimeSandboxBindingState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing(), ProductionReconciliationLanePlan(), ProductionRuntimeCandidateAuthority(), ProductionRuntimeAcceptance(), ProductionRuntimeCorrelationRouting(), ProductionRuntimeSandboxBinding()})
}
