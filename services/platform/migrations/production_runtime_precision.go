package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const productionRuntimePrecisionReadinessSQL = `SELECT zasp_production_runtime_precision_readiness($1,$2)`

//go:embed sql/0051_production_runtime_precision.up.sql
var productionRuntimePrecisionUpSQL string

//go:embed sql/0051_production_runtime_precision.down.sql
var productionRuntimePrecisionDownSQL string

//go:embed sql/fragments/runtime_precision.sql
var runtimePrecisionSQL string

//go:embed sql/fragments/runtime_precision_candidates.sql
var runtimePrecisionCandidatesSQL string

//go:embed sql/fragments/runtime_precision_completion.sql
var runtimePrecisionCompletionSQL string

func ProductionRuntimePrecision() Metadata {
	up := strings.Replace(productionRuntimePrecisionUpSQL, "-- precision fragments", runtimePrecisionSQL+"\n"+runtimePrecisionCandidatesSQL+"\n"+runtimePrecisionCompletionSQL, 1)
	up, down := strings.TrimSpace(up), strings.TrimSpace(productionRuntimePrecisionDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: 51, name: "production_runtime_precision", checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionRuntimePrecisionSemanticFingerprint() string {
	return semanticFingerprint(productionRuntimePrecisionUpSQL, "production_runtime_precision_fingerprint")
}

func (runner *Runner) UpProductionRuntimePrecision(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionRuntimePrecision(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionRuntimeSandboxBindingState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSandboxBinding()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimeSandboxBindingReadinessSQL, prior.Checksum(), ProductionRuntimeSandboxBindingSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionRuntimePrecision()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_precision_checksum',$1)`, metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimePrecisionState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionRuntimePrecisionReadinessSQL, metadata.Checksum(), ProductionRuntimePrecisionSemanticFingerprint())
	})
}

func (runner *Runner) DownProductionRuntimePrecision(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionRuntimePrecision(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionRuntimePrecisionState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionRuntimePrecision()
		if err := requireMigrationReadiness(ctx, transaction, productionRuntimePrecisionReadinessSQL, metadata.Checksum(), ProductionRuntimePrecisionSemanticFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionRuntimeSandboxBindingState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionRuntimeSandboxBinding()
		return requireMigrationReadiness(ctx, transaction, productionRuntimeSandboxBindingReadinessSQL, prior.Checksum(), ProductionRuntimeSandboxBindingSemanticFingerprint())
	})
}

func lockProductionRuntimePrecision(ctx context.Context, transaction Transaction) error {
	for _, statement := range []string{lockIntegrationSetupSQL + " NOWAIT", lockTableSQL + " NOWAIT", `LOCK TABLE public.zasp_schema_metadata IN ACCESS EXCLUSIVE MODE NOWAIT`, `LOCK TABLE public.zasp_runtime_batch_authorities,public.zasp_runtime_stage_work,public.zasp_runtime_candidate_observations,public.zasp_runtime_candidate_snapshots,public.zasp_runtime_session_events,public.zasp_runtime_session_projection_receipts,public.zasp_runtime_session_search_outbox,public.zasp_runtime_sandbox_search_outbox,public.zasp_runtime_ingest_reconciliation_work,public.zasp_runtime_ingest_reconciliation_state,public.zasp_discovery_outbox,public.zasp_discovery_outbox_topic_fairness,public.zasp_runtime_deliveries IN ACCESS EXCLUSIVE MODE NOWAIT`} {
		if err := transaction.Exec(ctx, statement); err != nil {
			return fixedDatabaseError(ctx, err)
		}
	}
	return nil
}

func readProductionRuntimePrecisionState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution(), ProductionIdentityAdministration(), ProductionSecurityAgentControls(), ProductionSecurityAgentAutonomousResponse(), ProductionSecurityAgentTemporaryPolicy(), ProductionSecurityAgentConnectorRevocation(), ProductionSecurityAgentSessionIsolation(), ProductionRedTeamExecution(), ProductionAttackLabExecution(), ProductionRecovery(), ProductionPolicyDeployment(), ProductionHomeAttention(), ProductionApprovalNotification(), ProductionWorkflowCompatibility(), ProductionSecurityAgentPlanner(), ProductionSecurityAgentAttackPath(), ProductionIntegrationSetup(), ProductionIntegrationWebhook(), ProductionRuntimeQueueReplay(), ProductionRedTeamSafety(), ProductionRedTeamInvocation(), ProductionRedTeamArtifacts(), ProductionRuntimeSessions(), ProductionRuntimeSessionReads(), ProductionRuntimeSessionSearch(), ProductionRuntimeSessionQuery(), ProductionRuntimeSessionEvidence(), ProductionRuntimeEnrollmentPairing(), ProductionReconciliationLanePlan(), ProductionRuntimeCandidateAuthority(), ProductionRuntimeAcceptance(), ProductionRuntimeCorrelationRouting(), ProductionRuntimeSandboxBinding(), ProductionRuntimePrecision()})
}
