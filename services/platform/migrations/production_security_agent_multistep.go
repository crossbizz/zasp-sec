package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Direct SQL installation remains a persistence candidate at release60. The
// Runner separately promotes it to the registered release61 authority.
//
//go:embed sql/0061_production_security_agent_multistep.up.sql
var securityAgentMultistepUpSQL string

//go:embed sql/0061_production_security_agent_multistep.down.sql
var securityAgentMultistepDownSQL string

//go:embed sql/0061_production_security_agent_multistep.promote.sql
var securityAgentMultistepPromoteSQL string

//go:embed sql/0061_production_security_agent_multistep.demote.sql
var securityAgentMultistepDemoteSQL string

//go:embed sql/0061_production_security_agent_multistep.admission.sql
var securityAgentMultistepAdmissionSQL string

//go:embed sql/0061_production_security_agent_multistep.progression.sql
var securityAgentMultistepProgressionSQL string

//go:embed sql/0061_production_security_agent_multistep.legacy_actions.sql
var securityAgentMultistepLegacyActionsSQL string

//go:embed sql/0061_production_security_agent_multistep.application.sql
var securityAgentMultistepApplicationSQL string

//go:embed sql/0061_production_security_agent_multistep.deployment.sql
var securityAgentMultistepDeploymentSQL string

//go:embed sql/0061_production_security_agent_multistep.test.sql
var securityAgentMultistepTestSQL string

//go:embed sql/0061_production_security_agent_multistep.test_artifacts.sql
var securityAgentMultistepTestArtifactsSQL string

//go:embed sql/0061_production_security_agent_multistep.test_settlement.sql
var securityAgentMultistepTestSettlementSQL string

//go:embed sql/0061_production_security_agent_multistep.cleanup.sql
var securityAgentMultistepCleanupSQL string

//go:embed sql/0061_production_security_agent_multistep.cleanup_deployment.sql
var securityAgentMultistepCleanupDeploymentSQL string

//go:embed sql/0061_production_security_agent_multistep.pricing.sql
var securityAgentMultistepPricingSQL string

//go:embed sql/0061_production_security_agent_multistep.planning.sql
var securityAgentMultistepPlanningSQL string

//go:embed sql/0061_production_security_agent_multistep.orchestration.sql
var securityAgentMultistepOrchestrationSQL string

func SecurityAgentMultistepFingerprint() string {
	return "2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98"
}

// The candidate and registered object sets differ; only this pin is published
// in shared production metadata after promotion.
func SecurityAgentMultistepRegisteredFingerprint() string {
	return "6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92"
}

func ProductionSecurityAgentMultistep() Metadata {
	up := strings.NewReplacer("-- multistep predecessor checksum", ProductionDiscoveryScheduleReplay().Checksum(), "-- multistep predecessor fingerprint", DiscoveryScheduleReplayFingerprint()).Replace(securityAgentMultistepUpSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + securityAgentMultistepDownSQL + "\x00" + securityAgentMultistepPromoteSQL + "\x00" + securityAgentMultistepDemoteSQL + "\x00" + securityAgentMultistepAdmissionSQL + "\x00" + securityAgentMultistepProgressionSQL + "\x00" + securityAgentMultistepLegacyActionsSQL + "\x00" + securityAgentMultistepApplicationSQL + "\x00" + securityAgentMultistepDeploymentSQL + "\x00" + securityAgentMultistepTestSQL + "\x00" + securityAgentMultistepTestArtifactsSQL + "\x00" + securityAgentMultistepTestSettlementSQL + "\x00" + securityAgentMultistepCleanupSQL + "\x00" + securityAgentMultistepCleanupDeploymentSQL + "\x00" + securityAgentMultistepPricingSQL + "\x00" + securityAgentMultistepPlanningSQL + "\x00" + securityAgentMultistepOrchestrationSQL))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- compiled multistep checksum", checksum, "-- compiled multistep fingerprint", SecurityAgentMultistepFingerprint())
	return Metadata{version: 61, name: "production_security_agent_multistep", checksum: checksum, up: bind.Replace(up), down: bind.Replace(securityAgentMultistepDownSQL)}
}

func multistepRegistrationSQL(source string) string {
	source = strings.ReplaceAll(source, "-- registered multistep admission", securityAgentMultistepAdmissionSQL)
	source = strings.ReplaceAll(source, "-- registered multistep progression", securityAgentMultistepProgressionSQL)
	source = strings.ReplaceAll(source, "-- registered multistep legacy actions", securityAgentMultistepLegacyActionsSQL)
	source = strings.ReplaceAll(source, "-- registered multistep application", securityAgentMultistepApplicationSQL)
	source = strings.ReplaceAll(source, "-- registered multistep deployment", securityAgentMultistepDeploymentSQL)
	source = strings.ReplaceAll(source, "-- registered multistep test artifacts", securityAgentMultistepTestArtifactsSQL)
	source = strings.ReplaceAll(source, "-- registered multistep test settlement", securityAgentMultistepTestSettlementSQL)
	source = strings.ReplaceAll(source, "-- registered multistep test", securityAgentMultistepTestSQL)
	source = strings.ReplaceAll(source, "-- registered multistep cleanup deployment", securityAgentMultistepCleanupDeploymentSQL)
	source = strings.ReplaceAll(source, "-- registered multistep cleanup", securityAgentMultistepCleanupSQL)
	source = strings.ReplaceAll(source, "-- registered multistep pricing", securityAgentMultistepPricingSQL)
	source = strings.ReplaceAll(source, "-- registered multistep planning", securityAgentMultistepPlanningSQL)
	source = strings.ReplaceAll(source, "-- registered multistep orchestration", securityAgentMultistepOrchestrationSQL)
	return strings.NewReplacer("-- compiled multistep checksum", ProductionSecurityAgentMultistep().Checksum(), "-- compiled multistep fingerprint", SecurityAgentMultistepFingerprint(), "-- registered multistep fingerprint", SecurityAgentMultistepRegisteredFingerprint(), "-- multistep predecessor checksum", ProductionDiscoveryScheduleReplay().Checksum(), "-- multistep predecessor fingerprint", DiscoveryScheduleReplayFingerprint()).Replace(source)
}

const multistepReadinessSQL = `SELECT public.zasp_sa_multistep_readiness($1,$2)`

func multistepPredecessors() []Metadata {
	return append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks(), ProductionDiscoveryScheduleReplay())
}

func readProductionSecurityAgentMultistepState(ctx context.Context, q Queryer) error {
	return readExactReleaseState(ctx, q, append(multistepPredecessors(), ProductionSecurityAgentMultistep()))
}

// Both directions acquire schema admission, legacy evidence tables, then shared
// identity, then candidate and restoration evidence. READ COMMITTED is required even for retry:
// every state/readiness check must see commits made while admission was waiting.
func lockSecurityAgentMultistep(ctx context.Context, tx Transaction) error {
	for _, statement := range []string{`DO $isolation$ BEGIN IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='multistep migration requires read committed isolation';END IF;END $isolation$`, `SET LOCAL lock_timeout='3s'`, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`, `LOCK TABLE public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions,public.zasp_security_agent_runs,public.zasp_security_agent_plans,public.zasp_security_agent_steps,public.zasp_security_agent_effects,public.zasp_security_agent_audit IN ACCESS EXCLUSIVE MODE`, lockTableSQL, `LOCK TABLE public.zasp_schema_metadata IN ACCESS EXCLUSIVE MODE`} {
		if err := tx.Exec(ctx, statement); err != nil {
			return fixedDatabaseError(ctx, err)
		}
	}
	return nil
}

func lockRegisteredMultistepEvidence(ctx context.Context, tx Transaction) error {
	// Freeze executable restoration rows before readiness reads them. Waiting
	// until DROP SCHEMA would discard a writer's post-readiness committed drift.
	if err := tx.Exec(ctx, `LOCK TABLE public.zasp_sa_multistep_definitions,public.zasp_sa_multistep_runs,public.zasp_sa_multistep_dependencies,public.zasp_sa_multistep_receipts,zasp_sa_multistep_prior.functions,zasp_sa_multistep_prior.admissions,zasp_sa_multistep_prior.pricing_policies,zasp_sa_multistep_prior.pricing_accounts,zasp_sa_multistep_prior.pricing_mutations,zasp_sa_multistep_prior.planning_jobs IN ACCESS EXCLUSIVE MODE`); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	return nil
}

func (r *Runner) UpProductionSecurityAgentMultistep(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		var count int64
		if err := scanRow(ctx, tx, countRowsSQL, nil, &count); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		m := ProductionSecurityAgentMultistep()
		if count == 61 {
			if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
				return err
			}
			if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
				return err
			}
			return requireMigrationReadiness(ctx, tx, multistepReadinessSQL, m.Checksum(), SecurityAgentMultistepRegisteredFingerprint())
		}
		if err := readProductionDiscoveryScheduleReplayState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, productionDiscoveryScheduleReplayReadinessSQL, ProductionDiscoveryScheduleReplay().Checksum(), DiscoveryScheduleReplayFingerprint()); err != nil {
			return err
		}
		for _, sql := range []string{m.UpSQL(), multistepRegistrationSQL(securityAgentMultistepPromoteSQL)} {
			if err := tx.Exec(ctx, sql); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_multistep_checksum',$1),('production_security_agent_multistep_fingerprint',$2)`, m.Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, insertRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, multistepReadinessSQL, m.Checksum(), SecurityAgentMultistepRegisteredFingerprint())
	})
}

func (r *Runner) DownProductionSecurityAgentMultistep(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockSecurityAgentMultistep(ctx, tx); err != nil {
			return err
		}
		// The public facade is separately registered to preserve this release's
		// immutable identity. Demote it first; never orphan its callable surface.
		if err := tx.Exec(ctx, `DO $extension$ BEGIN IF to_regnamespace('zasp_ordered_public62') IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='public ordered extension must be removed first';END IF;END $extension$`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := lockRegisteredMultistepEvidence(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentMultistepState(ctx, tx); err != nil {
			return err
		}
		m := ProductionSecurityAgentMultistep()
		if err := requireMigrationReadiness(ctx, tx, multistepReadinessSQL, m.Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, multistepRegistrationSQL(securityAgentMultistepDemoteSQL)); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, deleteRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, m.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionDiscoveryScheduleReplayState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionDiscoveryScheduleReplayReadinessSQL, ProductionDiscoveryScheduleReplay().Checksum(), DiscoveryScheduleReplayFingerprint())
	})
}
