package migrations

import "context"

const productionSecurityAgentBudgetsReadinessSQL = `SELECT public.zasp_production_security_agent_budgets_readiness($1,$2)`

func lockProductionSecurityAgentBudgets(ctx context.Context, transaction Transaction) error {
	if err := lockProductionAuditExports(ctx, transaction); err != nil {
		return err
	}
	for _, statement := range []string{
		`LOCK TABLE public.zasp_security_agent_runs,public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions,public.zasp_security_agent_plans,public.zasp_security_agent_steps,public.zasp_security_agent_effects,public.zasp_security_agent_controls,public.zasp_security_agent_planner_receipts,public.zasp_security_agent_temporary_policy_targets,public.zasp_policy_deployment_work,public.zasp_runtime_gateway_policy_bundles IN ACCESS EXCLUSIVE MODE NOWAIT`,
		`DO $lock$ DECLARE name text;BEGIN FOREACH name IN ARRAY ARRAY['zasp_security_agent_org_admissions','zasp_security_agent_run_budgets','zasp_security_agent_step_reservations','zasp_security_agent_provider_reservations'] LOOP IF to_regclass('public.'||name) IS NOT NULL THEN EXECUTE format('LOCK TABLE public.%I IN ACCESS EXCLUSIVE MODE NOWAIT',name);END IF;END LOOP;END $lock$`,
	} {
		if err := transaction.Exec(ctx, statement); err != nil {
			return fixedDatabaseError(ctx, err)
		}
	}
	return nil
}

func readProductionSecurityAgentBudgetsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets()))
}

func (runner *Runner) UpProductionSecurityAgentBudgets(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionAuditExportsState(ctx, transaction); err != nil {
			return err
		}
		prior := ProductionAuditExports()
		if err := requireMigrationReadiness(ctx, transaction, productionAuditExportsReadinessSQL, prior.Checksum(), ProductionAuditExportsSemanticFingerprint()); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentBudgets()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_budgets_checksum',$1),('production_security_agent_budgets_fingerprint',$2)`, metadata.Checksum(), SecurityAgentBudgetCandidateFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentBudgetsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionSecurityAgentBudgetsReadinessSQL, metadata.Checksum(), SecurityAgentBudgetCandidateFingerprint())
	})
}

func (runner *Runner) DownProductionSecurityAgentBudgets(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionSecurityAgentBudgetsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentBudgets()
		if err := requireMigrationReadiness(ctx, transaction, productionSecurityAgentBudgetsReadinessSQL, metadata.Checksum(), SecurityAgentBudgetCandidateFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionAuditExportsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionAuditExportsReadinessSQL, ProductionAuditExports().Checksum(), ProductionAuditExportsSemanticFingerprint())
	})
}
