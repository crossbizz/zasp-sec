package migrations

import "context"

const productionSecurityAgentRunContextReadinessSQL = `SELECT public.zasp_production_security_agent_run_context_readiness($1,$2)`

func readProductionSecurityAgentRunContextState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext()))
}

func (runner *Runner) UpProductionSecurityAgentRunContext(ctx context.Context) error {
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
		if err := requireMigrationReadiness(ctx, transaction, productionSecurityAgentBudgetsReadinessSQL, SecurityAgentBudgetCandidateChecksum(), SecurityAgentBudgetCandidateFingerprint()); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentRunContext()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_run_context_checksum',$1),('production_security_agent_run_context_fingerprint',$2)`, metadata.Checksum(), SecurityAgentRunContextFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentRunContextState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionSecurityAgentRunContextReadinessSQL, metadata.Checksum(), SecurityAgentRunContextFingerprint())
	})
}

func (runner *Runner) DownProductionSecurityAgentRunContext(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, transaction); err != nil {
			return err
		}
		if err := readProductionSecurityAgentRunContextState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentRunContext()
		if err := requireMigrationReadiness(ctx, transaction, productionSecurityAgentRunContextReadinessSQL, metadata.Checksum(), SecurityAgentRunContextFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentBudgetsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionSecurityAgentBudgetsReadinessSQL, SecurityAgentBudgetCandidateChecksum(), SecurityAgentBudgetCandidateFingerprint())
	})
}
