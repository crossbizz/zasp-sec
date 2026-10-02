package migrations

import "context"

const productionSecurityAgentExistingTestsReadinessSQL = `SELECT public.zasp_production_security_agent_existing_tests_readiness($1,$2)`

func readProductionSecurityAgentExistingTestsState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests()))
}

func (runner *Runner) UpProductionSecurityAgentExistingTests(ctx context.Context) error {
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
		if err := requireMigrationReadiness(ctx, transaction, productionSecurityAgentRunContextReadinessSQL, ProductionSecurityAgentRunContext().Checksum(), SecurityAgentRunContextFingerprint()); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentExistingTests()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_existing_tests_checksum',$1),('production_security_agent_existing_tests_fingerprint',$2)`, metadata.Checksum(), SecurityAgentExistingTestsFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentExistingTestsState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionSecurityAgentExistingTestsReadinessSQL, metadata.Checksum(), SecurityAgentExistingTestsFingerprint())
	})
}

func (runner *Runner) DownProductionSecurityAgentExistingTests(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, transaction); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, `LOCK TABLE public.zasp_security_agent_global_control_receipts,public.zasp_security_agent_kill_switches,public.zasp_security_agent_audit IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentExistingTestsState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentExistingTests()
		if err := requireMigrationReadiness(ctx, transaction, productionSecurityAgentExistingTestsReadinessSQL, metadata.Checksum(), SecurityAgentExistingTestsFingerprint()); err != nil {
			return err
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentRunContextState(ctx, transaction); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, transaction, productionSecurityAgentRunContextReadinessSQL, ProductionSecurityAgentRunContext().Checksum(), SecurityAgentRunContextFingerprint())
	})
}
