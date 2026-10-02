package migrations

import "context"

const productionSecurityAgentExportsReadinessSQL = `SELECT public.zasp_sa_export_readiness($1,$2)`

func readProductionSecurityAgentExportsState(ctx context.Context, q Queryer) error {
	return readExactReleaseState(ctx, q, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports()))
}

func (runner *Runner) UpProductionSecurityAgentExports(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentAttackLabState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentAttackLabReadinessSQL, ProductionSecurityAgentAttackLab().Checksum(), SecurityAgentAttackLabFingerprint()); err != nil {
			return err
		}
		m := ProductionSecurityAgentExports()
		if err := tx.Exec(ctx, m.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_exports_checksum',$1),('production_security_agent_exports_fingerprint',$2)`, m.Checksum(), SecurityAgentExportsFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, insertRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentExportsState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentExportsReadinessSQL, m.Checksum(), SecurityAgentExportsFingerprint())
	})
}

func (runner *Runner) DownProductionSecurityAgentExports(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentExportsState(ctx, tx); err != nil {
			return err
		}
		m := ProductionSecurityAgentExports()
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentExportsReadinessSQL, m.Checksum(), SecurityAgentExportsFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, m.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, deleteRowSQL, m.Version(), m.Name(), m.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentAttackLabState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentAttackLabReadinessSQL, ProductionSecurityAgentAttackLab().Checksum(), SecurityAgentAttackLabFingerprint())
	})
}
