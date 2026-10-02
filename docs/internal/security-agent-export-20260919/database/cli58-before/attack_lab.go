package migrations

import "context"

const productionSecurityAgentAttackLabReadinessSQL = `SELECT public.zasp_sa_attack_lab_readiness($1,$2)`

func readProductionSecurityAgentAttackLabState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab()))
}

func (runner *Runner) UpProductionSecurityAgentAttackLab(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, tx); err != nil {
			return err
		}
		if err := readProductionComplianceState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, productionComplianceReadinessSQL, ProductionCompliance().Checksum(), ComplianceFingerprint()); err != nil {
			return err
		}
		metadata := ProductionSecurityAgentAttackLab()
		if err := tx.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_security_agent_attack_lab_checksum',$1),('production_security_agent_attack_lab_fingerprint',$2)`, metadata.Checksum(), SecurityAgentAttackLabFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentAttackLabState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentAttackLabReadinessSQL, metadata.Checksum(), SecurityAgentAttackLabFingerprint())
	})
}

func (runner *Runner) DownProductionSecurityAgentAttackLab(ctx context.Context) error {
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
		metadata := ProductionSecurityAgentAttackLab()
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentAttackLabReadinessSQL, metadata.Checksum(), SecurityAgentAttackLabFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionComplianceState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionComplianceReadinessSQL, ProductionCompliance().Checksum(), ComplianceFingerprint())
	})
}

func (runner *Runner) RegisterSecurityAgentAttackLabReconciler(ctx context.Context, principal string) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := readProductionSecurityAgentAttackLabState(ctx, tx); err != nil {
			return err
		}
		m := ProductionSecurityAgentAttackLab()
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentAttackLabReadinessSQL, m.Checksum(), SecurityAgentAttackLabFingerprint()); err != nil {
			return err
		}
		var registered bool
		if err := scanRow(ctx, tx, `SELECT public.zasp_sa_attack_lab_register_reconciler($1,$2,$3)`, []any{principal, m.Checksum(), SecurityAgentAttackLabFingerprint()}, &registered); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !registered {
			return ErrInvalidState
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentAttackLabReadinessSQL, m.Checksum(), SecurityAgentAttackLabFingerprint())
	})
}
