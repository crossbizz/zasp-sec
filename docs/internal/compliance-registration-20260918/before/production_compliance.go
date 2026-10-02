package migrations

import "context"

const productionComplianceReadinessSQL = `SELECT public.zasp_compliance_readiness($1,$2)`

func readProductionComplianceState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance()))
}

func (runner *Runner) UpProductionCompliance(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := lockProductionSecurityAgentBudgets(ctx, tx); err != nil {
			return err
		}
		if err := readProductionSecurityAgentExistingTestsState(ctx, tx); err != nil {
			return err
		}
		if err := requireMigrationReadiness(ctx, tx, productionSecurityAgentExistingTestsReadinessSQL, ProductionSecurityAgentExistingTests().Checksum(), SecurityAgentExistingTestsFingerprint()); err != nil {
			return err
		}
		metadata := ProductionCompliance()
		if err := tx.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_compliance_checksum',$1),('production_compliance_fingerprint',$2)`, metadata.Checksum(), ComplianceFingerprint()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionComplianceState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionComplianceReadinessSQL, metadata.Checksum(), ComplianceFingerprint())
	})
}

func (runner *Runner) DownProductionCompliance(ctx context.Context) error {
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
		metadata := ProductionCompliance()
		if err := requireMigrationReadiness(ctx, tx, productionComplianceReadinessSQL, metadata.Checksum(), ComplianceFingerprint()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readProductionSecurityAgentExistingTestsState(ctx, tx); err != nil {
			return err
		}
		return requireMigrationReadiness(ctx, tx, productionSecurityAgentExistingTestsReadinessSQL, ProductionSecurityAgentExistingTests().Checksum(), SecurityAgentExistingTestsFingerprint())
	})
}
