package apiserver

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// VerifySecurityAgentBudgetRelease binds upgraded readiness to application
// constants. Do not cache absence: an already-warmed adapter can cross cutover.
func (database *PostgresJSONDatabase) VerifySecurityAgentBudgetRelease(ctx context.Context) error {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return ErrRepositoryUnavailable
	}
	// Never cache release absence: a warmed connection can cross an upgrade or
	// rollback. A present54 gate must pass its own application-compiled pins.
	if installed, err := database.securityAgentRunContextAvailableLocked(ctx); err != nil || installed {
		return err
	}
	var installed bool
	if err := database.driver.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_budgets_readiness(text,text)') IS NOT NULL`).Scan(&installed); err != nil {
		return ErrRepositoryUnavailable
	}
	if !installed {
		return nil
	}
	var ready bool
	if err := database.driver.QueryRow(ctx, `SELECT public.zasp_production_security_agent_budgets_client_ready($1,$2)`, migrations.SecurityAgentBudgetCandidateChecksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

// A missing release preserves the legacy read shape. A present but untrusted
// release is an error, never a silent fallback to older detail authority.
func (database *PostgresJSONDatabase) SecurityAgentRunContextAvailable(ctx context.Context) (bool, error) {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return false, ErrRepositoryUnavailable
	}
	return database.securityAgentRunContextAvailableLocked(ctx)
}

func (database *PostgresJSONDatabase) securityAgentRunContextAvailableLocked(ctx context.Context) (bool, error) {
	// Probe the newest installed release first on every use. An invalid55 is
	// never a reason to fall back to54, including on an already-warm connection.
	if available, err := database.securityAgentExistingTestsAvailableLocked(ctx); err != nil || available {
		return available, err
	}
	var installed bool
	if err := database.driver.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_run_context_readiness(text,text)') IS NOT NULL`).Scan(&installed); err != nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	if !installed {
		return false, nil
	}
	var ready bool
	metadata := migrations.ProductionSecurityAgentRunContext()
	if err := database.driver.QueryRow(ctx, `SELECT public.zasp_production_security_agent_run_context_client_ready($1,$2)`, metadata.Checksum(), migrations.SecurityAgentRunContextFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}

func (database *PostgresJSONDatabase) SecurityAgentExistingTestDefinitionsAvailable(ctx context.Context) (bool, error) {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return false, ErrRepositoryUnavailable
	}
	return database.securityAgentExistingTestsAvailableLocked(ctx)
}

func (database *PostgresJSONDatabase) securityAgentExistingTestsAvailableLocked(ctx context.Context) (bool, error) {
	var existingTestsInstalled bool
	if err := database.driver.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_existing_tests_readiness(text,text)') IS NOT NULL`).Scan(&existingTestsInstalled); err != nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	if existingTestsInstalled {
		var ready bool
		metadata := migrations.ProductionSecurityAgentExistingTests()
		if err := database.driver.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_client_ready($1,$2)`, metadata.Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
			return false, ErrRepositoryUnavailable
		}
		return true, nil
	}
	return false, nil
}
