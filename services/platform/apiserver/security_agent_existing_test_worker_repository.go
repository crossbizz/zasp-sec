package apiserver

import "context"

const (
	postgresSecurityAgentExistingTestPlannerContextSQL = `SELECT public.zasp_production_security_agent_existing_tests_planner_context($1,$2,$3,$4,$5,$6)`
	postgresSecurityAgentExistingTestReservePlannerSQL = `SELECT zasp_production_security_agent_existing_tests_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	postgresSecurityAgentExistingTestPrepareSQL        = `SELECT public.zasp_production_security_agent_existing_tests_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresSecurityAgentExistingTestAcceptSQL         = `SELECT public.zasp_production_security_agent_existing_tests_accept_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	postgresSecurityAgentExistingTestFailureSQL        = `SELECT public.zasp_production_security_agent_existing_tests_fail_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresSecurityAgentExistingTestExecuteSQL        = `SELECT public.zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
)

// The existing draft capability probes the entire compiled55 release, not a
// UI flag. Recheck on each operation so warm repositories cross cutover safely.
// Absence preserves legacy behavior; a present but invalid release never does.
func (repository *SecurityAgentWorkerRepository) existingTestPlannerRelease(ctx context.Context) (bool, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	verifier, ok := repository.database.(interface {
		SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	available, err := verifier.SecurityAgentExistingTestDefinitionsAvailable(ctx)
	if err != nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return available, nil
}
