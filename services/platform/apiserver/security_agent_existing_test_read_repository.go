package apiserver

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

const postgresExistingTestRunContextSQL = `SELECT zasp_production_security_agent_existing_tests_run_context($1,$2,$3,$4,$5,$6)`
const postgresExistingTestApprovalSQL = `SELECT zasp_production_security_agent_existing_tests_approval($1,$2,$3,$4,$5,$6)`
const postgresExistingTestApprovalPageSQL = `SELECT zasp_production_security_agent_existing_tests_approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8,$9,$10)`
const postgresExistingTestApprovalDecisionSQL = `SELECT zasp_production_security_agent_existing_tests_decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const postgresExistingTestActivateSQL = `SELECT zasp_production_security_agent_existing_tests_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const postgresExistingTestSimulateSQL = `SELECT zasp_production_security_agent_existing_tests_simulate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16)`

func existingTestReadPins(args []any) []any {
	return append(args, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
}
