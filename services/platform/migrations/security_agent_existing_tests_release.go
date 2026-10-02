package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0055_production_security_agent_existing_tests.up.sql
var securityAgentExistingTestsUpSQL string

//go:embed sql/0055_production_security_agent_existing_tests.down.sql
var securityAgentExistingTestsDownSQL string

//go:embed sql/fragments/security_agent_existing_test_planner.sql
var securityAgentExistingTestPlannerSQL string

//go:embed sql/fragments/security_agent_existing_test_approvals.sql
var securityAgentExistingTestApprovalsSQL string

//go:embed sql/fragments/security_agent_existing_test_reads.sql
var securityAgentExistingTestReadsSQL string

//go:embed sql/fragments/security_agent_existing_test_lifecycle.sql
var securityAgentExistingTestLifecycleSQL string

//go:embed sql/fragments/security_agent_existing_test_controls.sql
var securityAgentExistingTestControlsSQL string

//go:embed sql/fragments/security_agent_existing_test_admission.sql
var securityAgentExistingTestAdmissionSQL string

//go:embed sql/fragments/security_agent_existing_test_invocation.sql
var securityAgentExistingTestInvocationSQL string

//go:embed sql/fragments/security_agent_existing_test_invocation_journal.sql
var securityAgentExistingTestInvocationJournalSQL string

//go:embed sql/fragments/security_agent_existing_test_evidence.sql
var securityAgentExistingTestEvidenceSQL string

//go:embed sql/fragments/security_agent_existing_test_reconcile.sql
var securityAgentExistingTestReconcileSQL string

//go:embed sql/fragments/security_agent_existing_test_settlement.sql
var securityAgentExistingTestSettlementSQL string

//go:embed sql/fragments/security_agent_existing_test_execution.sql
var securityAgentExistingTestExecutionSQL string

//go:embed sql/fragments/security_agent_existing_test_public.sql
var securityAgentExistingTestPublicSQL string

//go:embed sql/fragments/security_agent_existing_test_global_control.sql
var securityAgentExistingTestGlobalControlSQL string

func SecurityAgentExistingTestsFingerprint() string {
	return "2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04"
}

func ProductionSecurityAgentExistingTests() Metadata {
	sql := strings.Replace(securityAgentExistingTestsUpSQL, "-- existing test candidate fragments", SecurityAgentExistingTestEnqueueCandidateSQL(), 1)
	sql += "\n" + securityAgentExistingTestPlannerSQL
	sql += "\n" + securityAgentExistingTestApprovalsSQL
	sql += "\n" + securityAgentExistingTestReadsSQL
	sql += "\n" + securityAgentExistingTestControlsSQL
	sql += "\n" + securityAgentExistingTestLifecycleSQL
	sql += "\n" + securityAgentExistingTestAdmissionSQL
	sql += "\n" + securityAgentExistingTestInvocationSQL
	sql += "\n" + securityAgentExistingTestInvocationJournalSQL
	sql += "\n" + securityAgentExistingTestEvidenceSQL
	sql += "\n" + securityAgentExistingTestReconcileSQL
	sql += "\n" + securityAgentExistingTestSettlementSQL
	sql += "\n" + securityAgentExistingTestExecutionSQL
	sql += "\n" + securityAgentExistingTestPublicSQL
	sql += "\n" + securityAgentExistingTestGlobalControlSQL
	sql = strings.NewReplacer(
		"-- existing tests budget checksum", ProductionSecurityAgentBudgets().Checksum(),
		"-- existing tests budget fingerprint", SecurityAgentBudgetCandidateFingerprint(),
		"-- existing tests context checksum", ProductionSecurityAgentRunContext().Checksum(),
		"-- existing tests context fingerprint", SecurityAgentRunContextFingerprint(),
	).Replace(sql)
	digest := sha256.Sum256([]byte(sql + "\x00" + securityAgentExistingTestsDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.ReplaceAll(sql, "-- compiled existing tests checksum", checksum)
	sql = strings.ReplaceAll(sql, "-- compiled existing tests fingerprint", SecurityAgentExistingTestsFingerprint())
	return Metadata{version: 55, name: "production_security_agent_existing_tests", checksum: checksum, up: sql, down: securityAgentExistingTestsDownSQL}
}
