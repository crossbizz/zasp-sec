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

func securityAgentExistingTestsTemplate(budget, context string) string {
	parts := []string{
		strings.Replace(securityAgentExistingTestsUpSQL, "-- existing test candidate fragments", securityAgentExistingTestEnqueueWithPredecessor(context), 1),
		securityAgentExistingTestPlannerSQL,
		securityAgentExistingTestApprovalsSQL,
		securityAgentExistingTestReadsSQL,
		securityAgentExistingTestControlsSQL,
		securityAgentExistingTestLifecycleSQL,
		securityAgentExistingTestAdmissionSQL,
		securityAgentExistingTestInvocationSQL,
		securityAgentExistingTestInvocationJournalSQL,
		securityAgentExistingTestEvidenceSQL,
		securityAgentExistingTestReconcileSQL,
		securityAgentExistingTestSettlementSQL,
		securityAgentExistingTestExecutionSQL,
		securityAgentExistingTestPublicSQL,
		securityAgentExistingTestGlobalControlSQL,
	}
	replacer := strings.NewReplacer(
		"-- existing tests budget checksum", budget,
		"-- existing tests budget fingerprint", SecurityAgentBudgetCandidateFingerprint(),
		"-- existing tests context checksum", context,
		"-- existing tests context fingerprint", SecurityAgentRunContextFingerprint(),
	)
	// Most fragments contain no release markers. Join them once after substituting
	// any marked parts; a marker cannot span the newline between two parts.
	for index, part := range parts {
		if strings.Contains(part, "-- existing tests ") {
			parts[index] = replacer.Replace(part)
		}
	}
	return strings.Join(parts, "\n")
}

func ProductionSecurityAgentExistingTests() Metadata {
	sql := securityAgentExistingTestsTemplate(ProductionSecurityAgentBudgets().Checksum(), ProductionSecurityAgentRunContext().Checksum())
	digest := sha256.Sum256([]byte(sql + "\x00" + securityAgentExistingTestsDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.ReplaceAll(sql, "-- compiled existing tests checksum", checksum)
	sql = strings.ReplaceAll(sql, "-- compiled existing tests fingerprint", SecurityAgentExistingTestsFingerprint())
	return Metadata{version: 55, name: "production_security_agent_existing_tests", checksum: checksum, up: sql, down: securityAgentExistingTestsDownSQL}
}
