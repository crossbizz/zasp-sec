package migrations

import (
	_ "embed"
	"strings"
)

//go:embed sql/fragments/security_agent_existing_test_enqueue.sql
var securityAgentExistingTestEnqueueSQL string

//go:embed sql/fragments/security_agent_existing_test_links.sql
var securityAgentExistingTestLinksSQL string

//go:embed sql/fragments/security_agent_existing_test_dispatch.sql
var securityAgentExistingTestDispatchSQL string

//go:embed sql/fragments/security_agent_existing_test_definition.sql
var securityAgentExistingTestDefinitionSQL string

//go:embed sql/fragments/security_agent_existing_test_candidate_down.sql
var securityAgentExistingTestCandidateDown string

// SecurityAgentExistingTestEnqueueCandidateSQL is unregistered release55 work.
// It must not be applied outside an owned test database until release55 pins,
// rollback and all linked-invocation safeguards are implemented.
func SecurityAgentExistingTestEnqueueCandidateSQL() string {
	return securityAgentExistingTestEnqueueWithPredecessor(ProductionSecurityAgentRunContext().Checksum())
}

func securityAgentExistingTestEnqueueWithPredecessor(predecessor string) string {
	sql := strings.ReplaceAll(securityAgentExistingTestEnqueueSQL, "-- existing test predecessor checksum", predecessor)
	return strings.ReplaceAll(sql, "-- existing test predecessor fingerprint", SecurityAgentRunContextFingerprint()) + "\n" + securityAgentExistingTestLinksSQL + "\n" + securityAgentExistingTestDispatchSQL + "\n" + securityAgentExistingTestDefinitionSQL
}

// SecurityAgentExistingTestCandidateDownSQL is owned-fixture rollback work,
// not a registered release or permission to downgrade a deployed database.
func SecurityAgentExistingTestCandidateDownSQL() string {
	return securityAgentExistingTestCandidateDown
}
