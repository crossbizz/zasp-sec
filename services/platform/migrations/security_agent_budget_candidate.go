package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Unpublished v53 candidate identity. Runner registration does not establish
// CLI, mixed-binary, full lifecycle or production release acceptance.
//
//go:embed sql/fragments/security_agent_budget_admission.sql
var securityAgentBudgetAdmissionCandidate string

//go:embed sql/fragments/security_agent_budget_starts.sql
var securityAgentBudgetStartsCandidate string

//go:embed sql/fragments/security_agent_budget_release.sql
var securityAgentBudgetReleaseCandidate string

//go:embed sql/0053_production_security_agent_budgets.up.sql
var securityAgentBudgetUpSQL string

//go:embed sql/0053_production_security_agent_budgets.down.sql
var securityAgentBudgetDownSQL string

func SecurityAgentBudgetCandidateFingerprint() string {
	return "10ac4fb7b3212c5b89164911070c184e5aa3525cb29aacbb526bf5e183e20eb5"
}

func securityAgentBudgetCandidateTemplate() string {
	sql := strings.Replace(securityAgentBudgetUpSQL, "-- budget admission fragment", securityAgentBudgetAdmissionCandidate, 1)
	sql = strings.Replace(sql, "-- budget starts fragment", securityAgentBudgetStartsCandidate, 1)
	sql = strings.Replace(sql, "-- budget release fragment", securityAgentBudgetReleaseCandidate, 1)
	sql = strings.ReplaceAll(sql, "-- budget predecessor checksum", ProductionAuditExports().Checksum())
	return strings.ReplaceAll(sql, "-- budget predecessor fingerprint", ProductionAuditExportsSemanticFingerprint())
}

func SecurityAgentBudgetCandidateChecksum() string {
	digest := sha256.Sum256([]byte(securityAgentBudgetCandidateTemplate() + "\x00" + securityAgentBudgetDownSQL))
	return hex.EncodeToString(digest[:])
}

func ProductionSecurityAgentBudgets() Metadata {
	return Metadata{version: 53, name: "production_security_agent_budgets", checksum: SecurityAgentBudgetCandidateChecksum(), up: SecurityAgentBudgetCandidateSQL(), down: securityAgentBudgetDownSQL}
}

func SecurityAgentBudgetCandidateSQL() string {
	sql := strings.Replace(securityAgentBudgetCandidateTemplate(), "-- compiled budget checksum", SecurityAgentBudgetCandidateChecksum(), 1)
	return strings.Replace(sql, "-- compiled budget fingerprint", SecurityAgentBudgetCandidateFingerprint(), 1)
}
