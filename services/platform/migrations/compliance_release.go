package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0056_production_compliance.up.sql
var complianceUpSQL string

//go:embed sql/0056_production_compliance.down.sql
var complianceDownSQL string

//go:embed sql/fragments/compliance_jobs.sql
var complianceJobsSQL string

func ComplianceFingerprint() string {
	return "8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced"
}

func ProductionCompliance() Metadata {
	sql := strings.NewReplacer(
		"-- compliance jobs fragment", complianceJobsSQL,
		"-- compliance budget checksum", ProductionSecurityAgentBudgets().Checksum(),
		"-- compliance budget fingerprint", SecurityAgentBudgetCandidateFingerprint(),
		"-- compliance context checksum", ProductionSecurityAgentRunContext().Checksum(),
		"-- compliance context fingerprint", SecurityAgentRunContextFingerprint(),
		"-- predecessor compliance checksum", ProductionSecurityAgentExistingTests().Checksum(),
		"-- predecessor compliance fingerprint", SecurityAgentExistingTestsFingerprint(),
	).Replace(complianceUpSQL)
	digest := sha256.Sum256([]byte(sql + "\x00" + complianceDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.NewReplacer("-- compiled compliance checksum", checksum, "-- compiled compliance fingerprint", ComplianceFingerprint()).Replace(sql)
	return Metadata{version: 56, name: "production_compliance", checksum: checksum, up: sql, down: complianceDownSQL}
}
