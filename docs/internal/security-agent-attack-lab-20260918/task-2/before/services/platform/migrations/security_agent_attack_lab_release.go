package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Release 57 is an admission foundation, not runtime or catalog availability.
//
//go:embed sql/0057_production_security_agent_attack_lab.up.sql
var securityAgentAttackLabUpSQL string

//go:embed sql/0057_production_security_agent_attack_lab.down.sql
var securityAgentAttackLabDownSQL string

//go:embed sql/fragments/security_agent_attack_lab_admission.sql
var securityAgentAttackLabAdmissionSQL string

//go:embed sql/fragments/security_agent_attack_lab_definition.sql
var securityAgentAttackLabDefinitionSQL string

//go:embed sql/fragments/security_agent_attack_lab_planner.sql
var securityAgentAttackLabPlannerSQL string

//go:embed sql/fragments/security_agent_attack_lab_links.sql
var securityAgentAttackLabLinksSQL string

func SecurityAgentAttackLabFingerprint() string {
	return "797b6bdf674dd33b0a2459e12f10660a262a0a365b213944db3bb4f2469849fd"
}

func ProductionSecurityAgentAttackLab() Metadata {
	sql := strings.NewReplacer(
		"-- attack lab admission fragment", securityAgentAttackLabAdmissionSQL,
		"-- attack lab definition fragment", securityAgentAttackLabDefinitionSQL,
		"-- attack lab planner fragment", securityAgentAttackLabPlannerSQL,
		"-- attack lab links fragment", securityAgentAttackLabLinksSQL,
		"-- attack lab predecessor checksum", ProductionCompliance().Checksum(),
		"-- attack lab predecessor fingerprint", ComplianceFingerprint(),
	).Replace(securityAgentAttackLabUpSQL)
	digest := sha256.Sum256([]byte(sql + "\x00" + securityAgentAttackLabDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.NewReplacer("-- compiled attack lab checksum", checksum, "-- compiled attack lab fingerprint", SecurityAgentAttackLabFingerprint()).Replace(sql)
	return Metadata{version: 57, name: "production_security_agent_attack_lab", checksum: checksum, up: sql, down: securityAgentAttackLabDownSQL}
}
