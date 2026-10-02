package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0058_production_security_agent_exports.up.sql
var securityAgentExportsUpSQL string

//go:embed sql/0058_production_security_agent_exports.down.sql
var securityAgentExportsDownSQL string

//go:embed sql/fragments/security_agent_export_sources.sql
var securityAgentExportSourcesSQL string

//go:embed sql/fragments/security_agent_export_jobs.sql
var securityAgentExportJobsSQL string

//go:embed sql/fragments/security_agent_export_links.sql
var securityAgentExportLinksSQL string

//go:embed sql/fragments/security_agent_export_planner.sql
var securityAgentExportPlannerSQL string

//go:embed sql/fragments/security_agent_export_accounting.sql
var securityAgentExportAccountingSQL string

//go:embed sql/fragments/security_agent_manual.sql
var securityAgentManualSQL string

//go:embed sql/fragments/security_agent_export_definition.sql
var securityAgentExportDefinitionSQL string

func SecurityAgentExportsFingerprint() string {
	return "67a4e601a5597f67a35f3be50f4a47a0a602b3097b3a9e4838e6fc09dcee6b72"
}

func ProductionSecurityAgentExports() Metadata {
	sql := strings.NewReplacer(
		"-- export sources fragment", securityAgentExportSourcesSQL,
		"-- export jobs fragment", securityAgentExportJobsSQL,
		"-- export links fragment", securityAgentExportLinksSQL,
		"-- export planner fragment", securityAgentExportPlannerSQL,
		"-- export accounting fragment", securityAgentExportAccountingSQL,
		"-- manual provenance fragment", securityAgentManualSQL,
		"-- export definition fragment", securityAgentExportDefinitionSQL,
		"-- export predecessor checksum", ProductionSecurityAgentAttackLab().Checksum(),
		"-- export predecessor fingerprint", SecurityAgentAttackLabFingerprint(),
	).Replace(securityAgentExportsUpSQL)
	digest := sha256.Sum256([]byte(sql + "\x00" + securityAgentExportsDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.NewReplacer("-- compiled export checksum", checksum, "-- compiled export fingerprint", SecurityAgentExportsFingerprint()).Replace(sql)
	return Metadata{version: 58, name: "production_security_agent_exports", checksum: checksum, up: sql, down: securityAgentExportsDownSQL}
}
