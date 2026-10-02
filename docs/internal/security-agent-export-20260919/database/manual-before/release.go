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

func SecurityAgentExportsFingerprint() string {
	return "16d71c1f47360dc46b7fba40e0ab438d0f902a0a0683978c99cf8a88e4a42336"
}

func ProductionSecurityAgentExports() Metadata {
	sql := strings.NewReplacer(
		"-- export sources fragment", securityAgentExportSourcesSQL,
		"-- export jobs fragment", securityAgentExportJobsSQL,
		"-- export links fragment", securityAgentExportLinksSQL,
		"-- export planner fragment", securityAgentExportPlannerSQL,
		"-- export accounting fragment", securityAgentExportAccountingSQL,
		"-- export predecessor checksum", ProductionSecurityAgentAttackLab().Checksum(),
		"-- export predecessor fingerprint", SecurityAgentAttackLabFingerprint(),
	).Replace(securityAgentExportsUpSQL)
	digest := sha256.Sum256([]byte(sql + "\x00" + securityAgentExportsDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.NewReplacer("-- compiled export checksum", checksum, "-- compiled export fingerprint", SecurityAgentExportsFingerprint()).Replace(sql)
	return Metadata{version: 58, name: "production_security_agent_exports", checksum: checksum, up: sql, down: securityAgentExportsDownSQL}
}
