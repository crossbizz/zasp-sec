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

func SecurityAgentExportsFingerprint() string {
	return "0d5ce2f2b6a6252ee8bc5e675b2776a5c23c03fb50754f7c46345f8fbae906f3"
}

func ProductionSecurityAgentExports() Metadata {
	sql := strings.NewReplacer(
		"-- export sources fragment", securityAgentExportSourcesSQL,
		"-- export jobs fragment", securityAgentExportJobsSQL,
		"-- export links fragment", securityAgentExportLinksSQL,
		"-- export planner fragment", securityAgentExportPlannerSQL,
		"-- export accounting fragment", securityAgentExportAccountingSQL,
		"-- manual provenance fragment", securityAgentManualSQL,
		"-- export predecessor checksum", ProductionSecurityAgentAttackLab().Checksum(),
		"-- export predecessor fingerprint", SecurityAgentAttackLabFingerprint(),
	).Replace(securityAgentExportsUpSQL)
	digest := sha256.Sum256([]byte(sql + "\x00" + securityAgentExportsDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql = strings.NewReplacer("-- compiled export checksum", checksum, "-- compiled export fingerprint", SecurityAgentExportsFingerprint()).Replace(sql)
	return Metadata{version: 58, name: "production_security_agent_exports", checksum: checksum, up: sql, down: securityAgentExportsDownSQL}
}
