package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0054_production_security_agent_run_context.up.sql
var securityAgentRunContextUpSQL string

//go:embed sql/0054_production_security_agent_run_context.down.sql
var securityAgentRunContextDownSQL string

//go:embed sql/fragments/security_agent_run_context.sql
var securityAgentRunContextProjectionSQL string

func SecurityAgentRunContextFingerprint() string {
	return "9fb3045069cc65a134e1c37dddd9f3c8871a8abc253840b458f511816660bceb"
}

func securityAgentRunContextTemplate() string {
	sql := strings.Replace(securityAgentRunContextUpSQL, "-- run context projection fragment", securityAgentRunContextProjectionSQL, 1)
	sql = strings.ReplaceAll(sql, "-- run context predecessor checksum", SecurityAgentBudgetCandidateChecksum())
	return strings.ReplaceAll(sql, "-- run context predecessor fingerprint", SecurityAgentBudgetCandidateFingerprint())
}

func ProductionSecurityAgentRunContext() Metadata {
	digest := sha256.Sum256([]byte(securityAgentRunContextTemplate() + "\x00" + securityAgentRunContextDownSQL))
	checksum := hex.EncodeToString(digest[:])
	sql := strings.ReplaceAll(securityAgentRunContextTemplate(), "-- compiled run context checksum", checksum)
	sql = strings.ReplaceAll(sql, "-- compiled run context fingerprint", SecurityAgentRunContextFingerprint())
	return Metadata{version: 54, name: "production_security_agent_run_context", checksum: checksum, up: sql, down: securityAgentRunContextDownSQL}
}
