package addonevidence

import "slices"

const LegacyRuleset = "zasp-static.v1"
const CurrentRuleset = "zasp-static.v2"

// These IDs form the closed findings-only protocol. Their lexical order is
// also the established CI attestation canonical order.
var legacyRules = []string{"dependency.unpinned", "instruction.hidden_text", "mcp.remote_endpoint", "mcp.unpinned_launcher", "script.network_access", "script.shell_execution"}
var currentRules = []string{"dependency.unpinned", "instruction.hidden_text", "instruction.override", "mcp.remote_endpoint", "mcp.unpinned_exec", "mcp.unpinned_launcher", "script.credential_path_access", "script.network_access", "script.remote_exec_pipe", "script.shell_execution"}

func Rules(version string) []string {
	switch version {
	case LegacyRuleset:
		return slices.Clone(legacyRules)
	case CurrentRuleset:
		return slices.Clone(currentRules)
	default:
		return nil
	}
}
