package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validAgentOwnerFilterRuntimeConfig(c RuntimeConfig) bool {
	if !c.AgentOwnerFilterEnabled {
		return c.AgentOwnerFilterProfileChecksum == ""
	}
	return c.RuntimeServices.Enabled && migrations.IsAgentOwnerFilterProfileChecksum(c.AgentOwnerFilterProfileChecksum)
}
