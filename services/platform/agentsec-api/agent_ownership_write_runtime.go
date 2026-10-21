package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validAgentOwnershipWriteRuntimeConfig(c RuntimeConfig) bool {
	return c.AgentOwnershipWriteProfileChecksum == "" || c.RuntimeServices.Enabled && migrations.IsAgentOwnershipWriteProfileChecksum(c.AgentOwnershipWriteProfileChecksum)
}
