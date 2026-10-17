package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validAgentReadRuntimeConfig(c RuntimeConfig) bool {
	return c.AgentReadProfileChecksum == "" || c.RuntimeServices.Enabled && migrations.IsAgentReadProfileChecksum(c.AgentReadProfileChecksum)
}
