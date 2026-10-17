package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validAgentExposureFilterRuntimeConfig(c RuntimeConfig) bool {
	return c.AgentExposureFilterProfileChecksum == "" || c.RuntimeServices.Enabled && migrations.IsAgentExposureFilterProfileChecksum(c.AgentExposureFilterProfileChecksum)
}
