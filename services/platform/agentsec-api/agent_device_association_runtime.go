package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

// The compiled optional pin selects only the association feature. Existing
// runtime identity/authorization configuration remains mandatory and unchanged.
func validAgentDeviceAssociationRuntimeConfig(c RuntimeConfig) bool {
	return c.AgentDeviceAssociationProfileChecksum == "" || c.RuntimeServices.Enabled && migrations.IsAgentDeviceAssociationProfileChecksum(c.AgentDeviceAssociationProfileChecksum)
}
