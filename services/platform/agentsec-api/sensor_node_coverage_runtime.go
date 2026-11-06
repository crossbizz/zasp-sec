package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validSensorNodeCoverageRuntimeConfig(c RuntimeConfig) bool {
	if !c.SensorNodeCoverageRetentionEnabled {
		return c.SensorNodeCoverageProfileChecksum == ""
	}
	return c.RuntimeServices.Enabled && migrations.IsSensorNodeCoverageProfileChecksum(c.SensorNodeCoverageProfileChecksum)
}
