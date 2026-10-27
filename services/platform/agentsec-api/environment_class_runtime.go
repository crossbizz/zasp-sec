package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validEnvironmentClassRuntimeConfig(c RuntimeConfig) bool {
	if !c.EnvironmentClassEnabled {
		return c.EnvironmentClassProfileChecksum == ""
	}
	return c.RuntimeServices.Enabled && migrations.IsEnvironmentClassProfileChecksum(c.EnvironmentClassProfileChecksum)
}
