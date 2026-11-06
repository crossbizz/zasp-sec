package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func validGatewayBootstrapRuntimeConfig(c RuntimeConfig) bool {
	return c.GatewayBootstrapProfileChecksum == "" || c.RuntimeServices.Enabled && migrations.IsGatewayBootstrapProfileChecksum(c.GatewayBootstrapProfileChecksum)
}
