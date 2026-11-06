package main

import (
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentDeviceAssociationRuntimeProfileIsExplicitAndFailClosed(t *testing.T) {
	if !validAgentDeviceAssociationRuntimeConfig(RuntimeConfig{}) {
		t.Fatal("empty profile must stay off")
	}
	for _, pin := range []string{migrations.AgentDeviceAssociationProfileChecksum(), migrations.AgentDeviceAssociationAuditProfileChecksum()} {
		c := RuntimeConfig{AgentDeviceAssociationProfileChecksum: pin}
		if validAgentDeviceAssociationRuntimeConfig(c) {
			t.Fatal("Agent Device association profile mounted without current runtime services")
		}
		c.RuntimeServices.Enabled = true
		if !validAgentDeviceAssociationRuntimeConfig(c) {
			t.Fatal("compiled selected Agent Device association profile refused")
		}
		c.AgentDeviceAssociationProfileChecksum = strings.Repeat("a", 64)
		if validAgentDeviceAssociationRuntimeConfig(c) {
			t.Fatal("unknown Agent Device association profile admitted")
		}
	}
	values := fixtureRuntimeEnvironment()
	values["ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM"] = strings.Repeat("a", 64)
	if _, err := loadRuntimeConfig(func(k string) string { return values[k] }); err == nil {
		t.Fatal("runtime loader ignored untrusted Agent Device association profile pin")
	}
}
