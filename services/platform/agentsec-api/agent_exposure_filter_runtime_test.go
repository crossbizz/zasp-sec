package main

import (
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentExposureFilterRuntimeProfileIsExplicitAndFailClosed(t *testing.T) {
	if !validAgentExposureFilterRuntimeConfig(RuntimeConfig{}) {
		t.Fatal("empty profile must stay off")
	}
	for _, pin := range []string{migrations.AgentExposureFilterProfileChecksum(), migrations.AgentExposureFilterAuditProfileChecksum()} {
		c := RuntimeConfig{AgentExposureFilterProfileChecksum: pin}
		if validAgentExposureFilterRuntimeConfig(c) {
			t.Fatal("Agent read profile mounted without current runtime services")
		}
		c.RuntimeServices.Enabled = true
		if !validAgentExposureFilterRuntimeConfig(c) {
			t.Fatal("compiled selected Agent read profile refused")
		}
		c.AgentExposureFilterProfileChecksum = strings.Repeat("a", 64)
		if validAgentExposureFilterRuntimeConfig(c) {
			t.Fatal("unknown Agent read profile admitted")
		}
	}
	values := fixtureRuntimeEnvironment()
	values["ZASP_AGENT_EXPOSURE_FILTER_PROFILE_CHECKSUM"] = strings.Repeat("a", 64)
	if _, err := loadRuntimeConfig(func(k string) string { return values[k] }); err == nil {
		t.Fatal("runtime loader ignored untrusted Agent read profile pin")
	}
}
