package main

import (
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentCurrentReadRuntimeProfileIsExplicitAndFailClosed(t *testing.T) {
	if !validAgentReadRuntimeConfig(RuntimeConfig{}) {
		t.Fatal("empty profile must stay off")
	}
	for _, pin := range []string{migrations.AgentReadProfileChecksum(), migrations.AgentReadAuditProfileChecksum()} {
		c := RuntimeConfig{AgentReadProfileChecksum: pin}
		if validAgentReadRuntimeConfig(c) {
			t.Fatal("Agent read profile mounted without current runtime services")
		}
		c.RuntimeServices.Enabled = true
		if !validAgentReadRuntimeConfig(c) {
			t.Fatal("compiled selected Agent read profile refused")
		}
		c.AgentReadProfileChecksum = strings.Repeat("a", 64)
		if validAgentReadRuntimeConfig(c) {
			t.Fatal("unknown Agent read profile admitted")
		}
	}
	values := fixtureRuntimeEnvironment()
	values["ZASP_AGENT_READ_PROFILE_CHECKSUM"] = strings.Repeat("a", 64)
	if _, err := loadRuntimeConfig(func(k string) string { return values[k] }); err == nil {
		t.Fatal("runtime loader ignored untrusted Agent read profile pin")
	}
}
