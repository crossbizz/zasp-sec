package main

import (
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentCurrentOwnershipWriteRuntimeProfileIsExplicitAndFailClosed(t *testing.T) {
	if !validAgentOwnershipWriteRuntimeConfig(RuntimeConfig{}) {
		t.Fatal("empty profile must stay off")
	}
	for _, pin := range []string{migrations.AgentOwnershipWriteProfileChecksum(), migrations.AgentOwnershipWriteAuditProfileChecksum()} {
		c := RuntimeConfig{AgentOwnershipWriteProfileChecksum: pin}
		if validAgentOwnershipWriteRuntimeConfig(c) {
			t.Fatal("Agent ownership write profile mounted without current runtime services")
		}
		c.RuntimeServices.Enabled = true
		if !validAgentOwnershipWriteRuntimeConfig(c) {
			t.Fatal("compiled selected Agent ownership write profile refused")
		}
		c.AgentOwnershipWriteProfileChecksum = strings.Repeat("a", 64)
		if validAgentOwnershipWriteRuntimeConfig(c) {
			t.Fatal("unknown Agent ownership write profile admitted")
		}
	}
	values := fixtureRuntimeEnvironment()
	values["ZASP_AGENT_OWNERSHIP_WRITE_PROFILE_CHECKSUM"] = strings.Repeat("a", 64)
	if _, err := loadRuntimeConfig(func(k string) string { return values[k] }); err == nil {
		t.Fatal("runtime loader ignored untrusted Agent ownership write profile pin")
	}
}
