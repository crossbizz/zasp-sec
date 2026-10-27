package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func TestAgentOwnerFilterRuntimeRequiresExplicitCompiledProfile(t *testing.T) {
	base := RuntimeConfig{}
	if !validAgentOwnerFilterRuntimeConfig(base) {
		t.Fatal("disabled legacy configuration refused")
	}
	for _, pin := range []string{migrations.AgentOwnerFilterProfileChecksum(), migrations.AgentOwnerFilterAuditProfileChecksum()} {
		c := base
		c.AgentOwnerFilterProfileChecksum = pin
		if validAgentOwnerFilterRuntimeConfig(c) {
			t.Fatal("orphan profile accepted")
		}
		c.AgentOwnerFilterEnabled = true
		if validAgentOwnerFilterRuntimeConfig(c) {
			t.Fatal("missing native services accepted")
		}
		c.RuntimeServices.Enabled = true
		if !validAgentOwnerFilterRuntimeConfig(c) {
			t.Fatal("compiled selected profile refused")
		}
		c.AgentOwnerFilterProfileChecksum = "invalid"
		if validAgentOwnerFilterRuntimeConfig(c) {
			t.Fatal("unknown profile accepted")
		}
	}
}
