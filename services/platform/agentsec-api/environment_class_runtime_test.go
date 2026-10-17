package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func TestEnvironmentClassRuntimeRequiresExplicitCompiledProfile(t *testing.T) {
	base := RuntimeConfig{}
	if !validEnvironmentClassRuntimeConfig(base) {
		t.Fatal("disabled legacy configuration refused")
	}
	for _, pin := range []string{migrations.EnvironmentClassProfileChecksum(), migrations.EnvironmentClassAuditProfileChecksum()} {
		c := base
		c.EnvironmentClassProfileChecksum = pin
		if validEnvironmentClassRuntimeConfig(c) {
			t.Fatal("orphan profile accepted")
		}
		c.EnvironmentClassEnabled = true
		if validEnvironmentClassRuntimeConfig(c) {
			t.Fatal("missing native services accepted")
		}
		c.RuntimeServices.Enabled = true
		if !validEnvironmentClassRuntimeConfig(c) {
			t.Fatal("compiled selected profile refused")
		}
		c.EnvironmentClassProfileChecksum = "invalid"
		if validEnvironmentClassRuntimeConfig(c) {
			t.Fatal("unknown profile accepted")
		}
	}
}
