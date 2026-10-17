package main

import (
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

func TestOptionalEgressRuntimeRequiresExplicitDistinctPurposeBinding(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if !validOptionalEgressRuntimeConfig(config) {
		t.Fatal("legacy runtime changed")
	}
	config.OptionalEgressEnabled = true
	config.RuntimeServices.Enabled = true
	config.OptionalEgressProfileChecksum = migrations.OptionalEgressAuditProfileChecksum()
	config.OptionalEgressSettlementDSN = "postgres://optional_captured@db.internal:5432/zasp?sslmode=require"
	if !validOptionalEgressRuntimeConfig(config) {
		t.Fatal("explicit separate settlement purpose rejected")
	}
	for _, dsn := range []string{config.PostgresDSN, config.SecurityAgentPostgresDSN, "postgres://optional_captured@another.internal:5432/zasp?sslmode=require", "postgres://optional_captured@db.internal:5432/other?sslmode=require", "postgres://optional_captured@db.internal:5432/zasp?sslmode=disable"} {
		changed := config
		changed.OptionalEgressSettlementDSN = dsn
		if validOptionalEgressRuntimeConfig(changed) {
			t.Fatal("invalid settlement principal or database accepted")
		}
	}
	config.OptionalEgressEnabled = false
	if validOptionalEgressRuntimeConfig(config) {
		t.Fatal("disabled runtime retained orphan purpose configuration")
	}
	values["ZASP_OPTIONAL_EGRESS_ENABLED"] = "TRUE"
	if _, err := loadRuntimeConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("noncanonical activation flag accepted")
	}
}

func TestOptionalEgressAISecretNamespaceBindsExactTenantScope(t *testing.T) {
	binding := optionalegress.Binding{Intent: optionalegress.Intent{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333"}}
	suffix := binding.OrganizationID + "/" + binding.WorkspaceID + "/" + binding.EnvironmentID + "/provider-credential"
	profile := optionalegress.Profile{CredentialReference: "secret_ref_ai/" + suffix}
	if path, ok := optionalCredentialPath(binding, profile); !ok || path != suffix {
		t.Fatal("valid canonical scoped AI reference was rejected")
	}
	for _, reference := range []string{"secret_ref_ai/" + strings.Replace(suffix, binding.OrganizationID, binding.WorkspaceID, 1), "secret_ref_webhook/" + suffix, "secret_ref_ai/" + suffix + "/child", "secret_ref_ai/" + strings.TrimSuffix(suffix, "provider-credential") + "..", "secret_ref_ai/" + suffix + strings.Repeat("a", 96)} {
		profile.CredentialReference = reference
		if _, ok := optionalCredentialPath(binding, profile); ok {
			t.Fatal("cross-purpose, cross-tenant or traversing AI reference accepted")
		}
	}
}
