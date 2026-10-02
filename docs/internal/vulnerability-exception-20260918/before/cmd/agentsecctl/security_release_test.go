package main

import (
	"errors"
	"testing"
)

func TestTenantIsolationAndSSRFGates(t *testing.T) {
	boundaries := []TenantBoundaryEvidence{
		{Name: "api", ReadDenied: true, MutationDenied: true, NoForeignData: true, GuardRecorded: true},
		{Name: "graph", ReadDenied: true, NoForeignData: true, GuardRecorded: true},
		{Name: "opensearch", ReadDenied: true, NoForeignData: true, GuardRecorded: true, ScopedFilter: true},
		{Name: "s3", ReadDenied: true, NoForeignData: true, GuardRecorded: true, NoURLOrBody: true},
	}
	if report, err := EvaluateTenantIsolation(boundaries); err != nil || !report.Ready || len(report.Checks) != 4 {
		t.Fatalf("EvaluateTenantIsolation() = %#v, %v", report, err)
	}
	boundaries[3].NoURLOrBody = false
	if _, err := EvaluateTenantIsolation(boundaries); !errors.Is(err, errSecurityReleaseRejected) {
		t.Fatalf("S3 leak error = %v", err)
	}
	if _, err := EvaluateConnectorSSRF(SSRFEvidence{OverrideRejected: true, NoRequestSent: true, AuditRecorded: true}); err != nil {
		t.Fatalf("EvaluateConnectorSSRF() error = %v", err)
	}
}

func TestSecretLeakageGateRequiresEverySink(t *testing.T) {
	values := make([]LeakageSinkEvidence, 0, 6)
	for _, name := range []string{"logs", "posthog", "ai", "otlp", "support_bundle", "evidence_store"} {
		values = append(values, LeakageSinkEvidence{Name: name, SeededValueAbsent: true, SensitiveFieldsGone: true, RejectedBeforeEgress: true})
	}
	if report, err := EvaluateSecretLeakage(values); err != nil || !report.Ready || len(report.Checks) != 6 {
		t.Fatalf("EvaluateSecretLeakage() = %#v, %v", report, err)
	}
	values[1].RejectedBeforeEgress = false
	if _, err := EvaluateSecretLeakage(values); !errors.Is(err, errSecurityReleaseRejected) {
		t.Fatalf("PostHog leak error = %v", err)
	}
}

func TestPolicyBypassAndAttackLabSafetyFailClosed(t *testing.T) {
	if _, err := EvaluatePolicyBypass(PolicyBypassEvidence{MalformedHTTPBlocked: true, MalformedMCPBlocked: true, ReplayBlocked: true, BlockPolicyRetained: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateAttackLabSafety(AttackLabSafetyEvidence{ProductionCredentialRejected: true, HostMountRejected: true, UndeclaredEgressRejected: true, VerdictNotVerified: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluatePolicyBypass(PolicyBypassEvidence{MalformedHTTPBlocked: true}); !errors.Is(err, errSecurityReleaseRejected) {
		t.Fatalf("partial bypass evidence error = %v", err)
	}
}

func TestSBOMIsDeterministicAndRequiresImmutableImages(t *testing.T) {
	image := ShippedImage{Reference: "registry.example/zasp/api@sha256:" + repeat("a", 64), Components: []SBOMComponent{{Name: "zlib", Version: "1.3.1", License: "Zlib"}, {Name: "app", Version: "1.5.0", License: "Proprietary"}}}
	sbom, err := GenerateSBOM([]ShippedImage{image})
	if err != nil || sbom.Format != "SPDX-2.3" || sbom.Images[0].Components[0].Name != "app" {
		t.Fatalf("GenerateSBOM() = %#v, %v", sbom, err)
	}
	image.Reference = "registry.example/zasp/api:latest"
	if _, err := GenerateSBOM([]ShippedImage{image}); !errors.Is(err, errSecurityReleaseRejected) {
		t.Fatalf("mutable image error = %v", err)
	}
}

func TestSigningAndVulnerabilityGatesRejectUnsafeRelease(t *testing.T) {
	reference := "registry.example/zasp/api@sha256:" + repeat("b", 64)
	if _, err := EvaluateImageSignatures([]ImageSignatureEvidence{{ImageReference: reference, Signed: true, Verified: true, TamperedRejected: true, UnsignedRejected: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateVulnerabilities([]Vulnerability{{ID: "CVE-2026-0001", Severity: "critical"}}); !errors.Is(err, errSecurityReleaseRejected) {
		t.Fatalf("critical vulnerability error = %v", err)
	}
	if _, err := EvaluateVulnerabilities([]Vulnerability{{ID: "CVE-2026-0001", Severity: "critical", ExceptionApproved: true, ExceptionOwner: "security", ExceptionExpires: "2026-09-01"}}); err != nil {
		t.Fatalf("approved exception error = %v", err)
	}
}

func TestSupplyChainHIPAAAndSOC2Boundaries(t *testing.T) {
	entries := make([]SupplyChainEntry, 0, 7)
	for _, name := range []string{"nango", "neo4j", "stytch", "neon", "posthog", "openrouter", "otlp"} {
		entries = append(entries, SupplyChainEntry{Name: name, Owner: "security", Status: "approved"})
	}
	if _, err := ValidateSupplyChainInventory(entries); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateHIPAAProfile(HIPAAProfileEvidence{PostHogDisabled: true, OpenRouterDisabled: true, RemoteOTLPDisabled: true, RawContentDisabled: true, BAARequirementsRecorded: true}); err != nil {
		t.Fatal(err)
	}
	checklist := make([]SOC2EvidenceItem, 0, 6)
	for _, domain := range []string{"release", "access", "change", "backup", "incident", "vendor"} {
		checklist = append(checklist, SOC2EvidenceItem{Domain: domain, Owner: "security", Location: "s3://compliance/" + domain, Cadence: "per_release"})
	}
	if _, err := ValidateSOC2Checklist(checklist); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenStageRequiresDiscoverExposureAttackLabAndBlockedRetest(t *testing.T) {
	value := GoldenStageEvidence{InventoryDiscovered: true, SourceFresh: true, ExposureOpened: true, RedTeamEvidence: true, AttackLabVerified: true, BlockPolicyEnforced: true, RetestBlocked: true}
	if report, err := EvaluateGoldenStage(value); err != nil || !report.Ready || len(report.Checks) != 4 {
		t.Fatalf("EvaluateGoldenStage() = %#v, %v", report, err)
	}
	value.RetestBlocked = false
	if _, err := EvaluateGoldenStage(value); !errors.Is(err, errSecurityReleaseRejected) {
		t.Fatalf("retest error = %v", err)
	}
}

func repeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
