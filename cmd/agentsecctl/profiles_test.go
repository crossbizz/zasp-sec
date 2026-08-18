package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGoldenAuditUsabilityAndPartnerValueGates(t *testing.T) {
	stages := GoldenStageEvidence{InventoryDiscovered: true, SourceFresh: true, ExposureOpened: true, RedTeamEvidence: true, AttackLabVerified: true, BlockPolicyEnforced: true, RetestBlocked: true}
	golden := GoldenAuditEvidence{Stages: stages, SessionTimeline: "s3://release/session", AuditRecord: "s3://release/audit", ComplianceRecord: "s3://release/compliance"}
	if _, err := EvaluateGoldenE2E(golden); err != nil {
		t.Fatal(err)
	}
	usability := InstallUsabilityEvidence{DocumentedTargetReady: true, InstallWithin: 12 * time.Minute, ExactProductMessages: true, FailureDiagnosed: true, DiagnosticsRedacted: true, NextActionUnderstood: true, OwnedRemediations: true}
	if _, err := EvaluateInstallUsability(usability); err != nil {
		t.Fatal(err)
	}
	partners := []PartnerOutcome{{PartnerID: "partner-a", PrioritizationChanged: true, EvidenceReference: "s3://value/a"}, {PartnerID: "partner-b", RemediationChanged: true, EvidenceReference: "s3://value/b"}}
	if _, err := EvaluateDesignPartnerValue(partners); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateDesignPartnerValue(partners[:1]); !errors.Is(err, errProfileRejected) {
		t.Fatalf("one-partner error = %v", err)
	}
}

func TestDeploymentProfilesPreserveImagesAndConstrainTopology(t *testing.T) {
	images := []string{"registry.example/zasp/api@sha256:" + repeat("a", 64)}
	profiles := []DeploymentProfile{
		{Mode: "saas", MultiTenant: true, ProductImages: images, ControlPlane: true},
		{Mode: "single_tenant", OrganizationID: "org-a", CustomerRecovery: true, ProductImages: images, ControlPlane: true},
		{Mode: "customer_edge", OrganizationID: "org-a", WorkspaceID: "workspace-a", EnvironmentID: "environment-a", ProductImages: images, Sensor: true, RuntimeGateway: true, PolicyCacheBytes: 64 << 20, EnrollmentSecretRef: "edge-enrollment"},
	}
	for _, profile := range profiles {
		if _, err := ValidateDeploymentProfile(profile); err != nil {
			t.Fatalf("ValidateDeploymentProfile(%s) error = %v", profile.Mode, err)
		}
	}
	profiles[2].ControlPlane = true
	if _, err := ValidateDeploymentProfile(profiles[2]); !errors.Is(err, errProfileRejected) {
		t.Fatalf("edge control-plane error = %v", err)
	}
}

func TestQuotaFixtureBoundsNoisyOrganizationAndProtectsNeighbor(t *testing.T) {
	runtime := &fakeQuotaRuntime{result: QuotaResult{RunID: "quota-run-1", Completed: true, NoisyBounded: true, NormalP95: 500 * time.Millisecond}}
	result, err := RunQuotaFixture(context.Background(), QuotaFixture{OrganizationA: "org-noisy", OrganizationB: "org-normal", NoisyRate: 5000, NormalRate: 100, Duration: 5 * time.Minute}, runtime)
	if err != nil || result.RunID != "quota-run-1" {
		t.Fatalf("RunQuotaFixture() = %#v, %v", result, err)
	}
	runtime.result.NormalP95 = 751 * time.Millisecond
	if _, err := RunQuotaFixture(context.Background(), QuotaFixture{OrganizationA: "org-noisy", OrganizationB: "org-normal", NoisyRate: 5000, NormalRate: 100, Duration: 5 * time.Minute}, runtime); !errors.Is(err, errProfileRejected) {
		t.Fatalf("slow neighbor error = %v", err)
	}
}

func TestIsolationSuiteRequiresEveryBoundaryAndNoLeaks(t *testing.T) {
	suite := IsolationSuite{OrganizationA: "org-a", OrganizationB: "org-b", Boundaries: []string{"api", "neon", "graph", "opensearch", "s3", "queue"}, Expected: map[string]string{"api": "deny_no_data", "neon": "deny_no_data", "graph": "deny_no_data", "opensearch": "deny_no_data", "s3": "deny_no_data", "queue": "deny_no_data"}}
	if err := ValidateIsolationSuite(suite); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeIsolationRuntime{result: IsolationResult{RunID: "isolation-run-1", Completed: true, AllDenied: true, NoDataLeaks: true}}
	if _, err := RunIsolationSuite(context.Background(), suite, runtime); err != nil {
		t.Fatal(err)
	}
	suite.Expected["queue"] = "allow"
	if err := ValidateIsolationSuite(suite); !errors.Is(err, errProfileRejected) {
		t.Fatalf("queue expectation error = %v", err)
	}
}

func TestSaaSGoldenFixtureUsesScopedTestIdentityAndOwnedResources(t *testing.T) {
	fixture := SaaSGoldenFixture{OrganizationID: "org-a", EnvironmentID: "env-a", CredentialClass: "test_write", ResourcesOwned: true, ExpectedFirstStage: "connection"}
	id, err := RunSaaSGoldenFixture(context.Background(), fixture, fakeSaaSGoldenRuntime{})
	if err != nil || id != "golden-run-1" {
		t.Fatalf("RunSaaSGoldenFixture() = %q, %v", id, err)
	}
	fixture.CredentialClass = "production_write"
	if _, err := RunSaaSGoldenFixture(context.Background(), fixture, fakeSaaSGoldenRuntime{}); !errors.Is(err, errProfileRejected) {
		t.Fatalf("production credential error = %v", err)
	}
}

type fakeQuotaRuntime struct{ result QuotaResult }

func (*fakeQuotaRuntime) StartQuota(context.Context, QuotaFixture) (string, error) {
	return "quota-run-1", nil
}
func (runtime *fakeQuotaRuntime) InspectQuota(context.Context, string) (QuotaResult, error) {
	return runtime.result, nil
}

type fakeIsolationRuntime struct{ result IsolationResult }

func (*fakeIsolationRuntime) StartIsolation(context.Context, IsolationSuite) (string, error) {
	return "isolation-run-1", nil
}
func (runtime *fakeIsolationRuntime) InspectIsolation(context.Context, string) (IsolationResult, error) {
	return runtime.result, nil
}

type fakeSaaSGoldenRuntime struct{}

func (fakeSaaSGoldenRuntime) StartSaaSGolden(context.Context, SaaSGoldenFixture) (string, string, error) {
	return "golden-run-1", "connection", nil
}
