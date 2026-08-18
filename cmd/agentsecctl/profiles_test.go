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

func TestGoldenResultsRequireExactWorkflowAndProfileParity(t *testing.T) {
	stages := []string{"bootstrap", "sso", "connectors", "edge", "discover", "path", "test", "verify", "plan", "authorize", "contain", "cleanup", "retest", "audit"}
	saas := GoldenProfileResult{RunID: "golden-run-1", Completed: true, Stages: stages, APIShape: "golden-v1", DeploymentMetadata: "saas", SessionLinked: true, AuditLinked: true}
	inspector := fakeGoldenInspector{result: saas}
	if _, err := InspectSaaSGoldenResult(context.Background(), "golden-run-1", inspector); err != nil {
		t.Fatal(err)
	}
	singleRuntime := &fakeSingleTenantGoldenRuntime{result: GoldenProfileResult{RunID: "single-run-1", Completed: true, Stages: stages, APIShape: "golden-v1", DeploymentMetadata: "single_tenant", SessionLinked: true, AuditLinked: true}}
	id, err := StartSingleTenantGolden(context.Background(), SingleTenantGoldenFixture{OrganizationID: "org-a", Contract: "golden-v1"}, singleRuntime)
	if err != nil || id != "single-run-1" {
		t.Fatalf("StartSingleTenantGolden() = %q, %v", id, err)
	}
	if _, err := InspectSingleTenantGolden(context.Background(), id, "golden-v1", singleRuntime); err != nil {
		t.Fatal(err)
	}
}

func TestSaaSOnboardingRequiresAllProductOwnedStages(t *testing.T) {
	stages := []OnboardingObservation{
		{Stage: "first_admin", Completed: true, Duration: 10 * time.Minute, ProductInstructionsOnly: true, ActionableRemediation: true, NoBypassOrManualEdit: true},
		{Stage: "aws", Completed: true, Duration: 11 * time.Minute, ProductInstructionsOnly: true, ActionableRemediation: true, MissingPermissionActionable: true},
		{Stage: "kubernetes", Completed: true, Duration: 12 * time.Minute, ProductInstructionsOnly: true, ActionableRemediation: true, CoverageClear: true},
		{Stage: "github", Completed: true, Duration: 9 * time.Minute, ProductInstructionsOnly: true, ActionableRemediation: true, ScopeClear: true},
		{Stage: "launch_idp", Completed: true, Duration: 8 * time.Minute, ProductInstructionsOnly: true, ActionableRemediation: true, IdentityDistinctionClear: true},
	}
	if _, err := EvaluateSaaSOnboarding(stages); err != nil {
		t.Fatal(err)
	}
	stages[2].VendorDashboardUsed = true
	if _, err := EvaluateSaaSOnboarding(stages); !errors.Is(err, errProfileRejected) {
		t.Fatalf("vendor dashboard error = %v", err)
	}
}

func TestSaaSRecoveryStagesAndReleaseGate(t *testing.T) {
	fixture := SaaSRecoveryFixture{FixtureID: "dr-fixture-1", OrganizationIDs: []string{"org-a", "org-b"}, SourceTimestamp: "2026-08-18T00:00:00Z", NeonRecoveryPoint: "s3://recovery/neon", EvidenceArchive: "s3://recovery/evidence", EventArchive: "s3://recovery/events", VersionedRelease: "release-v1", CredentialClass: "test_recovery"}
	if err := ValidateSaaSRecoveryFixture(fixture); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRecoveryRuntime{}
	runID, err := StartSaaSRecovery(context.Background(), fixture, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSaaSCoreRecovery(context.Background(), runID, fixture.OrganizationIDs, runtime); err != nil {
		t.Fatal(err)
	}
	runtime.core = RecoveryCoreResult{RunID: runID, OrganizationIDs: []string{"org-a", "org-a"}, ScopedRecordsPresent: true, ArchivesPresent: true, NoCrossOrganizationMix: true}
	if _, err := InspectSaaSCoreRecovery(context.Background(), runID, fixture.OrganizationIDs, runtime); !errors.Is(err, errProfileRejected) {
		t.Fatalf("duplicate recovered scope error = %v", err)
	}
	runtime.core = RecoveryCoreResult{}
	jobs, err := StartSaaSDerivedRebuild(context.Background(), runID, runtime)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("StartSaaSDerivedRebuild() = %v, %v", jobs, err)
	}
	objectives, err := EvaluateSaaSRecoveryObjectives(RecoveryObjectiveEvidence{RunID: runID, RPO: 30 * time.Minute, RTO: 3 * time.Hour, CoreUsable: true, RepresentativeQueriesUsable: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateSaaSDRGate(SaaSDRGateEvidence{Objectives: objectives, TenantIsolated: true, ProductUIAPIUsable: true, HiddenVendorSteps: false, Cleaned: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateM8ReleaseGate(M8ReleaseEvidence{RequiredGateCount: 7, PassedGateCount: 7, ExceptionCount: 0, UnresolvedBlockers: []string{"human_onboarding_not_run"}}); !errors.Is(err, errProfileRejected) {
		t.Fatalf("hidden blocker error = %v", err)
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

type fakeGoldenInspector struct{ result GoldenProfileResult }

func (runtime fakeGoldenInspector) InspectGolden(context.Context, string) (GoldenProfileResult, error) {
	return runtime.result, nil
}

type fakeSingleTenantGoldenRuntime struct{ result GoldenProfileResult }

func (*fakeSingleTenantGoldenRuntime) StartSingleTenant(context.Context, SingleTenantGoldenFixture) (string, error) {
	return "single-run-1", nil
}
func (runtime *fakeSingleTenantGoldenRuntime) InspectGolden(context.Context, string) (GoldenProfileResult, error) {
	return runtime.result, nil
}

type fakeRecoveryRuntime struct{ core RecoveryCoreResult }

func (*fakeRecoveryRuntime) StartRecovery(context.Context, SaaSRecoveryFixture) (string, string, error) {
	return "recovery-run-1", "2026-08-18T00:00:00Z", nil
}

func (runtime *fakeRecoveryRuntime) InspectCore(context.Context, string) (RecoveryCoreResult, error) {
	if runtime.core.RunID != "" {
		return runtime.core, nil
	}
	return RecoveryCoreResult{RunID: "recovery-run-1", OrganizationIDs: []string{"org-a", "org-b"}, ScopedRecordsPresent: true, ArchivesPresent: true, NoCrossOrganizationMix: true}, nil
}
func (*fakeRecoveryRuntime) StartDerivedRebuild(context.Context, string) ([]RebuildJob, error) {
	return []RebuildJob{{Kind: "opensearch", RunID: "search-rebuild-1"}, {Kind: "graph", RunID: "graph-rebuild-1"}}, nil
}
