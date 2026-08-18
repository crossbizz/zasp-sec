package main

import (
	"context"
	"errors"
	"time"
)

var errProfileRejected = errors.New("deployment profile evidence rejected")

type GoldenAuditEvidence struct {
	Stages           GoldenStageEvidence
	SessionTimeline  string
	AuditRecord      string
	ComplianceRecord string
}

func EvaluateGoldenE2E(value GoldenAuditEvidence) (SecurityGateReport, error) {
	if _, err := EvaluateGoldenStage(value.Stages); err != nil || !validReference(value.SessionTimeline) || !validReference(value.AuditRecord) || !validReference(value.ComplianceRecord) {
		return SecurityGateReport{}, errProfileRejected
	}
	return requireSecurityChecks([]PreflightCheck{
		check("golden_stages", true, true, "retain every previously completed stage without rerunning it"),
		check("investigate_audit", true, true, "link session timeline, audit, and compliance evidence"),
	})
}

type InstallUsabilityEvidence struct {
	DocumentedTargetReady bool
	UndocumentedSteps     int
	InstallWithin         time.Duration
	Blockers              []string
	ExactProductMessages  bool
	FailureDiagnosed      bool
	VendorDashboardUsed   bool
	DiagnosticsRedacted   bool
	NextActionUnderstood  bool
	OwnedRemediations     bool
}

func EvaluateInstallUsability(value InstallUsabilityEvidence) (SecurityGateReport, error) {
	passed := value.DocumentedTargetReady && value.UndocumentedSteps == 0 && value.InstallWithin > 0 && value.InstallWithin <= 15*time.Minute && len(value.Blockers) <= 32 && value.ExactProductMessages && value.FailureDiagnosed && !value.VendorDashboardUsed && value.DiagnosticsRedacted && value.NextActionUnderstood && value.OwnedRemediations
	return requireProfileCheck("single_tenant_usability", passed, "make every install blocker diagnosable and product-owned within the documented flow")
}

type PartnerOutcome struct {
	PartnerID             string
	PrioritizationChanged bool
	RemediationChanged    bool
	EvidenceReference     string
}

func EvaluateDesignPartnerValue(values []PartnerOutcome) (SecurityGateReport, error) {
	seen := map[string]bool{}
	changed := 0
	for _, value := range values {
		if !validIdentifier(value.PartnerID) || seen[value.PartnerID] || !validReference(value.EvidenceReference) {
			return SecurityGateReport{}, errProfileRejected
		}
		seen[value.PartnerID] = true
		if value.PrioritizationChanged || value.RemediationChanged {
			changed++
		}
	}
	return requireProfileCheck("design_partner_value", changed >= 2, "do not expand scope until two design partners change prioritization or remediation from verified evidence")
}

type DeploymentProfile struct {
	Mode                string
	OrganizationID      string
	MultiTenant         bool
	CustomerRecovery    bool
	ProductImages       []string
	ControlPlane        bool
	Sensor              bool
	RuntimeGateway      bool
	PolicyCacheBytes    uint64
	EnrollmentSecretRef string
	WorkspaceID         string
	EnvironmentID       string
}

func ValidateDeploymentProfile(value DeploymentProfile) (SecurityGateReport, error) {
	passed := len(value.ProductImages) > 0
	for _, reference := range value.ProductImages {
		passed = passed && immutableImageReference(reference)
	}
	switch value.Mode {
	case "saas":
		passed = passed && value.MultiTenant && !value.CustomerRecovery && value.OrganizationID == "" && value.ControlPlane
	case "single_tenant":
		passed = passed && !value.MultiTenant && value.CustomerRecovery && validIdentifier(value.OrganizationID) && value.ControlPlane
	case "customer_edge":
		passed = passed && !value.ControlPlane && value.Sensor && value.RuntimeGateway && value.PolicyCacheBytes > 0 && value.PolicyCacheBytes <= 64<<20 && validIdentifier(value.OrganizationID) && validIdentifier(value.WorkspaceID) && validIdentifier(value.EnvironmentID) && validIdentifier(value.EnrollmentSecretRef)
	default:
		return SecurityGateReport{}, errProfileRejected
	}
	return requireProfileCheck("deployment_profile", passed, "use one immutable product release with only approved topology and scoped configuration differences")
}

type QuotaFixture struct {
	OrganizationA string
	OrganizationB string
	NoisyRate     int
	NormalRate    int
	Duration      time.Duration
}

type QuotaResult struct {
	RunID        string
	NoisyBounded bool
	NormalP95    time.Duration
	Completed    bool
}

type QuotaRuntime interface {
	StartQuota(context.Context, QuotaFixture) (string, error)
	InspectQuota(context.Context, string) (QuotaResult, error)
}

func RunQuotaFixture(ctx context.Context, fixture QuotaFixture, runtime QuotaRuntime) (QuotaResult, error) {
	id, err := StartQuotaFixture(ctx, fixture, runtime)
	if err != nil {
		return QuotaResult{}, err
	}
	return InspectQuotaResult(ctx, id, runtime)
}

func StartQuotaFixture(ctx context.Context, fixture QuotaFixture, runtime QuotaRuntime) (string, error) {
	if ctx == nil || runtime == nil || !validIdentifier(fixture.OrganizationA) || !validIdentifier(fixture.OrganizationB) || fixture.OrganizationA == fixture.OrganizationB || fixture.NoisyRate <= fixture.NormalRate || fixture.NormalRate < 1 || fixture.NoisyRate > 10_000 || fixture.Duration <= 0 || fixture.Duration > 5*time.Minute {
		return "", errProfileRejected
	}
	id, err := runtime.StartQuota(ctx, fixture)
	if err != nil || !validIdentifier(id) {
		return "", errProfileRejected
	}
	return id, nil
}

func InspectQuotaResult(ctx context.Context, id string, runtime QuotaRuntime) (QuotaResult, error) {
	if ctx == nil || runtime == nil || !validIdentifier(id) {
		return QuotaResult{}, errProfileRejected
	}
	result, err := runtime.InspectQuota(ctx, id)
	if err != nil || result.RunID != id || !result.Completed || !result.NoisyBounded || result.NormalP95 <= 0 || result.NormalP95 > 750*time.Millisecond {
		return result, errProfileRejected
	}
	return result, nil
}

type IsolationSuite struct {
	OrganizationA string
	OrganizationB string
	Boundaries    []string
	Expected      map[string]string
}

func ValidateIsolationSuite(value IsolationSuite) error {
	expected := []string{"api", "neon", "graph", "opensearch", "s3", "queue"}
	if !validIdentifier(value.OrganizationA) || !validIdentifier(value.OrganizationB) || value.OrganizationA == value.OrganizationB || len(value.Boundaries) != len(expected) || len(value.Expected) != len(expected) {
		return errProfileRejected
	}
	seen := map[string]bool{}
	for _, boundary := range value.Boundaries {
		if !contains(expected, boundary) || seen[boundary] || value.Expected[boundary] != "deny_no_data" {
			return errProfileRejected
		}
		seen[boundary] = true
	}
	return nil
}

type IsolationResult struct {
	RunID       string
	Completed   bool
	AllDenied   bool
	NoDataLeaks bool
}

type IsolationRuntime interface {
	StartIsolation(context.Context, IsolationSuite) (string, error)
	InspectIsolation(context.Context, string) (IsolationResult, error)
}

func RunIsolationSuite(ctx context.Context, suite IsolationSuite, runtime IsolationRuntime) (IsolationResult, error) {
	id, err := StartIsolationSuite(ctx, suite, runtime)
	if err != nil {
		return IsolationResult{}, err
	}
	return InspectIsolationResult(ctx, id, runtime)
}

func StartIsolationSuite(ctx context.Context, suite IsolationSuite, runtime IsolationRuntime) (string, error) {
	if ctx == nil || runtime == nil || ValidateIsolationSuite(suite) != nil {
		return "", errProfileRejected
	}
	id, err := runtime.StartIsolation(ctx, suite)
	if err != nil || !validIdentifier(id) {
		return "", errProfileRejected
	}
	return id, nil
}

func InspectIsolationResult(ctx context.Context, id string, runtime IsolationRuntime) (IsolationResult, error) {
	if ctx == nil || runtime == nil || !validIdentifier(id) {
		return IsolationResult{}, errProfileRejected
	}
	result, err := runtime.InspectIsolation(ctx, id)
	if err != nil || result.RunID != id || !result.Completed || !result.AllDenied || !result.NoDataLeaks {
		return result, errProfileRejected
	}
	return result, nil
}

type SaaSGoldenFixture struct {
	OrganizationID     string
	EnvironmentID      string
	CredentialClass    string
	ResourcesOwned     bool
	ExpectedFirstStage string
}

type SaaSGoldenRuntime interface {
	StartSaaSGolden(context.Context, SaaSGoldenFixture) (string, string, error)
}

func RunSaaSGoldenFixture(ctx context.Context, fixture SaaSGoldenFixture, runtime SaaSGoldenRuntime) (string, error) {
	if ctx == nil || runtime == nil || !validIdentifier(fixture.OrganizationID) || !validIdentifier(fixture.EnvironmentID) || fixture.CredentialClass != "test_write" || !fixture.ResourcesOwned || fixture.ExpectedFirstStage != "connection" {
		return "", errProfileRejected
	}
	id, stage, err := runtime.StartSaaSGolden(ctx, fixture)
	if err != nil || !validIdentifier(id) || stage != fixture.ExpectedFirstStage {
		return "", errProfileRejected
	}
	return id, nil
}

func requireProfileCheck(name string, passed bool, hint string) (SecurityGateReport, error) {
	report, err := requireSecurityChecks([]PreflightCheck{check(name, passed, true, hint)})
	if err != nil {
		return report, errProfileRejected
	}
	return report, nil
}
