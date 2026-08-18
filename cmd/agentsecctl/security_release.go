package main

import (
	"errors"
	"sort"
	"strings"
	"time"
)

var errSecurityReleaseRejected = errors.New("security release evidence rejected")

type TenantBoundaryEvidence struct {
	Name           string
	ReadDenied     bool
	MutationDenied bool
	NoForeignData  bool
	GuardRecorded  bool
	ScopedFilter   bool
	NoURLOrBody    bool
}

type SecurityGateReport struct {
	Ready  bool             `json:"ready"`
	Checks []PreflightCheck `json:"checks"`
}

func EvaluateTenantIsolation(values []TenantBoundaryEvidence) (SecurityGateReport, error) {
	expected := []string{"api", "graph", "opensearch", "s3"}
	if len(values) != len(expected) {
		return SecurityGateReport{}, errSecurityReleaseRejected
	}
	byName := make(map[string]TenantBoundaryEvidence, len(values))
	for _, value := range values {
		if !contains(expected, value.Name) {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		if _, duplicate := byName[value.Name]; duplicate {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		byName[value.Name] = value
	}
	checks := make([]PreflightCheck, 0, len(expected))
	for _, name := range expected {
		value := byName[name]
		passed := value.ReadDenied && value.NoForeignData && value.GuardRecorded
		switch name {
		case "api":
			passed = passed && value.MutationDenied
		case "opensearch":
			passed = passed && value.ScopedFilter
		case "s3":
			passed = passed && value.NoURLOrBody
		}
		checks = append(checks, check(name, passed, true, "deny every cross-Organization and cross-Workspace access server-side"))
	}
	return requireSecurityChecks(checks)
}

type SSRFEvidence struct {
	OverrideRejected bool
	NoRequestSent    bool
	AuditRecorded    bool
}

func EvaluateConnectorSSRF(value SSRFEvidence) (SecurityGateReport, error) {
	return requireSecurityChecks([]PreflightCheck{check("connector_ssrf", value.OverrideRejected && value.NoRequestSent && value.AuditRecorded, true, "reject arbitrary connector/proxy/provider destinations before egress")})
}

type LeakageSinkEvidence struct {
	Name                 string
	SeededValueAbsent    bool
	SensitiveFieldsGone  bool
	RejectedBeforeEgress bool
}

func EvaluateSecretLeakage(values []LeakageSinkEvidence) (SecurityGateReport, error) {
	expected := []string{"logs", "posthog", "ai", "otlp", "support_bundle", "evidence_store"}
	if len(values) != len(expected) {
		return SecurityGateReport{}, errSecurityReleaseRejected
	}
	byName := make(map[string]LeakageSinkEvidence, len(values))
	for _, value := range values {
		if !contains(expected, value.Name) {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		if _, duplicate := byName[value.Name]; duplicate {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		byName[value.Name] = value
	}
	checks := make([]PreflightCheck, 0, len(expected))
	for _, name := range expected {
		value := byName[name]
		passed := value.SeededValueAbsent && value.SensitiveFieldsGone
		if name == "posthog" {
			passed = passed && value.RejectedBeforeEgress
		}
		checks = append(checks, check(name, passed, true, "remove seeded secrets and prohibited security content before egress or storage"))
	}
	return requireSecurityChecks(checks)
}

type PolicyBypassEvidence struct {
	MalformedHTTPBlocked bool
	MalformedMCPBlocked  bool
	ReplayBlocked        bool
	BlockPolicyRetained  bool
}

func EvaluatePolicyBypass(value PolicyBypassEvidence) (SecurityGateReport, error) {
	return requireSecurityChecks([]PreflightCheck{check("runtime_policy_bypass", value.MalformedHTTPBlocked && value.MalformedMCPBlocked && value.ReplayBlocked && value.BlockPolicyRetained, true, "reject malformed context and replay while retaining the signed Block decision")})
}

type AttackLabSafetyEvidence struct {
	ProductionCredentialRejected bool
	HostMountRejected            bool
	UndeclaredEgressRejected     bool
	VerdictNotVerified           bool
}

func EvaluateAttackLabSafety(value AttackLabSafetyEvidence) (SecurityGateReport, error) {
	return requireSecurityChecks([]PreflightCheck{check("attack_lab_safety", value.ProductionCredentialRejected && value.HostMountRejected && value.UndeclaredEgressRejected && value.VerdictNotVerified, true, "reject production-write identity, host mounts, and undeclared egress without a Verified verdict")})
}

type SBOMComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type ShippedImage struct {
	Reference  string          `json:"reference"`
	Components []SBOMComponent `json:"components"`
}

type SBOM struct {
	Format string         `json:"format"`
	Images []ShippedImage `json:"images"`
}

func GenerateSBOM(images []ShippedImage) (SBOM, error) {
	if len(images) == 0 || len(images) > 32 {
		return SBOM{}, errSecurityReleaseRejected
	}
	result := SBOM{Format: "SPDX-2.3", Images: make([]ShippedImage, len(images))}
	seen := map[string]bool{}
	for index, image := range images {
		if !immutableImageReference(image.Reference) || seen[image.Reference] || len(image.Components) == 0 || len(image.Components) > 10_000 {
			return SBOM{}, errSecurityReleaseRejected
		}
		seen[image.Reference] = true
		result.Images[index] = ShippedImage{Reference: image.Reference, Components: append([]SBOMComponent(nil), image.Components...)}
		for _, component := range image.Components {
			if !validIdentifier(component.Name) || !validBuildVersion(component.Version) || len(component.License) < 2 || len(component.License) > 128 {
				return SBOM{}, errSecurityReleaseRejected
			}
		}
		sort.Slice(result.Images[index].Components, func(left, right int) bool {
			return result.Images[index].Components[left].Name < result.Images[index].Components[right].Name
		})
	}
	sort.Slice(result.Images, func(left, right int) bool { return result.Images[left].Reference < result.Images[right].Reference })
	return result, nil
}

type ImageSignatureEvidence struct {
	ImageReference   string
	Signed           bool
	Verified         bool
	TamperedRejected bool
	UnsignedRejected bool
}

func EvaluateImageSignatures(values []ImageSignatureEvidence) (SecurityGateReport, error) {
	if len(values) == 0 || len(values) > 32 {
		return SecurityGateReport{}, errSecurityReleaseRejected
	}
	checks := make([]PreflightCheck, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if !immutableImageReference(value.ImageReference) || seen[value.ImageReference] {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		seen[value.ImageReference] = true
		checks = append(checks, check(value.ImageReference, value.Signed && value.Verified && value.TamperedRejected && value.UnsignedRejected, true, "sign and verify the immutable release image; reject tampered and unsigned variants"))
	}
	return requireSecurityChecks(checks)
}

type Vulnerability struct {
	ID                string
	Severity          string
	ExceptionApproved bool
	ExceptionOwner    string
	ExceptionExpires  string
}

func EvaluateVulnerabilities(values []Vulnerability) (SecurityGateReport, error) {
	checks := make([]PreflightCheck, 0, len(values))
	for _, value := range values {
		if !validIdentifier(value.ID) || !contains([]string{"low", "medium", "high", "critical"}, value.Severity) {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		_, expiryErr := time.Parse("2006-01-02", value.ExceptionExpires)
		accepted := value.Severity != "critical" || value.ExceptionApproved && validIdentifier(value.ExceptionOwner) && expiryErr == nil
		checks = append(checks, check(value.ID, accepted, true, "remediate the critical finding or attach an approved owner and expiry"))
	}
	return requireSecurityChecks(checks)
}

type SupplyChainEntry struct {
	Name   string
	Owner  string
	Status string
}

func ValidateSupplyChainInventory(values []SupplyChainEntry) (SecurityGateReport, error) {
	expected := []string{"nango", "neo4j", "stytch", "neon", "posthog", "openrouter", "otlp"}
	if len(values) != len(expected) {
		return SecurityGateReport{}, errSecurityReleaseRejected
	}
	byName := map[string]SupplyChainEntry{}
	for _, value := range values {
		if !contains(expected, value.Name) || !validIdentifier(value.Owner) || !contains([]string{"approved", "conditional", "disabled"}, value.Status) {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		if _, duplicate := byName[value.Name]; duplicate {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		byName[value.Name] = value
	}
	checks := make([]PreflightCheck, 0, len(expected))
	for _, name := range expected {
		_, present := byName[name]
		checks = append(checks, check(name, present, true, "assign a reviewed owner and deployment status"))
	}
	return requireSecurityChecks(checks)
}

type HIPAAProfileEvidence struct {
	PostHogDisabled         bool
	OpenRouterDisabled      bool
	RemoteOTLPDisabled      bool
	RawContentDisabled      bool
	BAARequirementsRecorded bool
}

func EvaluateHIPAAProfile(value HIPAAProfileEvidence) (SecurityGateReport, error) {
	return requireSecurityChecks([]PreflightCheck{check("hipaa_profile", value.PostHogDisabled && value.OpenRouterDisabled && value.RemoteOTLPDisabled && value.RawContentDisabled && value.BAARequirementsRecorded, true, "keep optional egress and raw content disabled until explicitly approved with required agreements")})
}

type SOC2EvidenceItem struct {
	Domain   string
	Owner    string
	Location string
	Cadence  string
}

func ValidateSOC2Checklist(values []SOC2EvidenceItem) (SecurityGateReport, error) {
	expected := []string{"release", "access", "change", "backup", "incident", "vendor"}
	if len(values) != len(expected) {
		return SecurityGateReport{}, errSecurityReleaseRejected
	}
	checks := make([]PreflightCheck, 0, len(expected))
	seen := map[string]bool{}
	for _, value := range values {
		if !contains(expected, value.Domain) || seen[value.Domain] || !validIdentifier(value.Owner) || !validReference(value.Location) || !contains([]string{"per_release", "monthly", "quarterly", "annual"}, value.Cadence) {
			return SecurityGateReport{}, errSecurityReleaseRejected
		}
		seen[value.Domain] = true
		checks = append(checks, check(value.Domain, true, true, "retain control owner, evidence location, and cadence without claiming audit completion"))
	}
	return requireSecurityChecks(checks)
}

type GoldenStageEvidence struct {
	InventoryDiscovered bool
	SourceFresh         bool
	ExposureOpened      bool
	RedTeamEvidence     bool
	AttackLabVerified   bool
	BlockPolicyEnforced bool
	RetestBlocked       bool
}

func EvaluateGoldenStage(value GoldenStageEvidence) (SecurityGateReport, error) {
	checks := []PreflightCheck{
		check("deploy_discover", value.InventoryDiscovered && value.SourceFresh, true, "complete install, connection, sensor, and fresh inventory discovery"),
		check("exposure_test", value.ExposureOpened && value.RedTeamEvidence, true, "retain the credible path and high-impact attempt evidence"),
		check("attack_lab", value.AttackLabVerified, true, "verify the canary-only Fargate attempt"),
		check("policy_retest", value.BlockPolicyEnforced && value.RetestBlocked, true, "simulate and enforce Block, then observe the supported retest blocked"),
	}
	return requireSecurityChecks(checks)
}

func requireSecurityChecks(checks []PreflightCheck) (SecurityGateReport, error) {
	if len(checks) == 0 {
		return SecurityGateReport{}, errSecurityReleaseRejected
	}
	report := SecurityGateReport{Ready: true, Checks: checks}
	for _, item := range checks {
		if item.Status != checkPass {
			report.Ready = false
		}
	}
	if !report.Ready {
		return report, errSecurityReleaseRejected
	}
	return report, nil
}

func immutableImageReference(value string) bool {
	parts := strings.Split(value, "@sha256:")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[1]) != 64 {
		return false
	}
	for _, character := range parts[1] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return !strings.ContainsAny(parts[0], "\r\n\x00 ")
}
