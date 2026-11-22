package compliancemap

import "time"

// These fields are frozen at export admission. Renderers read the captured
// edition and its evidence without consulting the currently shipped catalog.
type ReportEdition struct {
	Framework string `json:"framework"`
	Edition   string `json:"edition"`
	Total     int    `json:"total_controls"`
	Digest    string `json:"source_digest"`
}
type ReportRow struct {
	Control  CatalogEntry   `json:"control"`
	Counts   map[string]int `json:"evidence_counts"`
	Verified *time.Time     `json:"last_verified_at"`
	// Captured when a report is exported; live callers use last_verified_at and collected_at.
	VerificationStatus string `json:"verification_status,omitempty"`
}

// VerificationFreshness classifies a paired proof using the end of its verified
// observation window. A new import or a later render does not renew that proof.
func VerificationFreshness(verified *time.Time, collected time.Time) string {
	if verified == nil || verified.IsZero() || collected.IsZero() || verified.After(collected) {
		return "unknown"
	}
	if verified.Before(collected.Add(-30 * 24 * time.Hour)) {
		return "stale"
	}
	return "current"
}

type ReportSummary struct {
	Applicable    int `json:"applicable_controls"`
	Verified      int `json:"verified_applicable_controls"`
	Unassessed    int `json:"unassessed_controls"`
	Outside       int `json:"out_of_scope_controls"`
	Risks         int `json:"risks"`
	Techniques    int `json:"techniques"`
	Subtechniques int `json:"subtechniques"`
	Mitigations   int `json:"mitigations"`
}
type ReportPage struct {
	ReportEdition
	Matched   int           `json:"matched_controls"`
	Summary   ReportSummary `json:"summary"`
	Collected time.Time     `json:"collected_at"`
	Items     []ReportRow   `json:"items"`
	Next      *string       `json:"next_after"`
}
type ReportEvidence struct {
	ManifestDigest string    `json:"manifest_digest,omitempty"`
	Source         string    `json:"source_kind"`
	ID             string    `json:"source_id"`
	Rule           string    `json:"rule"`
	Version        string    `json:"rule_version"`
	Kind           string    `json:"evidence_kind"`
	At             time.Time `json:"occurred_at"`
	Framework      string    `json:"framework"`
	Edition        string    `json:"edition"`
	Upstream       string    `json:"upstream_id"`
	Session        string    `json:"session_id,omitempty"`
}

type ReportSelector struct {
	Framework    string `json:"framework"`
	Edition      string `json:"edition"`
	Upstream     string `json:"upstream_id,omitempty"`
	EvidenceKind string `json:"evidence_kind,omitempty"`
}
type FrozenReport struct {
	Schema       string           `json:"schema_version"`
	Organization string           `json:"organization_id"`
	Workspace    string           `json:"workspace_id"`
	Environment  string           `json:"environment_id"`
	Selector     ReportSelector   `json:"selector"`
	Coverage     ReportPage       `json:"coverage"`
	Evidence     []ReportEvidence `json:"evidence"`
}
