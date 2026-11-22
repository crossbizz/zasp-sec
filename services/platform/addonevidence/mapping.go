// Package addonevidence projects reviewed static scanner mappings for offline
// reports and authorized exact-version reads from the same release catalog.
package addonevidence

import "github.com/zasp-ai/zasp-sec/services/platform/compliancemap"

type Reference struct {
	RuleID       string `json:"rule_id"`
	RuleVersion  string `json:"rule_version"`
	EvidenceKind string `json:"evidence_kind"`
	Framework    string `json:"framework"`
	Edition      string `json:"edition"`
	UpstreamID   string `json:"upstream_id"`
	Title        string `json:"title"`
}

func References(rule, version string) []Reference {
	var refs []Reference
	for _, m := range compliancemap.ScopedRuleMappings(rule, version) {
		if m.EvidenceKind != "static_scan" {
			continue
		}
		entry, ok := compliancemap.LookupEdition(m.Framework, m.Edition, m.UpstreamID)
		if !ok {
			continue
		}
		refs = append(refs, Reference{m.Rule, m.RuleVersion, m.EvidenceKind, m.Framework, m.Edition, m.UpstreamID, entry.Title})
	}
	return refs
}
