// Edition-qualified reference data. Legacy References and ControlByKey retain
// the display names and meanings used by historical compliance exports.
package compliancemap

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

const (
	AgenticFramework    = "owasp_agentic_top10"
	LLMFramework        = "owasp_llm_top10"
	ATLASFramework      = "mitre_atlas"
	EnterpriseFramework = "mitre_attack_enterprise"
	ATLASEdition        = "2026.10"
	EnterpriseEdition   = "19.1"
)

// CatalogEntry describes a published reference and Zasp's scope review.
// Applicability is independent of receipts in any particular environment.
type CatalogEntry struct {
	Framework     string `json:"framework"`
	Edition       string `json:"edition"`
	UpstreamID    string `json:"upstream_id"`
	Title         string `json:"title"`
	Kind          string `json:"kind"`
	ParentID      string `json:"parent_id,omitempty"`
	Owner         string `json:"owner"`
	Applicability string `json:"applicability"`
	Scope         string `json:"scope"`
	Rationale     string `json:"rationale"`
	SourceURL     string `json:"source_url"`
	SourceDigest  string `json:"source_digest"`
	DigestBasis   string `json:"digest_basis"`
	License       string `json:"license"`
	Attribution   string `json:"attribution"`
	Status        string `json:"status"`
}

// RuleMapping is a source- and version-specific interpretation. A positive
// mapping describes why a receipt is relevant, never an unconditional claim.
type RuleMapping struct {
	Framework    string `json:"framework"`
	Edition      string `json:"edition"`
	UpstreamID   string `json:"upstream_id"`
	Rule         string `json:"rule"`
	RuleVersion  string `json:"rule_version"`
	Disposition  string `json:"disposition"`
	EvidenceKind string `json:"evidence_kind"`
	Rationale    string `json:"rationale"`
	Scope        string `json:"scope"`
}

//go:embed data/*.json
var snapshots embed.FS

type catalogRelease struct {
	Framework    string `json:"framework"`
	Edition      string `json:"edition"`
	SourceURL    string `json:"source_url"`
	SourceDigest string `json:"source_digest"`
	DigestBasis  string `json:"digest_basis"`
	License      string `json:"license"`
	Attribution  string `json:"attribution"`
	Entries      []struct {
		ID     string `json:"id"`
		Title  string `json:"title"`
		Kind   string `json:"kind"`
		Parent string `json:"parent,omitempty"`
		Status string `json:"status,omitempty"`
	} `json:"entries"`
}

type editionKey struct{ framework, edition, id string }

var editionRows, editionLookup = readSnapshots()

func readSnapshots() ([]CatalogEntry, map[editionKey]CatalogEntry) {
	files, err := snapshots.ReadDir("data")
	if err != nil {
		panic(err)
	}
	var rows []CatalogEntry
	index := make(map[editionKey]CatalogEntry)
	for _, file := range files {
		data, err := snapshots.ReadFile("data/" + file.Name())
		if err != nil {
			panic(err)
		}
		var r catalogRelease
		if err := json.Unmarshal(data, &r); err != nil {
			panic(fmt.Sprintf("read framework snapshot %s: %v", file.Name(), err))
		}
		for _, item := range r.Entries {
			status := item.Status
			if status == "" {
				status = "active"
			}
			entry := CatalogEntry{Framework: r.Framework, Edition: r.Edition, UpstreamID: item.ID, Title: item.Title, Kind: item.Kind, ParentID: item.Parent, SourceURL: r.SourceURL, SourceDigest: r.SourceDigest, DigestBasis: r.DigestBasis, License: r.License, Attribution: r.Attribution, Status: status}
			entry.Owner, entry.Applicability, entry.Scope, entry.Rationale = scopeReview(entry)
			key := editionKey{entry.Framework, entry.Edition, entry.UpstreamID}
			if _, duplicate := index[key]; duplicate {
				panic("duplicate framework identity: " + item.ID)
			}
			index[key] = entry
			rows = append(rows, entry)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Framework != b.Framework {
			return a.Framework < b.Framework
		}
		if a.Edition != b.Edition {
			return a.Edition < b.Edition
		}
		return a.UpstreamID < b.UpstreamID
	})
	return rows, index
}

// EditionCatalog lists the full reviewed denominator, including tombstones,
// ordered by framework, edition and upstream ID. Callers own the result.
func EditionCatalog() []CatalogEntry { return slices.Clone(editionRows) }

// LookupEdition accepts an exact published identity. No fallback to the
// latest edition is possible for identifiers reused in different years.
func LookupEdition(framework, edition, upstreamID string) (CatalogEntry, bool) {
	entry, ok := editionLookup[editionKey{framework, edition, upstreamID}]
	return entry, ok
}
