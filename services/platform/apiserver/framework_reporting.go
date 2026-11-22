package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

const frameworkSourcesSQL = `SELECT zasp_authorization80.framework_sources($1,$2,$3,$4,$5,$6,$7)`

func init() {
	productStatementRules[frameworkSourcesSQL] = productStatementRule{operations: []string{"listComplianceCoverage", "listComplianceCoverageEvidence", "createComplianceExport"}, arguments: 7, scope: 1, actor: 4, browserOnly: true, check: func(g RequestAuthorization, args []any) bool {
		return args[4] == g.OperationID && addonEnvAllowed(g, args)
	}}
}

type coverageEdition = compliancemap.ReportEdition
type coverageRow = compliancemap.ReportRow
type coverageSummary = compliancemap.ReportSummary
type coveragePage = compliancemap.ReportPage
type coverageEvidence = compliancemap.ReportEvidence
type coverageCandidate struct {
	Source         string                     `json:"source_kind"`
	ID             string                     `json:"source_id"`
	Rule           string                     `json:"rule"`
	Version        string                     `json:"rule_version"`
	At             time.Time                  `json:"occurred_at"`
	Agent          string                     `json:"agent_id,omitempty"`
	Session        string                     `json:"session_id,omitempty"`
	Classification string                     `json:"classification,omitempty"`
	Ticket         *redteam.TicketProofBundle `json:"ticket,omitempty"`
}
type coverageFilter struct {
	framework, edition, upstream, kind, source, id, after string
	limit                                                 int
}

func availableEditions() []coverageEdition {
	result := []coverageEdition{}
	for _, entry := range compliancemap.EditionCatalog() {
		if len(result) == 0 || result[len(result)-1].Framework != entry.Framework || result[len(result)-1].Edition != entry.Edition {
			result = append(result, coverageEdition{Framework: entry.Framework, Edition: entry.Edition, Digest: entry.SourceDigest})
		}
		if entry.Status != "retired" {
			result[len(result)-1].Total++
		}
	}
	return result
}
func (f coverageFilter) selectedEdition() (coverageEdition, bool) {
	for _, row := range availableEditions() {
		if row.Framework == f.framework && row.Edition == f.edition {
			return row, true
		}
	}
	return coverageEdition{}, false
}
func validCoverageKind(v string) bool {
	return stringIn(v, "posture_finding", "static_scan", "observed_event", "tested_control", "verified_prevention")
}
func parseCoverageFilter(q url.Values, evidence bool) (coverageFilter, bool) {
	f := coverageFilter{q.Get("framework"), q.Get("edition"), q.Get("upstream_id"), q.Get("evidence_kind"), q.Get("source_kind"), q.Get("source_id"), q.Get("after"), 50}
	for k, v := range q {
		if !stringIn(k, "framework", "edition", "upstream_id", "evidence_kind", "source_kind", "source_id", "after", "limit") || len(v) != 1 || v[0] == "" || len(v[0]) > 512 {
			return f, false
		}
	}
	if v := q.Get("limit"); v != "" {
		var err error
		f.limit, err = strconv.Atoi(v)
		if err != nil || f.limit < 1 || f.limit > 100 || strconv.Itoa(f.limit) != v {
			return f, false
		}
	}
	if f.kind != "" && !validCoverageKind(f.kind) {
		return f, false
	}
	if f.source != "" || f.id != "" {
		return f, evidence && f.framework == "" && f.edition == "" && f.upstream == "" && stringIn(f.source, "finding", "addon_version", "runtime_action", "ticket_test") && validProductID(f.id)
	}
	if _, ok := f.selectedEdition(); !ok {
		return f, false
	}
	if f.upstream != "" {
		_, ok := compliancemap.LookupEdition(f.framework, f.edition, f.upstream)
		return f, ok
	}
	return f, !evidence
}
func (h *complianceHTTPHandler) frameworkReport(w http.ResponseWriter, r *http.Request, i RequestIdentity, op string) {
	if _, ok := requestAuthorizationFromContext(r.Context()); !ok {
		writeComplianceError(w, r, ErrComplianceForbidden)
		return
	}
	if op == "listComplianceEditions" {
		if r.URL.RawQuery != "" {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
		writeJSONValue(w, r, 200, map[string]any{"items": availableEditions()}, nil)
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	f, valid := parseCoverageFilter(values, op == "listComplianceCoverageEvidence")
	if err != nil || !valid {
		writeComplianceError(w, r, ErrRepositoryOperation)
		return
	}
	evidence, err := h.source.frameworkEvidence(r.Context(), i, op, f)
	if err != nil {
		writeComplianceError(w, r, err)
		return
	}
	if op == "listComplianceCoverageEvidence" {
		rows, next := evidencePage(f, evidence)
		writeJSONValue(w, r, 200, map[string]any{"items": rows, "next_after": next}, nil)
		return
	}
	writeJSONValue(w, r, 200, buildCoveragePage(f, evidence, time.Now().UTC()), nil)
}

func (r *ComplianceRepository) frameworkEvidence(ctx context.Context, i RequestIdentity, op string, f coverageFilter) ([]coverageEvidence, error) {
	grant, hasGrant := requestAuthorizationFromContext(ctx)
	if !hasGrant || grant.OperationID != op || i.CredentialKind != CredentialBrowserSession {
		return nil, ErrComplianceForbidden
	}
	raw, err := r.database.QueryJSON(ctx, frameworkSourcesSQL, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), op, f.source, f.id)
	if err != nil {
		return nil, err
	}
	var candidates []coverageCandidate
	if decodeStrictDiscovery(raw, &candidates) != nil || candidates == nil || len(candidates) > 2000 {
		return nil, ErrRepositoryUnavailable
	}
	// A direct source lookup must be readable under its own product operation.
	// Reuse grants for identical source targets only within this request/revision.
	checked := map[string]bool{}
	digests := map[string]string{}
	allow := func(operation, id string) (bool, error) {
		key := operation + "/" + id
		if v, ok := checked[key]; ok {
			return v, nil
		}
		g, err := secondaryRequestAuthorization(ctx, i, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": id}})
		if errors.Is(err, ErrAuthorizationDenied) || errors.Is(err, ErrRepositoryNotFound) {
			checked[key] = false
			return false, nil
		}
		if err != nil || g.Revision != grant.Revision {
			return false, ErrRepositoryUnavailable
		}
		if operation == "getAddonVersion" {
			child := context.WithValue(ctx, requestAuthorizationContextKey{}, g)
			raw, err := r.database.QueryJSON(child, addonVersionSQL, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), id)
			if err != nil {
				return false, err
			}
			var version struct {
				ID     string `json:"id"`
				Digest string `json:"manifest_digest"`
			}
			if json.Unmarshal(raw, &version) != nil || version.ID != id || !addonDigest.MatchString(version.Digest) {
				return false, ErrRepositoryUnavailable
			}
			digests[id] = version.Digest
		}
		checked[key] = true
		return true, nil
	}
	result := []coverageEvidence{}
	for _, c := range candidates {
		if !validProductID(c.ID) || c.At.IsZero() {
			return nil, ErrRepositoryUnavailable
		}
		var sourceOp, ruleKind, sourceID string
		sourceID = c.ID
		switch c.Source {
		case "finding":
			sourceOp, ruleKind = "getFinding", "posture_finding"
		case "addon_version":
			sourceOp, ruleKind = "getAddonVersion", "static_scan"
		case "runtime_action":
			sourceOp, ruleKind, sourceID = "getAgentActionAnalysis", "observed_event", c.Agent
			if !validProductID(c.Agent) || !validProductID(c.Session) {
				return nil, ErrRepositoryUnavailable
			}
		case "ticket_test":
			sourceOp, ruleKind = "getTicketVerification", "tested_control"
		default:
			return nil, ErrRepositoryUnavailable
		}
		mappings := compliancemap.ScopedRuleMappings(c.Rule, c.Version)
		if c.Source == "runtime_action" && c.Version == "zasp.sqlite-context.v1" {
			mappings = compliancemap.ScopedContextRuleMappings(c.Rule, c.Version, c.Classification)
		}
		if len(mappings) == 0 {
			continue
		}
		visible, err := allow(sourceOp, sourceID)
		if err != nil {
			return nil, err
		}
		if !visible {
			continue
		}
		manifest := ""
		if c.Source == "addon_version" {
			manifest = digests[c.ID]
		}
		session := ""
		if c.Source == "runtime_action" {
			visible, err = allow("getSession", c.Session)
			if err != nil {
				return nil, err
			}
			if !visible {
				continue
			}
			session = c.Session
		}
		occurred := c.At
		if c.Source == "ticket_test" {
			if c.Ticket == nil || !c.Ticket.Archivable() || c.Ticket.Scenario.RunID != c.ID || c.Ticket.Scenario.Scope.OrganizationID != i.Scope.OrganizationID().String() || c.Ticket.Scenario.Scope.WorkspaceID != i.Scope.WorkspaceID().String() || c.Ticket.Scenario.Scope.EnvironmentID != i.Scope.EnvironmentID().String() {
				return nil, ErrRepositoryUnavailable
			}
			v, err := redteam.VerifyTicketProof(c.Ticket.Scenario, c.Ticket.Adapter, c.Ticket.Recorder, c.At)
			if err != nil {
				return nil, ErrRepositoryUnavailable
			}
			if v.Verdict != "passed" && v.Verdict != "unexpected_effect" {
				continue
			}
			qualification := ticketProofQualification(*c.Ticket, c.At)
			if qualification == "unknown" {
				continue
			}
			if qualification == "verified_prevention" {
				occurred = c.Ticket.Scenario.WindowEnd
				mappings = append(mappings, compliancemap.ScopedRuleMappings("ticket.verified_prevention", c.Version)...)
			}
		}
		for _, m := range mappings {
			if m.Disposition != "mapped" || m.RuleVersion != c.Version || (m.EvidenceKind != ruleKind && !(c.Source == "ticket_test" && m.Rule == "ticket.verified_prevention" && m.EvidenceKind == "verified_prevention")) || (f.framework != "" && (m.Framework != f.framework || m.Edition != f.edition)) {
				continue
			}
			result = append(result, coverageEvidence{ManifestDigest: manifest, Source: c.Source, ID: c.ID, Rule: m.Rule, Version: m.RuleVersion, Kind: m.EvidenceKind, At: occurred.UTC(), Framework: m.Framework, Edition: m.Edition, Upstream: m.UpstreamID, Session: session})
		}
	}
	slices.SortFunc(result, func(a, b coverageEvidence) int { return strings.Compare(evidenceKey(a), evidenceKey(b)) })
	return slices.CompactFunc(result, func(a, b coverageEvidence) bool { return evidenceKey(a) == evidenceKey(b) }), nil
}
func evidenceKey(x coverageEvidence) string {
	return strings.Join([]string{x.Framework, x.Edition, x.Upstream, x.Source, x.ID, x.Kind, x.Rule, x.Version}, "/")
}
func evidencePage(f coverageFilter, all []coverageEvidence) ([]coverageEvidence, *string) {
	result := []coverageEvidence{}
	for _, x := range all {
		if f.upstream != "" && f.upstream != x.Upstream || f.kind != "" && f.kind != x.Kind || evidenceKey(x) <= f.after {
			continue
		}
		if len(result) == f.limit {
			k := evidenceKey(result[len(result)-1])
			return result, &k
		}
		result = append(result, x)
	}
	return result, nil
}
func buildCoveragePage(f coverageFilter, evidence []coverageEvidence, at time.Time) coveragePage {
	ed, _ := f.selectedEdition()
	p := coveragePage{ReportEdition: ed, Collected: at, Items: []coverageRow{}}
	byID := map[string]coverageRow{}
	seen := map[string]bool{}
	for _, entry := range compliancemap.EditionCatalog() {
		if entry.Framework != ed.Framework || entry.Edition != ed.Edition {
			continue
		}
		if entry.Status == "retired" && f.upstream != entry.UpstreamID {
			continue
		}
		byID[entry.UpstreamID] = coverageRow{Control: entry, Counts: map[string]int{}}
		if entry.Status == "retired" {
			continue
		}
		switch entry.Applicability {
		case "applicable":
			p.Summary.Applicable++
		case "out_of_scope":
			p.Summary.Outside++
		default:
			p.Summary.Unassessed++
		}
		switch entry.Kind {
		case "risk":
			p.Summary.Risks++
		case "technique":
			p.Summary.Techniques++
		case "subtechnique":
			p.Summary.Subtechniques++
		case "mitigation":
			p.Summary.Mitigations++
		}
	}
	for _, x := range evidence {
		row, ok := byID[x.Upstream]
		if !ok || x.Framework != ed.Framework || x.Edition != ed.Edition || x.At.After(at) {
			continue
		}
		k := fmt.Sprintf("%s/%s/%s/%s", x.Upstream, x.Source, x.ID, x.Kind)
		if !seen[k] {
			row.Counts[x.Kind]++
			seen[k] = true
		}
		if x.Kind == "verified_prevention" && (row.Verified == nil || x.At.After(*row.Verified)) {
			v := x.At
			row.Verified = &v
		}
		byID[x.Upstream] = row
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := byID[id]
		if row.Control.Status != "retired" && row.Control.Applicability == "applicable" && compliancemap.VerificationFreshness(row.Verified, at) == "current" {
			p.Summary.Verified++
		}
		if f.upstream != "" && f.upstream != id || f.kind != "" && row.Counts[f.kind] == 0 {
			continue
		}
		p.Matched++
		if id <= f.after {
			continue
		}
		if len(p.Items) < f.limit {
			p.Items = append(p.Items, row)
		} else if p.Next == nil {
			k := p.Items[len(p.Items)-1].Control.UpstreamID
			p.Next = &k
		}
	}
	return p
}
