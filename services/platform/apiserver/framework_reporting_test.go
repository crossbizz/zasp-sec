package apiserver

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestFrameworkReportingSeparatesEditionScopeEvidenceAndCounts(t *testing.T) {
	f, ok := parseCoverageFilter(url.Values{"framework": {"owasp_agentic_top10"}, "edition": {"2026"}, "limit": {"2"}}, false)
	if !ok {
		t.Fatal("expected a released edition")
	}
	at := time.Now().UTC()
	const id = "pid_00000001-0101-4000-8000-000000000001"
	base := coverageEvidence{Source: "addon_version", ID: id, Rule: "dependency.unpinned", Version: "zasp-static.v1", Kind: "static_scan", At: at, Framework: f.framework, Edition: f.edition, Upstream: "ASI04"}
	duplicate := base
	duplicate.Rule = "other.scoped_rule"
	rows := []coverageEvidence{base, base, duplicate}
	page := buildCoveragePage(f, rows, at)
	if page.Total != 10 || page.Matched != 10 || page.Summary.Risks != 10 || len(page.Items) != 2 || page.Next == nil || page.Summary.Verified != 0 {
		t.Fatalf("unexpected denominator: %+v", page)
	}
	f.after = *page.Next
	f.kind = "static_scan"
	page = buildCoveragePage(f, rows, at)
	if page.Total != 10 || page.Matched != 1 || len(page.Items) != 1 || page.Items[0].Control.UpstreamID != "ASI04" || page.Items[0].Counts["static_scan"] != 1 || page.Items[0].Verified != nil {
		t.Fatal("duplicates inflated one local version or static evidence became verification")
	}
	f.kind = "verified_prevention"
	page = buildCoveragePage(f, rows, at)
	if page.Matched != 0 || page.Total != 10 {
		t.Fatal("missing proof removed denominator")
	}
	f.after = ""
	f.kind = ""
	f.upstream = "ASI04"
	f.limit = 1
	first, next := evidencePage(f, []coverageEvidence{base, duplicate})
	if len(first) != 1 || next == nil {
		t.Fatal("evidence page missing")
	}
	f.after = *next
	second, last := evidencePage(f, []coverageEvidence{base, duplicate})
	if len(second) != 1 || last != nil || second[0].Rule != duplicate.Rule {
		t.Fatal("unstable continuation")
	}
}
func TestFrameworkReportingCurrentProofUsesObservationWindow(t *testing.T) {
	f := coverageFilter{framework: "owasp_agentic_top10", edition: "2026", upstream: "ASI04", limit: 1}
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-30 * 24 * time.Hour)
	proof := coverageEvidence{Source: "ticket_test", ID: "run-1", Kind: "verified_prevention", Framework: f.framework, Edition: f.edition, Upstream: f.upstream}
	for _, tc := range []struct {
		name       string
		at         time.Time
		current    bool
		historical bool
	}{
		{"exact cutoff", cutoff, true, true},
		{"expired", cutoff.Add(-time.Nanosecond), false, true},
		{"now", now, true, true},
		{"future", now.Add(time.Nanosecond), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof.At = tc.at
			page := buildCoveragePage(f, []coverageEvidence{proof}, now)
			row := page.Items[0]
			if (page.Summary.Verified == 1) != tc.current || (row.Verified != nil) != tc.historical || (row.Counts["verified_prevention"] == 1) != tc.historical || row.Verified != nil && !row.Verified.Equal(tc.at) {
				t.Fatalf("summary=%+v last=%v counts=%v", page.Summary, row.Verified, row.Counts)
			}
		})
	}
	proof.At = cutoff
	original := buildCoveragePage(f, []coverageEvidence{proof}, now)
	later := buildCoveragePage(f, []coverageEvidence{proof}, now.Add(time.Second))
	if original.Summary.Verified != 1 || later.Summary.Verified != 0 || !later.Items[0].Verified.Equal(cutoff) {
		t.Fatal("historical proof or collection-time freshness changed")
	}
}

func TestFrameworkReportingRejectsAmbiguousSelectors(t *testing.T) {
	good := url.Values{"source_kind": {"addon_version"}, "source_id": {"pid_00000001-0101-4000-8000-000000000001"}}
	if _, ok := parseCoverageFilter(good, true); !ok {
		t.Fatal("direct source lookup refused")
	}
	for _, q := range []url.Values{{"framework": {"owasp_llm_top10"}, "edition": {"2030"}}, {"framework": {"owasp_agentic_top10"}, "edition": {"2026"}, "upstream_id": {"ASI88"}}, {"framework": {"owasp_agentic_top10"}, "edition": {"2026"}, "source_kind": {"addon_version"}}, {"source_kind": {"addon_version"}, "source_id": {"not-a-product-id"}}, {"source_kind": {"addon_version"}, "source_id": good["source_id"], "evidence_kind": {"unbounded"}}, {"source_kind": {"addon_version"}, "source_id": good["source_id"], "limit": {"101"}}, {"source_kind": {"addon_version", "ticket_test"}, "source_id": good["source_id"]}} {
		if _, ok := parseCoverageFilter(q, true); ok {
			t.Fatalf("admitted %v", q)
		}
	}
}

// Every category/source lookup is fenced on the selected Environment and runs
// the source's own product authorization before a count or manifest is returned.
func TestFrameworkReportingSourceIsolationOnInstalledBaselinePostgres(t *testing.T) {
	a := startInstalledV2Baseline(t)
	b := startInstalledV2Baseline(t)
	add := func(x *installedBaseline) string {
		id := x.id()
		x.exec(`INSERT INTO public.zasp_addon_versions(organization_id,workspace_id,environment_id,id,manifest_digest,origin,origin_credential,ruleset,findings) VALUES($1,$2,$3,$4,$5,'local',$6,'zasp-static.v1','[{"rule_id":"dependency.unpinned","count":3}]')`, x.o, x.w, x.e, id, "sha256:"+strings.Repeat("a", 64), x.id())
		return id
	}
	knownFinding, unknownFinding, foreignCollector := a.id(), a.id(), a.id()
	const knownRule = "agent_role_unused_ai_permissions"
	rows := []map[string]string{}
	for _, src := range []struct{ id, rule string }{{knownFinding, knownRule}, {unknownFinding, "new_unreviewed_rule"}, {foreignCollector, knownRule}} {
		rows = append(rows, map[string]string{"finding_id": src.id, "entity_id": a.id(), "check_id": src.rule, "source": "aws", "evidence_id": a.id()})
	}
	imported, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	a.exec(`SELECT public.zasp_inventory_apply_findings($1,$2,$3,$4::jsonb)`, a.o, a.w, a.e, string(imported))
	a.exec(`UPDATE public.zasp_risk_findings SET compliance_context='unverified:aws:' || rule WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, a.o, a.w, a.e, foreignCollector)
	source := add(a)
	_ = add(b)
	f := coverageFilter{source: "addon_version", id: source, limit: 10}
	for _, x := range []*installedBaseline{a, b} {
		if err := x.product.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		p := x.member("security_admin", "view", "view_audit", "view_compliance")
		route := RoutedOperation{OperationID: "listComplianceCoverageEvidence", PathParameters: map[string]string{}}
		ctx, err := x.checked(p, route)
		if err != nil {
			t.Fatal(err)
		}
		repo := &ComplianceRepository{database: x.product}
		rows, err := repo.frameworkEvidence(ctx, p.identity, route.OperationID, f)
		if err != nil {
			t.Fatal(err)
		}
		if x == b {
			if len(rows) != 0 {
				t.Fatal("foreign version disclosed")
			}
			continue
		}
		found := false
		for _, row := range rows {
			if row.Framework == "owasp_agentic_top10" && row.Edition == "2026" && row.Upstream == "ASI04" && row.Kind == "static_scan" && row.ID == source && row.ManifestDigest == "sha256:"+strings.Repeat("a", 64) {
				found = true
			}
		}
		if !found {
			t.Fatal("authorized ASI04 evidence missing")
		}
		for _, candidate := range []string{knownFinding, unknownFinding, foreignCollector} {
			check := coverageFilter{source: "finding", id: candidate, limit: 10}
			findings, err := repo.frameworkEvidence(ctx, p.identity, route.OperationID, check)
			if err != nil {
				t.Fatal(err)
			}
			if candidate == knownFinding {
				mapped := false
				for _, row := range findings {
					if row.Rule == knownRule && row.Kind == "posture_finding" && row.ID == candidate {
						mapped = true
					}
				}
				if !mapped {
					t.Fatal("trusted projected collector finding missing")
				}
			} else if len(findings) != 0 {
				t.Fatalf("unreviewed or untrusted finding escaped: %+v", findings)
			}
		}
		x.refused[p.identity.PrincipalID.String()+" view"] = true
		hidden, err := repo.frameworkEvidence(ctx, p.identity, route.OperationID, f)
		if err != nil || len(hidden) != 0 {
			t.Fatalf("subsequent denied source lookup: %d %v", len(hidden), err)
		}
	}
}
