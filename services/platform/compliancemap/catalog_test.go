package compliancemap

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestEditionIntegrity(t *testing.T) {
	rows := EditionCatalog()
	want := map[string]int{"owasp_agentic_top10/2026/risk": 10, "owasp_llm_top10/2025/risk": 10, "owasp_llm_top10/2026/risk": 10, "mitre_atlas/2026.10/technique": 129, "mitre_atlas/2026.10/subtechnique": 92, "mitre_atlas/2026.10/mitigation": 44, "mitre_attack_enterprise/19.1/technique": 1}
	counts := map[string]int{}
	retired := 0
	digest := regexp.MustCompile("^sha256:[a-f0-9]{64}$")
	for _, r := range rows {
		actual, ok := LookupEdition(r.Framework, r.Edition, r.UpstreamID)
		if !ok || actual != r || r.Title == "" || r.Owner == "" || r.Rationale == "" || r.Scope == "" || r.Attribution == "" || r.License == "" || !strings.HasPrefix(r.SourceURL, "https://") || !digest.MatchString(r.SourceDigest) || r.DigestBasis != "upstream_bytes" {
			t.Fatalf("incomplete row %+v", r)
		}
		if r.Status == "retired" {
			retired++
			if r.UpstreamID != "AML.T0057" {
				t.Fatal(r)
			}
			continue
		}
		counts[r.Framework+"/"+r.Edition+"/"+r.Kind]++
		if r.Kind == "subtechnique" {
			parent, ok := LookupEdition(r.Framework, r.Edition, r.ParentID)
			if !ok || parent.Kind != "technique" || parent.Status != "active" || !strings.HasPrefix(r.UpstreamID, parent.UpstreamID+".") {
				t.Fatalf("bad parent of %s", r.UpstreamID)
			}
		} else if r.ParentID != "" {
			t.Fatal(r)
		}
		for _, s := range strings.Split(allSurfaces, ",") {
			decision, reason, ok := ReviewSurface(r, s)
			if !ok || reason == "" || !slices.Contains([]string{"applicable", "unassessed", "out_of_scope"}, decision) {
				t.Fatalf("missing %s/%s review", r.UpstreamID, s)
			}
		}
	}
	if len(counts) != len(want) || retired != 1 {
		t.Fatal(counts, retired)
	}
	for k, n := range want {
		if counts[k] != n {
			t.Errorf("%s = %d; want %d", k, counts[k], n)
		}
	}
	rows[0].Title = "caller edits its own copy"
	if EditionCatalog()[0].Title == rows[0].Title {
		t.Fatal("shared mutable catalog result")
	}
}

func TestEditionCrosswalkAndLegacyLinks(t *testing.T) {
	for _, c := range []struct{ year, id, title string }{
		{"2025", "LLM06", "Excessive Agency"}, {"2026", "LLM03", "Excessive Agency"}, {"2026", "LLM06", "Unbounded Consumption"},
		{"2025", "LLM07", "System Prompt Leakage"}, {"2026", "LLM08", "Hidden Context Exposure"},
	} {
		r, ok := LookupEdition(LLMFramework, c.year, c.id)
		if !ok || r.Title != c.title {
			t.Fatal(c, r)
		}
	}
	if _, ok := LookupEdition(LLMFramework, "", "LLM06"); ok {
		t.Fatal("edition fallback")
	}
	for _, c := range []struct{ id, old, current, status string }{
		{"T0051", "LLM Prompt Injection", "LLM Prompt Injection", "active"}, {"T0053", "LLM Plugin Compromise", "AI Agent Tool Invocation", "active"},
		{"T0055", "Unsecured Credentials", "Unsecured Credentials", "active"}, {"T0057", "LLM Data Leakage", "LLM Data Leakage", "retired"},
	} {
		legacy, ok := ControlByKey(c.id)
		r, found := LookupEdition(ATLASFramework, ATLASEdition, legacy.Control)
		if !ok || !found || legacy.Title != c.old || r.Title != c.current || r.Status != c.status {
			t.Fatal(c, legacy, r)
		}
	}
}

func TestReviewAllLegacyRulesWithSourceSpecificRationales(t *testing.T) {
	if len(postureReviews) != 29 || len(Rules()) != 29 {
		t.Fatal("each production rule needs individual review")
	}
	for _, rule := range Rules() {
		rows := RuleMappings(rule)
		if len(rows) == 0 || postureReviews[rule].reason == "" {
			t.Fatalf("missing review for %s", rule)
		}
		for _, m := range rows {
			if _, ok := LookupEdition(m.Framework, m.Edition, m.UpstreamID); !ok || m.Rule != rule || m.Scope == "" || !strings.Contains(m.Rationale, postureReviews[rule].reason) || m.RuleVersion != PostureMapVersion || m.EvidenceKind != "posture_finding" {
				t.Fatal(m)
			}
			if m.Framework == ATLASFramework && m.Disposition != "insufficient_evidence" {
				t.Fatalf("posture reported an adversary behavior: %+v", m)
			}
		}
	}
}

func hasMapping(ms []RuleMapping, f, e, id, disposition, kind string) bool {
	for _, m := range ms {
		if m.Framework == f && m.Edition == e && m.UpstreamID == id && m.Disposition == disposition && m.EvidenceKind == kind {
			return true
		}
	}
	return false
}

func TestReceiptVersionAndTrustBoundaries(t *testing.T) {
	static := ScopedRuleMappings("dependency.unpinned", StaticMapVersion)
	if len(static) != 3 || !hasMapping(static, AgenticFramework, "2026", "ASI04", "mapped", "static_scan") || !hasMapping(static, LLMFramework, "2025", "LLM03", "mapped", "static_scan") || !hasMapping(static, LLMFramework, "2026", "LLM04", "mapped", "static_scan") {
		t.Fatal(static)
	}
	for _, rr := range [][2]string{{"dependency.unpinned", ""}, {"dependency.unpinned", "zasp-static.v999"}, {"context.retrieval", StaticMapVersion}, {"artifact.changed", StaticMapVersion}, {"ticket.verified_prevention", ContextMapVersion}, {"process.contains_shell", StaticMapVersion}} {
		if got := ScopedRuleMappings(rr[0], rr[1]); len(got) != 0 {
			t.Fatal(got)
		}
	}
	for _, op := range []string{"memory_write", "memory_recall", "grounded_decision", "retrieval", "hidden_context_check", "artifact_promotion"} {
		for _, m := range ScopedRuleMappings("context."+op, ContextMapVersion) {
			entry, _ := LookupEdition(m.Framework, m.Edition, m.UpstreamID)
			if entry.Kind == "technique" || entry.Kind == "subtechnique" || m.EvidenceKind != "observed_event" {
				t.Fatal(m)
			}
		}
	}
	ticket := ScopedRuleMappings("ticket.control_pair", TicketMapVersion)
	if !hasMapping(ticket, ATLASFramework, ATLASEdition, "AML.M0028", "mapped", "tested_control") || hasMapping(ticket, ATLASFramework, ATLASEdition, "AML.M0028", "mapped", "verified_prevention") {
		t.Fatal(ticket)
	}
}

func TestVerifiedAdapterDimension(t *testing.T) {
	for _, classification := range []string{"system_prompt", "retrieved_context", "untrusted", ""} {
		ms := ScopedContextRuleMappings("context.hidden_context_check", ContextMapVersion, classification)
		prompt := hasMapping(ms, LLMFramework, "2025", "LLM07", "mapped", "observed_event")
		current := hasMapping(ms, LLMFramework, "2026", "LLM08", "mapped", "observed_event")
		if prompt != (classification == "system_prompt") || current != (classification == "system_prompt" || classification == "retrieved_context") {
			t.Fatal(classification, ms)
		}
	}
	for _, classification := range []string{"model", "dataset", "document", "memory", ""} {
		ms := ScopedContextRuleMappings("context.artifact_promotion", ContextMapVersion, classification)
		model := hasMapping(ms, LLMFramework, "2026", "LLM05", "mapped", "observed_event")
		verification := hasMapping(ms, ATLASFramework, ATLASEdition, "AML.M0014", "mapped", "observed_event")
		if model != (classification == "model" || classification == "dataset") || verification != (model || classification == "document") {
			t.Fatal(classification, ms)
		}
	}
}

func TestWorkflowSourcesDoNotUpgradeReportedObservations(t *testing.T) {
	for operation, category := range map[string]string{"purpose": "ASI01", "approval": "ASI09", "handoff": "ASI07", "child": "ASI08", "budget": "LLM10"} {
		rows := ScopedRuleMappings("workflow."+operation, WorkflowMapVersion)
		want := AgenticFramework
		ed := "2026"
		if operation == "budget" {
			want, ed = LLMFramework, "2025"
			if !hasMapping(rows, LLMFramework, "2026", "LLM06", "mapped", "observed_event") {
				t.Fatal(rows)
			}
		}
		if !hasMapping(rows, want, ed, category, "mapped", "observed_event") {
			t.Fatal(rows)
		}
		for _, m := range rows {
			if m.EvidenceKind != "observed_event" {
				t.Fatal(m)
			}
		}
		if got := ScopedRuleMappings("workflow."+operation, ContextMapVersion); len(got) != 0 {
			t.Fatal(got)
		}
	}
	for _, notice := range []string{"Creative Commons Attribution-ShareAlike", "creativecommons.org/licenses/by-sa/4.0", "Apache License", "The MITRE Corporation"} {
		if !strings.Contains(CatalogNotices(), notice) {
			t.Errorf("missing embedded attribution %s", notice)
		}
	}
}

func TestStaticRulesRetainVersionedEvidence(t *testing.T) {
	for _, version := range []string{StaticMapVersion, StaticMapVersion2} {
		ms := ScopedRuleMappings("dependency.unpinned", version)
		if len(ms) != 3 {
			t.Fatal(version, ms)
		}
		for _, m := range ms {
			if m.RuleVersion != version || m.EvidenceKind != "static_scan" {
				t.Fatal(m)
			}
		}
	}
}

func TestAllLegacyReferenceLinksHaveIndividualReviews(t *testing.T) {
	total := 0
	for _, rule := range Rules() {
		rows := LegacyRuleReviews(rule)
		if len(rows) != len(References(rule)) {
			t.Fatal(rule)
		}
		for _, row := range rows {
			if row.Rule != rule || !strings.HasPrefix(row.Rationale, postureReviews[rule].reason+" ") || strings.HasSuffix(row.Rationale, " ") {
				t.Fatal(row)
			}
		}
		total += len(rows)
	}
	if total != len(Mappings()) {
		t.Fatalf("%d reviewed links vs %d historical links", total, len(Mappings()))
	}
}
