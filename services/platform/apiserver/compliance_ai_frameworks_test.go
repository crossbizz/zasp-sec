package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
)

func TestComplianceValidatorsKnowTheAIFrameworks(t *testing.T) {
	for _, framework := range compliancemap.FrameworkNames {
		if !validComplianceFramework(framework.ID) {
			t.Errorf("framework %s rejected", framework.ID)
		}
	}
	for _, control := range compliancemap.Controls() {
		if !validComplianceControl(control.Control, "") || !validComplianceControl(control.Control, control.Framework) || validComplianceControl(control.Control, "hipaa") || complianceControlFramework(control.Control) != control.Framework {
			t.Errorf("control %s of %s is not bound to its framework", control.Control, control.Framework)
		}
	}
	for control, framework := range map[string]string{"hipaa-findings": "hipaa", "soc2_security-configuration": "soc2_security"} {
		if complianceControlFramework(control) != framework || !validComplianceControl(control, framework) || validComplianceControl(control, compliancemap.EUAIAct) {
			t.Errorf("product control %s is not bound to %s", control, framework)
		}
	}
	for _, control := range []string{"", "ASI99", "hipaa-unknown", "owasp_agentic_top10_2026-ASI03", "govern 1.6"} {
		if validComplianceControl(control, "") || complianceControlFramework(control) != "" {
			t.Errorf("unknown control %q accepted", control)
		}
	}
	if validComplianceFramework("") || validComplianceFramework("iso_27001") {
		t.Error("unknown framework accepted")
	}
}

const complianceAIControlPage = `{"mapping_revision":"product-evidence-v1","collected_at":"2026-11-14T10:00:00.000000Z","next_cursor":null,"items":[
{"framework":"hipaa","control_id":"hipaa-findings","label":"Finding review","required_sources":["finding"],"maximum_age_seconds":86400,"freshness":"fresh","fresh_until":"2026-11-15T09:00:00.000000Z"},
{"framework":"owasp_agentic_top10_2026","control_id":"ASI03","label":"Identity and Privilege Abuse","required_sources":["finding"],"maximum_age_seconds":86400,"freshness":"fresh","fresh_until":"2026-11-15T09:00:00.000000Z","finding_ids":["pid_6b000001-0000-4000-8000-000000000001","pid_6b000002-0000-4000-8000-000000000002"],"finding_count":2},
{"framework":"owasp_agentic_top10_2026","control_id":"ASI10","label":"Rogue Agents","required_sources":["finding"],"maximum_age_seconds":86400,"freshness":"missing","fresh_until":"1970-01-01T00:00:00.000000Z","finding_ids":[],"finding_count":0}]}`

func TestComplianceControlsCarryTheFindingsOfAnAIControl(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "view_compliance"}
	database := &discoveryCallDatabase{schema: ProductionRecoverySchemaVersion, responses: map[string]json.RawMessage{postgresComplianceReadySQL: json.RawMessage(`true`), postgresComplianceReadSQL: json.RawMessage(complianceAIControlPage)}}
	repository, err := NewComplianceRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("owned-compliance-session"))
	page, err := repository.ListControls(context.Background(), identity, digest[:], ComplianceListOptions{Limit: 100})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("controls = %#v / %v", page, err)
	}
	if page.Items[0].FindingCount != nil || page.Items[0].FindingIDs != nil {
		t.Fatalf("a product control carries findings: %#v", page.Items[0])
	}
	if page.Items[1].FindingCount == nil || *page.Items[1].FindingCount != 2 || len(page.Items[1].FindingIDs) != 2 || page.Items[2].FindingCount == nil || *page.Items[2].FindingCount != 0 || page.Items[2].FindingIDs == nil {
		t.Fatalf("AI controls = %#v", page.Items[1:])
	}
	// The public control names the findings as its evidence and counts them;
	// a product control has no count.
	public := compliancePublicControl(page.Items[1], nil)
	body, _ := json.Marshal(public)
	if !strings.Contains(string(body), `"finding_count":2`) || len(public.EvidenceIDs) != 2 || public.ID != "ASI03" || public.Name != "Identity and Privilege Abuse" {
		t.Fatalf("public AI control = %s", body)
	}
	body, _ = json.Marshal(compliancePublicControl(page.Items[0], nil))
	if strings.Contains(string(body), "finding_count") {
		t.Fatalf("public product control = %s", body)
	}
	// An AI control needs no evidence read: its findings came with it.
	stub := &complianceEvidenceStub{}
	evidence, err := complianceControlEvidence(context.Background(), stub, identity, digest[:], page.Items[1:])
	if err != nil || len(stub.calls) != 0 || len(evidence) != 2 {
		t.Fatalf("evidence of AI controls read the sources %d times: %v", len(stub.calls), err)
	}
	// Malformed finding members are refused.
	for name, mutate := range map[string]func(string) string{
		"a product control with findings": func(s string) string {
			return strings.Replace(s, `"fresh_until":"2026-11-15T09:00:00.000000Z"},`, `"fresh_until":"2026-11-15T09:00:00.000000Z","finding_ids":[],"finding_count":0},`, 1)
		},
		"an AI control without findings": func(s string) string { return strings.Replace(s, `,"finding_ids":[],"finding_count":0`, ``, 1) },
		"a count below the list":         func(s string) string { return strings.Replace(s, `"finding_count":2`, `"finding_count":1`, 1) },
		"a count above a short list":     func(s string) string { return strings.Replace(s, `"finding_count":2`, `"finding_count":3`, 1) },
		"unordered findings": func(s string) string {
			return strings.Replace(s, `["pid_6b000001-0000-4000-8000-000000000001","pid_6b000002-0000-4000-8000-000000000002"]`, `["pid_6b000002-0000-4000-8000-000000000002","pid_6b000001-0000-4000-8000-000000000001"]`, 1)
		},
		"a control of another framework": func(s string) string { return strings.Replace(s, `"control_id":"ASI03"`, `"control_id":"LLM01"`, 1) },
	} {
		changed := mutate(complianceAIControlPage)
		if changed == complianceAIControlPage {
			t.Fatalf("%s: the fixture did not change", name)
		}
		database.responses[postgresComplianceReadSQL] = json.RawMessage(changed)
		if _, err := repository.ListControls(context.Background(), identity, digest[:], ComplianceListOptions{Limit: 100}); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Errorf("%s was accepted: %v", name, err)
		}
	}
}

func TestComplianceListOptionsForAIFrameworks(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for query, operation := range map[string]string{
		"framework=owasp_agentic_top10_2026":                 "listComplianceControls",
		"framework=nist_ai_rmf_1_0&control_id=GOVERN%201.6":  "listComplianceControls",
		"control_id=Article%2015":                            "listComplianceEvidence",
		"framework=mitre_atlas&control_id=AML.T0051&limit=5": "listComplianceEvidence",
	} {
		options, err := complianceHTTPListOptions(httptest.NewRequest("GET", "/api/v1/compliance/x?"+query, nil), identity, operation)
		if err != nil {
			t.Errorf("%s %s: %v", operation, query, err)
		}
		if strings.Contains(query, "GOVERN") && options.ControlID != "GOVERN 1.6" {
			t.Errorf("control = %q", options.ControlID)
		}
	}
	for query, operation := range map[string]string{
		// The evidence of an AI framework is listed per control.
		"framework=eu_ai_act":                       "listComplianceEvidence",
		"framework=hipaa&control_id=ASI03":          "listComplianceControls",
		"framework=eu_ai_act&control_id=GOVERN+1.6": "listComplianceEvidence",
		"framework=owasp":                           "listComplianceControls",
	} {
		if _, err := complianceHTTPListOptions(httptest.NewRequest("GET", "/api/v1/compliance/x?"+query, nil), identity, operation); !errors.Is(err, ErrRepositoryOperation) {
			t.Errorf("%s %s accepted: %v", operation, query, err)
		}
	}
}
