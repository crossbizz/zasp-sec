package securityagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const responseGolden = `{"schema_version":1,"type":"security_agent.response","delivery_id":"pid_00000000-0000-4000-8000-000000000001","organization_id":"pid_00000000-0000-4000-8000-000000000002","workspace_id":"pid_00000000-0000-4000-8000-000000000003","environment_id":"pid_00000000-0000-4000-8000-000000000004","run_id":"pid_00000000-0000-4000-8000-000000000005","step_id":"pid_00000000-0000-4000-8000-000000000006","plan_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence":[{"source_kind":"manual","source_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","source_version":1,"association_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`

func responseFixture(t *testing.T) ResponseWebhookPayload {
	t.Helper()
	var p ResponseWebhookPayload
	if err := json.Unmarshal([]byte(responseGolden), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// Removing structural rejection, allowing duplicate sources, or changing the
// wire field order must fail these tests. The golden is the literal design JSON.
func TestSecurityAgentWebhookPayloadClosedCanonical(t *testing.T) {
	p := responseFixture(t)
	body, digest, err := EncodeResponseWebhookPayload(p)
	expected := sha256.Sum256([]byte(responseGolden))
	if err != nil || string(body) != responseGolden || digest != "sha256:"+hex.EncodeToString(expected[:]) {
		t.Fatalf("golden encoding mismatch: %v", err)
	}
	for _, sentinel := range []string{"SECRET_SENTINEL", "PROMPT_SENTINEL", "TITLE_SENTINEL", "https://", "secret_ref_"} {
		if strings.Contains(string(body), sentinel) {
			t.Fatalf("payload leaked %q", sentinel)
		}
	}
	cases := []struct {
		name   string
		mutate func(*ResponseWebhookPayload)
	}{
		{"schema", func(p *ResponseWebhookPayload) { p.SchemaVersion = 2 }},
		{"event", func(p *ResponseWebhookPayload) { p.Type = "integration.webhook.test" }},
		{"empty", func(p *ResponseWebhookPayload) { p.Evidence = nil }},
		{"nine", func(p *ResponseWebhookPayload) {
			for len(p.Evidence) < 9 {
				p.Evidence = append(p.Evidence, p.Evidence[0])
			}
		}},
		{"duplicate", func(p *ResponseWebhookPayload) { p.Evidence = append(p.Evidence, p.Evidence[0]) }},
		{"same-source-new-version", func(p *ResponseWebhookPayload) {
			s := p.Evidence[0]
			s.SourceVersion = 2
			p.Evidence = append(p.Evidence, s)
		}},
		{"unsorted", func(p *ResponseWebhookPayload) {
			s := p.Evidence[0]
			s.SourceID = strings.Repeat("b", 64)
			p.Evidence = append(p.Evidence, s)
		}},
		{"unknown-kind", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceKind = "finding" }},
		{"manual-prefix", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceID = "sha256:" + p.Evidence[0].SourceID }},
		{"manual-uppercase", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceID = strings.Repeat("C", 64) }},
		{"run-audit-id", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceKind = "run_audit" }},
		{"zero-version", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceVersion = 0 }},
		{"overflow-version", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceVersion = 9007199254740992 }},
		{"association-digest", func(p *ResponseWebhookPayload) { p.Evidence[0].AssociationDigest = strings.Repeat("b", 64) }},
		{"plan-digest", func(p *ResponseWebhookPayload) { p.PlanHash = "sha256:" + strings.Repeat("A", 64) }},
		{"delivery-id", func(p *ResponseWebhookPayload) { p.DeliveryID = "pid_not-canonical" }},
		{"organization-id", func(p *ResponseWebhookPayload) { p.OrganizationID = "../tenant" }},
		{"workspace-id", func(p *ResponseWebhookPayload) { p.WorkspaceID = "" }},
		{"environment-id", func(p *ResponseWebhookPayload) { p.EnvironmentID = "" }},
		{"run-id", func(p *ResponseWebhookPayload) { p.RunID = "" }},
		{"step-id", func(p *ResponseWebhookPayload) { p.StepID = "" }},
		{"size-overflow", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceID = strings.Repeat("c", 16<<10) }},
		{"secret", func(p *ResponseWebhookPayload) { p.Evidence[0].SourceID = "SECRET_SENTINEL" }},
		{"prompt", func(p *ResponseWebhookPayload) { p.Type = "PROMPT_SENTINEL" }},
		{"title", func(p *ResponseWebhookPayload) { p.PlanHash = "TITLE_SENTINEL" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := responseFixture(t)
			tc.mutate(&p)
			b, d, e := EncodeResponseWebhookPayload(p)
			if e == nil || b != nil || d != "" {
				t.Fatal("invalid payload was not rejected without bytes/digest")
			}
		})
	}
	p = responseFixture(t)
	p.Evidence = append(p.Evidence, ResponseWebhookEvidence{SourceKind: "run_audit", SourceID: p.RunID, SourceVersion: 9007199254740991, AssociationDigest: p.PlanHash})
	if _, _, err := EncodeResponseWebhookPayload(p); err != nil {
		t.Fatalf("canonical sorted selection: %v", err)
	}
}
