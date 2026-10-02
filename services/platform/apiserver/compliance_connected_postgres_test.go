package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Discovery must offer a claimable head even when creation order opposes the
// scope tie-break. Four waiting jobs across three scopes exceed batch size one.
func TestComplianceCandidateAdmissionProgressPostgres(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		worker := f.connect("compliance_executor")
		ids := map[string][]string{}
		scopes := []string{"pid_20000003-0000-4000-8000-000000000003", "pid_30000003-0000-4000-8000-000000000003", "pid_40000003-0000-4000-8000-000000000003"}
		for n := 2; n >= 0; n-- {
			scope := scopes[n]
			f.exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'candidate','["view","view_audit","view_compliance"]'); INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES(digest($3,'sha256'),$4,$1,$2,$3,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp())`, complianceOrg, complianceWorkspace, scope, compliancePrincipal)
			count := 1
			if n == 0 {
				count = 2
			}
			for i := 0; i < count; i++ {
				var raw json.RawMessage
				if err := api.QueryRow(f.ctx, `SELECT zasp_compliance_export_create($1,$2,$3,$4,digest($3,'sha256'),$5,'{}',$6,$7)`, complianceOrg, complianceWorkspace, scope, compliancePrincipal, fmt.Sprintf("candidate-%d", i), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var v struct {
					ID string `json:"export_id"`
				}
				if err := json.Unmarshal(raw, &v); err != nil {
					t.Fatal(err)
				}
				ids[scope] = append(ids[scope], v.ID)
			}
		}
		for n, scope := range []string{scopes[0], scopes[1], scopes[2], scopes[0]} {
			var raw json.RawMessage
			if err := worker.QueryRow(f.ctx, `SELECT zasp_compliance_export_candidates('execute',1,$1,$2)`, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var page struct {
				Items []struct {
					Environment string `json:"environment_id"`
					ID          string `json:"export_id"`
				} `json:"items"`
			}
			if err := json.Unmarshal(raw, &page); err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 {
				t.Fatalf("poll %d: %s", n, raw)
			}
			candidate := page.Items[0]
			if err := worker.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'connected-worker',$5,'execute',$6,$7)`, complianceOrg, complianceWorkspace, candidate.Environment, candidate.ID, fmt.Sprintf("%064x", n+1), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if string(raw) == "null" {
				t.Fatalf("poll %d discovered unclaimable head %s: batch1 makes no progress", n, candidate.Environment)
			}
			if candidate.Environment != scope || candidate.ID != ids[scope][0] {
				t.Fatalf("poll %d lost fair oldest ordering: %+v want %s/%s", n, candidate, scope, ids[scope][0])
			}
			ids[scope] = ids[scope][1:]
		}
	})
}

func TestComplianceHTTPMaximumIDCursorPostgres(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		sessions, err := NewPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		source, err := NewComplianceRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := sessions.Authenticate(f.ctx, Credential{Kind: CredentialBrowserSession, Value: "compliance-fix-session"})
		if err != nil {
			t.Fatal(err)
		}
		router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, &complianceHTTPHandler{source: source})
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: sessions.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
		if err != nil {
			t.Fatal(err)
		}
		longID := "policy-" + strings.Repeat("a", 121)
		f.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'policy',$4,7,'{}'),($1,$2,$3,'policy','policy-z',8,'{}')`, complianceOrg, complianceWorkspace, complianceEnvironment, longID)
		for _, framework := range []string{"soc2_security", "hipaa"} {
			prefix := "/api/v1/compliance/evidence?framework=" + framework + "&control_id=" + framework + "-policies&limit=1"
			cursor := ""
			for i, id := range []string{longID, "policy-z"} {
				w := complianceHTTPRequest(t, mounted, identity, "GET", prefix+cursor, "", func(r *http.Request) { r.Header.Set("Cookie", browserSessionCookie+"=compliance-fix-session") })
				var page struct {
					Items []struct {
						Evidence []struct {
							ID string `json:"id"`
						} `json:"evidence"`
					} `json:"items"`
					Info struct {
						Cursor *string `json:"next_cursor"`
						More   bool    `json:"has_more"`
					} `json:"page_info"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || len(page.Items[0].Evidence) != 1 || page.Items[0].Evidence[0].ID != id {
					t.Fatalf("HTTP page %d: %d %s", i, w.Code, w.Body)
				}
				if i == 0 {
					if page.Info.Cursor == nil || !page.Info.More || len(*page.Info.Cursor) <= 512 {
						t.Fatalf("maximum source did not emit long cursor: %+v", page.Info)
					}
					cursor = "&cursor=" + *page.Info.Cursor
					t.Logf("%s actual HTTP cursor length=%d", framework, len(*page.Info.Cursor))
				} else if page.Info.More || page.Info.Cursor != nil {
					t.Fatal("unexpected third page")
				}
			}
		}
	})
}
