package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"net/http"
	"strings"
	"testing"
	"time"
)

type agentExportHTTPDatabase struct {
	exportSettlementDatabase
	pin        securityAgentExportReadReceipt
	operations []string
	revoked    bool
	formats    []string
	tokens     []string
}

func (d *agentExportHTTPDatabase) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	if len(args) != 13 {
		return nil, errors.New("unexpected query")
	}
	operation, ok := args[10].(string)
	if !ok {
		return nil, errors.New("bad operation")
	}
	d.operations = append(d.operations, operation)
	d.formats = append(d.formats, args[9].(string))
	d.tokens = append(d.tokens, args[8].(string))
	if operation == "read" {
		return json.Marshal(d.pin)
	}
	if operation == "consume" && d.revoked {
		return nil, &pgconn.PgError{Code: "42501", Message: "source authority revoked"}
	}
	return json.Marshal(complianceGrantResult{ExpiresAt: time.Now().Add(time.Minute), Consumed: operation == "consume"})
}

// Wrong format mapping, returning a non-token, or accepting malformed requests
// must fail through the real middleware and repository, before any storage I/O.
func TestSecurityAgentExportHTTPGrantAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, suffix, body string
		mutate             func(*http.Request)
		want               int
		format             string
	}{
		{"json", "/download-grants", `{"format":"json"}`, nil, 201, "json"},
		{"csv", "/download-grants", `{"format":"csv"}`, nil, 201, "csv"},
		{"human", "/download-grants", `{"format":"human"}`, nil, 201, "readable"},
		{"unknown format", "/download-grants", `{"format":"pdf"}`, nil, 400, ""},
		{"duplicate format", "/download-grants", `{"format":"json","format":"csv"}`, nil, 400, ""},
		{"unknown field", "/download-grants", `{"format":"json","key":"private"}`, nil, 400, ""},
		{"query", "/download-grants?key=private", `{"format":"json"}`, nil, 400, ""},
		{"invalid token", "/download", `{"format":"json","token":"bad"}`, nil, 400, ""},
		{"duplicate csrf", "/download-grants", `{"format":"json"}`, func(r *http.Request) { r.Header.Add("X-CSRF-Token", "duplicate") }, 400, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity, reader, pin, _ := agentDownloadFixture(t)
			db := &agentExportHTTPDatabase{pin: pin}
			repo, _ := NewSecurityAgentExportsRepository(db)
			router, err := NewCompositionWithSecurityAgentExports(auditExportCompositionDependencies(), nil, nil, &securityAgentExportHTTPHandler{exports: repo, reader: reader})
			if err != nil {
				t.Fatal(err)
			}
			h, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return identity, nil }}, router)
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/security-agent-runs/" + pin.Binding.RunID + "/steps/" + pin.Binding.StepID + "/export" + tc.suffix
			w := complianceHTTPRequest(t, h, identity, http.MethodPost, path, tc.body, tc.mutate)
			if w.Code != tc.want || reader.calls != 0 {
				t.Fatalf("status=%d body=%s storage=%d", w.Code, w.Body, reader.calls)
			}
			if tc.want != 201 {
				if len(db.operations) != 0 {
					t.Fatalf("invalid request reached SQL: %v", db.operations)
				}
				return
			}
			var response struct {
				Token     string    `json:"token"`
				Format    string    `json:"format"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(db.operations) != 1 || db.operations[0] != "issue" || db.formats[0] != tc.format || !validExistingTestPublicDigest(response.Token) || response.Token != db.tokens[0] || !response.ExpiresAt.After(time.Now()) || response.Format != tc.name {
				t.Fatalf("incorrect grant: %s operations=%v formats=%v", w.Body, db.operations, db.formats)
			}
		})
	}
}
func TestSecurityAgentExportHTTPConsumeBeforeBytes(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "allowed", true: "revoked"}[revoked], func(t *testing.T) {
			identity, reader, pin, manifest := agentDownloadFixture(t)
			db := &agentExportHTTPDatabase{pin: pin, revoked: revoked}
			repo, _ := NewSecurityAgentExportsRepository(db)
			router, err := NewCompositionWithSecurityAgentExports(auditExportCompositionDependencies(), nil, nil, &securityAgentExportHTTPHandler{exports: repo, reader: reader})
			if err != nil {
				t.Fatal(err)
			}
			h, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return identity, nil }}, router)
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/security-agent-runs/" + pin.Binding.RunID + "/steps/" + pin.Binding.StepID + "/export/download"
			response := complianceHTTPRequest(t, h, identity, http.MethodPost, path, `{"format":"json","token":"`+strings.Repeat("a", 64)+`"}`, nil)
			if !revoked {
				if response.Code != http.StatusOK || response.Body.String() != manifest || response.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(response.Header().Get("Content-Disposition"), "attachment;") {
					t.Fatalf("exact download failed: status=%d body=%s", response.Code, response.Body.String())
				}
			} else if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "persisted evidence") {
				t.Fatalf("revoked download disclosed bytes: %d %s", response.Code, response.Body.String())
			}
			if strings.Join(db.operations, ",") != "read,consume" || reader.calls != 1 {
				t.Fatalf("storage/consume sequence lost: %v reads=%d", db.operations, reader.calls)
			}
		})
	}
}
