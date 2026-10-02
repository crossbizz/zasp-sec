package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type manualStartDatabase struct {
	*securityAgentRepositoryDatabase
	available bool
	probeErr  error
	queryErr  error
}

func (d *manualStartDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	value, err := d.securityAgentRepositoryDatabase.QueryJSON(ctx, statement, arguments...)
	if d.queryErr != nil {
		return nil, d.queryErr
	}
	return value, err
}

func (d *manualStartDatabase) SecurityAgentExportsAvailable(context.Context) (bool, error) {
	return d.available, d.probeErr
}

// Catch missing optional-source admission, wrong scoped SQL arguments, and
// provenance stripped from the public response. SQL is the controlled boundary;
// the public handler and repository are real. This is not admission SQL proof.
func TestSecurityAgentManualStart(t *testing.T) {
	const statement = `SELECT public.zasp_sa_manual_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	const definition = "pid_78000004-0000-4000-8000-000000000004"
	const run = "pid_78000001-0000-4000-8000-000000000001"
	const audit = "pid_78000005-0000-4000-8000-000000000005"
	const receipt = "pid_78000007-0000-4000-8000-000000000007"
	const source = "pid_78000008-0000-4000-8000-000000000008"
	for _, variant := range []string{"fresh", "replay", "explicit source", "missing capability", "capability error", "absent capability", "bearer", "kind only", "id only", "null kind", "null id", "empty fields", "caller manual", "caller digest", "duplicate environment", "alias", "foreign environment", "null provenance", "missing provenance", "mixed evidence", "null evidence", "wrong definition", "wrong version", "wrong receipt", "duplicate response", "null replay", "wrong manual version", "revoked membership", "revoked permissions", "database privilege failure", "wrong denial code"} {
		t.Run(variant, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			env := identity.Scope.EnvironmentID().String()
			body := `{"environment_id":"` + env + `"}`
			value := map[string]any{"id": run, "agent_id": definition, "state": "queued", "definition_version": 1, "version": 1, "evidence_ids": []string{}, "manual_trigger": map[string]any{"kind": "manual", "intent_digest": "sha256:" + strings.Repeat("a", 64), "version": 1}, "audit_id": audit, "correlation_id": testCorrelationID, "receipt_id": receipt, "replayed": false}
			query := statement
			want := http.StatusServiceUnavailable
			switch variant {
			case "fresh":
				want = http.StatusAccepted
			case "bearer":
				want = http.StatusAccepted
				identity.CredentialKind = CredentialBearerToken
			case "replay":
				want = http.StatusAccepted
				value["replayed"] = true
				value["id"] = source
				value["receipt_id"] = source
			case "explicit source":
				want = http.StatusAccepted
				query = postgresSecurityAgentRunSQL
				body = `{"environment_id":"` + env + `","trigger_kind":"finding","trigger_id":"` + source + `"}`
				delete(value, "manual_trigger")
				value["evidence_ids"] = []string{source}
			case "kind only":
				body = `{"environment_id":"` + env + `","trigger_kind":"finding"}`
				want = http.StatusBadRequest
			case "id only":
				body = `{"environment_id":"` + env + `","trigger_id":"` + source + `"}`
				want = http.StatusBadRequest
			case "null kind":
				body = `{"environment_id":"` + env + `","trigger_kind":null}`
				want = http.StatusBadRequest
			case "null id":
				body = `{"environment_id":"` + env + `","trigger_id":null}`
				want = http.StatusBadRequest
			case "empty fields":
				body = `{"environment_id":"` + env + `","trigger_kind":"","trigger_id":""}`
				want = http.StatusBadRequest
			case "caller manual":
				body = `{"environment_id":"` + env + `","trigger_kind":"manual","trigger_id":"` + strings.Repeat("a", 64) + `"}`
				want = http.StatusBadRequest
			case "caller digest":
				body = `{"environment_id":"` + env + `","intent_digest":"sha256:` + strings.Repeat("a", 64) + `"}`
				want = http.StatusBadRequest
			case "duplicate environment":
				body = `{"environment_id":"` + env + `","environment_id":"` + env + `"}`
				want = http.StatusBadRequest
			case "alias":
				body = `{"Environment_ID":"` + env + `"}`
				want = http.StatusBadRequest
			case "foreign environment":
				body = `{"environment_id":"` + source + `"}`
				want = http.StatusBadRequest
			case "null provenance":
				value["manual_trigger"] = nil
			case "missing provenance":
				delete(value, "manual_trigger")
			case "mixed evidence":
				value["evidence_ids"] = []string{source}
			case "null evidence":
				value["evidence_ids"] = nil
			case "wrong definition":
				value["agent_id"] = source
			case "wrong version":
				value["definition_version"] = 2
			case "wrong receipt":
				value["receipt_id"] = source
			case "null replay":
				value["replayed"] = nil
			case "wrong manual version":
				value["manual_trigger"].(map[string]any)["version"] = 2
			case "revoked membership", "revoked permissions":
				want = http.StatusForbidden
			}
			raw, _ := json.Marshal(value)
			if variant == "duplicate response" {
				raw = append([]byte(`{"version":1,`), raw[1:]...)
			}
			db := &manualStartDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{query: raw}}, available: variant != "missing capability"}
			denial := &pgconn.PgError{Code: "42501", Message: "export membership rejected"}
			switch variant {
			case "revoked membership":
				db.queryErr = errors.Join(ErrRepositoryUnavailable, denial)
			case "revoked permissions":
				denial.Message = "export source permission rejected"
				db.queryErr = errors.Join(ErrRepositoryUnavailable, denial)
			case "database privilege failure":
				denial.Message = "permission denied for function zasp_sa_manual_run"
				db.queryErr = errors.Join(ErrRepositoryUnavailable, denial)
			case "wrong denial code":
				denial.Code = "55000"
				db.queryErr = errors.Join(ErrRepositoryUnavailable, denial)
			}
			if variant == "capability error" {
				db.probeErr = ErrRepositoryUnavailable
			}
			repository := &PostgresRepository{database: db, securityAgentExecution: true}
			if variant == "absent capability" {
				repository.database = db.securityAgentRepositoryDatabase
			}
			ids := []string{run, audit, receipt}
			handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC) }, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }})
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": definition}, http.MethodPost, "/api/v1/security-agents/"+definition+"/runs", body)
			request.Header.Set("Idempotency-Key", "manual-start-0001")
			request.Header.Set("If-Match", `"1"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
			if want == http.StatusBadRequest || variant == "missing capability" || variant == "capability error" || variant == "absent capability" {
				if len(db.statements) != 0 {
					t.Fatal("refused request reached mutation SQL")
				}
				return
			}
			if len(db.statements) != 1 || db.statements[0] != query {
				t.Fatalf("wrong admission route: %v", db.statements)
			}
			if variant != "explicit source" {
				wantArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), env, definition, identity.PrincipalID.String(), "manual-start-0001", int64(1), run, audit, testCorrelationID, receipt, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}
				if !reflect.DeepEqual(db.arguments[0], wantArgs) {
					t.Fatalf("manual intent scope/receipt arguments changed: %#v", db.arguments[0])
				}
			}
			if want != http.StatusAccepted {
				if want == http.StatusForbidden {
					var failure struct {
						Code      string `json:"code"`
						Retryable bool   `json:"retryable"`
					}
					if json.Unmarshal(response.Body.Bytes(), &failure) != nil || failure.Code != "authorization_rejected" || failure.Retryable || response.Header().Get("X-Mutation-Receipt-ID") != "" {
						t.Fatal("authority denial remained retryable or exposed a receipt")
					}
				}
				return
			}
			var public SecurityAgentRun
			wantReceipt := value["receipt_id"]
			if variant == "bearer" {
				wantReceipt = ""
			}
			if json.Unmarshal(response.Body.Bytes(), &public) != nil || public.ID != value["id"] || response.Header().Get("X-Mutation-Receipt-ID") != wantReceipt || response.Header().Get("ETag") != `"1"` {
				t.Fatal("admission lost run or original receipt")
			}
			if variant != "explicit source" && (public.ManualTrigger == nil || public.ManualTrigger.IntentDigest != "sha256:"+strings.Repeat("a", 64) || public.EvidenceIDs == nil || len(public.EvidenceIDs) != 0) {
				t.Fatal("manual provenance lost in public response")
			}
		})
	}
}
