package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Catch SQL/API contract drift, duplicate admission after a lost HTTP reply,
// and replay borrowing a revoked actor's authority. The real handler/repository
// use the registered API login. Identity is supplied at the middleware boundary;
// this is not proof of browser authentication or public definition activation.
func TestSecurityAgentManualHTTPPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "create_evidence_export", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _, actor, definition string, version int64) {
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository := &PostgresRepository{database: database, securityAgentExecution: true}
		parse := func(raw string) domain.ProductID {
			t.Helper()
			id, err := domain.ParseProductID(raw)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		scope, err := domain.NewScope(parse(o), parse(w), parse(e))
		if err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		identity.Scope, identity.PrincipalID = scope, parse(actor)
		identity.Permissions = []string{"view", "manage_workflows", "view_audit"}
		sequence := 0
		handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{
			Clock:      func() time.Time { return time.Now().UTC() },
			SigningKey: securityAgentTestSigningKey,
			NewProductID: func() (string, error) {
				sequence++
				return fmt.Sprintf("pid_8e200001-0000-4000-8000-%012d", sequence), nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		request := func(key string, expected int64) *httptest.ResponseRecorder {
			t.Helper()
			r := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": definition}, http.MethodPost, "/api/v1/security-agents/"+definition+"/runs", `{"environment_id":"`+e+`"}`)
			r.Header.Set("Idempotency-Key", key)
			r.Header.Set("If-Match", `"`+strconv.FormatInt(expected, 10)+`"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			return response
		}
		counts := func() [4]int {
			t.Helper()
			var result [4]int
			err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_request_receipts WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_audit WHERE organization_id=$1)`, o).Scan(&result[0], &result[1], &result[2], &result[3])
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
		if initial := counts(); initial != [4]int{} {
			t.Fatalf("fixture already contains execution authority: %v", initial)
		}
		first := request("manual-http-intent-0001", version)
		if first.Code != http.StatusAccepted {
			t.Fatalf("public manual admission status=%d body=%s", first.Code, first.Body.String())
		}
		var run SecurityAgentRun
		if err := json.Unmarshal(first.Body.Bytes(), &run); err != nil || run.ID != "pid_8e200001-0000-4000-8000-000000000001" || run.AgentID != definition || run.DefinitionVersion != version || run.State != "queued" || run.ManualTrigger == nil || run.ManualTrigger.Kind != "manual" || run.ManualTrigger.Version != 1 || run.EvidenceIDs == nil || len(run.EvidenceIDs) != 0 {
			t.Fatalf("public admission lost original manual authority: %#v %v", run, err)
		}
		if first.Header().Get("X-Mutation-Receipt-ID") != "pid_8e200001-0000-4000-8000-000000000003" || first.Header().Get("ETag") != `"1"` || counts() != [4]int{1, 1, 1, 1} {
			t.Fatal("admission did not return and persist one original receipt")
		}
		// A retry is a new HTTP invocation with newly generated IDs. The original
		// response is retained even if the client never received its first copy.
		retry := request("manual-http-intent-0001", version)
		if retry.Code != http.StatusAccepted || retry.Body.String() != first.Body.String() || retry.Header().Get("X-Mutation-Receipt-ID") != first.Header().Get("X-Mutation-Receipt-ID") || counts() != [4]int{1, 1, 1, 1} {
			t.Fatalf("retry changed admission: status=%d body=%s", retry.Code, retry.Body.String())
		}
		read := func(operation, path, id string) *httptest.ResponseRecorder {
			t.Helper()
			r := workflowRequest(t, identity, testCorrelationID, operation, map[string]string{"id": id}, http.MethodGet, path, "")
			r.Header.Set("X-Zasp-Run-Context", "v1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("persisted HTTP read %s status=%d body=%s", operation, response.Code, response.Body.String())
			}
			return response
		}
		var page struct {
			Items []SecurityAgentRun `json:"items"`
		}
		pageResponse := read("listSecurityAgentRuns", "/api/v1/security-agent-runs?agent_id="+definition+"&environment_id="+e+"&limit=10", "")
		if err := json.Unmarshal(pageResponse.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].ID != run.ID || !sameSecurityAgentManualTrigger(page.Items[0].ManualTrigger, run.ManualTrigger) || page.Items[0].EvidenceIDs == nil || len(page.Items[0].EvidenceIDs) != 0 {
			t.Fatalf("persisted HTTP run page lost manual authority: %#v %v", page, err)
		}
		var detail SecurityAgentRunDetail
		detailResponse := read("getSecurityAgentRun", "/api/v1/security-agent-runs/"+run.ID, run.ID)
		if err := json.Unmarshal(detailResponse.Body.Bytes(), &detail); err != nil || detail.Run.ID != run.ID || !sameSecurityAgentManualTrigger(detail.Run.ManualTrigger, run.ManualTrigger) || detail.EvidenceIDs == nil || len(detail.EvidenceIDs) != 0 || detail.RunContext == nil {
			t.Fatalf("persisted HTTP run detail lost manual authority: %#v %v", detail, err)
		}
		changed := request("manual-http-intent-0001", version+1)
		if changed.Code != http.StatusConflict || counts() != [4]int{1, 1, 1, 1} {
			t.Fatalf("changed-version retry was not a side-effect-free conflict: %d %s", changed.Code, changed.Body.String())
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"manual-http-intent-0001", "manual-http-intent-0002"} {
			denied := request(key, version)
			if denied.Code != http.StatusForbidden || denied.Header().Get("X-Mutation-Receipt-ID") != "" || counts() != [4]int{1, 1, 1, 1} {
				t.Fatalf("revoked actor retained HTTP admission authority: %d %s", denied.Code, denied.Body.String())
			}
		}
	})
}
