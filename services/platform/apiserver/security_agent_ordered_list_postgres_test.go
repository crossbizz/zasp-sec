package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentOrderedListSuccessorCandidatePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedApplication(t, ctx, owner, key, stored)
		if _, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "complete", 5, 2), keys); err != nil {
			t.Fatal(err)
		}
		if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, run, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
			t.Fatal(err)
		}
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		page, err := a.repository.invoke(ctx, id, "approval_candidates", map[string]any{"resource_filter": run, "state_filter": "pending", "limit": 10, "before_created_at": "", "before_id": ""})
		var wire struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err != nil || json.Unmarshal(page, &wire) != nil || len(wire.Items) != 1 {
			t.Fatalf("successor candidate: %s, %v", page, err)
		}
		h := orderedListPostgresHandler(t, a)
		got := orderedListCall(t, h, id, "listSecurityAgentApprovals", "run_id="+run+"&state=pending", 200)
		var result struct {
			Items []SecurityAgentApproval `json:"items"`
		}
		if json.Unmarshal(got.Body.Bytes(), &result) != nil || len(result.Items) != 1 || result.Items[0].StepID != steps[1] || result.Items[0].ExpectedEffect != "Run existing test" || result.Items[0].Reversible || result.Items[0].TTLSeconds != 0 {
			t.Fatal(got.Body.String())
		}
		orderedListCall(t, h, id, "listSecurityAgentApprovals", "run_id="+run, 200)
		first := orderedListCall(t, h, id, "listSecurityAgentApprovals", "run_id="+run+"&limit=1", 200)
		var firstPage struct {
			Items []SecurityAgentApproval `json:"items"`
			Next  string                  `json:"next_cursor"`
		}
		if json.Unmarshal(first.Body.Bytes(), &firstPage) != nil || len(firstPage.Items) != 1 || firstPage.Next == "" {
			t.Fatal(first.Body.String())
		}
		second := orderedListCall(t, h, id, "listSecurityAgentApprovals", "run_id="+run+"&limit=1&cursor="+firstPage.Next, 200)
		var secondPage struct {
			Items []SecurityAgentApproval `json:"items"`
			Next  string                  `json:"next_cursor"`
		}
		if json.Unmarshal(second.Body.Bytes(), &secondPage) != nil || len(secondPage.Items) != 1 || secondPage.Next != "" || secondPage.Items[0].ID == firstPage.Items[0].ID {
			t.Fatal(second.Body.String())
		}
		bearer := id
		bearer.CredentialKind = CredentialBearerToken
		orderedListCall(t, h, bearer, "listSecurityAgentApprovals", "run_id="+run, 400)
	})
}

func orderedListPostgresHandler(t *testing.T, a *SecurityAgentOrderedResourceAuthority) http.Handler {
	t.Helper()
	legacy := orderedListLegacyRepository(a)
	h, err := newSecurityAgentOrderedHTTPHandler(a, legacy, func() (http.Handler, error) {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("list delegated") }), nil
	}, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Limit this fixture to the committed QueryJSON contract. The unrelated dirty
// overlay adds optional release54/55 capability methods to this concrete DB;
// hiding those in tests does not change the committed repository's behavior.
type orderedListSQLDatabase struct{ JSONDatabase }

func orderedListLegacyRepository(a *SecurityAgentOrderedResourceAuthority) *PostgresRepository {
	return &PostgresRepository{database: orderedListSQLDatabase{a.repository.database}, securityAgentExecution: true, schema: SecurityAgentSessionIsolationSchemaVersion}
}

func orderedListCall(t *testing.T, h http.Handler, id RequestIdentity, op, query string, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := orderedHTTPRequest(id, op, "GET", "", "")
	r.URL.RawQuery = query
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s ?%s: %d %s", op, query, w.Code, w.Body.String())
	}
	return w
}

func TestSecurityAgentOrderedListMixedPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		const legacyDefinition = "pid_ffffffff-ffff-4fff-8fff-fffffffffff1"
		const legacyRun = "pid_f2000001-0000-4000-8000-000000000001"
		triggerKeyLegacyFixture(t, ctx, owner, api, o, w, e, actor, legacyDefinition, "list-legacy-first-trigger")
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		if _, err := a.Activate(ctx, id, SecurityAgentOrderedActivation{public62Definition, 1, "supervised", "list-ordered-activation"}); err != nil {
			t.Fatal(err)
		}
		run, err := a.Trigger(ctx, id, SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{public62Definition, 2, public62Finding, 1, "list-ordered-trigger"}, "finding", "credential"})
		if err != nil {
			t.Fatal(err)
		}
		newLegacy := func(n int, runID string) {
			t.Helper()
			finding := fmt.Sprintf("pid_0700000%d-0000-4000-8000-000000000001", n)
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','List trigger','high','open')`, o, w, e, finding); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			args := []any{o, w, e, legacyDefinition, actor, fmt.Sprintf("list-legacy-trigger-%d", n), 3, runID, "finding", finding, fmt.Sprintf("pid_0800000%d-0000-4000-8000-000000000001", n), fmt.Sprintf("pid_0800000%d-0000-4000-8000-000000000002", n), fmt.Sprintf("pid_0800000%d-0000-4000-8000-000000000003", n)}
			if err := api.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
		const low = "pid_01000001-0000-4000-8000-000000000001"
		newLegacy(1, low)
		stamp := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET created_at=$4 WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e, stamp); err != nil {
			t.Fatal(err)
		}
		h := orderedListPostgresHandler(t, a)
		first := orderedListCall(t, h, id, "listSecurityAgentRuns", "limit=2", 200)
		var firstPage struct {
			Items []SecurityAgentRun `json:"items"`
			Next  string             `json:"next_cursor"`
		}
		if json.Unmarshal(first.Body.Bytes(), &firstPage) != nil || len(firstPage.Items) != 2 || firstPage.Next == "" {
			t.Fatal(first.Body.String())
		}
		newLegacy(2, "pid_ffffffff-ffff-4fff-8fff-fffffffffff2")
		second := orderedListCall(t, h, id, "listSecurityAgentRuns", "limit=2&cursor="+firstPage.Next, 200)
		var secondPage struct {
			Items []SecurityAgentRun `json:"items"`
			Next  string             `json:"next_cursor"`
		}
		if json.Unmarshal(second.Body.Bytes(), &secondPage) != nil || len(secondPage.Items) != 1 || secondPage.Next != "" {
			t.Fatal(second.Body.String())
		}
		want := []string{legacyRun, run.ID, low}
		sort.Sort(sort.Reverse(sort.StringSlice(want)))
		got := []string{firstPage.Items[0].ID, firstPage.Items[1].ID, secondPage.Items[0].ID}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatal(got, want)
		}
		// Pure legacy results retain the established page bytes and signed cursor.
		legacy := orderedListLegacyRepository(a)
		old := &securityAgentPublicHTTPHandler{repository: legacy, config: SecurityAgentPublicHandlerConfig{SigningKey: []byte(strings.Repeat("k", 32))}}
		r := orderedHTTPRequest(id, "listSecurityAgentRuns", "GET", "", "")
		r.URL.RawQuery = "agent_id=" + legacyDefinition + "&limit=2"
		expected := httptest.NewRecorder()
		old.listRuns(expected, r, RoutedOperation{})
		actual := orderedListCall(t, h, id, "listSecurityAgentRuns", r.URL.RawQuery, 200)
		if expected.Body.String() != actual.Body.String() {
			t.Fatal("legacy bytes differ", expected.Body.String(), actual.Body.String())
		}
		bearer := id
		bearer.CredentialKind = CredentialBearerToken
		orderedListCall(t, h, bearer, "listSecurityAgentRuns", "agent_id="+legacyDefinition, 200)
		orderedListCall(t, h, bearer, "listSecurityAgentRuns", "", 400)
		foreign := id
		other, _ := domain.ParseProductID("pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
		foreign.Scope, _ = domain.NewScope(other, id.Scope.WorkspaceID(), id.Scope.EnvironmentID())
		before := public62Snapshot(t, ctx, owner)
		orderedListCall(t, h, foreign, "listSecurityAgentRuns", "", 503)
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("foreign read mutated owner")
		}
		// An authorized but empty foreign organization cannot see the owner's IDs.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'list-foreign-org','list-foreign-member','security_engineer',true);
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'List foreign scope','["view"]',false)`, pgx.QueryExecModeSimpleProtocol, actor, other.String(), w, e); err != nil {
			t.Fatal(err)
		}
		before = public62Snapshot(t, ctx, owner)
		for _, op := range []string{"listSecurityAgentRuns", "listSecurityAgentApprovals"} {
			if got := orderedListCall(t, h, foreign, op, "", 200); got.Body.String() != "{\"items\":[]}\n" {
				t.Fatal(got.Body.String())
			}
		}
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("authorized foreign read changed owner")
		}
		// Immutable history remains the ordered resource authority after revision/deletion.
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET deleted_at=clock_timestamp(),body=(body-'existing_test')||jsonb_build_object('allowed_actions',jsonb_build_array('update_finding_response'),'max_steps',1,'verification_kind','finding_state') WHERE definition_id=$1`, public62Definition); err != nil {
			t.Fatal(err)
		}
		orderedListCall(t, h, id, "listSecurityAgentRuns", "agent_id="+public62Definition, 200)
		conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		restarted, _ := orderedResourceGo(t, conn, o, w, e, actor)
		orderedListCall(t, orderedListPostgresHandler(t, restarted), id, "listSecurityAgentRuns", "agent_id="+public62Definition, 200)
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET intent=intent-'trigger_version' WHERE idempotency_key='list-ordered-trigger'`); err != nil {
			t.Fatal(err)
		}
		before = public62Snapshot(t, ctx, owner)
		orderedListCall(t, h, id, "listSecurityAgentRuns", "", 503)
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("corrupt page changed state")
		}
	})
}

func TestSecurityAgentOrderedListCandidateSecurityPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		for _, op := range []string{"run_candidates", "approval_candidates"} {
			q := public62Request(o, w, e, actor, op)
			q["resource_filter"], q["state_filter"], q["limit"], q["before_created_at"], q["before_id"] = "", "", 100, "", ""
			for name, mutate := range map[string]func(map[string]any){"extra": func(q map[string]any) { q["private"] = true }, "over-limit": func(q map[string]any) { q["limit"] = 101 }, "wrong-limit-type": func(q map[string]any) { q["limit"] = "1" }, "null": func(q map[string]any) { q["resource_filter"] = nil }, "bad-filter": func(q map[string]any) { q["resource_filter"] = "bad" }, "state": func(q map[string]any) { q["state_filter"] = "simulated" }, "cursor-pair": func(q map[string]any) { q["before_id"] = public62Definition }, "cursor-date": func(q map[string]any) {
				q["before_id"] = public62Definition
				q["before_created_at"] = "2026-99-20T00:00:00.000000Z"
			}} {
				t.Run(op+"/"+name, func(t *testing.T) {
					bad := map[string]any{}
					for k, v := range q {
						bad[k] = v
					}
					mutate(bad)
					_, err := public62Call(ctx, api, bad)
					if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "22023" {
						t.Fatal(err)
					}
				})
			}
		}
		var exposed bool
		if err := api.QueryRow(ctx, `SELECT has_function_privilege(current_user,'zasp_ordered_public62.candidates(jsonb)','EXECUTE') OR has_table_privilege(current_user,'zasp_security_agent_runs','SELECT') OR has_table_privilege(current_user,'zasp_security_agent_approvals','SELECT') OR has_table_privilege(current_user,'zasp_ordered_public62.registration','SELECT')`).Scan(&exposed); err != nil || exposed {
			t.Fatal("private authority exposed", exposed, err)
		}
		for name, drift := range map[string]string{"acl": `GRANT EXECUTE ON FUNCTION zasp_ordered_public62.candidates(jsonb) TO zasp_security_agent_api`, "owner": `ALTER FUNCTION zasp_ordered_public62.candidates(jsonb) OWNER TO CURRENT_USER`, "rls": `ALTER TABLE zasp_ordered_public62.registration DISABLE ROW LEVEL SECURITY`, "registration": `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64)`} {
			t.Run(name, func(t *testing.T) {
				before := public62Snapshot(t, ctx, owner)
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, drift); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				other, _ := orderedResourceGo(t, owner, o, w, e, actor)
				if _, err := other.candidates(ctx, id, "run_candidates", "", "", 10, time.Time{}, ""); err != ErrRepositoryUnavailable {
					t.Error(err)
				}
				if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("drift test changed state")
				}
			})
		}
		for _, up := range []bool{true, false, false, true} {
			var err error
			if up {
				err = runner.UpProductionSecurityAgentPublic(ctx)
			} else {
				err = runner.DownProductionSecurityAgentPublic(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.candidates(ctx, id, "run_candidates", "", "", 100, time.Time{}, "")
			if up && err != nil || !up && err != ErrRepositoryUnavailable {
				t.Fatal(up, err)
			}
		}
	})
}
