package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const ownershipWriteTestSQL = `SELECT zasp_agent_ownership_write_v1.update_agent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`

// Exact application statement and transaction fence; native ACL/replay/expiry
// acceptance is separate. Positive pins come only from the actual compiler.
func TestAgentCurrentOwnershipWriteClosedPermissionAndTransaction(t *testing.T) {
	for _, mode := range []string{"normal_browser", "audit_browser", "PAT", "no_fresh_auth_required", "wrong_purpose", "foreign_scope", "wrong_actor", "wrong_parent", "denied_parent", "collection", "unknown_profile", "PAT_ceiling_denied", "wrong_credential", "invalid_version", "untyped_tags", "noncanonical_tags", "malformed_key", "legacy_SQL", "fence_refused"} {
		t.Run(mode, func(t *testing.T) {
			g := agentCurrentReadGrant(t, "updateAgent")
			pin := migrations.AgentOwnershipWriteProfileChecksum()
			if mode == "audit_browser" {
				pin = migrations.AgentOwnershipWriteAuditProfileChecksum()
			}
			if mode == "PAT" || mode == "PAT_ceiling_denied" {
				g.Identity.CredentialKind = CredentialBearerToken
				g.Credential.Kind = CredentialBearerToken
				g.Credential.PATCeiling = []string{"manage_workflows"}
			}
			if mode == "no_fresh_auth_required" {
				g.Identity.FreshAuthenticated = false
			}
			args := []any{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String(), g.PathParameters["id"], "agent-owner-key-0001", int64(1), "security", "platform", json.RawMessage(`["critical","production"]`), "pid_60000001-0000-4000-8000-000000000001", "pid_60000002-0000-4000-8000-000000000002", pin}
			query := ownershipWriteTestSQL
			switch mode {
			case "wrong_purpose":
				g.OperationID = "getAgent"
			case "foreign_scope":
				args[2] = "pid_88000002-0000-4000-8000-000000000002"
			case "wrong_actor":
				args[3] = "pid_88000002-0000-4000-8000-000000000002"
			case "wrong_parent":
				args[4] = "pid_88000002-0000-4000-8000-000000000002"
			case "denied_parent":
				g.Allowed = nil
			case "collection":
				g.Collection = true
			case "unknown_profile":
				args[12] = strings.Repeat("a", 64)
			case "PAT_ceiling_denied":
				g.Credential.PATCeiling = []string{"view"}
			case "wrong_credential":
				g.Identity.CredentialKind = CredentialKind(99)
				g.Credential.Kind = CredentialKind(99)
			case "invalid_version":
				args[6] = int64(0)
			case "untyped_tags":
				args[9] = string(`["critical"]`)
			case "noncanonical_tags":
				args[9] = json.RawMessage(`["production","critical"]`)
			case "malformed_key":
				args[5] = "short"
			case "legacy_SQL":
				query = postgresInventoryUpdateAgentSQL
				args = args[:12]
			}
			var e error
			g, e = attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
			if e != nil {
				t.Fatal(e)
			}
			admitted := mode == "normal_browser" || mode == "audit_browser" || mode == "PAT" || mode == "no_fresh_auth_required" || mode == "fence_refused"
			if authorizationStatementAllowed(g, query, args) != admitted {
				t.Fatal("fixed current ownership statement lost actor/parent/purpose/credential/input/profile boundary")
			}
			tx := &authorizationTxFixture{}
			if mode == "fence_refused" {
				tx.fenceError = errors.New("stale current proof")
			}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			_, e = db.QueryJSON(ctx, query, args...)
			if admitted && mode != "fence_refused" {
				if e != nil || driver.direct || !reflect.DeepEqual(tx.steps, []string{"begin", "fence", "effect", "commit", "rollback"}) {
					t.Fatal("ownership effect escaped confirmed current transaction")
				}
			} else if mode == "fence_refused" {
				if e == nil || driver.direct || !reflect.DeepEqual(tx.steps, []string{"begin", "fence", "rollback"}) {
					t.Fatal("refused current fence reached mutation/replay")
				}
			} else if !errors.Is(e, ErrAuthorizationDenied) || driver.direct || len(tx.steps) != 0 {
				t.Fatal("denied ownership SQL reached Begin/effect")
			}
		})
	}
}

type ownershipWriteHandlerDatabase struct {
	inventoryJSONDatabase
	replay bool
}

func (d *ownershipWriteHandlerDatabase) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	d.statement = q
	d.arguments = append([]any(nil), args...)
	if d.err != nil {
		return nil, d.err
	}
	if q != ownershipWriteTestSQL || len(args) != 13 {
		return nil, ErrAuthorizationDenied
	}
	var agent InventorySummary
	if json.Unmarshal([]byte(inventorySummaryJSON(args[4].(string), "agent")), &agent) != nil {
		return nil, ErrRepositoryUnavailable
	}
	agent.Owner = args[7].(string)
	agent.Team = args[8].(string)
	agent.Version = args[6].(int64) + 1
	if json.Unmarshal(args[9].(json.RawMessage), &agent.Tags) != nil {
		return nil, ErrRepositoryUnavailable
	}
	audit, correlation := args[10].(string), args[11].(string)
	if d.replay {
		audit = "pid_70000001-0000-4000-8000-000000000001"
		correlation = "pid_70000002-0000-4000-8000-000000000002"
	}
	return json.Marshal(AgentMutationResult{Agent: agent, AuditID: audit, CorrelationID: correlation, Replayed: d.replay})
}

// Actual typed repository+handler composition, preserving original If-Match,
// sorting, replay-aware audit response and unavailable/no-fallback behavior.
func TestAgentCurrentOwnershipWriteActualHandlerSelectsPrivateProfile(t *testing.T) {
	for _, mode := range []string{"normal", "audit", "replay", "unavailable", "profile_unset", "malformed_body"} {
		t.Run(mode, func(t *testing.T) {
			g := agentCurrentReadGrant(t, "updateAgent")
			d := &ownershipWriteHandlerDatabase{replay: mode == "replay"}
			if mode == "unavailable" {
				d.err = ErrRepositoryUnavailable
			}
			repository := &PostgresInventoryRepository{database: d}
			if mode != "profile_unset" {
				pin := migrations.AgentOwnershipWriteProfileChecksum()
				if mode == "audit" {
					pin = migrations.AgentOwnershipWriteAuditProfileChecksum()
				}
				if e := repository.RequireAgentOwnershipWriteProfile(pin); e != nil {
					t.Fatal(e)
				}
			}
			h, e := newInventoryHTTPHandler(repository, []byte(strings.Repeat("a", 32)))
			if e != nil {
				t.Fatal(e)
			}
			request := httptest.NewRequest(http.MethodPatch, "/api/v1/agents/"+g.PathParameters["id"], nil)
			body := `{"owner":"security","team":"platform","tags":["production","critical"]}`
			if mode == "malformed_body" {
				body = `{"owner":"security","team":"platform","tags":[],"secret":true}`
			}
			request.Body = io.NopCloser(strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "agent-owner-key-0001")
			ctx := context.WithValue(request.Context(), identityContextKey{}, g.Identity)
			ctx = context.WithValue(ctx, routedOperationContextKey{}, RoutedOperation{OperationID: "updateAgent", PathParameters: g.PathParameters})
			ctx = context.WithValue(ctx, requestAuthorizationContextKey{}, g)
			ctx = context.WithValue(ctx, correlationContextKey{}, "pid_60000002-0000-4000-8000-000000000002")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request.WithContext(ctx))
			if mode == "profile_unset" || mode == "malformed_body" {
				if w.Code == http.StatusOK || d.statement != "" {
					t.Fatal("unselected/malformed current ownership request reached legacy or private SQL")
				}
				return
			}
			if mode == "unavailable" {
				if w.Code == http.StatusOK || d.statement != ownershipWriteTestSQL {
					t.Fatal("private profile failure fell back or returned success")
				}
				return
			}
			if w.Code != http.StatusOK || w.Header().Get("ETag") != `"2"` || d.statement != ownershipWriteTestSQL || len(d.arguments) != 13 || string(d.arguments[9].(json.RawMessage)) != `["critical","production"]` || !strings.Contains(w.Body.String(), g.PathParameters["id"]) {
				t.Fatal("actual current PATCH lost private selector/atomic result/preconditions", w.Code)
			}
			if mode == "replay" && w.Header().Get("X-Audit-ID") != "pid_70000001-0000-4000-8000-000000000001" {
				t.Fatal("replay replaced immutable original audit identity")
			}
		})
	}
}
