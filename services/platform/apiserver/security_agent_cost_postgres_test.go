package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This is a migrated local API/repository test, not a live provider spending test.
func TestProductionSecurityAgentCostDefinitionWriteRead(t *testing.T) {
	runSecurityAgentCostDefinitionFixture(t, nil)
}

func runSecurityAgentCostDefinitionFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *PostgresRepository, RequestIdentity, string)) {
	t.Helper()
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		identity := fixtureRequestIdentity(t)
		org, _ := domain.ParseProductID("pid_6a000001-0000-4000-8000-000000000001")
		workspace, _ := domain.ParseProductID("pid_6a000002-0000-4000-8000-000000000002")
		environment, _ := domain.ParseProductID("pid_6a000003-0000-4000-8000-000000000003")
		var err error
		identity.Scope, err = domain.NewScope(org, workspace, environment)
		if err != nil {
			t.Fatal(err)
		}
		identity.CredentialKind = CredentialBrowserSession
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_api_login"
		config.Tracer = costDefinitionQueryTrace{t: t}
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close(context.Background())
		// Keep driver timestamp decoding independent of the host's timezone.
		if _, err := connection.Exec(ctx, `SET TIME ZONE 'UTC'`); err != nil {
			t.Fatal(err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		definition := map[string]any{"name": "Explicit cost response", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{environment.String()}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": int64(123456789), "concurrency_limit": 1, "allowed_actions": []string{"update_finding_response"}, "verification_kind": "finding_state", "definition_version": 1, "enabled": false}
		var id string
		for _, action := range []string{"create", "update"} {
			method, operation, path := http.MethodPost, "createSecurityAgent", "/api/v1/security-agents"
			var params map[string]string
			if action == "update" {
				method, operation, path = http.MethodPut, "updateSecurityAgent", path+"/"+id
				params = map[string]string{"id": id}
				definition["id"] = id
				definition["max_ai_cost_nano_credits"] = int64(987654321)
			}
			body, err := json.Marshal(definition)
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", operation, params, method, path, string(body))
			request.Header.Set("Idempotency-Key", "cost-definition-"+action+"-0001")
			if action == "update" {
				request.Header.Set("If-Match", `"1"`)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantStatus := http.StatusCreated
			if action == "update" {
				wantStatus = http.StatusOK
			}
			if response.Code != wantStatus {
				t.Fatalf("%s status=%d body=%s", action, response.Code, response.Body.String())
			}
			var result struct {
				ID   string `json:"id"`
				Cost int64  `json:"max_ai_cost_nano_credits"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Cost != definition["max_ai_cost_nano_credits"].(int64) {
				t.Fatalf("%s response cost=%d", action, result.Cost)
			}
			id = result.ID
			state, err := repository.GetSecurityAgentActivation(ctx, identity, id)
			if err != nil || state.Activation != "draft" || state.Enabled {
				t.Fatalf("%s state=%+v err=%v", action, state, err)
			}
			var exact bool
			if err := owner.QueryRow(ctx, `SELECT body->>'max_ai_cost_nano_credits'=$5 FROM zasp_security_agent_definitions WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND definition_id=$4`, org.String(), workspace.String(), environment.String(), id, strconv.FormatInt(result.Cost, 10)).Scan(&exact); err != nil || !exact {
				t.Fatalf("%s durable cost=%v err=%v", action, exact, err)
			}
		}
		if exercise != nil {
			exercise(ctx, owner, repository, identity, id)
		}
	})
}

// Report database failure locations without logging statement arguments or bodies.
type costDefinitionQueryTrace struct{ t *testing.T }

func (trace costDefinitionQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (trace costDefinitionQueryTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	var failure *pgconn.PgError
	if errors.As(data.Err, &failure) {
		trace.t.Logf("database failure: code=%s message=%s location=%s", failure.Code, failure.Message, failure.Where)
	}
}

func TestProductionSecurityAgentActivationRequiresCostAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, cost string
		valid      bool
	}{
		{"configured", "987654321", true}, {"minimum", "1", true}, {"maximum", "1000000000000", true},
		{"missing", "", false}, {"null", "null", false}, {"zero", "0", false},
		{"negative", "-1", false}, {"excess", "1000000000001", false}, {"string", `"1"`, false},
		{"fraction", "1.5", false}, {"overflow", "9223372036854775808", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runSecurityAgentCostDefinitionFixture(t, func(ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, id string) {
				if tc.cost == "" {
					// Model a readable legacy definition. Both modes use identical activation calls.
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=body-'max_ai_cost_nano_credits' WHERE organization_id=$1 AND definition_id=$2`, identity.Scope.OrganizationID().String(), id); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=body||jsonb_build_object('max_ai_cost_nano_credits',$3::jsonb) WHERE organization_id=$1 AND definition_id=$2`, identity.Scope.OrganizationID().String(), id, tc.cost); err != nil {
						t.Fatal(err)
					}
				}
				identity.FreshAuthenticated = true
				identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
				snapshot := func() string {
					t.Helper()
					var value string
					if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_definitions t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_definition_versions t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_request_receipts t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_audit t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_kill_switches t))::text`).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				for index, target := range []string{"validated", "supervised", "autonomous"} {
					if !tc.valid && target == "autonomous" {
						// Independently exercise upgrade of an older enabled definition.
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='supervised',version=4,body=body||'{"enabled":true}'::jsonb WHERE organization_id=$1 AND definition_id=$2`, identity.Scope.OrganizationID().String(), id); err != nil {
							t.Fatal(err)
						}
					}
					input := SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "cost-activation-" + target + "-0001", ExpectedVersion: int64(index + 2), TargetActivation: target, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: "pid_aa000001-0000-4000-8000-00000000000" + strconv.Itoa(index+1), CorrelationID: "pid_bb000001-0000-4000-8000-000000000001", ReceiptID: "pid_cc000001-0000-4000-8000-00000000000" + strconv.Itoa(index+1)}
					before := snapshot()
					result, err := repository.ActivateSecurityAgent(ctx, identity, input)
					if !tc.valid && target != "validated" {
						if !errors.Is(err, ErrRepositoryCostBudgetRequired) {
							t.Errorf("%s invalid cost result=%+v err=%v", target, result, err)
						}
						if snapshot() != before {
							t.Errorf("%s refusal changed definition, revision, receipt, audit or controls", target)
						}
					} else if err != nil || result.Activation != target {
						t.Fatalf("%s result=%+v err=%v", target, result, err)
					} else {
						settled := snapshot()
						replay, err := repository.ActivateSecurityAgent(ctx, identity, input)
						if err != nil || !replay.Replayed {
							t.Fatalf("%s replay=%+v err=%v", target, replay, err)
						}
						replay.Replayed = false
						if replay != result || snapshot() != settled {
							t.Fatalf("%s replay changed response or durable state", target)
						}
					}
				}
			})
		})
	}
}
