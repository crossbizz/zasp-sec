package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are real registered API reads of prepared intent, not executed tests.
func exerciseExistingTestApprovalReads(t *testing.T, ctx context.Context, api *pgx.Conn, org, ws, env, run, approval, step, testID, action string) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	o, _ := domain.ParseProductID(org)
	w, _ := domain.ParseProductID(ws)
	e, _ := domain.ParseProductID(env)
	identity.Scope, _ = domain.NewScope(o, w, e)
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	pin := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	for _, mode := range []string{"approval", "page", "run"} {
		t.Run("read_"+mode, func(t *testing.T) {
			var raw json.RawMessage
			args := []any{org, ws, env, approval}
			statement := `SELECT zasp_production_security_agent_existing_tests_approval($1,$2,$3,$4,$5,$6)`
			private := `SELECT zasp_production_security_agent_existing_tests_approval_ctx_core($1,$2,$3,$4)`
			if mode == "page" {
				statement = `SELECT zasp_production_security_agent_existing_tests_approval_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
				args = []any{org, ws, env, "pending", run, nil, nil, 10}
				private = `SELECT zasp_production_security_agent_existing_tests_page_ctx_core($1,$2,$3,$4,$5,$6,$7,$8)`
			} else if mode == "run" {
				statement = `SELECT zasp_production_security_agent_existing_tests_run_context($1,$2,$3,$4,$5,$6)`
				args[3] = run
				private = `SELECT zasp_production_security_agent_existing_tests_run_context_core($1,$2,$3,$4)`
			}
			var refused *pgconn.PgError
			if err := api.QueryRow(ctx, private, args...).Scan(&raw); !errors.As(err, &refused) || refused.Code != "42501" {
				t.Fatalf("private read core exposed: %v", err)
			}
			args = append(args, pin...)
			badPin := append([]any(nil), args...)
			badPin[len(badPin)-1] = "invalid-release"
			if err := api.QueryRow(ctx, statement, badPin...).Scan(&raw); !errors.As(err, &refused) || refused.Code != "55000" {
				t.Fatalf("read accepted stale release: %v", err)
			}
			for dimension := 0; dimension < 3; dimension++ {
				foreign := append([]any(nil), args...)
				foreign[dimension] = "pid_89c0ff00-0000-4000-8000-000000000001"
				err := api.QueryRow(ctx, statement, foreign...).Scan(&raw)
				if mode != "page" {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatalf("foreign dimension %d read=%s err=%v", dimension, raw, err)
					}
					continue
				}
				var page struct {
					Items         []json.RawMessage `json:"items"`
					NextCreatedAt *string           `json:"next_created_at"`
					NextID        *string           `json:"next_id"`
				}
				if err != nil || !exactJSONFields(raw, "items", "next_created_at", "next_id") || json.Unmarshal(raw, &page) != nil || page.Items == nil || len(page.Items) != 0 || page.NextCreatedAt != nil || page.NextID != nil {
					t.Fatalf("foreign dimension %d page=%s err=%v", dimension, raw, err)
				}
			}
			if err := api.QueryRow(ctx, statement, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "approval":
				value, err := decodeApprovalContextEnvelope(raw, approval)
				if err != nil || value.Context == nil || value.Context.Action != action || value.Context.TargetID == nil || *value.Context.TargetID != testID {
					t.Fatalf("API approval decode: %+v %v", value, err)
				}
				stored, err := repository.GetSecurityAgentApproval(ctx, identity, approval)
				if err != nil || stored.Context == nil || stored.Context.Action != action {
					t.Fatalf("repository approval read: %+v %v", stored, err)
				}
			case "page":
				value, err := decodeApprovalContextPage(raw, SecurityAgentApprovalPageRequest{RunID: run, State: "pending", Limit: 10})
				if err != nil || len(value.Items) != 1 || value.Items[0].Context == nil || value.Items[0].Context.Action != action {
					t.Fatalf("API approval page decode: %+v %v", value, err)
				}
				stored, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{RunID: run, State: "pending", Limit: 10})
				if err != nil || len(stored.Items) != 1 || stored.Items[0].Context == nil || stored.Items[0].Context.Action != action {
					t.Fatalf("repository approval page: %+v %v", stored, err)
				}
			case "run":
				value, err := decodeSecurityAgentRunContextEnvelope(raw, run)
				if err != nil || len(value.ActionDetails) != 1 || value.ActionDetails[0].Arguments == nil || value.ActionDetails[0].Arguments.TargetID != testID || value.ActionDetails[0].Arguments.ExpectedVersion != 1 || value.ActionDetails[0].Verification.State != "unavailable" || value.ActionDetails[0].Rollback.Support != "not_supported" {
					t.Fatalf("API run context decode: %+v %v", value, err)
				}
				stored, err := repository.GetSecurityAgentRun(ctx, identity, run)
				if err != nil || len(stored.ActionDetails) != 1 || stored.ActionDetails[0].Arguments == nil || stored.ActionDetails[0].Arguments.TargetID != testID {
					t.Fatalf("repository run read: %+v %v", stored, err)
				}
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			if mode == "page" {
				var items []json.RawMessage
				if err := json.Unmarshal(envelope["items"], &items); err != nil || len(items) != 1 {
					t.Fatalf("page=%s %v", raw, err)
				}
				if err := json.Unmarshal(items[0], &envelope); err != nil {
					t.Fatal(err)
				}
			}
			var detail map[string]json.RawMessage
			if err := json.Unmarshal(envelope["detail"], &detail); err != nil {
				t.Fatal(err)
			}
			if mode == "run" {
				var approvals []SecurityAgentApproval
				if err := json.Unmarshal(detail["approvals"], &approvals); err != nil || len(approvals) != 1 || approvals[0].ID != approval {
					t.Fatalf("run approvals=%s %v", raw, err)
				}
				var actions struct {
					Steps []struct {
						StepID    string          `json:"step_id"`
						Action    string          `json:"action"`
						Arguments json.RawMessage `json:"arguments"`
					} `json:"steps"`
				}
				if err := json.Unmarshal(envelope["action_details"], &actions); err != nil || len(actions.Steps) != 1 || actions.Steps[0].StepID != step || actions.Steps[0].Action != action {
					t.Fatalf("run action details=%s %v", raw, err)
				}
				assertExistingTestReadArguments(t, actions.Steps[0].Arguments, testID)
			} else {
				var value SecurityAgentApproval
				if err := json.Unmarshal(envelope["detail"], &value); err != nil || value.ID != approval || value.RunID != run || value.StepID != step || value.State != "pending" || value.Reversible {
					t.Fatalf("approval=%s %v", raw, err)
				}
				var context struct {
					Action    string          `json:"action"`
					Arguments json.RawMessage `json:"arguments"`
				}
				if err := json.Unmarshal(envelope["context"], &context); err != nil || context.Action != action {
					t.Fatalf("approval context=%s %v", raw, err)
				}
				assertExistingTestReadArguments(t, context.Arguments, testID)
			}
		})
	}
}

func assertExistingTestReadArguments(t *testing.T, raw json.RawMessage, testID string) {
	t.Helper()
	var value struct {
		TargetID        string `json:"target_id"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	if !exactJSONFields(raw, "target_id", "expected_version") || json.Unmarshal(raw, &value) != nil || value.TargetID != testID || value.ExpectedVersion != 1 {
		t.Fatalf("unbound or unsafe test arguments: %s", raw)
	}
}
