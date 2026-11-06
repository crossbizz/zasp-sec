package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentExposureFilterExactPageStatementFencesCombinedPermissionContract(t *testing.T) {
	const query = `SELECT zasp_agent_exposure_filter_v1.page($1,$2,$3,NULLIF($4,''),$5,$6::jsonb,$7)`
	for _, mode := range []string{"normal", "audit", "unknown_selectors", "internal_empty", "wrong_purpose", "foreign_scope", "object_not_collection", "unknown_profile", "blank_risk", "invalid_execution", "invalid_impact", "null_owner", "unknown_member", "duplicate_member", "null_filters", "untyped_filters", "invalid_after", "invalid_limit", "borrow_metadata"} {
		t.Run(mode, func(t *testing.T) {
			g := agentCurrentReadGrant(t, "listAgents")
			g.Collection = true
			pin := migrations.AgentExposureFilterProfileChecksum()
			if mode == "audit" {
				pin = migrations.AgentExposureFilterAuditProfileChecksum()
			}
			filters := json.RawMessage(`{"owner":"","risk":"high","execution":"shell_or_code","impact":"high"}`)
			args := []any{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), "", 1, filters, pin}
			statement := query
			switch mode {
			case "unknown_selectors":
				args[5] = json.RawMessage(`{"risk":"unknown","execution":"unknown","impact":"unknown"}`)
			case "internal_empty":
				args[5] = json.RawMessage(`{}`)
			case "wrong_purpose":
				g.OperationID = "listTools"
			case "foreign_scope":
				args[2] = "pid_88000002-0000-4000-8000-000000000002"
			case "object_not_collection":
				g.Collection = false
			case "unknown_profile":
				args[6] = strings.Repeat("a", 64)
			case "blank_risk":
				args[5] = json.RawMessage(`{"risk":""}`)
			case "invalid_execution":
				args[5] = json.RawMessage(`{"execution":"any"}`)
			case "invalid_impact":
				args[5] = json.RawMessage(`{"impact":"reachable"}`)
			case "null_owner":
				args[5] = json.RawMessage(`{"owner":null}`)
			case "unknown_member":
				args[5] = json.RawMessage(`{"risk":"high","coverage":true}`)
			case "duplicate_member":
				args[5] = json.RawMessage(`{"risk":"high","risk":"low"}`)
			case "null_filters":
				args[5] = json.RawMessage(`null`)
			case "untyped_filters":
				args[5] = string(filters)
			case "invalid_after":
				args[3] = "invalid"
			case "invalid_limit":
				args[4] = 101
			case "borrow_metadata":
				statement = `SELECT zasp_agent_exposure_filter_v1.resolve_risk($1,$2,$3,$4)`
				args = []any{args[0], args[1], args[2], pin}
			}
			var err error
			g, err = attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			accepted := mode == "normal" || mode == "audit" || mode == "unknown_selectors" || mode == "internal_empty"
			if authorizationStatementAllowed(g, statement, args) != accepted {
				t.Fatal("closed exposure page classifier lost exact scope/purpose/filter/pin contract")
			}
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			_, err = db.QueryJSON(ctx, statement, args...)
			if accepted {
				if err != nil || driver.direct || !reflect.DeepEqual(tx.steps, []string{"begin", "fence", "effect", "commit", "rollback"}) {
					t.Fatal("combined page did not use current same-transaction fence and confirmed commit")
				}
			} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
				t.Fatal("denied combined page reached SQL or bypassed purpose fence")
			}
		})
	}
}
