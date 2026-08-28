package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestPolicyDecisionRepositoryListsExactTenantPolicyHistory(t *testing.T) {
	scope := policyDecisionScope(t)
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"block","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T12:00:00Z"}]}`)}
	repository, err := NewPolicyDecisionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	values, err := repository.ListPolicyDecisions(context.Background(), scope, "policy-runtime-history", 25)
	if err != nil || len(values) != 1 || values[0].PolicyID != "policy-runtime-history" || !values[0].At.Equal(time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("values=%#v err=%v", values, err)
	}
	want := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "policy-runtime-history", 25}
	if database.query != postgresListPolicyDecisionsSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("query=%q args=%#v", database.query, database.args)
	}
}

func TestPolicyDecisionRepositoryRejectsMalformedOrForeignHistory(t *testing.T) {
	scope := policyDecisionScope(t)
	for name, payload := range map[string]string{
		"foreign environment":   `{"items":[{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff","result":"block","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T12:00:00Z"}]}`,
		"unknown field":         `{"items":[],"secret":"provider-body"}`,
		"duplicate id":          `{"items":[{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"block","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T12:00:00Z"},{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"block","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T11:00:00Z"}]}`,
		"ascending time":        `{"items":[{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"block","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T11:00:00Z"},{"id":"pid_70000004-0000-4000-8000-000000000004","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"monitor","correlation_id":"pid_70000004-0000-4000-8000-000000000004","at":"2026-08-28T12:00:00Z"}]}`,
		"equal time reverse id": `{"items":[{"id":"pid_70000004-0000-4000-8000-000000000004","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"block","correlation_id":"pid_70000004-0000-4000-8000-000000000004","at":"2026-08-28T12:00:00Z"},{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"monitor","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T12:00:00Z"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			repository, _ := NewPolicyDecisionRepository(&workflowCallDatabase{response: json.RawMessage(payload)})
			if values, err := repository.ListPolicyDecisions(context.Background(), scope, "policy-runtime-history", 25); err == nil || values != nil {
				t.Fatalf("values=%#v err=%v", values, err)
			}
		})
	}
}

func TestPolicyDecisionRepositoryAcceptsDeterministicEqualTimeOrder(t *testing.T) {
	scope := policyDecisionScope(t)
	payload := json.RawMessage(`{"items":[{"id":"pid_70000003-0000-4000-8000-000000000003","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"block","correlation_id":"pid_70000003-0000-4000-8000-000000000003","at":"2026-08-28T12:00:00Z"},{"id":"pid_70000004-0000-4000-8000-000000000004","policy_id":"policy-runtime-history","environment_id":"` + scope.EnvironmentID().String() + `","result":"monitor","correlation_id":"pid_70000004-0000-4000-8000-000000000004","at":"2026-08-28T12:00:00Z"}]}`)
	repository, _ := NewPolicyDecisionRepository(&workflowCallDatabase{response: payload})
	if values, err := repository.ListPolicyDecisions(context.Background(), scope, "policy-runtime-history", 25); err != nil || len(values) != 2 {
		t.Fatalf("values=%#v err=%v", values, err)
	}
}

func policyDecisionScope(t *testing.T) domain.Scope {
	t.Helper()
	value, err := domain.NewScope(policyDecisionID(t), policyDecisionID(t), policyDecisionID(t))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func policyDecisionID(t *testing.T) domain.ProductID {
	t.Helper()
	value, err := domain.NewProductID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
