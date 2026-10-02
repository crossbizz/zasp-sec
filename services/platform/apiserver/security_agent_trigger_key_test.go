package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentTriggerKeyBoundary(t *testing.T) {
	for _, kind := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		for _, mode := range []string{"ordered_release61", "legacy_or_missing", "error", "private", "wrong-key", "wrong-definition", "wrong-family", "missing", "timeout"} {
			t.Run(string(kind)+"/"+mode, func(t *testing.T) {
				id := orderedPublicIdentity()
				id.CredentialKind = kind
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				db := &orderedPublicDB{query: func(bounded context.Context, sql string, args ...any) (json.RawMessage, error) {
					if sql != securityAgentPublicSQL || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() {
						t.Fatal("unpinned boundary")
					}
					deadline, ok := bounded.Deadline()
					if !ok || time.Until(deadline) > 5*time.Second {
						t.Fatal("unbounded")
					}
					var q map[string]any
					_ = json.Unmarshal(args[2].(json.RawMessage), &q)
					want := map[string]any{"operation": "classify_trigger_key", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "definition_id": public62Definition, "idempotency_key": "trigger-key-unit-0001"}
					if !reflect.DeepEqual(q, want) {
						t.Fatal(q)
					}
					if mode == "error" {
						return nil, errors.New("private SQL detail")
					}
					family := "ordered_release61"
					if mode == "legacy_or_missing" {
						family = mode
					}
					response := map[string]any{"contract_version": 62, "definition_id": public62Definition, "idempotency_key": "trigger-key-unit-0001", "family": family}
					switch mode {
					case "private":
						response["receipt"] = "secret"
					case "wrong-key":
						response["idempotency_key"] = "trigger-key-other-0001"
					case "wrong-definition":
						response["definition_id"] = public62Finding
					case "wrong-family":
						response["family"] = "unknown"
					case "missing":
						delete(response, "family")
					case "timeout":
						cancel()
					}
					return json.Marshal(response)
				}}
				resolver, _ := NewSecurityAgentOwnershipResolver(db)
				family, err := resolver.resolveTriggerKey(ctx, id, public62Definition, "trigger-key-unit-0001")
				if mode == "ordered_release61" || mode == "legacy_or_missing" {
					if err != nil || string(family) != mode {
						t.Fatal(family, err)
					}
				} else if err != ErrRepositoryUnavailable || family != "" {
					t.Fatal(family, err)
				}
				if db.calls != 1 {
					t.Fatal(db.calls)
				}
			})
		}
	}
}

func TestSecurityAgentTriggerKeyValidation(t *testing.T) {
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("invalid input reached SQL")
		return nil, nil
	}}
	resolver, _ := NewSecurityAgentOwnershipResolver(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, v := range []struct {
		ctx             context.Context
		id              RequestIdentity
		definition, key string
	}{
		{nil, orderedPublicIdentity(), public62Definition, "trigger-key-unit-0001"}, {ctx, orderedPublicIdentity(), public62Definition, "trigger-key-unit-0001"},
		{context.Background(), RequestIdentity{}, public62Definition, "trigger-key-unit-0001"}, {context.Background(), orderedPublicIdentity(), "bad", "trigger-key-unit-0001"}, {context.Background(), orderedPublicIdentity(), public62Definition, "bad"},
	} {
		if _, err := resolver.resolveTriggerKey(v.ctx, v.id, v.definition, v.key); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	var missing *SecurityAgentOwnershipResolver
	if _, err := missing.resolveTriggerKey(context.Background(), orderedPublicIdentity(), public62Definition, "trigger-key-unit-0001"); err != ErrRepositoryOperation {
		t.Fatal(err)
	}
}
