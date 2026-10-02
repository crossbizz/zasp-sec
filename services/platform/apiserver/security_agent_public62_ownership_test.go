package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentPublic62OwnershipResolver(t *testing.T) {
	id := orderedPublicIdentity()
	db := &orderedPublicDB{}
	r, err := NewSecurityAgentOwnershipResolver(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		id.CredentialKind = credential
		for _, kind := range []SecurityAgentResourceKind{SecurityAgentResourceDefinition, SecurityAgentResourceRun, SecurityAgentResourceApproval} {
			for _, family := range []SecurityAgentFamily{SecurityAgentFamilyOrderedRelease61, SecurityAgentFamilyLegacyOrMissing} {
				db.query = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
					if sql != "SELECT zasp_ordered_public62.api($1,$2,$3::jsonb)" || len(args) != 3 || args[0] != migrations.ProductionSecurityAgentPublic().Checksum() || args[1] != migrations.SecurityAgentPublicFingerprint() {
						t.Fatalf("unsafe boundary: %s %v", sql, args)
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) <= 0 {
						t.Fatal("unbounded call")
					}
					var q map[string]any
					if json.Unmarshal(args[2].(json.RawMessage), &q) != nil {
						t.Fatal("invalid request")
					}
					want := map[string]any{"operation": "classify", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "resource_kind": string(kind), "resource_id": public62Definition}
					if !reflect.DeepEqual(q, want) {
						t.Fatalf("caller authority leaked: %v", q)
					}
					return json.Marshal(map[string]any{"contract_version": 62, "resource_kind": kind, "resource_id": public62Definition, "family": family})
				}
				got, err := r.Resolve(context.Background(), id, kind, public62Definition)
				if err != nil || got != family {
					t.Fatal(got, err)
				}
			}
		}
	}
	if db.calls != 12 {
		t.Fatal("fallback or cached classification", db.calls)
	}
}

func TestSecurityAgentPublic62OwnershipValidation(t *testing.T) {
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Error("invalid input reached database")
		return nil, nil
	}}
	r, _ := NewSecurityAgentOwnershipResolver(db)
	ctx := context.Background()
	id := orderedPublicIdentity()
	var typedNil *orderedPublicDB
	for _, database := range []JSONDatabase{nil, typedNil} {
		if _, err := NewSecurityAgentOwnershipResolver(database); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, c := range []context.Context{nil, canceled} {
		if _, err := r.Resolve(c, id, SecurityAgentResourceRun, public62Definition); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, kind := range []SecurityAgentResourceKind{"", "step", "Run"} {
		if _, err := r.Resolve(ctx, id, kind, public62Definition); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, resource := range []string{"", strings.ToUpper(public62Definition), public62Definition + " ", "pid_bad", strings.Repeat("x", 10000)} {
		if _, err := r.Resolve(ctx, id, SecurityAgentResourceRun, resource); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*RequestIdentity){func(i *RequestIdentity) { i.CredentialKind = 0 }, func(i *RequestIdentity) { i.PrincipalID = domain.ProductID{} }, func(i *RequestIdentity) { i.Scope = domain.Scope{} }, func(i *RequestIdentity) { i.CSRFToken = "" }, func(i *RequestIdentity) { i.Permissions = []string{"invalid"} }, func(i *RequestIdentity) { i.Permissions = []string{"view", "view"} }} {
		bad := id
		change(&bad)
		if _, err := r.Resolve(ctx, bad, SecurityAgentResourceRun, public62Definition); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	for _, invalid := range []*SecurityAgentOwnershipResolver{nil, {}} {
		if _, err := invalid.Resolve(ctx, id, SecurityAgentResourceRun, public62Definition); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	if db.calls != 0 {
		t.Fatal(db.calls)
	}
}

func TestSecurityAgentPublic62OwnershipResponse(t *testing.T) {
	id := orderedPublicIdentity()
	valid := `{"contract_version":62,"resource_kind":"run","resource_id":"` + public62Definition + `","family":"ordered_release61"}`
	for _, raw := range []string{"null", "{}", valid + valid, strings.Replace(valid, "62", "61", 1), strings.Replace(valid, "\"run\"", "\"approval\"", 1), strings.Replace(valid, public62Definition, public62Finding, 1), strings.Replace(valid, "ordered_release61", "legacy", 1), strings.Replace(valid, "ordered_release61", "", 1), strings.Replace(valid, `"family":`, `"private":"secret","family":`, 1), strings.Replace(valid, `"family":`, `"family":"legacy_or_missing","family":`, 1), strings.Replace(valid, `"family":"ordered_release61"`, `"family":null`, 1), strings.Repeat(" ", 1025) + valid} {
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return json.RawMessage(raw), nil }}
		r, _ := NewSecurityAgentOwnershipResolver(db)
		got, err := r.Resolve(context.Background(), id, SecurityAgentResourceRun, public62Definition)
		if err != ErrRepositoryUnavailable || got != "" || db.calls != 1 {
			t.Fatalf("accepted malformed response %q: %q %v calls=%d", raw, got, err, db.calls)
		}
	}
	for _, provider := range []error{errors.New("private SQL secret"), &pgconn.PgError{Code: "40001", Detail: "private"}, &pgconn.PgError{Code: "55000"}} {
		db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) { return nil, provider }}
		r, _ := NewSecurityAgentOwnershipResolver(db)
		got, err := r.Resolve(context.Background(), id, SecurityAgentResourceRun, public62Definition)
		if err != ErrRepositoryUnavailable || got != "" || db.calls != 1 {
			t.Fatal("unsafe error/fallback", got, err, db.calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		cancel()
		return json.RawMessage(valid), nil
	}}
	r, _ := NewSecurityAgentOwnershipResolver(db)
	if _, err := r.Resolve(ctx, id, SecurityAgentResourceRun, public62Definition); err != ErrRepositoryUnavailable {
		t.Fatal(err)
	}
}

func TestSecurityAgentPublic62OwnershipBearerCannotUseLifecycle(t *testing.T) {
	db := &orderedPublicDB{query: func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("bearer reached lifecycle SQL")
		return nil, nil
	}}
	r, _ := NewSecurityAgentPublicRepository(db)
	id := orderedPublicIdentity()
	id.CredentialKind = CredentialBearerToken
	id.CSRFToken = ""
	id.FreshAuthenticated = true
	id.FreshAuthExpiresAt = time.Now().UTC().Add(time.Minute)
	ctx := context.Background()
	for _, call := range []func() error{
		func() error { return r.Ready(ctx, id) },
		func() error { _, e := r.Activate(ctx, id, public62Definition, 1); return e },
		func() error {
			_, e := r.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "ownership-trigger-0001"})
			return e
		},
		func() error { _, e := r.Run(ctx, id, public62Definition); return e },
		func() error { _, e := r.Runs(ctx, id, "", 1); return e },
		func() error {
			_, e := r.Decide(ctx, id, SecurityAgentPublicDecision{RunID: public62Definition, RunVersion: 3, ApprovalID: public62Finding, ApprovalVersion: 1, Decision: "approved", IdempotencyKey: "ownership-decision-0001"})
			return e
		},
		func() error {
			_, e := r.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: public62Definition, RunVersion: 3, IdempotencyKey: "ownership-cancel-0001"})
			return e
		},
	} {
		if err := call(); err != ErrRepositoryOperation {
			t.Fatal(err)
		}
	}
	if db.calls != 0 {
		t.Fatal(db.calls)
	}
}
