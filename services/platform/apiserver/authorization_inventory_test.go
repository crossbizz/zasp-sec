package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A mixed subresource collection must permit filtering a hidden endpoint, but
// may never borrow an endpoint's permission to disclose a denied parent agent.
func TestInventoryAuthorizationRequiresParentBeforeFiltering(t *testing.T) {
	for _, operation := range []string{"getAgentCapabilities", "getAgentRelationships", "listAgentSessions"} {
		for _, name := range []string{"hidden candidate", "denied parent", "empty parent", "missing parent", "duplicate parent", "wrong parent", "foreign workspace", "unsupported kind", "incomplete", "PAT ceiling"} {
			t.Run(operation+"/"+name, func(t *testing.T) {
				i := fixtureRequestIdentity(t)
				i.CredentialKind = CredentialBrowserSession
				parent := AuthorizationTarget{Scope: i.Scope, Kind: "agent", ID: "pid_91000001-0000-4000-8000-000000000001", Version: 1}
				candidate := AuthorizationTarget{Scope: i.Scope, Kind: "tool", ID: "pid_91000002-0000-4000-8000-000000000002", Version: 1}
				if operation == "listAgentSessions" {
					candidate.Kind = "session"
				}
				targets := AuthorizationTargets{Collection: true, Complete: true, Targets: []AuthorizationTarget{candidate, parent}}
				want := error(nil)
				parentAllowed := true
				binding := CredentialBinding{Kind: i.CredentialKind, ID: "inventory-current", Digest: [32]byte{1}}
				switch name {
				case "denied parent":
					parentAllowed = false
					want = ErrAuthorizationDenied
				case "empty parent":
					targets.Targets = []AuthorizationTarget{}
					want = ErrAuthorizationDenied
				case "missing parent":
					targets.Targets = []AuthorizationTarget{candidate}
					want = authorization.ErrInvalid
				case "duplicate parent":
					targets.Targets = append(targets.Targets, parent)
					want = authorization.ErrInvalid
				case "wrong parent":
					targets.Targets[1].ID = candidate.ID
					want = authorization.ErrInvalid
				case "foreign workspace":
					w, _ := domain.ParseProductID("pid_91000003-0000-4000-8000-000000000003")
					targets.Targets[0].Scope, _ = domain.NewScope(i.Scope.OrganizationID(), w, i.Scope.EnvironmentID())
					want = authorization.ErrInvalid
				case "unsupported kind":
					targets.Targets[0].Kind = "environment"
					want = authorization.ErrInvalid
				case "incomplete":
					targets.Complete = false
					want = authorization.ErrUnavailable
				case "PAT ceiling":
					i.CredentialKind = CredentialBearerToken
					binding.Kind = i.CredentialKind
					binding.PATCeiling = []string{"manage_workflows"}
					want = ErrAuthorizationDenied
				}
				revision := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
				a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t), Resolver: authorizationTargetFixture{targets}, Checker: authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
					return authorization.Decision{Allowed: parentAllowed && q.ResourceType == "agent" && q.ResourceID == parent.ID, ModelID: revision.ModelID}, nil
				})}
				grant, err := a.Authorize(context.Background(), i, binding, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": parent.ID}})
				if want != nil {
					if !errors.Is(err, want) {
						t.Fatalf("want %v, allowed=%d error=%v", want, len(grant.Allowed), err)
					}
				} else if err != nil || !grant.Collection || len(grant.Allowed) != 1 || grant.Allowed[0] != parent {
					t.Fatalf("hidden candidate prevented authorized parent collection: allowed=%d error=%v", len(grant.Allowed), err)
				}
			})
		}
	}
}

type inventoryBoundaryRow struct{ payload []byte }

func (r inventoryBoundaryRow) Scan(values ...any) error { *values[0].(*[]byte) = r.payload; return nil }

type inventoryBoundaryTx struct {
	authorizationTxFixture
	query     string
	arguments []any
	payload   []byte
}

func (t *inventoryBoundaryTx) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	if query == migrations.AuthorizationInventoryReadySourceSQL() {
		t.steps = append(t.steps, "source_ready")
		return inventoryReadyRow{}
	}
	t.steps = append(t.steps, "effect")
	t.query, t.arguments = query, append([]any(nil), arguments...)
	return inventoryBoundaryRow{t.payload}
}

type inventoryBoundaryDriver struct {
	authorizationDriverFixture
	transaction *inventoryBoundaryTx
}

type inventoryReadyRow struct{}

func (inventoryReadyRow) Scan(values ...any) error { *values[0].(*bool) = true; return nil }
func (d *inventoryBoundaryDriver) QueryRow(_ context.Context, query string, _ ...any) PostgresRow {
	if query == migrations.AuthorizationInventoryReadySourceSQL() {
		return inventoryReadyRow{}
	}
	d.direct = true
	return authorizationRowFixture{}
}

func (d *inventoryBoundaryDriver) Begin(context.Context) (pgx.Tx, error) {
	d.transaction.steps = append(d.transaction.steps, "begin")
	return d.transaction, nil
}

func inventoryCheckedDetailJSON(id, kind string) []byte {
	return []byte(`{"summary":` + inventorySummaryJSON(id, kind) + `,"sources":[{"integration_id":"pid_30000001-0000-4000-8000-000000000001","provider":"aws","source":"aws","source_identifier":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","snapshot_id":"pid_40000001-0000-4000-8000-000000000001","generation":1,"evidence_id":"pid_20000001-0000-4000-8000-000000000001","confidence_basis_points":9000,"observed_at":"2026-08-19T01:00:00Z","fresh_until":"2026-08-20T01:00:00Z","projection_version":1,"winning":true}],"evidence":[{"id":"pid_20000001-0000-4000-8000-000000000001","checksum":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","media_type":"application/json","schema_version":"raw-v1","parser_version":"parser-v1","tool_version":"tool-v1","collected_at":"2026-08-19T01:00:00Z","size_bytes":128}]}`)
}

// Controlled database responses keep repository decoding and the real private
// decision/statement/transaction boundary active. Native SQL is tested separately.
func TestInventoryCurrentRepositoryBoundary(t *testing.T) {
	for _, credential := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		for _, operation := range []string{"getAgent", "getTool", "getIdentity", "getRuntime", "getAsset", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions", "updateAgent"} {
			t.Run(operation+"/"+map[CredentialKind]string{CredentialBrowserSession: "browser", CredentialBearerToken: "PAT"}[credential], func(t *testing.T) {
				i := fixtureRequestIdentity(t)
				i.CredentialKind = credential
				i.FreshAuthenticated = false
				id, _ := domain.ParseProductID("pid_92000001-0000-4000-8000-000000000001")
				kind := map[string]InventoryKind{"getAgent": InventoryKindAgent, "getTool": InventoryKindTool, "getIdentity": InventoryKindIdentity, "getRuntime": InventoryKindRuntime, "getAsset": InventoryKindAsset}[operation]
				if kind == "" {
					kind = InventoryKindAgent
				}
				target := AuthorizationTarget{Scope: i.Scope, Kind: string(kind), ID: id.String(), Version: 1}
				revision := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
				binding := CredentialBinding{Kind: credential, ID: "inventory-credential", Digest: [32]byte{1}, PATCeiling: []string{"view", "manage_workflows"}}
				a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t), Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Collection: inventorySubresourceOperation(operation), Targets: []AuthorizationTarget{target}}}, Checker: authorizationDecisionFixture{allow: map[string]bool{id.String(): true}, model: revision.ModelID}}
				grant, err := a.Authorize(context.Background(), i, binding, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": id.String()}})
				if err != nil {
					t.Fatal(err)
				}
				payload := inventoryCheckedDetailJSON(id.String(), string(kind))
				if inventorySubresourceOperation(operation) {
					payload = []byte(`{"items":[],"next_key":null}`)
				}
				if operation == "listAgentSessions" {
					payload = []byte(`{"items":[{"id":"pid_92000002-0000-4000-8000-000000000002","agent_id":"` + id.String() + `","started_at":"2026-08-19T00:00:00Z"}],"next_key":null}`)
				}
				if operation == "updateAgent" {
					summary := strings.ReplaceAll(inventorySummaryJSON(id.String(), "agent"), `"version":1`, `"version":2`)
					summary = strings.ReplaceAll(strings.ReplaceAll(summary, `"owner":""`, `"owner":"security"`), `"team":""`, `"team":"platform"`)
					payload = []byte(`{"agent":` + summary + `,"audit_id":"pid_92000003-0000-4000-8000-000000000003","correlation_id":"pid_92000004-0000-4000-8000-000000000004","replayed":false}`)
				}
				tx := &inventoryBoundaryTx{payload: payload}
				driver := &inventoryBoundaryDriver{transaction: tx}
				db, _ := NewPostgresJSONDatabase(driver)
				db.currentAuthorization = true
				repo := &PostgresInventoryRepository{database: db}
				ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
				switch operation {
				case "getAgentCapabilities":
					_, err = repo.ListAgentCapabilitiesPage(ctx, i.Scope, id, "", 2)
				case "getAgentRelationships":
					_, err = repo.ListAgentRelationshipsPage(ctx, i.Scope, id, "", 2)
				case "listAgentSessions":
					var page SessionPage
					page, err = repo.ListAgentSessionsPage(ctx, i.Scope, id, "", 2)
					if err == nil && len(page.Items) != 1 {
						t.Fatal("real session response lost")
					}
				case "updateAgent":
					_, err = repo.UpdateAgentOwnership(ctx, i, id, 1, "inventory-owner-key", AgentOwnershipInput{Owner: "security", Team: "platform", Tags: []string{}}, "pid_92000003-0000-4000-8000-000000000003", "pid_92000004-0000-4000-8000-000000000004")
				default:
					_, err = repo.GetInventory(ctx, i.Scope, id, kind)
				}
				if err != nil {
					t.Fatalf("authorized repository rejected current %s: %v", operation, err)
				}
				if driver.direct || !reflect.DeepEqual(tx.steps, []string{"begin", "source_ready", "fence", "effect", "commit", "rollback"}) {
					t.Fatalf("current query bypassed fence: %v", tx.steps)
				}
				if !strings.HasPrefix(tx.query, "SELECT zasp_authorization80_inventory.") {
					t.Fatalf("current query used retained SQL: %s", tx.query)
				}
				checksum, ok := tx.arguments[len(tx.arguments)-1].(string)
				if !ok || len(checksum) != 64 {
					t.Fatal("missing compiled profile pin")
				}
				// Old public statements never acquire permission from these decisions.
				legacy := postgresInventoryDetailSQL
				before := len(tx.steps)
				if _, err = db.QueryJSON(ctx, legacy, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), id.String(), kind); !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != before {
					t.Fatalf("legacy SQL borrowed current proof: %v", err)
				}
			})
		}
	}
}

// Genuine authorizer decisions cannot be borrowed for another native scope,
// target, statement, profile, actor, kind or pagination shape.
func TestInventoryClosedStatementBindings(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	id := "pid_93000001-0000-4000-8000-000000000001"
	foreign := "pid_93000002-0000-4000-8000-000000000002"
	revision := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	for _, operation := range []string{"getAgent", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions", "updateAgent"} {
		target := AuthorizationTarget{Scope: i.Scope, Kind: "agent", ID: id, Version: 1}
		a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, Checker: authorizationDecisionFixture{allow: map[string]bool{id: true}, model: revision.ModelID}, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Collection: inventorySubresourceOperation(operation), Targets: []AuthorizationTarget{target}}}, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
		grant, err := a.Authorize(context.Background(), i, CredentialBinding{Kind: i.CredentialKind, ID: "inventory-bindings", Digest: [32]byte{1}}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": id}})
		if err != nil {
			t.Fatal(err)
		}
		query := map[string]string{"getAgent": postgresCurrentInventoryDetailSQL, "getAgentCapabilities": postgresCurrentInventoryCapabilitiesSQL, "getAgentRelationships": postgresCurrentInventoryRelationshipsSQL, "listAgentSessions": postgresCurrentInventorySessionsSQL, "updateAgent": postgresCurrentInventoryUpdateSQL}[operation]
		args := []any{o, w, e, id, "", 1, migrations.AuthorizationInventoryProfileChecksum()}
		targetArg := 3
		if operation == "getAgent" {
			args = []any{o, w, e, id, InventoryKindAgent, migrations.AuthorizationInventoryProfileChecksum()}
		}
		if operation == "updateAgent" {
			targetArg = 4
			args = []any{o, w, e, p, id, "owned-key", int64(1), "security", "platform", json.RawMessage(`[]`), foreign, foreign, migrations.AuthorizationInventoryProfileChecksum()}
		}
		for _, name := range []string{"exact", "organization", "workspace", "environment", "target", "profile", "missing", "extra", "unknown SQL", "kind actor or page"} {
			t.Run(operation+"/"+name, func(t *testing.T) {
				values := append([]any(nil), args...)
				statement := query
				switch name {
				case "organization":
					values[0] = foreign
				case "workspace":
					values[1] = foreign
				case "environment":
					values[2] = foreign
				case "target":
					values[targetArg] = foreign
				case "profile":
					values[len(values)-1] = strings.Repeat("0", 64)
				case "missing":
					values = values[:len(values)-1]
				case "extra":
					values = append(values, foreign)
				case "unknown SQL":
					statement += "; SELECT 1"
				case "kind actor or page":
					if operation == "getAgent" {
						values[4] = InventoryKindTool
					} else if operation == "updateAgent" {
						values[3] = foreign
					} else {
						values[5] = 101
					}
				}
				tx := &inventoryBoundaryTx{payload: []byte(`{"ok":true}`)}
				driver := &inventoryBoundaryDriver{transaction: tx}
				db, _ := NewPostgresJSONDatabase(driver)
				db.currentAuthorization = true
				_, err := db.QueryJSON(context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant), statement, values...)
				if name == "exact" {
					if err != nil || len(tx.steps) == 0 {
						t.Fatalf("exact closed statement rejected: %v", err)
					}
				} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
					t.Fatalf("borrowed decision reached native effect: %v steps=%v", err, tx.steps)
				}
			})
		}
	}
}
