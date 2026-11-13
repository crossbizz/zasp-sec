package apiserver

import (
	"context"
	"slices"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

const inventoryCurrentPageSQL = `SELECT zasp_authorization80.inventory_page($1,$2,$3,$4,NULLIF($5,''),$6)`

// The repository binds its typed InventoryKind. The statement contract must
// admit exactly that value for the matching collection operation and nothing
// else: comparing it to an untyped string as an interface never matched.
func TestInventoryStatementKindBinding(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	for _, tc := range []struct {
		name, operation string
		collection      bool
		args            []any
		allow           bool
	}{
		{"typed agent", "listAgents", true, []any{o, w, e, InventoryKindAgent, "", 25}, true},
		{"typed tool", "listTools", true, []any{o, w, e, InventoryKindTool, "", 25}, true},
		{"typed identity", "listIdentities", true, []any{o, w, e, InventoryKindIdentity, "", 25}, true},
		{"typed runtime", "listRuntimes", true, []any{o, w, e, InventoryKindRuntime, "", 25}, true},
		{"string agent", "listAgents", true, []any{o, w, e, "agent", "", 25}, true},
		{"other kind", "listAgents", true, []any{o, w, e, InventoryKindTool, "", 25}, false},
		{"other kind string", "listTools", true, []any{o, w, e, "agent", "", 25}, false},
		{"unknown kind", "listAgents", true, []any{o, w, e, InventoryKind("finding"), "", 25}, false},
		{"untyped kind value", "listAgents", true, []any{o, w, e, []byte("agent"), "", 25}, false},
		{"other operation", "listFindings", true, []any{o, w, e, InventoryKindAgent, "", 25}, false},
		{"object grant", "listAgents", false, []any{o, w, e, InventoryKindAgent, "", 25}, false},
		{"other organization", "listAgents", true, []any{w, w, e, InventoryKindAgent, "", 25}, false},
		{"other environment", "listAgents", true, []any{o, w, o, InventoryKindAgent, "", 25}, false},
		{"missing limit", "listAgents", true, []any{o, w, e, InventoryKindAgent, ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := RequestAuthorization{OperationID: tc.operation, Identity: i, Collection: tc.collection}
			if got := authorizationStatementAllowed(g, inventoryCurrentPageSQL, tc.args); got != tc.allow {
				t.Fatalf("inventory statement admitted=%v want=%v", got, tc.allow)
			}
		})
	}
}

// The real repository call must reach the fenced transaction for its own
// operation and stay refused, before any SQL, under another operation's grant.
func TestInventoryRepositoryListReachesAuthorizedStatement(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o := i.Scope.OrganizationID().String()
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	k := CredentialBinding{Kind: CredentialBrowserSession, ID: "inventory-current", Digest: [32]byte{1}}
	a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: authorizationDecisionFixture{allow: map[string]bool{}, model: rev.ModelID}, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Collection: true, Targets: []AuthorizationTarget{}}}, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	for _, tc := range []struct {
		operation string
		kind      InventoryKind
		reach     bool
	}{
		{"listAgents", InventoryKindAgent, true},
		{"listTools", InventoryKindTool, true},
		{"listIdentities", InventoryKindIdentity, true},
		{"listRuntimes", InventoryKindRuntime, true},
		{"listAgents", InventoryKindTool, false},
		{"listFindings", InventoryKindAgent, false},
	} {
		t.Run(tc.operation+"/"+string(tc.kind), func(t *testing.T) {
			g, err := a.Authorize(context.Background(), i, k, RoutedOperation{OperationID: tc.operation})
			if err != nil {
				t.Fatal(err)
			}
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, err := NewPostgresJSONDatabase(driver)
			if err != nil {
				t.Fatal(err)
			}
			repository := &PostgresInventoryRepository{database: db}
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			// The fixture row is not an inventory page, so only the SQL steps matter.
			_, _ = repository.ListInventoryPage(ctx, i.Scope, tc.kind, "", 25)
			reached := slices.Contains(tx.steps, "fence") && slices.Contains(tx.steps, "effect")
			if reached != tc.reach || driver.direct {
				t.Fatalf("authorized inventory statement reached=%v want=%v direct=%v steps=%v", reached, tc.reach, driver.direct, tx.steps)
			}
		})
	}
}
