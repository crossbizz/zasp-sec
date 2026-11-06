package apiserver

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

// Coverage successor after product draft; no behavior RED is claimed here.
func TestAgentOwnerFilterAuthorizationStatementBoundaries(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	id := "pid_88000001-0000-4000-8000-000000000001"
	foreign := "pid_88000002-0000-4000-8000-000000000002"
	for _, tc := range []struct {
		name, op          string
		change            func([]any)
		collection, allow bool
	}{
		{"literal-unowned", "listAgents", func(a []any) { a[5] = "" }, true, true},
		{"unicode-whitespace", "listAgents", func(a []any) { a[5] = " Security 😀 " }, true, true},
		{"audit-compiled-pin", "listAgents", func(a []any) { a[6] = migrations.AgentOwnerFilterAuditProfileChecksum() }, true, true},
		{"foreign-org", "listAgents", func(a []any) { a[0] = foreign }, true, false},
		{"foreign-workspace", "listAgents", func(a []any) { a[1] = foreign }, true, false},
		{"foreign-environment", "listAgents", func(a []any) { a[2] = foreign }, true, false},
		{"wrong-purpose", "listTools", func([]any) {}, true, false},
		{"object-not-collection", "listAgents", func([]any) {}, false, false},
		{"invalid-owner", "listAgents", func(a []any) { a[5] = "a\x00b" }, true, false},
		{"unknown-pin", "listAgents", func(a []any) { a[6] = strings.Repeat("a", 64) }, true, false},
		{"invalid-after", "listAgents", func(a []any) { a[3] = "arbitrary" }, true, false},
		{"over-limit", "listAgents", func(a []any) { a[4] = 101 }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := AuthorizationTarget{Scope: i.Scope, Kind: "agent", ID: id, SourceID: id, Version: 1}
			g := RequestAuthorization{OperationID: tc.op, Collection: tc.collection, Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "owner-current", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}}
			g, err := attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
			if err != nil {
				t.Fatal("application grant setup refused")
			}
			args := []any{o, w, e, "", 1, "Security", migrations.AgentOwnerFilterProfileChecksum()}
			tc.change(args)
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			body, err := db.QueryJSON(ctx, postgresAgentOwnerPageSQL, args...)
			if tc.allow {
				if err != nil || string(body) != `{"ok":true}` {
					t.Fatal("bound owner query refused")
				}
			} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
				t.Fatal("owner statement escaped scope/purpose/parameter fence")
			}
		})
	}
}
