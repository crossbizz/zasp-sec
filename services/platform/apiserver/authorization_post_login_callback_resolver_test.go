package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"slices"
	"strings"
	"testing"
)

// Exercise the real preparation path, including the transaction-bound snapshot
// and FGA calls. Controlled application dependencies are not native acceptance.
func TestPostLoginKnownCallbackResolverKeepsCurrentSnapshotBinding(t *testing.T) {
	for _, mode := range []string{"direct", "known_wrapper", "nil_wrapper", "wrong_database", "wrong_profile", "nested_wrapper", "unrecognized_resolver", "missing_original"} {
		t.Run(mode, func(t *testing.T) {
			i := fixtureRequestIdentity(t)
			i.CredentialKind = CredentialBrowserSession
			i.credentialBinding = CredentialBinding{Kind: CredentialBrowserSession, ID: "fixture-session", Digest: [32]byte{1}}
			i.CSRFToken = strings.Repeat("c", 32)
			tx := &postLoginOutputTx{t: t, snapshot: true, mutate: func(map[string]any) {}, identity: i}
			db := &PostgresJSONDatabase{driver: &postLoginOutputDriver{tx: tx}, currentAuthorization: true}
			original, _ := NewPostgresAuthorizationResolver(db)
			pin, err := migrations.ConnectorMaintenanceProfileChecksum()
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := NewConnectorMaintenanceCallbackResolver(original, db, pin)
			if err != nil {
				t.Fatal(err)
			}
			var resolver AuthorizationTargetResolver = wrapped
			expected := mode == "direct" || mode == "known_wrapper"
			switch mode {
			case "direct":
				resolver = original
			case "nil_wrapper":
				resolver = (*ConnectorMaintenanceCallbackResolver)(nil)
			case "wrong_database":
				wrapped.database = &PostgresJSONDatabase{}
			case "wrong_profile":
				wrapped.profile = "unbound"
			case "nested_wrapper":
				wrapped.original = &ConnectorMaintenanceCallbackResolver{original: original, database: db, profile: pin}
			case "unrecognized_resolver":
				resolver = authorizationTargetFixture{AuthorizationTargets{Complete: true}}
			case "missing_original":
				wrapped.original = nil
			}
			rev := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
			checks := 0
			a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
				checks++
				return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
			}), Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID}
			grant, err := a.preparePostLogin(context.Background(), i, RoutedOperation{OperationID: "bootstrapSession"})
			if expected {
				if err != nil || grant.revision != rev || !slices.Contains(grant.capabilities, "identity.scopes.manage") || checks == 0 || tx.commits != 1 {
					t.Fatal("current bootstrap unavailable through supported resolver composition", err)
				}
			} else if err == nil || checks != 0 || tx.commits != 0 {
				t.Fatal("unsupported resolver manufactured snapshot authority")
			}
		})
	}
}
