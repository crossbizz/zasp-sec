package apiserver

import (
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func TestEnvironmentClassificationStatementsBindCurrentActorScopeAndProfile(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	i.FreshAuthenticated = true
	o, w, e, a := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	id := "pid_88100001-0000-4000-8000-000000000001"
	audit := "pid_88100002-0000-4000-8000-000000000002"
	target := AuthorizationTarget{Scope: i.Scope, Kind: "environment", ID: e, Version: 1}
	for _, operation := range []string{"createEnvironment", "updateEnvironment"} {
		t.Run(operation, func(t *testing.T) {
			g := RequestAuthorization{OperationID: operation, Identity: i, Allowed: []AuthorizationTarget{target}, Targets: []AuthorizationTarget{target}, PathParameters: map[string]string{"id": e}}
			q := postgresClassifiedEnvironmentCreateSQL
			original := []any{id, o, w, "Classified", "staging", audit, a, w, e, []byte("[]"), migrations.EnvironmentClassProfileChecksum()}
			if operation == "updateEnvironment" {
				q = postgresClassifiedEnvironmentUpdateSQL
				original = []any{o, w, e, e, "Classified", "production", int64(1), audit, a, migrations.EnvironmentClassAuditProfileChecksum()}
			}
			if !authorizationStatementAllowed(g, q, original) {
				t.Fatal("exact selected class statement refused")
			}
			for n := range original {
				changed := append([]any(nil), original...)
				changed[n] = "unbound"
				// Name remains caller input; enum alternatives and newly generated IDs are
				// validated values rather than authority bindings.
				if operation == "createEnvironment" && (n == 0 || n == 3 || n == 4 || n == 5) {
					continue
				}
				if operation == "updateEnvironment" && (n == 4 || n == 5 || n == 7) {
					continue
				}
				if authorizationStatementAllowed(g, q, changed) {
					t.Fatalf("unbound positional argument accepted at %d", n+1)
				}
			}
			for _, mode := range []string{"collection", "stale_browser", "bearer", "wrong_operation", "wrong_target", "missing_pin", "extra_argument"} {
				changed := g
				args := append([]any(nil), original...)
				switch mode {
				case "collection":
					changed.Collection = true
				case "stale_browser":
					changed.Identity.FreshAuthenticated = false
				case "bearer":
					changed.Identity.CredentialKind = CredentialBearerToken
				case "wrong_operation":
					changed.OperationID = "getEnvironment"
				case "wrong_target":
					changed.Allowed = nil
				case "missing_pin":
					args[len(args)-1] = ""
				case "extra_argument":
					args = append(args, "extra")
				}
				if authorizationStatementAllowed(changed, q, args) {
					t.Fatal("unbound class mutation admitted", mode)
				}
			}
			if operation == "updateEnvironment" {
				args := append([]any(nil), original...)
				args[5] = nil
				if !authorizationStatementAllowed(g, q, args) {
					t.Fatal("omitted update class refused")
				}
			}
		})
	}
}
