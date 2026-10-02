package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Omitting a fixed native72 contract rejects the actual checked API before SQL;
// broadening it permits a proof to act for another tenant, actor or integration.
func TestP7Discovery72CheckedStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	id := "pid_88008001-0000-4000-8000-000000000001"
	foreign := "pid_88008002-0000-4000-8000-000000000002"
	for _, contract := range []struct {
		op, legacy string
		count      int
	}{
		{"syncIntegration", postgresExecutionPublicRequestSyncSQL, 16},
		{"putIntegrationSchedule", postgresExecutionPublicPutScheduleSQL, 12},
		{"deleteIntegrationSchedule", postgresExecutionPublicDeleteScheduleSQL, 10},
	} {
		for _, mutation := range []string{"exact", "PAT", "credential", "allowed-empty", "allowed-scope", "organization", "workspace", "environment", "actor", "target", "route", "operation", "collection", "legacy", "arity", "unknown"} {
			t.Run(contract.op+"/"+mutation, func(t *testing.T) {
				target := AuthorizationTarget{Scope: i.Scope, Kind: "integration", ID: id, SourceID: id, Version: 1}
				grant := RequestAuthorization{OperationID: contract.op, Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "session-discovery-contract", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}, PathParameters: map[string]string{"id": id}}
				args := make([]any, contract.count)
				copy(args, []any{o, w, e, p, id})
				for n := 5; n < len(args); n++ {
					args[n] = "native-validation-owned"
				}
				query := strings.Replace(contract.legacy, "zasp_execution_", "zasp_temporal72.", 1)
				switch mutation {
				case "PAT":
					grant.Identity.CredentialKind = CredentialBearerToken
					grant.Credential.Kind = CredentialBearerToken
					grant.Credential.ID = foreign
					grant.Credential.PATCeiling = []string{"manage_workflows", "view"}
				case "allowed-empty":
					grant.Allowed = nil
				case "allowed-scope":
					other, _ := domain.ParseProductID(foreign)
					grant.Allowed[0].Scope, _ = domain.NewScope(i.Scope.OrganizationID(), i.Scope.WorkspaceID(), other)
				case "organization":
					args[0] = foreign
				case "workspace":
					args[1] = foreign
				case "environment":
					args[2] = foreign
				case "actor":
					args[3] = foreign
				case "target":
					args[4] = foreign
				case "route":
					grant.PathParameters["id"] = foreign
				case "operation":
					grant.OperationID = "getIntegration"
				case "collection":
					grant.Collection = true
				case "legacy":
					query = contract.legacy
				case "arity":
					args = args[:len(args)-1]
				case "unknown":
					query += " "
				}
				var err error
				grant, err = attestAuthorization(grant, authorizationFixtureAttestor(t), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "credential" {
					// The attestor itself refuses unsupported credentials. Change an
					// otherwise valid grant to exercise the downstream closed selector.
					grant.Identity.CredentialKind = CredentialKind(99)
					if authorizationStatementAllowed(grant, query, args) {
						t.Fatal("unsupported credential passed the statement selector")
					}
				}
				tx := &authorizationTxFixture{}
				driver := &authorizationDriverFixture{tx: tx}
				db, _ := NewPostgresJSONDatabase(driver)
				body, err := db.QueryJSON(context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant), query, args...)
				if mutation == "exact" || mutation == "PAT" {
					if err != nil || string(body) != `{"ok":true}` {
						t.Fatalf("exact native discovery contract refused: %v", err)
					}
				} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
					t.Fatalf("unbound discovery statement reached SQL: %v", err)
				}
			})
		}
	}
}
