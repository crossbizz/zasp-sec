package apiserver

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAgentExposureBootstrapUsesCurrentSnapshotAndInstalledReadiness(t *testing.T) {
	for _, mode := range []string{"normal", "audit", "callback_composition", "not_ready", "readiness_error", "wrong_database"} {
		t.Run(mode, func(t *testing.T) {
			i := fixtureRequestIdentity(t)
			i.CredentialKind = CredentialBrowserSession
			i.credentialBinding = CredentialBinding{Kind: CredentialBrowserSession, ID: "fixture-session", Digest: [32]byte{1}}
			i.CSRFToken = strings.Repeat("c", 32)
			tx := &postLoginOutputTx{t: t, snapshot: true, mutate: func(map[string]any) {}, identity: i}
			db := &PostgresJSONDatabase{driver: &postLoginOutputDriver{tx: tx}, currentAuthorization: true}
			original, _ := NewPostgresAuthorizationResolver(db)
			var inner AuthorizationTargetResolver = original
			if mode == "callback_composition" {
				pin, e := migrations.ConnectorMaintenanceProfileChecksum()
				if e != nil {
					t.Fatal(e)
				}
				inner, e = NewConnectorMaintenanceCallbackResolver(original, db, pin)
				if e != nil {
					t.Fatal(e)
				}
			}
			pin := migrations.AgentExposureFilterProfileChecksum()
			if mode == "audit" {
				pin = migrations.AgentExposureFilterAuditProfileChecksum()
			}
			selected, e := NewAgentExposureFilterResolver(inner, db, pin)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "wrong_database" {
				selected.database = &PostgresJSONDatabase{}
			}
			rev := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
			calls := 0
			a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
				return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
			}), Resolver: selected, StoreID: rev.StoreID, ModelID: rev.ModelID, AgentExposureFilterReady: func(context.Context) (bool, error) {
				calls++
				if mode == "readiness_error" {
					return false, errors.New("private readiness detail")
				}
				return mode != "not_ready", nil
			}}
			grant, e := a.preparePostLogin(context.Background(), i, RoutedOperation{OperationID: "bootstrapSession"})
			if mode == "readiness_error" || mode == "wrong_database" {
				if e == nil {
					t.Fatal("unbound readiness manufactured capability")
				}
				return
			}
			if e != nil || tx.commits != 1 || calls != 1 {
				t.Fatal("current snapshot/readiness composition unavailable", e)
			}
			want := mode != "not_ready"
			if slices.Contains(grant.capabilities, "inventory.agents.exposure_filter") != want || slices.Contains(grant.capabilities, "inventory.agents.owner_filter") != want {
				t.Fatal("capabilities do not reflect installed selected profile")
			}
		})
	}
}
