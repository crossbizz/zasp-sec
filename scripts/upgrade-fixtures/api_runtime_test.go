// This test is overlaid onto apiserver separately in the pinned predecessor and
// the candidate. Both processes retain their own service connections until EOF.
package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestPinnedReleaseDatabaseContract(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, os.Getenv("ZASP_V2_UPGRADE_ADMIN_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	b := &installedBaseline{t: t, ctx: ctx, admin: admin}
	b.product, b.agents = b.database("zasp_svc_api"), b.database("zasp_svc_security_agent_api")
	b.product.RequireCurrentAuthorization()
	b.agents.RequireCurrentAuthorization()
	key, err := authorization.NewAttestationKey(bytes.Repeat([]byte{0x47}, 32))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewPostgresAuthorizationResolverWithSecurityAgent(b.product, b.agents)
	if err != nil {
		t.Fatal(err)
	}
	b.authorizer = &OpenFGAAuthorizer{Reader: installedRevisionReader{b}, Checker: authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: true, ModelID: installedModel}, nil
	}), Resolver: resolver, StoreID: installedStore, ModelID: installedModel, AttestationKey: key}
	repository, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	handler := &hostedGatewayHandler{database: b.product}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, _ := RoutedOperationFromRequest(r)
		handler.ServeHTTP(w, r, route)
	})
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		if input.Text() != "read" {
			t.Fatal("unknown probe command")
		}
		for _, service := range []struct {
			db   *PostgresJSONDatabase
			role string
		}{{b.product, "zasp_discovery_api"}, {b.agents, "zasp_security_agent_api"}} {
			if err := service.db.CurrentAuthorizationRuntimeReady(ctx, service.role, key.Version()); err != nil {
				t.Fatalf("%s authorization runtime readiness: %v", service.role, err)
			}
		}
		for tenant := 1; tenant <= 2; tenant++ {
			id := func(entity int) string { return fmt.Sprintf("pid_85a0000%d-0000-4000-8000-%012d", tenant, entity) }
			secret := fmt.Sprintf("upgrade-rehearsal-ephemeral-credential-%d", tenant)
			identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: secret})
			if err != nil {
				t.Fatalf("tenant %d authenticate: %v", tenant, err)
			}
			o, w, e := gatewayScope(identity)
			if o != id(1) || w != id(2) || e != id(3) || identity.PrincipalID.String() != id(4) || identity.credentialBinding.ID != id(5) {
				t.Fatal("credential scope or identities changed")
			}
			principal := installedPrincipal{identity: identity, binding: identity.credentialBinding}
			response := b.serve(surface, principal, "getGatewayPolicy", http.MethodGet, "/api/v1/gateway/policy", nil, "", nil)
			var policy GatewayPolicy
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &policy) != nil || policy.EnvironmentID != id(3) || policy.Version != 4 || policy.RequestsPerMinute != 50+tenant {
				t.Fatalf("tenant %d scoped gateway policy %d: %s", tenant, response.Code, response.Body.String())
			}
			other := 3 - tenant
			otherID := func(entity int) string { return fmt.Sprintf("pid_85a0000%d-0000-4000-8000-%012d", other, entity) }
			if _, err := b.fenced("zasp_svc_api", principal, RoutedOperation{OperationID: "getGatewayPolicy", PathParameters: map[string]string{}}, currentGatewayPolicySQL, otherID(1), otherID(2), otherID(3)); err == nil {
				t.Fatal("cross-tenant policy read succeeded")
			}
		}
		if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: "unknown-ephemeral-upgrade-rehearsal-credential"}); err == nil {
			t.Fatal("invalid PAT accepted")
		}
		fmt.Println("SCOPED_READS_OK")
	}
	if err := input.Err(); err != nil {
		t.Fatal(err)
	}
}
