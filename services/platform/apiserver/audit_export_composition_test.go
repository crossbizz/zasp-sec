package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
)

// Removing router-local installation binding, or using role/permission alone,
// must break bootstrap behavior while both routers share the same dependencies.
func TestAuditExportCompositionBootstrapInstallationIsRouterLocal(t *testing.T) {
	_, exportDB, _, _ := auditExportRepositoryFixture(t)
	config, _ := auditExportProductionConfigFixture(t)
	exports, err := NewAuditExportProductionHandler(context.Background(), exportDB, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, security := range []bool{false, true} {
		identity := fixtureRequestIdentity(t)
		identity.Permissions = []string{"view", "view_audit"}
		payload, _ := json.Marshal(bootstrapJSON(identity))
		db := &discoveryCallDatabase{schema: ReferenceSchemaVersion, responses: map[string]json.RawMessage{postgresBootstrapSQL: payload}}
		var securityRepository *PostgresRepository
		if security {
			db.schema = SecurityAgentExecutionSchemaVersion
			db.responses[postgresSecurityAgentExecutionReadinessSQL] = json.RawMessage(`true`)
			db.responses[postgresDiscoveryPrincipalReadySQL] = json.RawMessage(`true`)
			securityDB := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentAuthorityReadySQL: json.RawMessage(`{"release":true,"principal":true}`)}}
			securityRepository, err = NewSecurityAgentPostgresRepository(securityDB)
			if err != nil {
				t.Fatal(err)
			}
		}
		repository, err := NewPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		provider := CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) { return SessionGrant{}, nil })
		var dependencies Dependencies
		if security {
			dependencies, _, err = NewProductionHandlersWithSecurityAgent(repository, securityRepository, provider, http.NotFoundHandler(), fixtureCookiePolicy())
		} else {
			dependencies, _, err = NewProductionHandlers(repository, provider, http.NotFoundHandler(), fixtureCookiePolicy())
		}
		if err != nil {
			t.Fatal(err)
		}
		enabled, err := NewCompositionWithAuditExports(dependencies, exports)
		if err != nil {
			t.Fatal(err)
		}
		disabled, err := NewComposition(dependencies)
		if err != nil {
			t.Fatal(err)
		}
		generic, err := NewCompositionWithAuditExports(dependencies, handlerResponse("custom export"))
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name             string
			router           http.Handler
			permission, want bool
		}{
			{"enabled effective grant", enabled, true, true}, {"disabled", disabled, true, false},
			{"enabled without grant", enabled, false, false}, {"generic handler", generic, true, false},
			{"enabled remains independent", enabled, true, true}, {"original session", dependencies.Session, true, false},
		} {
			t.Run(fmt.Sprintf("security=%t/%s", security, test.name), func(t *testing.T) {
				current := identity
				if !test.permission {
					current.Permissions = []string{"view"}
				}
				request := httptest.NewRequest(http.MethodGet, "/api/v1/session/bootstrap", nil)
				request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, current))
				response := httptest.NewRecorder()
				test.router.ServeHTTP(response, request)
				var value struct {
					Capabilities []string `json:"capabilities"`
				}
				if json.Unmarshal(response.Body.Bytes(), &value) != nil || response.Code != 200 {
					t.Fatalf("bootstrap %d %s", response.Code, response.Body.String())
				}
				if slices.Contains(value.Capabilities, "audit.exports") != test.want || slices.Contains(value.Capabilities, "audit.read") != test.permission {
					t.Fatalf("capabilities %v", value.Capabilities)
				}
			})
		}
	}
}

func auditExportCompositionDependencies() Dependencies {
	return Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")}
}

func TestAuditExportCompositionRegistersExactBrowserOperations(t *testing.T) {
	dependencies := auditExportCompositionDependencies()
	router, err := NewCompositionWithAuditExports(dependencies, handlerResponse("export"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewComposition(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	baseRoutes := base.(*operationRouter).operations
	extended := router.(*operationRouter).operations
	if len(baseRoutes) != 150 || len(extended) != 152 || !reflect.DeepEqual(baseRoutes, extended[:150]) {
		t.Fatal("export extension changed the existing route surface")
	}
	seenIDs, seenPaths := map[string]bool{}, map[string]bool{}
	for _, operation := range extended {
		key := operation.method + " " + operation.pattern
		if seenIDs[operation.operationID] || seenPaths[key] {
			t.Fatal("duplicate registered export/core operation")
		}
		seenIDs[operation.operationID], seenPaths[key] = true, true
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		path := "/api/v1/audit-exports"
		if method == http.MethodGet {
			path += "/pid_52000001-0000-4000-8000-000000000001"
		}
		for _, kind := range []string{"valid", "PAT", "stale", "role", "scope", "csrf"} {
			identity := fixtureRequestIdentity(t)
			identity.Permissions = []string{"view_audit"}
			request := httptest.NewRequest(method, path, nil)
			request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
			request.Header.Set("Origin", "https://audit-export.invalid")
			want := http.StatusOK
			switch kind {
			case "PAT":
				identity.CredentialKind = CredentialBearerToken
				want = http.StatusUnauthorized
			case "stale":
				identity.FreshAuthenticated = false
				identity.FreshAuthExpiresAt = identity.FreshAuthExpiresAt.AddDate(-1, 0, 0)
				if method == http.MethodPost {
					want = http.StatusForbidden
				}
			case "role":
				identity.Permissions = []string{"view"}
				want = http.StatusForbidden
			case "scope":
				request.Header.Set(expectedScopeHeader, "wrong")
				want = http.StatusConflict
			case "csrf":
				request.Header.Set("X-CSRF-Token", "wrong")
				if method == http.MethodPost {
					want = http.StatusForbidden
				}
			}
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://audit-export.invalid"}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != want || want == http.StatusOK && response.Body.String() != "export" {
				t.Fatalf("%s/%s status%d want%d", method, kind, response.Code, want)
			}
		}
	}
}

func TestAuditExportCompositionRejectsMissingOrSharedHandler(t *testing.T) {
	dependencies := auditExportCompositionDependencies()
	var missing *constantHandler
	for _, handler := range []http.Handler{nil, missing, dependencies.Session, dependencies.Identity, dependencies.Workflow} {
		if router, err := NewCompositionWithAuditExports(dependencies, handler); err == nil || router != nil {
			t.Fatal("invalid export dependency accepted")
		}
	}
	dependencies.Risk = nil
	if router, err := NewCompositionWithAuditExports(dependencies, handlerResponse("export")); err == nil || router != nil {
		t.Fatal("extended composition bypassed core validation")
	}
}
