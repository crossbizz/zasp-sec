package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func securityAgentPricingPolicyFixture(i RequestIdentity) SecurityAgentPlannerPricingPolicy {
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	return SecurityAgentPlannerPricingPolicy{Provider: "openrouter", Model: "openai/gpt-5-mini", AccountProfile: "default", CostUnit: "openrouter_credit", MaximumTokens: 4096, MaximumCostNanoCredits: 50000000,
		RequestPolicyVersion: "security-agent-planner-v1", RequestTokenLimit: 2048, CredentialReference: "secret_ref_planner/" + o + "/" + w + "/" + e + "/openrouter", CredentialDigest: "sha256:" + strings.Repeat("a", 64),
		EffectiveAt: "2026-11-13T00:00:00.000000Z", ExpiresAt: "2026-11-27T00:00:00.000000Z"}
}

// The pricing approval is admitted only as setSecurityAgentPlannerPricing of
// a freshly authenticated browser session, for the request's own scope and
// actor, with the Environment as the allowed target and a closed request
// that carries no time of fresh authentication.
func TestSecurityAgentPricingStatementContract(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	request := func(mutate func(map[string]any)) json.RawMessage {
		policy, _ := json.Marshal(securityAgentPricingPolicyFixture(i))
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": p, "operation": "create", "idempotency_key": "idempotency-key-0001", "expected_version": 0, "expected_account_version": 0, "policy": json.RawMessage(policy)}
		if mutate != nil {
			mutate(q)
		}
		raw, _ := json.Marshal(q)
		return raw
	}
	policyWith := func(mutate func(*SecurityAgentPlannerPricingPolicy)) func(map[string]any) {
		return func(q map[string]any) {
			policy := securityAgentPricingPolicyFixture(i)
			mutate(&policy)
			q["policy"] = policy
		}
	}
	grant := func() RequestAuthorization {
		return RequestAuthorization{OperationID: "setSecurityAgentPlannerPricing", Identity: i, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: "environment", ID: e, Version: 1}}}
	}
	args := func(mutate func(map[string]any)) []any { return []any{o, w, e, p, request(mutate)} }
	if handled, allowed := securityAgentPricingStatementAllowed(grant(), currentSecurityAgentPricingAdminSQL, args(nil)); !handled || !allowed {
		t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
	}
	if !authorizationStatementAllowed(grant(), currentSecurityAgentPricingAdminSQL, args(nil)) {
		t.Fatal("statement allowlist refused the contract")
	}
	for _, version := range []func(map[string]any){
		func(q map[string]any) {
			q["operation"], q["expected_version"], q["expected_account_version"] = "version", 1, 1
		},
		func(q map[string]any) {
			q["operation"], q["expected_version"], q["expected_account_version"] = "disable", 7, 1000000
		},
	} {
		if !authorizationStatementAllowed(grant(), currentSecurityAgentPricingAdminSQL, args(version)) {
			t.Fatal("a later revision was refused")
		}
	}
	refusals := map[string]func() (RequestAuthorization, []any){
		"another operation": func() (RequestAuthorization, []any) {
			g := grant()
			g.OperationID = "setSecurityAgentExecutionControl"
			return g, args(nil)
		},
		"a collection request": func() (RequestAuthorization, []any) { g := grant(); g.Collection = true; return g, args(nil) },
		"an API token": func() (RequestAuthorization, []any) {
			g := grant()
			g.Identity.CredentialKind = CredentialBearerToken
			return g, args(nil)
		},
		"stale authentication": func() (RequestAuthorization, []any) {
			g := grant()
			g.Identity.FreshAuthenticated = false
			return g, args(nil)
		},
		"no fresh window": func() (RequestAuthorization, []any) {
			g := grant()
			g.Identity.FreshAuthExpiresAt = time.Time{}
			return g, args(nil)
		},
		"no allowed target": func() (RequestAuthorization, []any) { g := grant(); g.Allowed = nil; return g, args(nil) },
		"another target kind": func() (RequestAuthorization, []any) {
			g := grant()
			g.Allowed[0].Kind = "organization"
			return g, args(nil)
		},
		"another environment":  func() (RequestAuthorization, []any) { a := args(nil); a[2] = w; return grant(), a },
		"another organization": func() (RequestAuthorization, []any) { a := args(nil); a[0] = w; return grant(), a },
		"another principal":    func() (RequestAuthorization, []any) { a := args(nil); a[3] = o; return grant(), a },
		"an extra argument":    func() (RequestAuthorization, []any) { return grant(), append(args(nil), "x") },
		"a request as a string": func() (RequestAuthorization, []any) {
			a := args(nil)
			a[4] = string(a[4].(json.RawMessage))
			return grant(), a
		},
		"body: other scope": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["environment_id"] = w })
		},
		"body: other actor": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["actor_id"] = o })
		},
		"body: fresh time": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["fresh_auth_at"] = "2026-11-13T00:00:00.000000Z" })
		},
		"body: unknown field": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["extra"] = true })
		},
		"body: operation": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["operation"] = "delete" })
		},
		"body: create at one": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["expected_version"] = 1 })
		},
		"body: version at zero": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["operation"] = "version" })
		},
		"body: idempotency key": func() (RequestAuthorization, []any) {
			return grant(), args(func(q map[string]any) { q["idempotency_key"] = "short" })
		},
		"policy: provider": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) { v.Provider = "other" }))
		},
		"policy: foreign secret": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) {
				v.CredentialReference = "secret_ref_planner/" + o + "/" + w + "/" + w + "/openrouter"
			}))
		},
		"policy: bare prefix": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) {
				v.CredentialReference = "secret_ref_planner/" + o + "/" + w + "/" + e + "/"
			}))
		},
		"policy: raw credential": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) { v.CredentialDigest = "sk-or-v1-secret" }))
		},
		"policy: token ceiling": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) { v.MaximumTokens = 12001 }))
		},
		"policy: request limit": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) { v.RequestTokenLimit = 4097 }))
		},
		"policy: lifetime": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) { v.ExpiresAt = "2026-12-14T00:00:00.000001Z" }))
		},
		"policy: time format": func() (RequestAuthorization, []any) {
			return grant(), args(policyWith(func(v *SecurityAgentPlannerPricingPolicy) { v.EffectiveAt = "2026-11-13T00:00:00Z" }))
		},
	}
	for name, refusal := range refusals {
		g, a := refusal()
		if authorizationStatementAllowed(g, currentSecurityAgentPricingAdminSQL, a) {
			t.Fatalf("%s was admitted", name)
		}
	}
	policy, err := authorization.LookupOperation("setSecurityAgentPlannerPricing")
	if err != nil || policy.Permission != "manage_identity" || !policy.FreshAuth || !slices.Equal(policy.Security, []string{"BrowserSession"}) || policy.Method != http.MethodPut || policy.Path != "/api/v1/security-agent-planner-pricing" {
		t.Fatalf("operation policy=%+v err=%v", policy, err)
	}
	if target, err := authorizationTargetPolicy("setSecurityAgentPlannerPricing"); err != nil || target.Mode != "scope" || target.Kind != "environment" {
		t.Fatalf("target policy=%+v err=%v", target, err)
	}
	if !requiresFreshAuthentication("setSecurityAgentPlannerPricing") {
		t.Fatal("the route does not require fresh authentication")
	}
}

// With a checked request the repository sends exactly the one authorized
// statement, with the request's scope and actor and no time of fresh
// authentication, and refuses a result that does not answer the request.
func TestSecurityAgentPricingRepositoryUsesAuthorizedStatement(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.Permissions = []string{"view", "manage_identity"}
	i.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "security-agent-pricing", Digest: [32]byte{1}}
	resolver := authorizationTargetFunc(func(_ context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
		return AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: "environment", ID: identity.Scope.EnvironmentID().String(), Version: 1}}}, nil
	})
	checker := authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
	})
	authorizer := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	policy := securityAgentPricingPolicyFixture(i)
	wirePolicy, _ := json.Marshal(policy)
	const policyID, accountID, mutationID = "pid_40000001-0000-4000-8000-000000000001", "pid_40000002-0000-4000-8000-000000000002", "pid_40000003-0000-4000-8000-000000000003"
	response := func(mutate func(map[string]any)) string {
		v := map[string]any{"contract_version": 61, "organization_id": o, "workspace_id": w, "environment_id": e, "policy_id": policyID, "version": 1, "policy_digest": "sha256:" + strings.Repeat("b", 64), "account_id": accountID, "account_version": 1, "disabled": false, "policy": json.RawMessage(wirePolicy), "mutation_id": mutationID}
		if mutate != nil {
			mutate(v)
		}
		raw, _ := json.Marshal(v)
		return string(raw)
	}
	input := SecurityAgentPlannerPricingMutation{Operation: "create", IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 0, ExpectedAccountVersion: 0, Policy: policy}
	exercise := func(operation, payload string) (*completionTxFixture, *completionDriverFixture, SecurityAgentPlannerPricingResult, error) {
		grant, err := authorizer.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: operation})
		if err != nil {
			t.Fatalf("authorize %s: %v", operation, err)
		}
		tx := &completionTxFixture{payload: payload}
		driver := &completionDriverFixture{tx: tx, ready: true}
		database, err := NewPostgresJSONDatabase(driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
		result, err := (&PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion}).SetSecurityAgentPlannerPricing(ctx, i, input)
		return tx, driver, result, err
	}
	tx, driver, result, err := exercise("setSecurityAgentPlannerPricing", response(nil))
	if err != nil || result.PolicyID != policyID || result.Version != 1 || result.Policy != policy || result.MutationID != mutationID {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !slices.Equal(tx.steps, []string{"fence", "effect"}) || !slices.Equal(tx.statements, []string{currentSecurityAgentPricingAdminSQL}) || len(driver.direct) != 0 {
		t.Fatalf("steps=%v statements=%v direct=%v", tx.steps, tx.statements, driver.direct)
	}
	sent := tx.arguments[0]
	var body map[string]any
	if len(sent) != 5 || sent[0] != o || sent[1] != w || sent[2] != e || sent[3] != p || json.Unmarshal(sent[4].(json.RawMessage), &body) != nil || body["actor_id"] != p || body["environment_id"] != e {
		t.Fatalf("statement arguments=%v", sent)
	}
	if _, present := body["fresh_auth_at"]; present {
		t.Fatal("the API named the time of fresh authentication")
	}
	if tx, driver, _, err = exercise("setSecurityAgentExecutionControl", response(nil)); err == nil || slices.Contains(tx.steps, "effect") || len(driver.direct) != 0 {
		t.Fatalf("statement under another operation: err=%v steps=%v", err, tx.steps)
	}
	for name, mutate := range map[string]func(map[string]any){
		"another environment": func(v map[string]any) { v["environment_id"] = w },
		"another version":     func(v map[string]any) { v["version"] = 2 },
		"another contract":    func(v map[string]any) { v["contract_version"] = 60 },
		"disabled":            func(v map[string]any) { v["disabled"] = true },
		"another policy":      func(v map[string]any) { other := policy; other.MaximumTokens = 1; v["policy"] = other },
		"an extra field":      func(v map[string]any) { v["credential"] = "secret" },
		"a missing field":     func(v map[string]any) { delete(v, "mutation_id") },
	} {
		if _, _, _, err := exercise("setSecurityAgentPlannerPricing", response(mutate)); err != ErrRepositoryUnavailable {
			t.Fatalf("result with %s: err=%v", name, err)
		}
	}
	token := i
	token.CredentialKind = CredentialBearerToken
	if _, err := (&PostgresRepository{database: &completionJSONFixture{}}).SetSecurityAgentPlannerPricing(context.Background(), token, input); err != ErrRepositoryOperation {
		t.Fatalf("API token: err=%v", err)
	}
}

type securityAgentPricingAuthorityFixture struct {
	calls []SecurityAgentPlannerPricingMutation
	err   error
}

func (f *securityAgentPricingAuthorityFixture) SetSecurityAgentPlannerPricing(_ context.Context, _ RequestIdentity, input SecurityAgentPlannerPricingMutation) (SecurityAgentPlannerPricingResult, error) {
	f.calls = append(f.calls, input)
	return SecurityAgentPlannerPricingResult{PolicyID: "pid_40000001-0000-4000-8000-000000000001", Version: input.ExpectedVersion + 1, PolicyDigest: "sha256:" + strings.Repeat("b", 64), AccountID: "pid_40000002-0000-4000-8000-000000000002", AccountVersion: 1, Disabled: input.Operation == "disable", Policy: input.Policy, MutationID: "pid_40000003-0000-4000-8000-000000000003"}, f.err
}

// The route is a browser session with fresh authentication and its explicit
// confirmation; it reaches the authority only with a complete request for
// the session's own Environment.
func TestSecurityAgentPricingHandler(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	i := fixtureRequestIdentity(t)
	i.FreshAuthExpiresAt = now.Add(4 * time.Minute)
	policy, _ := json.Marshal(securityAgentPricingPolicyFixture(i))
	body := func(environment string) string {
		return `{"environment_id":"` + environment + `","operation":"create","expected_account_version":0,"policy":` + string(policy) + `}`
	}
	serve := func(identity RequestIdentity, operation string, mutate func(*http.Request), payload string) (*httptest.ResponseRecorder, *securityAgentPricingAuthorityFixture) {
		authority := &securityAgentPricingAuthorityFixture{}
		handler, err := NewSecurityAgentPricingHTTPHandler(authority, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.WithValue(context.Background(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}})
		ctx = context.WithValue(ctx, identityContextKey{}, identity)
		request := httptest.NewRequest(http.MethodPut, "/api/v1/security-agent-planner-pricing", strings.NewReader(payload)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "idempotency-key-0001")
		request.Header.Set("If-Match", `"0"`)
		request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
		if mutate != nil {
			mutate(request)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response, authority
	}
	response, authority := serve(i, "setSecurityAgentPlannerPricing", nil, body(i.Scope.EnvironmentID().String()))
	if response.Code != http.StatusOK || len(authority.calls) != 1 || authority.calls[0].Operation != "create" || authority.calls[0].ExpectedVersion != 0 || authority.calls[0].IdempotencyKey != "idempotency-key-0001" ||
		response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != "pid_40000003-0000-4000-8000-000000000003" || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"policy_id":"pid_40000001-0000-4000-8000-000000000001"`) {
		t.Fatalf("status=%d headers=%v body=%s calls=%+v", response.Code, response.Header(), response.Body.String(), authority.calls)
	}
	token, stale, expired := i, i, i
	token.CredentialKind = CredentialBearerToken
	stale.FreshAuthenticated = false
	expired.FreshAuthExpiresAt = now.Add(-time.Second)
	for name, tc := range map[string]struct {
		identity  RequestIdentity
		operation string
		mutate    func(*http.Request)
		payload   string
		status    int
	}{
		"API token":            {token, "setSecurityAgentPlannerPricing", nil, body(i.Scope.EnvironmentID().String()), http.StatusUnauthorized},
		"stale authentication": {stale, "setSecurityAgentPlannerPricing", nil, body(i.Scope.EnvironmentID().String()), http.StatusUnauthorized},
		"expired fresh window": {expired, "setSecurityAgentPlannerPricing", nil, body(i.Scope.EnvironmentID().String()), http.StatusUnauthorized},
		"another operation":    {i, "setSecurityAgentExecutionControl", nil, body(i.Scope.EnvironmentID().String()), http.StatusNotFound},
		"no confirmation":      {i, "setSecurityAgentPlannerPricing", func(r *http.Request) { r.Header.Del("X-Zasp-Fresh-Auth") }, body(i.Scope.EnvironmentID().String()), http.StatusBadRequest},
		"no idempotency key":   {i, "setSecurityAgentPlannerPricing", func(r *http.Request) { r.Header.Del("Idempotency-Key") }, body(i.Scope.EnvironmentID().String()), http.StatusBadRequest},
		"no version":           {i, "setSecurityAgentPlannerPricing", func(r *http.Request) { r.Header.Del("If-Match") }, body(i.Scope.EnvironmentID().String()), http.StatusBadRequest},
		"a query":              {i, "setSecurityAgentPlannerPricing", func(r *http.Request) { r.URL.RawQuery = "x=1" }, body(i.Scope.EnvironmentID().String()), http.StatusBadRequest},
		"another environment":  {i, "setSecurityAgentPlannerPricing", nil, body(i.Scope.WorkspaceID().String()), http.StatusBadRequest},
		"an unknown field":     {i, "setSecurityAgentPlannerPricing", nil, strings.Replace(body(i.Scope.EnvironmentID().String()), `"operation"`, `"fresh_auth_at":"2026-11-13T00:00:00.000000Z","operation"`, 1), http.StatusBadRequest},
		"no account version":   {i, "setSecurityAgentPlannerPricing", nil, strings.Replace(body(i.Scope.EnvironmentID().String()), `"expected_account_version":0,`, ``, 1), http.StatusBadRequest},
		"another content type": {i, "setSecurityAgentPlannerPricing", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, body(i.Scope.EnvironmentID().String()), http.StatusBadRequest},
	} {
		response, authority := serve(tc.identity, tc.operation, tc.mutate, tc.payload)
		if response.Code != tc.status || len(authority.calls) != 0 {
			t.Fatalf("%s: status=%d calls=%d body=%s", name, response.Code, len(authority.calls), response.Body.String())
		}
	}
	surface, err := NewSecurityAgentPricingWorkflowSurface(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	if err != nil {
		t.Fatal(err)
	}
	for operation, status := range map[string]int{"setSecurityAgentPlannerPricing": http.StatusAccepted, "setSecurityAgentExecutionControl": http.StatusTeapot, "": http.StatusTeapot} {
		ctx := context.Background()
		if operation != "" {
			ctx = context.WithValue(ctx, routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}})
		}
		response := httptest.NewRecorder()
		surface.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/", nil).WithContext(ctx))
		if response.Code != status {
			t.Fatalf("surface routed %q to status %d", operation, response.Code)
		}
	}
}
