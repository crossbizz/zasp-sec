package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A token's expiry is the caller's choice inside the lifetime its
// permissions allow; without one it is 24 hours.
func TestAPITokenExpiryFollowsThePermissions(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	if expires, defaulted, err := parseAPITokenExpiry("", []string{"view"}, now, nil); err != nil || !defaulted || !expires.Equal(now.Add(day)) {
		t.Fatalf("no expiry = (%s, %t, %v)", expires, defaulted, err)
	}
	for name, test := range map[string]struct {
		permissions []string
		lifetime    time.Duration
		accepted    bool
	}{
		"a reader for a day":                      {[]string{"view"}, day, true},
		"a reader for 30 days":                    {[]string{"view"}, 30 * day, true},
		"a reader for exactly 90 days":            {[]string{"view"}, 90 * day, true},
		"a reader for 90 days and six minutes":    {[]string{"view"}, 90*day + 6*time.Minute, false},
		"a reader whose clock runs a minute fast": {[]string{"view"}, 90*day + time.Minute, true},
		"a reader for a year":                     {[]string{"view"}, 365 * day, false},
		"a manager for 90 days":                   {[]string{"manage_workflows", "view"}, 90 * day, true},
		"a manager for 91 days":                   {[]string{"manage_workflows", "view"}, 91 * day, false},
		"a gateway for a year":                    {[]string{"decide_guardrails"}, 365 * day, true},
		"a gateway for a year and six minutes":    {[]string{"decide_guardrails"}, 365*day + 6*time.Minute, false},
		"decisions and reading for 91 days":       {[]string{"decide_guardrails", "view"}, 91 * day, false},
		"decisions named twice for a year":        {[]string{"decide_guardrails", "decide_guardrails"}, 365 * day, false},
		"no permission for a year":                {nil, 365 * day, false},
		"a token that expired a second ago":       {[]string{"view"}, -time.Second, false},
		"a token that expires this very instant":  {[]string{"view"}, 0, false},
		"a gateway token that expired a year ago": {[]string{"decide_guardrails"}, -365 * day, false},
	} {
		value := now.Add(test.lifetime).Format(time.RFC3339Nano)
		expires, defaulted, err := parseAPITokenExpiry(value, test.permissions, now, nil)
		if test.accepted != (err == nil) || defaulted || test.accepted && !expires.Equal(now.Add(test.lifetime)) || !test.accepted && !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("%s: (%s, %t, %v), accepted want %t", name, expires, defaulted, err, test.accepted)
		}
	}
	for _, malformed := range []string{"tomorrow", "2026-11-15", "1763208000", " "} {
		if _, _, err := parseAPITokenExpiry(malformed, []string{"view"}, now, nil); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("expiry %q: %v", malformed, err)
		}
	}
	// An earlier failure of the request is kept.
	if _, _, err := parseAPITokenExpiry("", []string{"view"}, now, ErrRepositoryUnavailable); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("an earlier failure was lost: %v", err)
	}
	if apiTokenLifetimeCeilingDays([]string{PermissionDecideGuardrails}) != 365 || apiTokenLifetimeCeilingDays([]string{"view"}) != 90 || apiTokenLifetimeCeilingDays(nil) != 90 {
		t.Fatal("the fixed lifetimes changed")
	}
	// A token of the hosted gateway, alone or with decisions, reads nothing
	// and may live as long; with anything else it may not.
	if apiTokenLifetimeCeilingDays([]string{PermissionUseGateway}) != 365 || apiTokenLifetimeCeilingDays([]string{PermissionDecideGuardrails, PermissionUseGateway}) != 365 ||
		apiTokenLifetimeCeilingDays([]string{PermissionUseGateway, "view"}) != 90 || apiTokenLifetimeCeilingDays([]string{PermissionDecideGuardrails, "manage_workflows"}) != 90 || apiTokenLifetimeCeilingDays([]string{}) != 90 {
		t.Fatal("the lifetime of a gateway token changed")
	}
}

func apiTokenPolicyFixture(environment string, days int, version int64) string {
	updated := "null"
	if version > 0 {
		updated = `"2026-11-14T12:00:00.000000Z"`
	}
	value, _ := json.Marshal(map[string]any{"environment_id": environment, "max_lifetime_days": days, "version": version, "default_lifetime_days": 1,
		"decision_token_max_lifetime_days": min(365, days), "token_max_lifetime_days": min(90, days)})
	return strings.TrimSuffix(string(value), "}") + `,"updated_at":` + updated + `}`
}

// The handler serves the setting to a browser session of the Environment,
// requires fresh authentication and an exact body to change it, and refuses
// an answer of the database that is not the setting.
func TestAPITokenPolicyHandlerIsExact(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind, identity.FreshAuthenticated = CredentialBrowserSession, true
	environment := identity.Scope.EnvironmentID().String()
	database := &connectorCallDatabase{responses: map[string]json.RawMessage{
		currentAPITokenPolicySQL:    json.RawMessage(apiTokenPolicyFixture(environment, 365, 0)),
		currentAPITokenSetPolicySQL: json.RawMessage(strings.TrimSuffix(apiTokenPolicyFixture(environment, 30, 1), "}") + `,"audit_id":"pid_62000001-0000-4000-8000-000000000001","correlation_id":"pid_62000002-0000-4000-8000-000000000002"}`),
	}}
	handler := &apiTokenPolicyHTTPHandler{database: database, newProductID: func() (string, error) { return "pid_62000001-0000-4000-8000-000000000001", nil }}
	serve := func(identity RequestIdentity, operation, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		ctx := context.WithValue(context.Background(), identityContextKey{}, identity)
		ctx = context.WithValue(ctx, correlationContextKey{}, "pid_62000002-0000-4000-8000-000000000002")
		request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(ctx)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request, operation)
		return recorder
	}
	headers := map[string]string{"Idempotency-Key": "token-policy-0000001", "If-Match": `"0"`}

	read := serve(identity, "getAPITokenPolicy", http.MethodGet, "/api/v1/admin/api-token-policy", "", nil)
	var policy APITokenPolicy
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &policy) != nil || policy.MaxLifetimeDays != 365 || policy.DecisionTokenMaxLifetimeDays != 365 || policy.TokenMaxLifetimeDays != 90 || policy.Version != 0 || policy.UpdatedAt != nil ||
		read.Header().Get("ETag") != `"0"` || read.Header().Get("Cache-Control") != "no-store" || len(database.args) != 3 || database.args[2] != environment {
		t.Fatalf("read: status=%d body=%s args=%v", read.Code, read.Body.String(), database.args)
	}
	written := serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30}`, headers)
	if written.Code != http.StatusOK || json.Unmarshal(written.Body.Bytes(), &policy) != nil || policy.MaxLifetimeDays != 30 || policy.DecisionTokenMaxLifetimeDays != 30 || policy.TokenMaxLifetimeDays != 30 || policy.Version != 1 ||
		written.Header().Get("ETag") != `"1"` || written.Header().Get("X-Audit-ID") != "pid_62000001-0000-4000-8000-000000000001" ||
		len(database.args) != 8 || database.args[3] != identity.PrincipalID.String() || database.args[4] != 30 || database.args[5] != int64(0) {
		t.Fatalf("write: status=%d body=%s args=%v", written.Code, written.Body.String(), database.args)
	}

	// What is refused before the database is asked.
	database.query = ""
	bearer := identity
	bearer.CredentialKind = CredentialBearerToken
	stale := identity
	stale.FreshAuthenticated = false
	for name, response := range map[string]*httptest.ResponseRecorder{
		"an API token reads":            serve(bearer, "getAPITokenPolicy", http.MethodGet, "/api/v1/admin/api-token-policy", "", nil),
		"an API token writes":           serve(bearer, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30}`, headers),
		"a query":                       serve(identity, "getAPITokenPolicy", http.MethodGet, "/api/v1/admin/api-token-policy?environment_id=other", "", nil),
		"no fresh authentication":       serve(stale, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30}`, headers),
		"no version":                    serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30}`, map[string]string{"Idempotency-Key": "token-policy-0000001"}),
		"zero days":                     serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":0}`, headers),
		"more than a year":              serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":366}`, headers),
		"no number":                     serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{}`, headers),
		"a member the contract lacks":   serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30,"environment_id":"other"}`, headers),
		"an operation of another route": serve(identity, "listAPITokens", http.MethodGet, "/api/v1/admin/api-tokens", "", nil),
	} {
		if response.Code == http.StatusOK || database.query != "" {
			t.Fatalf("%s: status=%d, database asked %q", name, response.Code, database.query)
		}
	}
	if response := serve(stale, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30}`, headers); response.Code != http.StatusForbidden {
		t.Fatalf("without fresh authentication: status=%d", response.Code)
	}

	// What is refused when the database answers something else.
	for name, hostile := range map[string]string{
		"another Environment":           apiTokenPolicyFixture("pid_62000009-0000-4000-8000-000000000009", 365, 0),
		"a limit above the fixed one":   strings.Replace(apiTokenPolicyFixture(environment, 365, 0), `"token_max_lifetime_days":90`, `"token_max_lifetime_days":365`, 1),
		"a limit without a version":     apiTokenPolicyFixture(environment, 30, 0),
		"a version without a timestamp": strings.Replace(apiTokenPolicyFixture(environment, 30, 1), `"updated_at":"2026-11-14T12:00:00.000000Z"`, `"updated_at":null`, 1),
		"an extra member":               strings.TrimSuffix(apiTokenPolicyFixture(environment, 365, 0), "}") + `,"token_digest":"00"}`,
		"another default":               strings.Replace(apiTokenPolicyFixture(environment, 365, 0), `"default_lifetime_days":1`, `"default_lifetime_days":30`, 1),
	} {
		database.responses[currentAPITokenPolicySQL] = json.RawMessage(hostile)
		if response := serve(identity, "getAPITokenPolicy", http.MethodGet, "/api/v1/admin/api-token-policy", "", nil); response.Code == http.StatusOK {
			t.Fatalf("%s was served: %s", name, response.Body.String())
		}
	}
	// The database recorded another limit than the one asked for.
	database.responses[currentAPITokenSetPolicySQL] = json.RawMessage(strings.TrimSuffix(apiTokenPolicyFixture(environment, 60, 1), "}") + `,"audit_id":"pid_62000001-0000-4000-8000-000000000001","correlation_id":"pid_62000002-0000-4000-8000-000000000002"}`)
	if response := serve(identity, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", `{"max_lifetime_days":30}`, headers); response.Code == http.StatusOK {
		t.Fatalf("another limit than the one asked for was served: %s", response.Body.String())
	}
}

// The two policy statements are admitted for a browser session's request on
// its own Environment, the write only for its own principal and with fresh
// authentication.
func TestAPITokenPolicyStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind, i.FreshAuthenticated = CredentialBrowserSession, true
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const other, audit, correlation = "pid_63000001-0000-4000-8000-000000000001", "pid_63000002-0000-4000-8000-000000000002", "pid_63000003-0000-4000-8000-000000000003"
	grant := func(operation string) RequestAuthorization {
		return RequestAuthorization{OperationID: operation, Identity: i, PathParameters: map[string]string{}, Allowed: []AuthorizationTarget{{Scope: i.Scope, Kind: "environment", ID: e}}}
	}
	read := func() []any { return []any{o, w, e} }
	write := func() []any { return []any{o, w, e, p, 30, int64(0), audit, correlation} }
	for _, operation := range []string{"getAPITokenPolicy", "putAPITokenPolicy", "listAPITokens", "createAPIToken", "getGuardrailPolicy", "getDataControls"} {
		if got := authorizationStatementAllowed(grant(operation), currentAPITokenPolicySQL, read()); got != (operation == "getAPITokenPolicy") {
			t.Fatalf("read under %s admitted=%t", operation, got)
		}
		if got := authorizationStatementAllowed(grant(operation), currentAPITokenSetPolicySQL, write()); got != (operation == "putAPITokenPolicy") {
			t.Fatalf("write under %s admitted=%t", operation, got)
		}
	}
	for name, change := range map[string]func(g *RequestAuthorization, read, write []any){
		"another organization": func(_ *RequestAuthorization, read, write []any) { read[0], write[0] = other, other },
		"another workspace":    func(_ *RequestAuthorization, read, write []any) { read[1], write[1] = other, other },
		"another environment":  func(_ *RequestAuthorization, read, write []any) { read[2], write[2] = other, other },
		"an API token":         func(g *RequestAuthorization, _, _ []any) { g.Identity.CredentialKind = CredentialBearerToken },
		"a collection":         func(g *RequestAuthorization, _, _ []any) { g.Collection = true },
		"no allowed object":    func(g *RequestAuthorization, _, _ []any) { g.Allowed = nil },
		"a path object":        func(g *RequestAuthorization, _, _ []any) { g.PathParameters = map[string]string{"id": other} },
	} {
		readGrant, writeGrant, readArguments, writeArguments := grant("getAPITokenPolicy"), grant("putAPITokenPolicy"), read(), write()
		change(&readGrant, readArguments, writeArguments)
		change(&writeGrant, readArguments, writeArguments)
		if authorizationStatementAllowed(readGrant, currentAPITokenPolicySQL, readArguments) || authorizationStatementAllowed(writeGrant, currentAPITokenSetPolicySQL, writeArguments) {
			t.Fatalf("%s was admitted", name)
		}
	}
	for name, change := range map[string]func(g *RequestAuthorization, arguments []any){
		"another principal":       func(_ *RequestAuthorization, arguments []any) { arguments[3] = other },
		"no fresh authentication": func(g *RequestAuthorization, _ []any) { g.Identity.FreshAuthenticated = false },
		"zero days":               func(_ *RequestAuthorization, arguments []any) { arguments[4] = 0 },
		"two years":               func(_ *RequestAuthorization, arguments []any) { arguments[4] = 730 },
		"days as text":            func(_ *RequestAuthorization, arguments []any) { arguments[4] = "30" },
		"a negative version":      func(_ *RequestAuthorization, arguments []any) { arguments[5] = int64(-1) },
		"no audit identifier":     func(_ *RequestAuthorization, arguments []any) { arguments[6] = "" },
	} {
		g, arguments := grant("putAPITokenPolicy"), write()
		change(&g, arguments)
		if authorizationStatementAllowed(g, currentAPITokenSetPolicySQL, arguments) {
			t.Fatalf("a write with %s was admitted", name)
		}
	}
	if authorizationStatementAllowed(grant("putAPITokenPolicy"), currentAPITokenSetPolicySQL, append(write(), "extra")) || authorizationStatementAllowed(grant("getAPITokenPolicy"), currentAPITokenPolicySQL, append(read(), p)) {
		t.Fatal("another argument count was admitted")
	}
}
