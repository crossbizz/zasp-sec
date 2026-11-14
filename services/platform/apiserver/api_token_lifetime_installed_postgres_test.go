package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// installedIdentityVerifiers registers the deployment's two identity
// verifiers where a bare installation has none (step 2 after installing:
// agentsec-migrate register-identity-session-verifier and
// register-identity-webhook-verifier). Token administration needs them.
func installedIdentityVerifiers(baseline *installedBaseline) {
	baseline.t.Helper()
	if baseline.text(`SELECT count(*)::text FROM zasp_authorization80_identity.verifiers`) != "0" {
		return
	}
	seed := bytes.Repeat([]byte{0x63}, 32)
	session, sessionErr := authorization.NewIdentitySessionKey(seed)
	webhook, webhookErr := authorization.NewIdentityWebhookKey(seed)
	if sessionErr != nil || webhookErr != nil {
		baseline.t.Fatal(sessionErr, webhookErr)
	}
	operator := baseline.login("zasp_operator")
	audience := sha256.Sum256([]byte("https://zasp.test.invalid"))
	for statement, key := range map[string][2]any{
		`SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,$5,$6)`: {session.Version(), session.Verifier()},
		`SELECT zasp_authorization80_identity.register_webhook($1,$2,$3,$4,$5,$6)`: {webhook.Version(), webhook.Verifier()},
	} {
		if _, err := operator.Exec(baseline.ctx, statement, key[0], key[1], hex.EncodeToString(audience[:]), "project-test-installed", "zasp_svc_api", ""); err != nil {
			baseline.t.Fatalf("register identity verifier: %v", err)
		}
	}
}

// TestAPITokenLifetimeOnInstalledBaselinePostgres proves on an installed
// baseline, through the product's token administration handlers, how long an
// API token may live (completion.sql section WS10c):
//
//   - without an expiry a token lives 24 hours, and a repeated request
//     answers the same token;
//   - a token that holds decide_guardrails only may live 365 days, any other
//     90 days, and the database refuses a longer expiry even when the API
//     server's own check is bypassed;
//   - an administrator lowers the limit for the Environment (fresh
//     authentication, optimistic version, audited); new tokens obey it and
//     existing tokens keep their expiry;
//   - the list shows each token's expiry and when it was last used;
//   - a rotation keeps the expiry, and a revocation takes effect at once,
//     also for a request that was authorized before it.
func TestAPITokenLifetimeOnInstalledBaselinePostgres(t *testing.T) {
	baseline := startInstalledBaseline(t)
	ctx := baseline.ctx
	administrator := baseline.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	engineer := baseline.member("security_engineer", "investigate_sessions", "manage_findings", "manage_workflows", "run_tests", "view")
	if err := baseline.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(baseline.product)
	if err != nil {
		t.Fatalf("product repository on the installed baseline: %v", err)
	}
	installedIdentityVerifiers(baseline)
	handler := &identityHTTPHandler{repository: repository, administration: repository, tokenPolicy: &apiTokenPolicyHTTPHandler{database: baseline.product, newProductID: func() (string, error) { return baseline.id(), nil }},
		signingKey: bytes.Repeat([]byte{0x31}, 32), tokenRevealKey: bytes.Repeat([]byte{0x52}, 32), now: func() time.Time { return time.Now().UTC() }}
	send := func(principal installedPrincipal, operation, method, target string, parameters map[string]string, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		if parameters == nil {
			parameters = map[string]string{}
		}
		checked, err := baseline.checked(principal, RoutedOperation{OperationID: operation, PathParameters: parameters})
		if err != nil {
			t.Fatalf("authorize %s: %v", operation, err)
		}
		request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(context.WithValue(checked, correlationContextKey{}, baseline.id()))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	type tokenView struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		ExpiresAt  time.Time  `json:"expires_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		RevokedAt  *time.Time `json:"revoked_at"`
		Version    int64      `json:"version"`
	}
	type created struct {
		GrantID string    `json:"grant_id"`
		Token   tokenView `json:"token"`
	}
	day := 24 * time.Hour
	// create asks for a token; lifetime 0 names no expiry.
	create := func(name, permissions, key string, lifetime time.Duration) (*httptest.ResponseRecorder, created) {
		t.Helper()
		expiry := ""
		if lifetime != 0 {
			expiry = `,"expires_at":"` + time.Now().UTC().Add(lifetime).Format(time.RFC3339Nano) + `"`
		}
		response := send(administrator, "createAPIToken", http.MethodPost, "/api/v1/admin/api-tokens", nil,
			`{"name":"`+name+`","workspace_id":"`+baseline.w+`","environment_id":"`+baseline.e+`","permissions":`+permissions+expiry+`}`, map[string]string{"Idempotency-Key": key})
		var value created
		if response.Code == http.StatusCreated && (json.Unmarshal(response.Body.Bytes(), &value) != nil || !validProductID(value.Token.ID) || !validProductID(value.GrantID)) {
			t.Fatalf("create %s: %s", name, response.Body.String())
		}
		return response, value
	}
	accepted := func(name, permissions string, lifetime time.Duration) created {
		t.Helper()
		response, value := create(name, permissions, "create-"+baseline.id()[4:], lifetime)
		want := lifetime
		if want == 0 {
			want = day
		}
		if response.Code != http.StatusCreated || value.Token.ExpiresAt.Before(time.Now().Add(want-time.Minute)) || value.Token.ExpiresAt.After(time.Now().Add(want+time.Minute)) {
			t.Fatalf("create %s for %s: status=%d expires=%s body=%s", name, lifetime, response.Code, value.Token.ExpiresAt, response.Body.String())
		}
		return value
	}
	refused := func(name, permissions string, lifetime time.Duration) {
		t.Helper()
		if response, value := create(name, permissions, "create-"+baseline.id()[4:], lifetime); response.Code != http.StatusBadRequest || value.Token.ID != "" {
			t.Fatalf("create %s for %s was not refused: status=%d body=%s", name, lifetime, response.Code, response.Body.String())
		}
		if exists := baseline.text(`SELECT count(*)::text FROM zasp_product_api_tokens WHERE organization_id=$1 AND name=$2`, baseline.o, name); exists != "0" {
			t.Fatalf("a refused token %s exists", name)
		}
	}
	// reveal reads the raw credential of a token's pending grant, the way
	// the page shows it once.
	reveal := func(grant string) string {
		t.Helper()
		response := send(administrator, "revealAPIToken", http.MethodPost, "/api/v1/admin/api-token-reveal-grants/"+grant+"/reveal", map[string]string{"id": grant}, `{}`, nil)
		var value struct {
			Raw string `json:"raw_token"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || len(value.Raw) < 32 {
			t.Fatalf("reveal: status=%d", response.Code)
		}
		return value.Raw
	}
	list := func() map[string]tokenView {
		t.Helper()
		response := send(administrator, "listAPITokens", http.MethodGet, "/api/v1/admin/api-tokens?limit=100", nil, "", nil)
		var page struct {
			Items []tokenView `json:"items"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
			t.Fatalf("list tokens: status=%d body=%s", response.Code, response.Body.String())
		}
		tokens := map[string]tokenView{}
		for _, token := range page.Items {
			tokens[token.ID] = token
		}
		return tokens
	}
	policy := func() APITokenPolicy {
		t.Helper()
		response := send(administrator, "getAPITokenPolicy", http.MethodGet, "/api/v1/admin/api-token-policy", nil, "", nil)
		var value APITokenPolicy
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || response.Header().Get("ETag") != quoteVersion(value.Version) {
			t.Fatalf("policy: status=%d body=%s", response.Code, response.Body.String())
		}
		return value
	}
	setPolicy := func(principal installedPrincipal, days int, version int64) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]int{"max_lifetime_days": days})
		return send(principal, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", nil, string(body), map[string]string{"Idempotency-Key": "token-policy-" + baseline.id()[4:], "If-Match": quoteVersion(version)})
	}

	// 1. Without an expiry: 24 hours. The same request again answers the
	// same token, although it arrives later.
	first, defaulted := create("Default lifetime", `["view"]`, "create-default-"+baseline.e[4:], 0)
	if first.Code != http.StatusCreated || defaulted.Token.ExpiresAt.Before(time.Now().Add(day-time.Minute)) || defaulted.Token.ExpiresAt.After(time.Now().Add(day+time.Minute)) {
		t.Fatalf("default lifetime: status=%d expires=%s body=%s", first.Code, defaulted.Token.ExpiresAt, first.Body.String())
	}
	time.Sleep(20 * time.Millisecond)
	if again, replay := create("Default lifetime", `["view"]`, "create-default-"+baseline.e[4:], 0); again.Code != http.StatusCreated || replay.Token.ID != defaulted.Token.ID || !replay.Token.ExpiresAt.Equal(defaulted.Token.ExpiresAt) {
		t.Fatalf("repeated default request: status=%d token=%s want %s body=%s", again.Code, replay.Token.ID, defaulted.Token.ID, again.Body.String())
	}

	// 2. The setting before anyone changed it, and the fixed limits.
	if value := policy(); value.Version != 0 || value.MaxLifetimeDays != 365 || value.UpdatedAt != nil || value.DecisionTokenMaxLifetimeDays != 365 || value.TokenMaxLifetimeDays != 90 || value.DefaultLifetimeDays != 1 || value.EnvironmentID != baseline.e {
		t.Fatalf("initial policy: %+v", value)
	}
	reader := accepted("Reader 30 days", `["view"]`, 30*day)
	accepted("Reader 90 days", `["view"]`, 90*day-time.Hour)
	gateway := accepted("Gateway one year", `["decide_guardrails"]`, 365*day-time.Hour)
	refused("Reader 91 days", `["view"]`, 91*day)
	refused("Workflow manager one year", `["view","manage_workflows"]`, 365*day-time.Hour)
	refused("Reader with decisions 120 days", `["decide_guardrails","view"]`, 120*day)
	refused("Gateway 366 days", `["decide_guardrails"]`, 366*day)
	// A token of the hosted gateway reads nothing either: alone or with
	// decide_guardrails it may live a year, with anything else 90 days.
	accepted("Hosted gateway one year", `["use_gateway"]`, 365*day-time.Hour)
	accepted("Hosted gateway with decisions one year", `["decide_guardrails","use_gateway"]`, 365*day-time.Hour)
	accepted("Hosted gateway reader 90 days", `["use_gateway","view"]`, 90*day-time.Hour)
	refused("Hosted gateway 366 days", `["use_gateway"]`, 366*day)
	refused("Hosted gateway reader 120 days", `["use_gateway","view"]`, 120*day)
	refused("Hosted gateway with decisions and reads one year", `["decide_guardrails","use_gateway","view"]`, 365*day-time.Hour)
	refused("Expired at birth", `["view"]`, -time.Hour)

	// The database decides, not only the API server: the same statement the
	// handler sends, with an expiry above the limit, inside a checked request.
	direct := func(permissions string, lifetime time.Duration) error {
		t.Helper()
		mutation := administrationMutation{Operation: "createAPIToken", ID: baseline.id(), Name: "Direct", WorkspaceID: baseline.w, EnvironmentID: baseline.e, Permissions: json.RawMessage(permissions), ExpiresAt: time.Now().UTC().Add(lifetime),
			IdempotencyKey: "create-direct-" + baseline.id()[4:], GrantID: baseline.id(), AuditID: baseline.id(), revealKey: bytes.Repeat([]byte{0x52}, 32)}
		if err := prepareAPITokenReveal(administrator.identity, &mutation, mutation.Operation, "zasp_pat_"+strings.ReplaceAll(baseline.id()[4:], "-", "")+strings.Repeat("C", 11), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		_, err := baseline.fenced("zasp_svc_api", administrator, RoutedOperation{OperationID: "createAPIToken"}, currentCreatePatSQL,
			baseline.o, administrator.identity.PrincipalID.String(), mutation.IdempotencyKey, bytes.Repeat([]byte{1}, 32), mutation.TokenDigest, mutation.ID, baseline.w, baseline.e, mutation.Name, mutation.Permissions, mutation.ExpiresAt, mutation.AuditID, mutation.GrantID, mutation.GrantExpiresAt, mutation.Ciphertext, mutation.Nonce, mutation.AuthenticationTag)
		return err
	}
	for name, attempt := range map[string]struct {
		permissions string
		lifetime    time.Duration
	}{
		"a reader for 200 days":                   {`["view"]`, 200 * day},
		"a manager for 91 days":                   {`["manage_workflows","view"]`, 91 * day},
		"a gateway for two years":                 {`["decide_guardrails"]`, 730 * day},
		"decisions listed twice to look narrow":   {`["decide_guardrails","decide_guardrails"]`, 200 * day},
		"decisions with another permission first": {`["view","decide_guardrails"]`, 200 * day},
	} {
		if err := direct(attempt.permissions, attempt.lifetime); installedSQLState(err) != "22023" {
			t.Fatalf("%s was not refused by PostgreSQL: %v", name, err)
		}
	}
	if err := direct(`["decide_guardrails"]`, 364*day); err != nil {
		t.Fatalf("a gateway token within its lifetime was refused by PostgreSQL: %v", err)
	}

	// 3. The list shows the expiry, and the last use once the token was used.
	raw := reveal(gateway.GrantID)
	if listed := list()[gateway.Token.ID]; listed.LastUsedAt != nil || !listed.ExpiresAt.Equal(gateway.Token.ExpiresAt) || listed.RevokedAt != nil {
		t.Fatalf("gateway token before its first use: %+v", listed)
	}
	used, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw})
	if err != nil || used.CredentialKind != CredentialBearerToken || used.PrincipalID != administrator.identity.PrincipalID {
		t.Fatalf("authenticate the gateway token: %+v %v", used, err)
	}
	if listed := list()[gateway.Token.ID]; listed.LastUsedAt == nil || time.Since(*listed.LastUsedAt) > time.Minute || !listed.ExpiresAt.Equal(gateway.Token.ExpiresAt) {
		t.Fatalf("gateway token after its first use: %+v", listed)
	}

	// 4. The Environment's own limit. Who may set it, and how.
	baseline.refused[engineer.identity.PrincipalID.String()+" manage_api_tokens"] = true
	if _, err := baseline.checked(engineer, RoutedOperation{OperationID: "putAPITokenPolicy", PathParameters: map[string]string{}}); err == nil {
		t.Fatal("a person without manage_api_tokens was authorized to set the token policy")
	}
	stale := administrator
	stale.identity.FreshAuthenticated = false
	if staleContext, err := baseline.checked(stale, RoutedOperation{OperationID: "putAPITokenPolicy", PathParameters: map[string]string{}}); err == nil {
		if _, err := baseline.product.QueryJSON(staleContext, currentAPITokenSetPolicySQL, baseline.o, baseline.w, baseline.e, administrator.identity.PrincipalID.String(), 7, int64(0), baseline.id(), baseline.id()); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("the policy was set without fresh authentication: %v", err)
		}
	}
	for name, body := range map[string]string{"zero days": `{"max_lifetime_days":0}`, "two years": `{"max_lifetime_days":730}`, "no number": `{}`, "another member": `{"max_lifetime_days":7,"permissions":["view"]}`} {
		if response := send(administrator, "putAPITokenPolicy", http.MethodPut, "/api/v1/admin/api-token-policy", nil, body, map[string]string{"Idempotency-Key": "token-policy-" + baseline.id()[4:], "If-Match": `"0"`}); response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	lowered := setPolicy(administrator, 7, 0)
	var after APITokenPolicy
	if lowered.Code != http.StatusOK || json.Unmarshal(lowered.Body.Bytes(), &after) != nil || after.Version != 1 || after.MaxLifetimeDays != 7 || after.DecisionTokenMaxLifetimeDays != 7 || after.TokenMaxLifetimeDays != 7 || after.UpdatedAt == nil || lowered.Header().Get("ETag") != `"1"` || !validProductID(lowered.Header().Get("X-Audit-ID")) {
		t.Fatalf("lower the limit: status=%d body=%s", lowered.Code, lowered.Body.String())
	}
	if audited := baseline.text(`SELECT count(*)::text FROM zasp_workflow_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=($1,$2,$3,$4) AND operation='putAPITokenPolicy' AND principal_id=$5 AND resource_kind='environment' AND resource_id=$3 AND resource_version=1`,
		baseline.o, baseline.w, baseline.e, lowered.Header().Get("X-Audit-ID"), administrator.identity.PrincipalID.String()); audited != "1" {
		t.Fatalf("%s audit rows for the policy change", audited)
	}
	// A repeated or stale request names a version that is no longer current.
	if response := setPolicy(administrator, 30, 0); response.Code != http.StatusConflict {
		t.Fatalf("a stale policy version: status=%d body=%s", response.Code, response.Body.String())
	}
	if value := policy(); value.UpdatedAt == nil || !value.UpdatedAt.Equal(*after.UpdatedAt) || value.Version != 1 || value.MaxLifetimeDays != 7 || value.DecisionTokenMaxLifetimeDays != 7 || value.TokenMaxLifetimeDays != 7 {
		t.Fatalf("policy after the change: %+v want %+v", value, after)
	}
	// New tokens obey the lower limit, whatever they may do.
	refused("Reader 30 days after the limit", `["view"]`, 30*day)
	refused("Gateway 30 days after the limit", `["decide_guardrails"]`, 30*day)
	accepted("Reader 7 days", `["view"]`, 7*day-time.Hour)
	accepted("Gateway 7 days", `["decide_guardrails"]`, 7*day-time.Hour)
	refused("Hosted gateway 30 days after the limit", `["use_gateway"]`, 30*day)
	accepted("Hosted gateway 7 days", `["use_gateway"]`, 7*day-time.Hour)
	accepted("Default after the limit", `["view"]`, 0)
	// Existing tokens keep their expiry and still work.
	if listed := list(); !listed[gateway.Token.ID].ExpiresAt.Equal(gateway.Token.ExpiresAt) || !listed[reader.Token.ID].ExpiresAt.Equal(reader.Token.ExpiresAt) {
		t.Fatalf("existing tokens after the limit: %+v %+v", listed[gateway.Token.ID], listed[reader.Token.ID])
	}
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw}); err != nil {
		t.Fatalf("an existing token after the limit was lowered: %v", err)
	}
	// The limit is another Environment's business nowhere: a statement for
	// another scope than the request's is refused by PostgreSQL.
	if _, err := baseline.fenced("zasp_svc_api", administrator, RoutedOperation{OperationID: "getAPITokenPolicy"}, currentAPITokenPolicySQL, baseline.o, baseline.w, baseline.id()); installedSQLState(err) != "42501" {
		t.Fatalf("the policy of another Environment was read: %v", err)
	}
	if _, err := baseline.fenced("zasp_svc_api", administrator, RoutedOperation{OperationID: "listAPITokens"}, currentAPITokenPolicySQL, baseline.o, baseline.w, baseline.e); installedSQLState(err) != "42501" {
		t.Fatalf("the policy was read under another operation: %v", err)
	}
	var unfenced json.RawMessage
	if err := baseline.login("zasp_svc_api").QueryRow(ctx, currentAPITokenSetPolicySQL, baseline.o, baseline.w, baseline.e, administrator.identity.PrincipalID.String(), 365, int64(1), baseline.id(), baseline.id()).Scan(&unfenced); installedSQLState(err) != "42501" {
		t.Fatalf("the API login set the policy outside a checked request: %s %v", unfenced, err)
	}
	if restored := setPolicy(administrator, 365, 1); restored.Code != http.StatusOK {
		t.Fatalf("restore the limit: status=%d body=%s", restored.Code, restored.Body.String())
	}

	// 5. A rotation keeps the expiry of the token it replaces.
	rotated := send(administrator, "rotateAPIToken", http.MethodPost, "/api/v1/admin/api-tokens/"+reader.Token.ID+"/rotate", map[string]string{"id": reader.Token.ID}, `{}`,
		map[string]string{"Idempotency-Key": "rotate-" + baseline.id()[4:], "If-Match": quoteVersion(reader.Token.Version)})
	var replacement created
	if rotated.Code != http.StatusCreated || json.Unmarshal(rotated.Body.Bytes(), &replacement) != nil || replacement.Token.ID == reader.Token.ID || !replacement.Token.ExpiresAt.Equal(reader.Token.ExpiresAt) {
		t.Fatalf("rotation: status=%d replacement expires %s, original %s, body=%s", rotated.Code, replacement.Token.ExpiresAt, reader.Token.ExpiresAt, rotated.Body.String())
	}

	// 6. Revocation takes effect at once: for the next request, and for a
	// request that was authorized just before it.
	gatewayPrincipal := installedPrincipal{identity: used, binding: used.credentialBinding}
	authorized, err := baseline.checked(gatewayPrincipal, RoutedOperation{OperationID: "createGuardrailDecision", PathParameters: map[string]string{}})
	if err != nil {
		t.Fatalf("authorize a decision with the gateway token: %v", err)
	}
	decisions := &guardrailHTTPHandler{database: baseline.product, newProductID: func() (string, error) { return baseline.id(), nil }}
	decide := func() int {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/guardrails/decisions", strings.NewReader(`{"direction":"input","text":"hello","agent_id":"support-agent"}`)).WithContext(authorized)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		decisions.ServeHTTP(recorder, request, "createGuardrailDecision")
		return recorder.Code
	}
	if code := decide(); code != http.StatusOK {
		t.Fatalf("a decision with the year-long gateway token: status=%d", code)
	}
	current := list()[gateway.Token.ID]
	revoked := send(administrator, "revokeAPIToken", http.MethodDelete, "/api/v1/admin/api-tokens/"+gateway.Token.ID, map[string]string{"id": gateway.Token.ID}, "", map[string]string{"If-Match": quoteVersion(current.Version)})
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke: status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw}); err == nil {
		t.Fatal("a revoked token was authenticated")
	}
	if code := decide(); code == http.StatusOK {
		t.Fatal("a request authorized before the revocation was served after it")
	}
	if listed := list()[gateway.Token.ID]; listed.RevokedAt == nil || !listed.ExpiresAt.Equal(gateway.Token.ExpiresAt) {
		t.Fatalf("the revoked token in the list: %+v", listed)
	}
	if intact := baseline.text(`SELECT zasp_baseline.intact()::text`); intact != "true" {
		t.Fatal("the flow left the catalog not intact")
	}
}
