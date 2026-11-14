package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// installedSaaSSignIn stands for Nango during a sign-in: every start gets a
// state of its own, and every completion creates a connection of its own.
type installedSaaSSignIn struct {
	starts, completions int
}

func (*installedSaaSSignIn) Available(context.Context, string) bool { return true }

func (provider *installedSaaSSignIn) Start(_ context.Context, request SaaSSignInRequest) (ConnectorAuthorizationTarget, error) {
	provider.starts++
	// The attempt's identifier is unique, so the state is too.
	state := "nango_" + strings.ReplaceAll(strings.TrimPrefix(request.AttemptID, "pid_"), "-", "")
	return ConnectorAuthorizationTarget{URL: "https://" + request.TenantID + ".service-now.com/oauth_auth.do?state=" + state, State: state, ExpiresAt: time.Now().UTC().Add(9 * time.Minute)}, nil
}

func (provider *installedSaaSSignIn) Complete(_ context.Context, request SaaSSignInCompletion) (string, error) {
	provider.completions++
	return "ref:nango/connection/" + strings.TrimPrefix(request.AttemptID, "pid_"), nil
}

// installedSaaSProbe answers the tenant a saas connection reaches: the one
// its integration names.
type installedSaaSProbe struct{}

func (installedSaaSProbe) ProbeReferenceAuthorization(_ context.Context, target ReferenceAuthorizationTarget) (ReferenceAuthorizationSubject, error) {
	var configuration struct {
		Platform string `json:"platform"`
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal(target.Configuration, &configuration) != nil {
		return ReferenceAuthorizationSubject{}, ErrRepositoryUnavailable
	}
	return ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: configuration.Platform + "/" + configuration.TenantID}, nil
}

// installedNango is Nango's connection store as the release worker sees it.
type installedNango struct {
	connections map[string]bool
	down        bool
	removals    []SaaSConnectionRelease
}

func (nango *installedNango) RemoveConnection(_ context.Context, release SaaSConnectionRelease) error {
	nango.removals = append(nango.removals, release)
	if nango.down {
		return ErrRepositoryUnavailable
	}
	delete(nango.connections, release.ConnectionReference)
	return nil
}

// TestSaaSConnectionReleaseOnInstalledBaselinePostgres proves on an installed
// baseline, through the product's HTTP handlers and workers, that the Nango
// connection a sign-in created is deleted when its saas integration is
// deleted or given another connection, and that a connection the product did
// not create is left alone (completion.sql section
// ws10_saas_connection_release):
//
//   - an integration that was connected by sign-in and authorized is deleted:
//     the reconciler finishes the deletion and the connection is listed in
//     the same transaction; the release worker deletes it at Nango;
//   - Nango is unavailable: the release is kept and tried again later;
//   - the worker stops after claiming (a crash between the database and
//     Nango): the lease expires and the release is claimed again;
//   - a sign-in whose connection was never stored is released with the
//     integration, a replaced connection is released when the integration
//     names another one, and a reference a person pasted is never released;
//   - a connection another live integration names is retained, and released
//     once that integration is deleted too;
//   - the API login reaches the release functions; a tenant session cannot
//     finish a release without the worker's lease.
func TestSaaSConnectionReleaseOnInstalledBaselinePostgres(t *testing.T) {
	baseline := startInstalledBaseline(t)
	ctx := baseline.ctx
	administrator := baseline.member("security_admin", "investigate_sessions", "manage_findings", "manage_workflows", "run_tests", "view")
	if err := baseline.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(baseline.product)
	if err != nil {
		t.Fatalf("repository: %v", err)
	}
	connectors, err := NewConnectorRepository(baseline.product)
	if err != nil {
		t.Fatalf("connector repository: %v", err)
	}
	signInStore, err := NewSaaSSignInRepository(ctx, baseline.product)
	if err != nil {
		t.Fatalf("sign-in repository: %v", err)
	}
	signIn := &installedSaaSSignIn{}
	secrets := &installedOAuthSecrets{material: map[string]OAuthSecretMaterial{}}
	connectorHandler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: connectors, Workflows: repository, Secrets: secrets, SaaSSignIn: &SaaSSignIn{Store: signInStore, Provider: signIn}, Providers: map[string]ConnectorOAuthProviderDefinition{
		"github": {Provider: &installedOAuthProvider{host: "github.com"}, RequestedScopes: []string{"metadata:read"}, CredentialClass: "github_installation_reference"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	references, err := NewReferenceAuthorizationRepository(baseline.product)
	if err != nil {
		t.Fatalf("reference repository: %v", err)
	}
	referenceRegistry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"saas": installedSaaSProbe{}}, map[string]ConnectorCapabilityCheck{"saas": func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	referenceHandler, err := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: references, Workflows: repository, Registry: referenceRegistry})
	if err != nil {
		t.Fatal(err)
	}
	oauthRegistry := connectorHandler.(*connectorHTTPHandler).registry
	workflows, err := newWorkflowHTTPHandler(repository, bytes.Repeat([]byte{0x31}, 32), nil, CombinedConnectorCapabilities{OAuth: oauthRegistry, Reference: referenceRegistry})
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: connectors, Workflows: repository, Registry: oauthRegistry, Secrets: secrets, Owner: "installed-reconciler", LeaseSeconds: 30, Limit: 1, Interval: time.Second}) // One effect a pass: this test's database handle is a single connection.
	if err != nil {
		t.Fatal(err)
	}
	releases, err := NewSaaSConnectionReleaseRepository(ctx, baseline.product)
	if err != nil {
		t.Fatalf("release repository on the installed baseline: %v", err)
	}
	nango := &installedNango{connections: map[string]bool{}}
	releaser, err := NewSaaSConnectionReleaser(SaaSConnectionReleaserConfig{Repository: releases, Remover: nango, Owner: "installed-releaser", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	scoped := func(rest ...any) []any { return append([]any{baseline.o, baseline.w, baseline.e}, rest...) }
	send := func(handler http.Handler, operation, method, target string, parameters map[string]string, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		if parameters == nil {
			parameters = map[string]string{}
		}
		checked, err := baseline.checked(administrator, RoutedOperation{OperationID: operation, PathParameters: parameters})
		if err != nil {
			t.Fatalf("authorize %s: %v", operation, err)
		}
		// Every request has a correlation identifier of its own, as the
		// router gives it.
		request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(context.WithValue(checked, correlationContextKey{}, baseline.id()))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session-secret-" + administrator.identity.PrincipalID.String()})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	version := func(integration string) string {
		t.Helper()
		return baseline.text(`SELECT version::text FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4)`, scoped(integration)...)
	}
	create := func(name, configuration string) string {
		t.Helper()
		response := send(workflows, "createIntegration", http.MethodPost, "/api/v1/integrations", nil, `{"connector_key":"saas","name":"`+name+`","configuration":`+configuration+`}`, map[string]string{"Idempotency-Key": "create-integration-" + baseline.id()[4:]})
		var created struct {
			ID string `json:"id"`
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || !validProductID(created.ID) {
			t.Fatalf("create %s: status=%d body=%s", name, response.Code, response.Body.String())
		}
		return created.ID
	}
	// A person signs in: the authorize request, then the provider's return.
	// The reference of the connection Nango created comes back in the address
	// the browser is sent to.
	signInTo := func(integration string) string {
		t.Helper()
		path := map[string]string{"id": integration}
		started := send(connectorHandler, "authorizeIntegration", http.MethodPost, "/api/v1/integrations/"+integration+"/authorize", path, `{}`, map[string]string{"Idempotency-Key": "sign-in-" + baseline.id()[4:]})
		var authorization struct {
			URL string `json:"authorization_url"`
		}
		if started.Code != http.StatusOK || json.Unmarshal(started.Body.Bytes(), &authorization) != nil {
			t.Fatalf("start sign-in: status=%d body=%s", started.Code, started.Body.String())
		}
		address, err := url.Parse(authorization.URL)
		if err != nil || address.Query().Get("state") == "" {
			t.Fatalf("sign-in address %q", authorization.URL)
		}
		returned := send(connectorHandler, "completeIntegrationOAuthCallback", http.MethodGet, "/api/v1/integrations/oauth/callback?"+url.Values{"state": {address.Query().Get("state")}, "code": {"provider-code-12345678"}}.Encode(), nil, "", nil)
		location, err := url.Parse(returned.Header().Get("Location"))
		if returned.Code != http.StatusSeeOther || err != nil || location.Path != "/connectors" || location.Query().Get("saas_sign_in") != integration || location.Query().Get("saas_connection") == "" {
			t.Fatalf("sign-in return: status=%d location=%q body=%s", returned.Code, returned.Header().Get("Location"), returned.Body.String())
		}
		reference := "ref:nango/connection/" + location.Query().Get("saas_connection")
		nango.connections[reference] = true
		return reference
	}
	// The page stores a connection in the integration with an ordinary update.
	store := func(integration, tenant, reference string) {
		t.Helper()
		response := send(workflows, "updateIntegration", http.MethodPatch, "/api/v1/integrations/"+integration, map[string]string{"id": integration},
			`{"name":"ServiceNow `+tenant+`","configuration":{"platform":"servicenow","tenant_id":"`+tenant+`","connection_reference":"`+reference+`"}}`,
			map[string]string{"Idempotency-Key": "store-connection-" + baseline.id()[4:], "If-Match": `"` + version(integration) + `"`})
		if response.Code != http.StatusOK {
			t.Fatalf("store %s in %s: status=%d body=%s", reference, integration, response.Code, response.Body.String())
		}
	}
	authorizeByReference := func(integration string) {
		t.Helper()
		response := send(referenceHandler, "authorizeIntegrationReference", http.MethodPost, "/api/v1/integrations/"+integration+"/reference-authorization", map[string]string{"id": integration}, `{}`,
			map[string]string{"Idempotency-Key": "reference-" + baseline.id()[4:], "If-Match": `"` + version(integration) + `"`, "X-Zasp-Fresh-Auth": "confirmed"})
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"active"`) && !strings.Contains(response.Body.String(), `"status": "active"`) {
			t.Fatalf("authorize %s by reference: status=%d body=%s", integration, response.Code, response.Body.String())
		}
	}
	remove := func(integration string) int {
		t.Helper()
		response := send(workflows, "deleteIntegration", http.MethodDelete, "/api/v1/integrations/"+integration, map[string]string{"id": integration}, "",
			map[string]string{"Idempotency-Key": "delete-integration-" + baseline.id()[4:], "If-Match": `"` + version(integration) + `"`})
		if response.Code != http.StatusNoContent && response.Code != http.StatusAccepted {
			t.Fatalf("delete %s: status=%d body=%s", integration, response.Code, response.Body.String())
		}
		return response.Code
	}
	deleted := func(integration string) bool {
		t.Helper()
		return baseline.text(`SELECT (deleted_at IS NOT NULL)::text FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4)`, scoped(integration)...) == "true"
	}
	// The reconciler finishes the revocation a deletion of an authorized
	// integration leaves. It takes the oldest effect of a provider first and
	// waits fifteen seconds before taking one, so the effect is aged here.
	// Effects another tenant of this database left behind can hold the
	// provider's lane for the length of a lease; the passes continue until
	// that lease has ended.
	revoke := func(integration string) {
		t.Helper()
		for deadline := time.Now().Add(75 * time.Second); time.Now().Before(deadline) && !deleted(integration); time.Sleep(250 * time.Millisecond) {
			baseline.exec(`UPDATE zasp_connector_effects SET updated_at='2000-01-01T00:00:00Z' WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4) AND status='unknown' AND lease_owner IS NULL`, scoped(integration)...)
			// A pass also takes effects of other tenants of this database,
			// whose providers this test does not serve; only this
			// integration's outcome is judged.
			if err := reconciler.reconcileOnce(ctx); err != nil {
				t.Logf("reconciler pass: %v", err)
			}
		}
		if !deleted(integration) {
			t.Fatalf("integration %s was not deleted: status=%s effects=%s", integration,
				baseline.text(`SELECT body->>'status' FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4)`, scoped(integration)...),
				baseline.text(`SELECT string_agg(operation||':'||status||':'||attempt||':'||COALESCE(last_error_code,''),',') FROM zasp_connector_effects WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`, scoped(integration)...))
		}
	}
	release := func(reference string) string {
		t.Helper()
		return baseline.text(`SELECT (SELECT status||':'||reason||':'||attempt||':'||COALESCE(last_error_code,'') FROM zasp_saas_connection_releases WHERE (organization_id,workspace_id,environment_id,connection_reference)=($1,$2,$3,$4))`, scoped(reference)...)
	}
	due := func(reference string) {
		t.Helper()
		baseline.exec(`UPDATE zasp_saas_connection_releases SET available_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,connection_reference)=($1,$2,$3,$4) AND status='pending'`, scoped(reference)...)
	}
	// asked counts how often Nango was asked to delete a connection. Other
	// tenants of this database may have releases of their own.
	asked := func(reference string) int {
		count := 0
		for _, removal := range nango.removals {
			if removal.ConnectionReference == reference {
				count++
			}
		}
		return count
	}
	sweep := func() {
		t.Helper()
		if _, err := releaser.releaseOnce(ctx); err != nil {
			t.Fatalf("release worker: %v", err)
		}
	}

	// 1. Connected by sign-in, authorized, deleted.
	first := create("ServiceNow acme", `{"platform":"servicenow","tenant_id":"acme"}`)
	firstConnection := signInTo(first)
	store(first, "acme", firstConnection)
	authorizeByReference(first)
	if release(firstConnection) != "" {
		t.Fatalf("a connection in use was listed for release: %s", release(firstConnection))
	}
	if code := remove(first); code != http.StatusAccepted && code != http.StatusNoContent {
		t.Fatalf("delete status %d", code)
	}
	if !deleted(first) {
		// The integration held a verified connection: its deletion is finished
		// by the reconciler. Nothing is listed before the integration is gone.
		if release(firstConnection) != "" {
			t.Fatalf("listed before the integration was deleted: %s", release(firstConnection))
		}
		revoke(first)
	}
	if got := release(firstConnection); got != "pending:integration_deleted:0:" {
		t.Fatalf("release after deletion: %q", got)
	}

	// Nango is unavailable: the release stays, with the reason, for later.
	nango.down = true
	sweep()
	if got := release(firstConnection); got != "pending:integration_deleted:1:nango_unavailable" || !nango.connections[firstConnection] {
		t.Fatalf("release while Nango is unavailable: %q", got)
	}
	// It is not tried again before its delay has passed.
	sweep()
	if asked(firstConnection) != 1 {
		t.Fatalf("%d removals before the delay passed", asked(firstConnection))
	}
	nango.down = false

	// The worker stops after the claim, before Nango was asked (a crash): the
	// claim is a lease, which expires, and the release is claimed again.
	due(firstConnection)
	batch, err := releases.Claim(withConnectorMaintenance(ctx), "installed-crashed-worker", 5, 100)
	var claimed []SaaSConnectionRelease
	for _, item := range batch {
		if item.ConnectionReference == firstConnection {
			claimed = append(claimed, item)
		}
	}
	if err != nil || len(claimed) != 1 || claimed[0].IntegrationID != first || claimed[0].Platform != "servicenow" || claimed[0].Attempt != 2 {
		t.Fatalf("claim: %+v %v", batch, err)
	}
	sweep()
	if asked(firstConnection) != 1 || !nango.connections[firstConnection] {
		t.Fatal("a release under another worker's live lease was taken")
	}
	// Another worker cannot record an outcome for a lease it does not hold.
	stolen := claimed[0]
	stolen.LeaseToken = strings.Repeat("0", 64)
	if _, err := releases.Finish(withConnectorMaintenance(ctx), stolen, true, ""); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("an outcome without the lease: %v", err)
	}
	baseline.exec(`UPDATE zasp_saas_connection_releases SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,connection_reference)=($1,$2,$3,$4)`, scoped(firstConnection)...)
	if _, err := releases.Finish(withConnectorMaintenance(ctx), claimed[0], true, ""); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("an outcome after the lease expired: %v", err)
	}
	sweep()
	if got := release(firstConnection); got != "released:integration_deleted:3:" || nango.connections[firstConnection] {
		t.Fatalf("release after the lease expired: %q, connection still in Nango: %t", got, nango.connections[firstConnection])
	}
	var last SaaSConnectionRelease
	for _, removal := range nango.removals {
		if removal.ConnectionReference == firstConnection {
			last = removal
		}
	}
	if last.OrganizationID != baseline.o || last.WorkspaceID != baseline.w || last.EnvironmentID != baseline.e || last.IntegrationID != first || last.Platform != "servicenow" || last.Reason != "integration_deleted" {
		t.Fatalf("removal request: %+v", last)
	}
	// A released connection is not asked for again.
	removals := asked(firstConnection)
	sweep()
	if asked(firstConnection) != removals {
		t.Fatal("a released connection was removed again")
	}

	// 2. A reference a person pasted names a connection made outside the
	// product: deleting the integration, authorized or not, releases nothing.
	pasted := "ref:nango/connection/" + strings.TrimPrefix(baseline.id(), "pid_")
	nango.connections[pasted] = true
	second := create("ServiceNow globex", `{"platform":"servicenow","tenant_id":"globex","connection_reference":"`+pasted+`"}`)
	authorizeByReference(second)
	remove(second)
	if !deleted(second) {
		revoke(second)
	}
	sweep()
	if release(pasted) != "" || !nango.connections[pasted] {
		t.Fatalf("a pasted connection was released: %q", release(pasted))
	}

	// 3. Two sign-ins; only the second connection was stored. Storing it
	// releases the first, which nothing names. Replacing it with a pasted
	// reference releases the second. The pasted one is never listed.
	third := create("ServiceNow initech", `{"platform":"servicenow","tenant_id":"initech"}`)
	abandoned := signInTo(third)
	kept := signInTo(third)
	if release(abandoned) != "" || release(kept) != "" {
		t.Fatal("a sign-in listed a connection before any change of the integration")
	}
	store(third, "initech", kept)
	if got := release(abandoned); got != "pending:reference_replaced:0:" || release(kept) != "" {
		t.Fatalf("after storing the second connection: abandoned=%q kept=%q", got, release(kept))
	}
	store(third, "initech", pasted)
	if got := release(kept); got != "pending:reference_replaced:0:" || release(pasted) != "" {
		t.Fatalf("after replacing the connection: kept=%q pasted=%q", got, release(pasted))
	}
	sweep()
	if release(abandoned) != "released:reference_replaced:1:" || release(kept) != "released:reference_replaced:1:" || nango.connections[abandoned] || nango.connections[kept] || !nango.connections[pasted] {
		t.Fatalf("after the release worker: abandoned=%q kept=%q", release(abandoned), release(kept))
	}

	// 4. A sign-in whose connection was never stored (the tab was closed) is
	// released when the integration is deleted.
	fourth := create("ServiceNow umbrella", `{"platform":"servicenow","tenant_id":"umbrella"}`)
	orphan := signInTo(fourth)
	if remove(fourth); !deleted(fourth) {
		revoke(fourth)
	}
	if got := release(orphan); got != "pending:integration_deleted:0:" {
		t.Fatalf("an unstored sign-in connection after deletion: %q", got)
	}
	sweep()
	if release(orphan) != "released:integration_deleted:1:" || nango.connections[orphan] {
		t.Fatalf("an unstored sign-in connection after the worker: %q", release(orphan))
	}

	// 5. A connection another live integration names is kept, and released
	// when that integration is deleted too.
	fifth := create("ServiceNow hooli", `{"platform":"servicenow","tenant_id":"hooli"}`)
	shared := signInTo(fifth)
	store(fifth, "hooli", shared)
	sixth := create("ServiceNow hooli copy", `{"platform":"servicenow","tenant_id":"hooli","connection_reference":"`+shared+`"}`)
	if remove(fifth); !deleted(fifth) {
		revoke(fifth)
	}
	sweep()
	if got := release(shared); !strings.HasPrefix(got, "retained:integration_deleted:") || !nango.connections[shared] {
		t.Fatalf("a connection another integration names: %q", got)
	}
	// The other integration was not connected by a sign-in of its own, but it
	// was the reason the connection was kept: its deletion gives the
	// connection its turn again, and nothing names it any more.
	if remove(sixth); !deleted(sixth) {
		revoke(sixth)
	}
	if got := release(shared); got != "pending:integration_deleted:0:" {
		t.Fatalf("after the naming integration was deleted: %q", got)
	}
	sweep()
	if got := release(shared); got != "released:integration_deleted:1:" || nango.connections[shared] {
		t.Fatalf("after the release worker: %q", got)
	}

	// The fiftieth failure is final and names its reason.
	seventh := create("ServiceNow vandelay", `{"platform":"servicenow","tenant_id":"vandelay"}`)
	stubborn := signInTo(seventh)
	if remove(seventh); !deleted(seventh) {
		revoke(seventh)
	}
	baseline.exec(`UPDATE zasp_saas_connection_releases SET attempt=49 WHERE (organization_id,workspace_id,environment_id,connection_reference)=($1,$2,$3,$4)`, scoped(stubborn)...)
	nango.down = true
	sweep()
	nango.down = false
	if got := release(stubborn); got != "failed:integration_deleted:50:nango_unavailable" {
		t.Fatalf("after the last attempt: %q", got)
	}
	sweep()
	if asked(stubborn) != 1 || !nango.connections[stubborn] {
		t.Fatal("a failed release was tried again")
	}

	// Who reaches the release functions: the API login, as maintenance; not a
	// request of a tenant, and not the worker logins of other services.
	checked, err := baseline.checked(administrator, RoutedOperation{OperationID: "listIntegrations", PathParameters: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := baseline.product.QueryJSON(checked, postgresSaaSConnectionReleaseClaimSQL, "tenant-request", 30, 10); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("a request claimed releases: %v", err)
	}
	if _, err := baseline.product.QueryJSON(ctx, postgresSaaSConnectionReleaseClaimSQL, "unmarked-context", 30, 10); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("an unmarked context claimed releases: %v", err)
	}
	for _, login := range []string{"zasp_svc_discovery", "zasp_svc_scheduler", "zasp_svc_security_agent_api"} {
		var raw json.RawMessage
		if err := baseline.login(login).QueryRow(ctx, postgresSaaSConnectionReleaseClaimSQL, "another-service", 30, 10).Scan(&raw); installedSQLState(err) != "42501" {
			t.Fatalf("%s claimed releases: %s %v", login, raw, err)
		}
	}
	var direct int
	if err := baseline.login("zasp_svc_api").QueryRow(ctx, `SELECT count(*) FROM zasp_saas_connection_releases`).Scan(&direct); installedSQLState(err) != "42501" {
		t.Fatalf("the API login read the release table directly: %d %v", direct, err)
	}
	if count, _ := strconv.Atoi(baseline.text(`SELECT count(*)::text FROM zasp_saas_connection_releases WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, scoped()...)); count != 6 {
		t.Fatalf("%d releases recorded for the tenant, want 6", count)
	}
	if intact := baseline.text(`SELECT zasp_baseline.intact()::text`); intact != "true" {
		t.Fatal("the flow left the catalog not intact")
	}
}
