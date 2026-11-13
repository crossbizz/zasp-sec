package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Every completion read is admitted only for its own operation, the scope of
// the checked request, the request's principal where the function takes one,
// and, for scope-level reads, the target the request was checked against.
func TestCompletionStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	environment := AuthorizationTarget{Scope: i.Scope, Kind: "environment", ID: e, Version: 1}
	organization := AuthorizationTarget{Scope: i.Scope, Kind: "organization", ID: o}
	identityTarget := AuthorizationTarget{Scope: i.Scope, Kind: "organization_identity", ID: o}
	var before any
	type contract struct {
		query, operation string
		collection       bool
		args             []any
		allowed          []AuthorizationTarget
		actor            int // Zero-based index of the principal argument, -1 when absent.
		browserOnly      bool
	}
	contracts := []contract{
		{currentSecurityAgentPageSQL, "listSecurityAgents", true, []any{o, w, e, "", 25}, nil, -1, false},
		{currentSecurityAgentExecutionControlsSQL, "getSecurityAgentExecutionControls", false, []any{o, w, e, p}, []AuthorizationTarget{environment}, 3, true},
		{currentSecurityAgentRunPageSQL, "listSecurityAgentRuns", true, []any{o, w, e, "", "", before, "", 25}, nil, -1, false},
		{currentSecurityAgentApprovalPageSQL, "listSecurityAgentApprovals", true, []any{o, w, e, "", "", before, "", 25, p}, nil, 8, false},
		{currentTestPageSQL, "listTests", true, []any{o, w, e, "", 25}, nil, -1, false},
		{currentTestRunPageSQL, "listTestRuns", true, []any{o, w, e, before, "", 25}, nil, -1, false},
		{currentAttackLabRunPageSQL, "listAttackLabRuns", true, []any{o, w, e, before, "", 25}, nil, -1, false},
		{currentOrganizationSQL, "getOrganization", false, []any{o, w, e}, []AuthorizationTarget{organization}, -1, true},
		{currentMemberPageSQL, "listMembers", false, []any{o, w, e, p, "", 51}, []AuthorizationTarget{identityTarget}, 3, true},
		{currentGroupMappingPageSQL, "listGroupMappings", false, []any{o, w, e, p, "", 51}, []AuthorizationTarget{environment}, 3, true},
		{currentIdentityProviderOrganizationSQL, "listSSOConnections", false, []any{o, w, e, p}, []AuthorizationTarget{identityTarget}, 3, true},
		{currentIdentityProviderOrganizationSQL, "listSCIMConnections", false, []any{o, w, e, p}, []AuthorizationTarget{identityTarget}, 3, true},
	}
	operations := []string{"listSecurityAgents", "getSecurityAgentExecutionControls", "listSecurityAgentRuns", "listSecurityAgentApprovals", "listTests", "listTestRuns", "listAttackLabRuns", "getOrganization", "listMembers", "listGroupMappings", "listSSOConnections", "listSCIMConnections", "createSSOConnection", "updateMemberRole", "listAgents", "getHomeSummary"}
	for _, c := range contracts {
		t.Run(c.operation, func(t *testing.T) {
			grant := func() RequestAuthorization {
				return RequestAuthorization{OperationID: c.operation, Identity: i, Collection: c.collection, Allowed: append([]AuthorizationTarget(nil), c.allowed...)}
			}
			arguments := func() []any { return append([]any(nil), c.args...) }
			if handled, allowed := completionStatementAllowed(grant(), c.query, arguments()); !handled || !allowed {
				t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
			}
			if !authorizationStatementAllowed(grant(), c.query, arguments()) {
				t.Fatal("statement allowlist refused the completion contract")
			}
			for _, other := range operations {
				if other == c.operation || c.query == currentIdentityProviderOrganizationSQL && stringIn(other, "listSSOConnections", "listSCIMConnections") {
					continue
				}
				g := grant()
				g.OperationID = other
				if authorizationStatementAllowed(g, c.query, arguments()) {
					t.Fatalf("operation %s borrowed the %s statement", other, c.operation)
				}
			}
			g := grant()
			g.Collection = !c.collection
			if authorizationStatementAllowed(g, c.query, arguments()) {
				t.Fatal("collection mode was not bound")
			}
			for n, name := range []string{"organization", "workspace", "environment"} {
				args := arguments()
				args[n] = p
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatalf("another %s was admitted", name)
				}
			}
			if authorizationStatementAllowed(grant(), c.query, append(arguments(), "extra")) || authorizationStatementAllowed(grant(), c.query, arguments()[:len(c.args)-1]) {
				t.Fatal("argument count was not bound")
			}
			if c.actor >= 0 {
				args := arguments()
				args[c.actor] = o
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatal("another principal was admitted")
				}
			}
			if len(c.allowed) > 0 {
				g = grant()
				g.Allowed = nil
				if authorizationStatementAllowed(g, c.query, arguments()) {
					t.Fatal("statement admitted without its checked target")
				}
				g = grant()
				g.Allowed[0].Kind = "finding"
				if authorizationStatementAllowed(g, c.query, arguments()) {
					t.Fatal("a target of another kind was admitted")
				}
			}
			g = grant()
			g.Identity.CredentialKind = CredentialBearerToken
			if got := authorizationStatementAllowed(g, c.query, arguments()); got == c.browserOnly {
				t.Fatalf("API token admitted=%v for browserOnly=%v", got, c.browserOnly)
			}
		})
	}
	// The historical statements these reads replace stay refused.
	legacy := RequestAuthorization{OperationID: "listTests", Identity: i, Collection: true}
	for _, statement := range []string{postgresRedTeamListDefinitionsSQL, postgresRedTeamListRunsSQL, postgresAttackLabListRunsSQL, postgresSecurityAgentRunPageSQL, postgresSecurityAgentApprovalPageSQL, postgresSecurityAgentDefinitionPageSQL, postgresExportDefinitionPageSQL, postgresExportControlsSQL, postgresGetOrganizationSQL, postgresListMembersSQL, postgresListGroupMappingsSQL, postgresIdentityProviderOrganizationSQL} {
		if authorizationStatementAllowed(legacy, statement, []any{o, w, e, "", 25}) {
			t.Fatalf("historical statement admitted: %s", statement)
		}
	}
}

type completionRowFixture struct {
	payload []byte
	ready   bool
	err     error
}

func (f completionRowFixture) Scan(values ...any) error {
	if f.err != nil {
		return f.err
	}
	switch target := values[0].(type) {
	case *[]byte:
		*target = f.payload
	case *bool:
		*target = f.ready
	}
	return nil
}

// completionTxFixture records the statement executed after the fence.
type completionTxFixture struct {
	pgx.Tx
	steps      []string
	statements []string
	arguments  [][]any
	payload    string
}

func (f *completionTxFixture) Exec(_ context.Context, statement string, _ ...any) (pgconn.CommandTag, error) {
	if statement == `SELECT zasp_authorization80.fence($1::text)` {
		f.steps = append(f.steps, "fence")
	}
	return pgconn.CommandTag{}, nil
}
func (f *completionTxFixture) QueryRow(_ context.Context, statement string, arguments ...any) pgx.Row {
	f.steps = append(f.steps, "effect")
	f.statements = append(f.statements, statement)
	f.arguments = append(f.arguments, arguments)
	return completionRowFixture{payload: []byte(f.payload)}
}
func (f *completionTxFixture) Commit(context.Context) error   { return nil }
func (f *completionTxFixture) Rollback(context.Context) error { return nil }

type completionDriverFixture struct {
	tx     *completionTxFixture
	direct []string
	ready  bool
	err    error
}

func (f *completionDriverFixture) Begin(context.Context) (pgx.Tx, error) { return f.tx, nil }
func (f *completionDriverFixture) QueryRow(_ context.Context, statement string, _ ...any) PostgresRow {
	f.direct = append(f.direct, statement)
	return completionRowFixture{ready: f.ready, err: f.err}
}
func (f *completionDriverFixture) Exec(context.Context, string, ...any) error { return nil }
func (f *completionDriverFixture) Close() error                               { return nil }

// Each repository read, called with a checked request, executes exactly its
// authorized statement inside the fenced transaction with the request's scope
// (and principal), and never a direct or historical statement.
func TestCompletionRepositoryReadsUseAuthorizedStatements(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	i.Permissions = []string{"view", "manage_identity"}
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "completion-current", Digest: [32]byte{1}}
	resolver := authorizationTargetFunc(func(_ context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
		policy, err := authorizationTargetPolicy(route.OperationID)
		if err != nil {
			return AuthorizationTargets{}, err
		}
		if policy.Mode == "collection" {
			return AuthorizationTargets{Complete: true, Collection: true, Targets: []AuthorizationTarget{}}, nil
		}
		id := identity.Scope.EnvironmentID().String()
		if policy.Kind != "environment" {
			id = identity.Scope.OrganizationID().String()
		}
		return AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: policy.Kind, ID: id, Version: 1}}}, nil
	})
	checker := authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
	})
	authorizer := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	before := time.Time{}
	for _, tc := range []struct {
		operation, statement, payload string
		tail                          []any // Arguments after organization, workspace, environment.
		call                          func(context.Context, *PostgresRepository) error
	}{
		{"listSecurityAgents", currentSecurityAgentPageSQL, `{"items":[],"next_id":null}`, []any{"", 25}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ListWorkflowPageForIdentity(ctx, i, "security_agent", "", 25)
			return err
		}},
		{"getSecurityAgentExecutionControls", currentSecurityAgentExecutionControlsSQL, `{"global":{"target":"global","action_key":"*","enabled":true,"version":1},"environment":{"target":"environment","action_key":"*","enabled":false,"version":0},"actions":[{"target":"action","action_key":"create_evidence_export","enabled":false,"version":0},{"target":"action","action_key":"create_temporary_policy","enabled":false,"version":0},{"target":"action","action_key":"isolate_session","enabled":false,"version":0},{"target":"action","action_key":"rerun_test","enabled":false,"version":0},{"target":"action","action_key":"revoke_integration_connection","enabled":false,"version":0},{"target":"action","action_key":"run_test","enabled":false,"version":0},{"target":"action","action_key":"start_attack_lab","enabled":false,"version":0},{"target":"action","action_key":"update_finding_response","enabled":false,"version":0}]}`, []any{p}, func(ctx context.Context, r *PostgresRepository) error {
			controls, err := r.GetSecurityAgentExecutionControls(ctx, i)
			if err == nil && len(controls.Actions) != 8 {
				return errors.New("execution controls lost an action")
			}
			return err
		}},
		{"listSecurityAgentRuns", currentSecurityAgentRunPageSQL, `{"items":[],"next_created_at":null,"next_id":null}`, []any{"", "", nil, "", 25}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ListSecurityAgentRuns(ctx, i, SecurityAgentRunPageRequest{Limit: 25, BeforeCreatedAt: before})
			return err
		}},
		{"listSecurityAgentApprovals", currentSecurityAgentApprovalPageSQL, `{"items":[],"next_created_at":null,"next_id":null}`, []any{"", "", nil, "", 25, p}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ListSecurityAgentApprovals(ctx, i, SecurityAgentApprovalPageRequest{Limit: 25, BeforeCreatedAt: before})
			return err
		}},
		{"listTests", currentTestPageSQL, `{"items":[],"next_cursor":null}`, []any{"", 25}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ListRedTeamDefinitions(ctx, i, RedTeamDefinitionPageRequest{Limit: 25})
			return err
		}},
		{"listTestRuns", currentTestRunPageSQL, `{"items":[],"next_cursor":null}`, []any{nil, "", 25}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ListRedTeamRuns(ctx, i, RedTeamRunPageRequest{Limit: 25})
			return err
		}},
		{"listAttackLabRuns", currentAttackLabRunPageSQL, `{"items":[],"next_cursor":null}`, []any{nil, "", 25}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ListAttackLabRuns(ctx, i, AttackLabRunPageRequest{Limit: 25})
			return err
		}},
		{"getOrganization", currentOrganizationSQL, `{"id":"x"}`, nil, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ReadAdministration(ctx, i, "getOrganization", nil)
			return err
		}},
		{"listMembers", currentMemberPageSQL, `{"items":[]}`, []any{p, "", 26}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ReadAdministration(ctx, i, "listMembers", map[string]string{"limit": "25"})
			return err
		}},
		{"listGroupMappings", currentGroupMappingPageSQL, `{"items":[]}`, []any{p, "", 26}, func(ctx context.Context, r *PostgresRepository) error {
			_, err := r.ReadAdministration(ctx, i, "listGroupMappings", map[string]string{"limit": "25"})
			return err
		}},
		{"listSSOConnections", currentIdentityProviderOrganizationSQL, `"organization-test-1"`, []any{p}, func(ctx context.Context, r *PostgresRepository) error {
			reference, err := r.identityProviderOrganization(ctx, i)
			if err == nil && reference != "organization-test-1" {
				return errors.New("provider organization reference changed")
			}
			return err
		}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			run := func(operation string) (*completionTxFixture, *completionDriverFixture, error) {
				grant, err := authorizer.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: operation})
				if err != nil {
					t.Fatalf("authorize %s: %v", operation, err)
				}
				tx := &completionTxFixture{payload: tc.payload}
				driver := &completionDriverFixture{tx: tx, ready: true}
				database, err := NewPostgresJSONDatabase(driver)
				if err != nil {
					t.Fatal(err)
				}
				if err := database.RequireCurrentAuthorization(); err != nil {
					t.Fatal(err)
				}
				repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true}
				ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
				return tx, driver, tc.call(ctx, repository)
			}
			tx, driver, err := run(tc.operation)
			if err != nil {
				t.Fatalf("authorized read failed: %v", err)
			}
			if !slices.Equal(tx.steps, []string{"fence", "effect"}) || len(tx.statements) != 1 || tx.statements[0] != tc.statement {
				t.Fatalf("steps=%v statements=%v, want one fenced %s", tx.steps, tx.statements, tc.statement)
			}
			if len(driver.direct) != 0 {
				t.Fatalf("read used direct statements: %v", driver.direct)
			}
			want := append([]any{o, w, e}, tc.tail...)
			got := tx.arguments[0]
			if len(got) != len(want) {
				t.Fatalf("arguments=%v want=%v", got, want)
			}
			for n := range want {
				if got[n] != want[n] {
					t.Fatalf("argument %d=%v want %v", n+1, got[n], want[n])
				}
			}
			// Under another operation's checked request nothing is executed.
			other := "listAgents"
			tx, driver, err = run(other)
			if err == nil || slices.Contains(tx.steps, "effect") || len(driver.direct) != 0 {
				t.Fatalf("read under %s: err=%v steps=%v direct=%v", other, err, tx.steps, driver.direct)
			}
		})
	}
}

// Under the current model the capability probes ask the readiness functions of
// the current catalog with the compiled release identity. A false or failed
// answer is unavailable; it is never "not installed", which would select a
// historical reader.
func TestCompletionCapabilityProbes(t *testing.T) {
	for _, tc := range []struct {
		name, statement string
		probe           func(*PostgresJSONDatabase, context.Context) (bool, error)
	}{
		{"attack lab", currentSecurityAgentAttackLabReadySQL, (*PostgresJSONDatabase).SecurityAgentAttackLabAvailable},
		{"export definitions", currentSecurityAgentExportReadySQL, (*PostgresJSONDatabase).SecurityAgentExportDefinitionsAvailable},
		{"exports", currentSecurityAgentExportReadySQL, (*PostgresJSONDatabase).SecurityAgentExportsAvailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, state := range []struct {
				ready bool
				err   error
			}{{true, nil}, {false, nil}, {true, errors.New("refused")}} {
				driver := &completionDriverFixture{tx: &completionTxFixture{}, ready: state.ready, err: state.err}
				database, err := NewPostgresJSONDatabase(driver)
				if err != nil || database.RequireCurrentAuthorization() != nil {
					t.Fatal("database fixture rejected")
				}
				available, err := tc.probe(database, context.Background())
				want := state.ready && state.err == nil
				if available != want || (err == nil) != want || !want && !errors.Is(err, ErrRepositoryUnavailable) {
					t.Fatalf("ready=%v failure=%v: available=%v err=%v", state.ready, state.err, available, err)
				}
				if !slices.Equal(driver.direct, []string{tc.statement}) {
					t.Fatalf("probe statements=%v want only %s", driver.direct, tc.statement)
				}
			}
			// A database outside the current model keeps the historical probe.
			driver := &completionDriverFixture{tx: &completionTxFixture{}, ready: true}
			database, _ := NewPostgresJSONDatabase(driver)
			if _, err := tc.probe(database, context.Background()); err != nil || slices.Contains(driver.direct, tc.statement) {
				t.Fatalf("historical probe changed: err=%v statements=%v", err, driver.direct)
			}
		})
	}
}

// The audit source readiness of the product API role asks the single-test
// release through the function that role may execute.
func TestCompletionAuditSourceReadinessUsesTestReleaseFunction(t *testing.T) {
	driver := &completionDriverFixture{tx: &completionTxFixture{}, ready: true}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil || database.RequireCurrentAuthorization() != nil {
		t.Fatal("database fixture rejected")
	}
	current, err := database.CurrentAuthorizationSourceReady(context.Background(), 52, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint())
	if !current || err != nil {
		t.Fatalf("current=%v err=%v", current, err)
	}
	if !slices.Contains(driver.direct, currentTestReleaseReadySQL) || slices.Contains(driver.direct, `SELECT zasp_temporal74.api_ready($1,$2)`) {
		t.Fatalf("readiness statements=%v", driver.direct)
	}
	driver = &completionDriverFixture{tx: &completionTxFixture{}, ready: false}
	database, _ = NewPostgresJSONDatabase(driver)
	_ = database.RequireCurrentAuthorization()
	if current, err = database.CurrentAuthorizationSourceReady(context.Background(), 52, "c", "f"); !current || !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unready source: current=%v err=%v", current, err)
	}
}

// The connection writes are admitted only for the request's own operation,
// scope and principal, from a browser session with fresh authentication, with
// the Organization's identity as the checked target; a delete or a test must
// reserve the connection named by the request path.
func TestIdentityProviderWriteStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	target := AuthorizationTarget{Scope: i.Scope, Kind: "organization_identity", ID: o}
	const key, mutation, audit, correlation, receipt = "identity-key-00000001", "pid_40000001-0000-4000-8000-000000000001", "pid_40000002-0000-4000-8000-000000000002", "pid_40000003-0000-4000-8000-000000000003", "pid_40000004-0000-4000-8000-000000000004"
	owner := make([]byte, 32)
	digest := make([]byte, 32)
	create := json.RawMessage(`{"display_name":"Corp","protocol":"saml","identity_provider":"okta"}`)
	named := json.RawMessage(`{"reference":"saml-connection-test-abc123"}`)
	var expires any
	type contract struct {
		name, query, operation, path string
		args                         func() []any
	}
	contracts := []contract{
		{"reserve create", currentIdentityProviderReserveSQL, "createSSOConnection", "", func() []any {
			return []any{o, w, e, p, "createSSOConnection", key, mutation, digest, create, audit, correlation, receipt, owner, 30}
		}},
		{"reserve delete", currentIdentityProviderReserveSQL, "deleteSSOConnection", "saml-connection-test-abc123", func() []any {
			return []any{o, w, e, p, "deleteSSOConnection", key, mutation, digest, named, audit, correlation, receipt, owner, 30}
		}},
		{"mark unknown", currentIdentityProviderMarkUnknownSQL, "createSCIMConnection", "", func() []any {
			return []any{o, w, e, p, "createSCIMConnection", key, mutation, owner}
		}},
		{"complete", currentIdentityProviderCompleteSQL, "testSSOConnection", "saml-connection-test-abc123", func() []any {
			return []any{o, w, e, p, "testSSOConnection", key, mutation, owner, json.RawMessage(`{}`), nil, nil, nil, nil, expires}
		}},
		{"reveal", currentIdentityProviderRevealSQL, "createSCIMConnection", "", func() []any { return []any{o, w, e, p, mutation} }},
	}
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			grant := func() RequestAuthorization {
				g := RequestAuthorization{OperationID: c.operation, Identity: i, Allowed: []AuthorizationTarget{target}}
				if c.path != "" {
					g.PathParameters = map[string]string{"id": c.path}
				}
				return g
			}
			if !authorizationStatementAllowed(grant(), c.query, c.args()) {
				t.Fatal("own contract was refused")
			}
			for _, operation := range []string{"listSSOConnections", "createSSOConnection", "deleteSSOConnection", "testSSOConnection", "createSCIMConnection", "deleteSCIMConnection", "updateMemberRole"} {
				if operation == c.operation {
					continue
				}
				g := grant()
				g.OperationID = operation
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatalf("operation %s borrowed the statement", operation)
				}
			}
			for n, name := range []string{"organization", "workspace", "environment", "principal"} {
				args := c.args()
				args[n] = mutation
				if authorizationStatementAllowed(grant(), c.query, args) {
					t.Fatalf("another %s was admitted", name)
				}
			}
			g := grant()
			g.Identity.CredentialKind = CredentialBearerToken
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("an API token was admitted")
			}
			g = grant()
			g.Identity.FreshAuthenticated = false
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("admitted without fresh authentication")
			}
			g = grant()
			g.Collection = true
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("a collection request was admitted")
			}
			g = grant()
			g.Allowed[0].Kind = "environment"
			if authorizationStatementAllowed(g, c.query, c.args()) {
				t.Fatal("admitted without the Organization identity target")
			}
			if authorizationStatementAllowed(grant(), c.query, append(c.args(), "extra")) {
				t.Fatal("argument count was not bound")
			}
		})
	}
	other := RequestAuthorization{OperationID: "deleteSSOConnection", Identity: i, Allowed: []AuthorizationTarget{target}, PathParameters: map[string]string{"id": "saml-connection-test-zzz999"}}
	if authorizationStatementAllowed(other, currentIdentityProviderReserveSQL, []any{o, w, e, p, "deleteSSOConnection", key, mutation, digest, named, audit, correlation, receipt, owner, 30}) {
		t.Fatal("a reservation for a connection other than the path connection was admitted")
	}
	legacy := RequestAuthorization{OperationID: "createSSOConnection", Identity: i, Allowed: []AuthorizationTarget{target}}
	for _, statement := range []string{postgresIdentityReserveMutationSQL, postgresIdentityMarkUnknownSQL, postgresIdentityCompleteMutationSQL, postgresIdentityRevealSecretSQL, `SELECT zasp_identity_admin_ack_secret($1,$2,$3)`} {
		if authorizationStatementAllowed(legacy, statement, []any{o, p, "createSSOConnection", key, mutation, owner}) {
			t.Fatalf("historical statement admitted: %s", statement)
		}
	}
}
