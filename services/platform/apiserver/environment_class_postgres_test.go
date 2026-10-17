package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type environmentClassNativeFixture struct {
	ctx              context.Context
	owner, bootstrap *pgx.Conn
	db               *PostgresJSONDatabase
	repository       *PostgresRepository
	identity         RequestIdentity
	authorizer       *OpenFGAAuthorizer
	reconcile        func()
	configDSN, pin   string
}

func newEnvironmentClassNativeFixture(t *testing.T) environmentClassNativeFixture {
	t.Helper()
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires actual PostgreSQL and OpenFGA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancel)
	bootstrapDSN := startDisposablePostgresAs(t, "zasp_test")
	bootstrap, err := pgx.Connect(ctx, bootstrapDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bootstrap.Close(context.Background()) })
	if _, err = bootstrap.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(bootstrapDSN)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "zasp_e2e"
	owner, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	runner := migrateEnvironmentClassCanonical(t, ctx, owner)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{"envclass_scheduler", "envclass_risk", "envclass_graph", "envclass_search", "envclass_security_api", "envclass_security_worker", "envclass_attack_controller", "envclass_attack_outbox", "envclass_attack_proxy", "envclass_executor", "envclass_compensation"} {
		exec(`CREATE ROLE ` + pgx.Identifier{name}.Sanitize() + ` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
	}
	exec(`SELECT public.zasp_execution_register_principals(session_user,'envclass_scheduler','auth80_discovery','envclass_risk','envclass_graph','envclass_search')`)
	exec(`SELECT public.zasp_security_agent_register_principals(session_user,'envclass_security_api','envclass_security_worker')`)
	exec(`SELECT public.zasp_attack_lab_register_principals(session_user,'envclass_attack_controller','envclass_attack_outbox','envclass_attack_proxy')`)
	for index, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
		if err := up(ctx); err != nil {
			t.Fatal("environment class temporal prerequisite refused", err)
		}
		if index == 1 {
			exec(`SELECT zasp_temporal68.register_principals('envclass_executor','envclass_compensation')`)
		}
	}
	installTemporal, installWorker := runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile
	pin := migrations.EnvironmentClassProfileChecksum()
	installAddon := runner.UpProductionEnvironmentClassProfile
	if os.Getenv("ZASP_P7_AUDIT_TEST") == "1" {
		installTemporal = runner.UpProductionAuthorizationTemporalIdentityProfile
		installWorker = runner.UpProductionAuthorizationWorkerAuditProfile
		installAddon = runner.UpProductionEnvironmentClassAuditProfile
		pin = migrations.EnvironmentClassAuditProfileChecksum()
	}
	for _, up := range []func(context.Context) error{installTemporal, installWorker} {
		if err := up(ctx); err != nil {
			t.Fatal("environment class parent refused", err)
		}
	}
	key := authorizationFixtureAttestor(t)
	exec(`SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier())
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const foreign = "pid_78000009-0000-4000-8000-000000000009"
	const foreignEnvironment = "pid_78000007-0000-4000-8000-000000000007"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Hierarchy','hierarchy.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Selected'),($1,$3,'Foreign')`, o, w, foreign)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production'),($1,$4,$5,'Foreign','production')`, o, w, e, foreign, foreignEnvironment)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-hierarchy80','member-hierarchy80','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','[]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('hierarchy80-session','sha256'),'session-hierarchy80',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true)`, o, w, e)
	exec(`INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,$3,'session_bootstrap:'||$4,'{}')`, o, w, e, p)
	pc, err := pgxpool.ParseConfig(config.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	client, fgaConfig := newAuthorizationProjectionFGA(t)
	writer, err := authorization.NewOpenFGATupleWriter(client, fgaConfig)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, fgaConfig)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, fgaConfig.StoreID, fgaConfig.ModelID)
	reconcile := func() {
		t.Helper()
		receipt, err := authorization.Reconcile(ctx, projection, writer, o, fgaConfig.StoreID, fgaConfig.ModelID)
		if err != nil || !receipt.Applied {
			t.Fatalf("reconcile=%+v %v", receipt, err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, config.ConnString(), "auth80_api")
	t.Cleanup(func() { _ = api.Close(context.Background()) })
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err = db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, _ := NewPostgresRepository(db)
	i, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "hierarchy80-session"})
	if err != nil {
		t.Fatal(err)
	}
	if len(i.Permissions) != 0 {
		t.Fatal("current identity carries legacy permissions")
	}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	a := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: fgaConfig.StoreID, ModelID: fgaConfig.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	// Only this owned disposable cluster is demoted. Restore through bootstrap,
	// verify using the original registered owner session, then join cluster cleanup.
	var priorSuper, priorBypass bool
	if err = owner.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&priorSuper, &priorBypass); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		super, bypass := "NOSUPERUSER", "NOBYPASSRLS"
		if priorSuper {
			super = "SUPERUSER"
		}
		if priorBypass {
			bypass = "BYPASSRLS"
		}
		if _, err := bootstrap.Exec(c, `ALTER ROLE zasp_e2e INHERIT `+super+` `+bypass); err != nil {
			t.Error(err)
			return
		}
		var ok bool
		if err := owner.QueryRow(c, `SELECT rolsuper=$1 AND rolbypassrls=$2 FROM pg_roles WHERE rolname=session_user`, priorSuper, priorBypass).Scan(&ok); err != nil || !ok {
			t.Errorf("owner restoration=%v %v", ok, err)
		} else {
			t.Log("restored disposable registered owner role attributes")
		}
	})
	// The actual migration LOGIN needs CREATE on this owned disposable database
	// to bootstrap its new namespace. No public-schema or production grant.
	if _, err = bootstrap.Exec(ctx, `GRANT CREATE ON DATABASE `+pgx.Identifier{config.Database}.Sanitize()+` TO zasp_e2e`); err != nil {
		t.Fatal("disposable migration namespace prerequisite unavailable")
	}
	if _, err = bootstrap.Exec(ctx, `ALTER ROLE zasp_e2e NOINHERIT NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var ownerBound bool
	if err = owner.QueryRow(ctx, `SELECT session_user='zasp_e2e' AND current_user=session_user AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&ownerBound); err != nil || !ownerBound {
		t.Fatalf("nonsuper owner=%v %v", ownerBound, err)
	}
	var databaseCreate bool
	if err = owner.QueryRow(ctx, `SELECT has_database_privilege(session_user,current_database(),'CREATE')`).Scan(&databaseCreate); err != nil || !databaseCreate {
		t.Fatal("actual migration LOGIN database CREATE prerequisite absent")
	}
	t.Log("committed owner demotion; original session_user/current_user=zasp_e2e NOINHERIT NOSUPERUSER NOBYPASSRLS")

	if err := installAddon(ctx); err != nil {
		t.Fatal("environment class supplementary profile refused", err)
	}
	if err := repo.RequireEnvironmentClassProfile(pin); err != nil {
		t.Fatal("environment class repository mount refused", err)
	}
	a.EnvironmentClassReady = func(c context.Context) (bool, error) { return db.EnvironmentClassProfileReady(c, pin) }
	return environmentClassNativeFixture{ctx: ctx, owner: owner, bootstrap: bootstrap, db: db, repository: repo, identity: i, authorizer: a, reconcile: reconcile, configDSN: config.ConnString(), pin: pin}
}

func TestEnvironmentClassificationMountedPostgres(t *testing.T) {
	runEnvironmentClassificationMounted(t, false)
}

func TestEnvironmentClassificationAuditMountedPostgres(t *testing.T) {
	runEnvironmentClassificationMounted(t, true)
}

func runEnvironmentClassificationMounted(t *testing.T, audit bool) {
	t.Helper()
	if audit {
		t.Setenv("ZASP_P7_AUDIT_TEST", "1")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	} else {
		t.Setenv("ZASP_P7_AUDIT_TEST", "")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "")
	}
	f := newEnvironmentClassNativeFixture(t)
	ctx, i := f.ctx, f.identity
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	handler := &identityHTTPHandler{administration: f.repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
	var operations []Operation
	for _, name := range []string{"createEnvironment", "updateEnvironment"} {
		policy, _ := authorization.LookupOperation(name)
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: name, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, RequireFreshAuth: true, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = f.authorizer
	call := func(identity RequestIdentity, method, path, body string, version int64) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		request.Header.Set("Origin", "https://console.example")
		request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		if version > 0 {
			request.Header.Set("If-Match", strconv.FormatInt(version, 10))
		}
		c := context.WithValue(ctx, identityContextKey{}, identity)
		c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request.WithContext(c))
		return response
	}
	type environment struct {
		ID      string `json:"id"`
		Class   string `json:"environment_class"`
		Version int64  `json:"version"`
		Audit   string `json:"audit_correlation_id"`
	}
	decode := func(response *httptest.ResponseRecorder, wantStatus int) environment {
		t.Helper()
		if response.Code != wantStatus {
			t.Fatalf("mounted environment classification status=%d expected=%d", response.Code, wantStatus)
		}
		var result environment
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.ID == "" || result.Version < 1 || result.Audit == "" {
			t.Fatal("invalid authoritative environment response")
		}
		return result
	}
	current := func() (string, int64, int64, int64) {
		t.Helper()
		var class string
		var ev, cv, desired int64
		if err := f.owner.QueryRow(ctx, `SELECT environment.environment_class,environment.version,controls.version FROM public.zasp_environments environment JOIN public.zasp_data_controls controls ON controls.organization_id=environment.organization_id AND controls.workspace_id=environment.workspace_id AND controls.environment_id=environment.id WHERE environment.organization_id=$1 AND environment.workspace_id=$2 AND environment.id=$3`, o, w, e).Scan(&class, &ev, &cv); err != nil {
			t.Fatal("native classification state unavailable", err)
		}
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal("revision read transaction unavailable")
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			t.Fatal("revision reader role refused")
		}
		if err = tx.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&desired); err != nil {
			t.Fatal("classification revision unavailable")
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal("revision read commit unconfirmed")
		}
		return class, ev, cv, desired
	}
	update := func(class *string) environment {
		t.Helper()
		_, version, _, _ := current()
		body := `{"name":"Selected environment"`
		if class != nil {
			body += `,"environment_class":` + strconv.Quote(*class)
		}
		body += `}`
		return decode(call(i, http.MethodPatch, "/api/v1/environments/"+e, body, version), http.StatusOK)
	}
	t.Run("compiled_profile_and_current_capability", func(t *testing.T) {
		ready, err := f.db.EnvironmentClassProfileReady(ctx, f.pin)
		if err != nil || !ready {
			t.Fatal("registered API caller readiness refused")
		}
		grant, err := f.authorizer.preparePostLogin(ctx, i, RoutedOperation{OperationID: "bootstrapSession"})
		if err != nil || !slices.Contains(grant.capabilities, "identity.environments.classify") {
			t.Fatal("current profile classification capability absent", err)
		}
	})
	t.Run("four_classes_create_atomically_without_collection_expansion", func(t *testing.T) {
		for _, class := range []string{"development", "test", "staging", "production"} {
			result := decode(call(i, http.MethodPost, "/api/v1/environments", fmt.Sprintf(`{"workspace_id":%q,"name":%q,"environment_class":%q}`, w, "Created "+class, class), 0), http.StatusCreated)
			if result.Class != class {
				t.Fatal("requested class not preserved")
			}
			var atomic bool
			if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.zasp_environments environment JOIN public.zasp_data_controls controls ON controls.organization_id=environment.organization_id AND controls.workspace_id=environment.workspace_id AND controls.environment_id=environment.id WHERE environment.organization_id=$1 AND environment.workspace_id=$2 AND environment.id=$3 AND environment.environment_class=$4 AND controls.environment_class=$4 AND controls.collection_mode='metadata_only' AND controls.retention_days=30 AND controls.deletion_enabled AND controls.version=1) AND EXISTS(SELECT 1 FROM public.zasp_admin_audit WHERE organization_id=$1 AND id=$5 AND target_id=$3 AND action='environment.create')`, o, w, result.ID, class, result.Audit).Scan(&atomic); err != nil || !atomic {
				t.Fatal("class create effects not atomic", err)
			}
			f.reconcile()
		}
	})
	t.Run("omission_preserves_legacy_create_and_update_semantics", func(t *testing.T) {
		result := decode(call(i, http.MethodPost, "/api/v1/environments", fmt.Sprintf(`{"workspace_id":%q,"name":"Default development"}`, w), 0), http.StatusCreated)
		if result.Class != "development" {
			t.Fatal("omitted creation class did not default development")
		}
		f.reconcile()
		before, _, controls, desired := current()
		result = update(nil)
		after, _, afterControls, afterDesired := current()
		if result.Class != before || after != before || controls != afterControls || desired != afterDesired {
			t.Fatal("name-only update changed classification or revision")
		}
	})
	t.Run("class_change_invalidates_controls_and_other_resource_proofs", func(t *testing.T) {
		_, version, controls, desired := current()
		g, err := f.authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "updateEnvironment", PathParameters: map[string]string{"id": e}})
		if err != nil {
			t.Fatal(err)
		}
		other, err := f.authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "getOrganization"})
		if err != nil || len(other.Targets) != 1 || other.Targets[0].Kind != "organization" {
			t.Fatal("unchanged organization proof unavailable", err)
		}
		proof, err := authorizationProofJSON(other)
		if err != nil {
			t.Fatal("signed organization proof unavailable")
		}
		api := f.db.driver.(*authorizationConnectionDriver).conn
		fence := func() error {
			tx, err := api.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			_, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof))
			return err
		}
		if err := fence(); err != nil {
			t.Fatal("original unchanged-resource proof was not usable before class change", err)
		}
		var originalOrganizationVersion int64
		if err := f.owner.QueryRow(ctx, `SELECT version FROM public.zasp_organizations WHERE id=$1`, o).Scan(&originalOrganizationVersion); err != nil {
			t.Fatal(err)
		}
		class := "staging"
		result := update(&class)
		actual, afterVersion, afterControls, afterDesired := current()
		if result.Class != class || actual != class || afterVersion != version+1 || afterControls != controls+1 || afterDesired != desired+1 {
			t.Fatal("class change did not advance exact atomic version/revision")
		}
		var currentOrganizationVersion int64
		if err := f.owner.QueryRow(ctx, `SELECT version FROM public.zasp_organizations WHERE id=$1`, o).Scan(&currentOrganizationVersion); err != nil || currentOrganizationVersion != originalOrganizationVersion {
			t.Fatal("other resource version changed, invalidating the independent proof control")
		}
		if err := fence(); err == nil {
			t.Fatal("unchanged non-environment resource proof survived class-only revision invalidation")
		}
		stale := administrationMutation{Operation: "updateEnvironment", ID: e, Name: "Stale captured proof", ExpectedVersion: afterVersion, AuditID: "pid_f0810000-0000-4000-8000-000000000001"}
		if _, err := f.repository.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, stale); err == nil {
			t.Fatal("old captured proof survived class change")
		}
		if _, err := f.authorizer.preparePostLogin(ctx, i, RoutedOperation{OperationID: "bootstrapSession"}); err == nil {
			t.Fatal("pending class projection exposed capability")
		}
		f.reconcile()
		settingsGrant, err := f.authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: "updateDataControls"})
		if err != nil {
			t.Fatal("current settings proof unavailable after reconciliation", err)
		}
		settings := administrationMutation{Operation: "updateDataControls", EnvironmentID: e, EnvironmentClass: class, CollectionMode: "metadata_only", RetentionDays: 30, DeletionEnabled: true, ExpectedVersion: controls, AuditID: "pid_f0810000-0000-4000-8000-000000000002"}
		if _, err := f.repository.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, settingsGrant), i, settings); err == nil {
			t.Fatal("pre-class-change settings version remained writable after current reauthorization")
		}
		_, unchangedEnvironment, unchangedControls, unchangedRevision := current()
		if unchangedEnvironment != afterVersion || unchangedControls != afterControls || unchangedRevision != afterDesired {
			t.Fatal("stale settings request changed classification state")
		}
		beforeClass, _, beforeControls, beforeDesired := current()
		result = update(&beforeClass)
		_, _, afterControls, afterDesired = current()
		if result.Class != beforeClass || afterControls != beforeControls || afterDesired != beforeDesired {
			t.Fatal("same class rename emitted extra invalidation")
		}
	})
	t.Run("production_extended_refuses_and_departure_never_expands", func(t *testing.T) {
		class, version, controls, desired := current()
		if _, err := f.owner.Exec(ctx, `UPDATE public.zasp_data_controls SET collection_mode='extended' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e); err != nil {
			t.Fatal(err)
		}
		response := call(i, http.MethodPatch, "/api/v1/environments/"+e, `{"name":"Unsafe promotion","environment_class":"production"}`, version)
		if response.Code < 400 {
			t.Fatal("production extended transition accepted")
		}
		after, afterVersion, afterControls, afterDesired := current()
		if after != class || afterVersion != version || afterControls != controls || afterDesired != desired {
			t.Fatal("refused promotion left partial effects")
		}
		if _, err := f.owner.Exec(ctx, `UPDATE public.zasp_data_controls SET collection_mode='metadata_only' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e); err != nil {
			t.Fatal(err)
		}
		production := "production"
		update(&production)
		f.reconcile()
		development := "development"
		update(&development)
		f.reconcile()
		var narrow bool
		if err := f.owner.QueryRow(ctx, `SELECT collection_mode='metadata_only' AND retention_days=30 AND deletion_enabled FROM public.zasp_data_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e).Scan(&narrow); err != nil || !narrow {
			t.Fatal("class change expanded collection or changed retention", err)
		}
	})
	t.Run("hostile_class_bodies_have_zero_effects", func(t *testing.T) {
		class, version, controls, desired := current()
		for _, body := range []string{`{"name":"Refused","environment_class":null}`, `{"name":"Refused","Environment_Class":"production"}`, `{"name":"Refused","environment_class":"test","environment_class":"production"}`, `{"name":"Refused","environment_class":"unknown"}`} {
			if response := call(i, http.MethodPatch, "/api/v1/environments/"+e, body, version); response.Code != http.StatusBadRequest {
				t.Fatalf("hostile classification status=%d", response.Code)
			}
		}
		after, afterVersion, afterControls, afterDesired := current()
		if after != class || afterVersion != version || afterControls != controls || afterDesired != desired {
			t.Fatal("hostile class body reached effects")
		}
	})
	t.Run("attack_lab_future_effects_refuse_class_drift_and_production", func(t *testing.T) {
		exerciseEnvironmentClassAttackLabConsumer(t, f, func(class string) { update(&class); f.reconcile() })
	})
	t.Run("revoked_session_and_stale_version_cannot_write", func(t *testing.T) {
		class, version, controls, desired := current()
		if response := call(i, http.MethodPatch, "/api/v1/environments/"+e, `{"name":"Stale","environment_class":"test"}`, version+1); response.Code < 400 {
			t.Fatal("stale version accepted")
		}
		if _, err := f.owner.Exec(ctx, `UPDATE public.zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-hierarchy80'`); err != nil {
			t.Fatal(err)
		}
		response := call(i, http.MethodPatch, "/api/v1/environments/"+e, `{"name":"Revoked","environment_class":"test"}`, version)
		if response.Code < 400 {
			t.Fatal("revoked session accepted")
		}
		after, afterVersion, afterControls, afterDesired := current()
		if after != class || afterVersion != version || afterControls != controls || afterDesired != desired {
			t.Fatal("refused authority left partial effects")
		}
	})
}

// Retain the existing complete canonical61 application install sequence while
// leaving79/80 absent for the actual composed Temporal parent constructor.
func migrateEnvironmentClassCanonical(t *testing.T, ctx context.Context, conn *pgx.Conn) *migrations.Runner {
	t.Helper()
	migrateToTypedInventoryCutover(t, ctx, conn)
	runner, err := migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: conn, t: t})
	if err != nil {
		t.Fatal("canonical migration runner unavailable")
	}
	for _, name := range []string{"auth80_api", "auth80_discovery", "auth80_ingest", "auth80_runtime", "auth80_outbox", "auth80_gateway"} {
		if _, err := conn.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal("owned original principal preparation refused")
		}
	}
	if _, err := conn.Exec(ctx, `SELECT public.zasp_discovery_register_principals(session_user,'auth80_api','auth80_discovery','auth80_ingest','auth80_runtime','auth80_outbox','auth80_gateway')`); err != nil {
		t.Fatal("owned original principal registration refused")
	}
	for _, up := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution,
		runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook, runner.UpProductionRuntimeQueueReplay, runner.UpProductionRedTeamSafety, runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority, runner.UpProductionRuntimeAcceptance, runner.UpProductionRuntimeCorrelationRouting, runner.UpProductionRuntimeSandboxBinding, runner.UpProductionRuntimePrecision, runner.UpProductionAuditExports, runner.UpProductionSecurityAgentBudgets, runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
		if err := up(ctx); err != nil {
			t.Fatal("canonical61 prerequisite installation refused", err)
		}
	}
	return runner
}
