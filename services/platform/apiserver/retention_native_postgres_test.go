package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// One owned PostgreSQL/OpenFGA join. Provider archives and cutover artifacts are
// controlled local fixture artifacts; they are never deployed fleet evidence.
func TestRetentionAuditProfileNativePostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned local OpenFGA")
	}
	t.Setenv("ZASP_P7_AUDIT_TEST", "1")
	t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	// Separate bootstrap permits a genuine NOSUPERUSER/NOBYPASSRLS/NOINHERIT
	// registered source owner. The initdb superuser never runs an application call.
	bootstrap, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_test"))
	if err != nil {
		t.Fatal("owned bootstrap refused")
	}
	defer bootstrap.Close(context.Background())
	if _, err = bootstrap.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
		t.Fatal("owned migration login refused")
	}
	cfg := bootstrap.Config().Copy()
	cfg.User = "zasp_e2e"
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owned migration connection refused")
	}
	defer owner.Close(context.Background())
	runner := migrateIntegrationClientComposed(t, ctx, owner)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, a...); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("retention native source operation refused")
		}
	}
	exec(`CREATE ROLE retention_executor LOGIN;CREATE ROLE retention_compensation LOGIN;SELECT zasp_temporal68.register_principals('retention_executor','retention_compensation')`)
	exec(`CREATE ROLE retention_coordinator LOGIN;CREATE ROLE retention_archive LOGIN;CREATE ROLE retention_index LOGIN;CREATE ROLE retention_correlation LOGIN;CREATE ROLE retention_projection LOGIN;CREATE ROLE retention_gateway LOGIN;SELECT zasp_runtime_register_principals(session_user,'retention_coordinator','retention_archive','retention_index','retention_correlation','retention_projection','retention_gateway')`)
	deployment := authorization.IdentityDeployment{PublicOrigin: "https://console.example", ProviderBaseURL: "https://test.stytch.com", ProjectID: "project-test-retention-native", ConfiguredOrganization: "organization-retention-native", Mode: "saas"}
	audience, err := deployment.Audience()
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("retention-native-identity-key-01234567890123456789")
	sessionKey, err := authorization.NewIdentitySessionKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	webhookKey, err := authorization.NewIdentityWebhookKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	var epoch int64
	if err = owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,'auth80_api','')`, sessionKey.Version(), sessionKey.Verifier(), audience, deployment.ProjectID).Scan(&epoch); err != nil || epoch < 1 {
		t.Fatal("native session registration refused")
	}
	if err = owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_webhook($1,$2,$3,$4,'auth80_api','')`, webhookKey.Version(), webhookKey.Verifier(), audience, deployment.ProjectID).Scan(&epoch); err != nil || epoch < 1 {
		t.Fatal("native webhook registration refused")
	}
	if err = runner.UpProductionAuthorizationWorkerAuditProfile(ctx); err != nil {
		t.Fatal("actual Audit parent refused", err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	o, w, e, actor := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), identity.PrincipalID.String()
	const otherEnv = "pid_98000001-0000-4000-8000-000000000001"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Retention native','retention.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Retention')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'A','production'),($1,$2,$4,'B','production')`, o, w, e, otherEnv)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-retention-native','member-retention-native','organization_admin',true)`, actor, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'A','[]',true)`, actor, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('retention-native-session','sha256'),'session-retention-native',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, actor, o, w, e)
	exec(`INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) VALUES($1,'session-retention-native','legacy-originless','tool','protected legacy','legacy-evidence','product','exact',clock_timestamp()-interval '3 days')`, o)
	exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES($1,$2,$3,'production','metadata_only',30,true,false),($1,$2,$4,'production','metadata_only',1,true,false)`, o, w, e, otherEnv)
	type projectionCase struct {
		name, entry string
		args        []any
		projected   runtimeprojection.ProjectedBatch
	}
	var cases []projectionCase
	for i, family := range []struct {
		name             string
		sandbox, precise bool
	}{{"session", false, false}, {"sandbox_session", true, false}, {"precise_session", false, true}} {
		args, projected := seedRetentionMixedProjection(t, ctx, owner, scope, automaticSourceID(99001), family.sandbox, family.precise, 99010+i*10)
		cases = append(cases, projectionCase{family.name, "zasp_retention_v1.current_finish_" + family.name + "_projection", args, projected})
	}
	connect := func(login string) *pgx.Conn {
		t.Helper()
		c := cfg.Copy()
		c.User = login
		connection, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal("registered retention connection refused")
		}
		t.Cleanup(func() { _ = connection.Close(context.Background()) })
		return connection
	}
	api, executor, coordinator := connect("auth80_api"), connect("retention_executor"), connect("retention_coordinator")
	db, err := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	identity, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "retention-native-session"})
	if err != nil {
		t.Fatal("native browser authentication refused")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	poolCfg.ConnConfig.User = "auth80_outbox"
	poolCfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	client, pins := newAuthorizationProjectionFGA(t)
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID)
	reconcile := func() {
		t.Helper()
		result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID)
		if err != nil || !result.Applied {
			t.Fatal("actual retention FGA projection refused")
		}
	}
	reconcile()
	resolver, err := NewPostgresAuthorizationResolver(db)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	checked := func(operation string, path map[string]string) context.Context {
		t.Helper()
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: operation, PathParameters: path})
		if err != nil {
			t.Fatal("actual retention Check refused")
		}
		return context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	}
	// This is the actual operator role transition used by the CLI, not a worker
	// impersonation. Every application operation uses a separate registered login.
	operator := func(query string, args ...any) json.RawMessage {
		t.Helper()
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			t.Fatal("registered operator role refused")
		}
		var raw json.RawMessage
		if err = tx.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("retention operator operation refused")
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal("retention operator commit refused")
		}
		return raw
	}
	boolOp := func(query string, args ...any) bool {
		t.Helper()
		var result bool
		if json.Unmarshal(operator(`SELECT to_jsonb((`+query+`))`, args...), &result) != nil {
			t.Fatal("retention operator result malformed")
		}
		return result
	}
	countOp := func(query string, args ...any) int {
		t.Helper()
		var result int
		if json.Unmarshal(operator(`SELECT to_jsonb((`+query+`))`, args...), &result) != nil {
			t.Fatal("retention count malformed")
		}
		return result
	}
	pin := migrations.RetentionAuditProfileChecksum()
	var cutover string
	var active bool
	var allIDs []string
	var retainedIDs, expiredIDs []string
	for _, c := range cases {
		for _, item := range c.projected.Items {
			allIDs = append(allIDs, item.EventID.String())
			eventAt, parseErr := time.Parse("2006-01-02T15:04:05.000Z", item.EventTime)
			if parseErr != nil {
				t.Fatal("controlled source timestamp malformed")
			}
			if eventAt.Before(time.Now().Add(-24 * time.Hour)) {
				expiredIDs = append(expiredIDs, item.EventID.String())
			} else {
				retainedIDs = append(retainedIDs, item.EventID.String())
			}
		}
	}
	t.Run("prepared_exact_recipe_and_noinherit_owner", func(t *testing.T) {
		if _, err := bootstrap.Exec(ctx, `GRANT CREATE ON DATABASE postgres TO zasp_e2e;ALTER ROLE zasp_e2e NOSUPERUSER NOBYPASSRLS NOINHERIT`); err != nil {
			t.Fatal("owned migration role demotion refused")
		}
		var genuine bool
		if err := owner.QueryRow(ctx, `SELECT session_user=current_user AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit FROM pg_roles WHERE rolname=session_user`).Scan(&genuine); err != nil || !genuine {
			t.Fatal("genuine source owner required")
		}
		if err := runner.UpProductionRetentionAuditProfile(ctx); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("retention prepare refused")
		}
		if err := runner.UpProductionRetentionAuditProfile(ctx); err != nil {
			t.Fatal("retention prepare replay refused")
		}
		if !boolOp(`SELECT zasp_retention_v1.prepared_ready($1) AND (SELECT count(*)=23 FROM zasp_retention_v1.preimages) AND (SELECT count(*)=17 FROM zasp_retention_v1.successors)`, pin) {
			t.Fatal("exact prepared closure missing")
		}
		var ready bool
		if err := executor.QueryRow(ctx, `SELECT zasp_retention_v1.caller_ready('sweep',$1)`, pin).Scan(&ready); err != nil || ready {
			t.Fatal("unactivated authority admitted")
		}
	})
	t.Run("registered_purposes_and_explicit_local_cutover", func(t *testing.T) {
		if !boolOp(`SELECT zasp_retention_v1.register_principal('auth80_api','human-read') AND zasp_retention_v1.register_principal('retention_index','runtime-index') AND zasp_retention_v1.register_principal('retention_coordinator','runtime-coordinator') AND zasp_retention_v1.register_principal('retention_executor','sweep')`) {
			t.Fatal("purpose registration refused")
		}
		artifacts := map[string]string{"profile_checksum": pin}
		// Hash real owned local artifacts, never invented production evidence.
		// Production deployment/credential withdrawal remain explicitly false.
		sourcePins := map[string]string{}
		for _, name := range []string{"retention_profile.sql", "retention_successor.sql", "retention_index.sql", "retention_partition.sql", "retention_cleanup.sql"} {
			source, readErr := os.ReadFile("../migrations/sql/" + name)
			if readErr != nil {
				t.Fatal("owned source artifact unavailable")
			}
			sum := sha256.Sum256(source)
			sourcePins[name] = fmt.Sprintf("%x", sum)
		}
		observed := map[string]any{"kind": "owned_native_fixture", "production_deployment_verified": false, "operator_nosuper_nobypass_noinherit": true, "profile_checksum": pin, "canonical_versions": 61}
		consumers := map[string]any{"kind": "owned_native_consumer_contract", "profile_checksum": pin, "consumers": []string{"agentsec-api", "agentsec-runtime-coordinator", "agentsec-runtime-complete", "agentsec-runtime-index", "agentsec-runtime-session-index-v2", "agentsec-retention-reference-expiry"}}
		withdrawal := map[string]any{"kind": "owned_native_principal_inventory", "production_credential_withdrawal_verified": false, "runtime_index_login": "retention_index", "runtime_coordinator_login": "retention_coordinator", "scope": "disposable_database_only"}
		local := map[string]any{"release_digest": sourcePins, "consumer_manifest_digest": consumers, "deployment_evidence_digest": observed, "credential_withdrawal_digest": withdrawal}
		artifactRoot := t.TempDir()
		for key, value := range local {
			body, marshalErr := json.Marshal(value)
			if marshalErr != nil {
				t.Fatal("owned artifact encoding refused")
			}
			if writeErr := os.WriteFile(artifactRoot+"/"+key+".json", body, 0600); writeErr != nil {
				t.Fatal("owned artifact persistence refused")
			}
			sum := sha256.Sum256(body)
			artifacts[key] = fmt.Sprintf("%x", sum)
		}
		raw, _ := json.Marshal(artifacts)
		var receipt struct {
			Digest string `json:"receipt_digest"`
		}
		if json.Unmarshal(operator(`SELECT zasp_retention_v1.record_cutover($1::jsonb)`, raw), &receipt) != nil || len(receipt.Digest) != 64 {
			t.Fatal("local artifact receipt refused")
		}
		cutover = receipt.Digest
		active = boolOp(`SELECT zasp_retention_v1.activate($1,$2)`, pin, cutover)
		if !active {
			t.Fatal("exact successor activation refused")
		}
		if !boolOp(`SELECT zasp_retention_v1.activate($1,$2) AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_runtime.current_ready()`, pin, cutover) {
			t.Fatal("full current Audit parent equivalence failed")
		}
	})
	t.Run("same_full_receipt_current_writers_before_expiry", func(t *testing.T) {
		if !active {
			t.Fatal("activation prerequisite failed")
		}
		for _, c := range cases {
			query := `SELECT ` + c.entry + `($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
			var raw json.RawMessage
			if err := coordinator.QueryRow(ctx, query, c.args...).Scan(&raw); err != nil {
				connectorFixtureErrorDiagnostic(t, err)
				t.Fatal("actual retained writer refused", c.name)
			}
		}
		if countOp(`SELECT count(*) FROM public.zasp_runtime_session_events WHERE organization_id=$1`, o) != len(allIDs) {
			t.Fatal("original projection lost events")
		}
		reconcile()
	})
	t.Run("immutable_origin_scope_switch_and_legacy_replay", func(t *testing.T) {
		exec(`INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) VALUES($1,'session-retention-native','bound-in-A','tool','A origin','origin-evidence','product','exact',clock_timestamp()-interval '2 days')`, o)
		exec(`UPDATE zasp_product_sessions SET environment_id=$1 WHERE session_id='session-retention-native'`, otherEnv)
		_, err := owner.Exec(ctx, `INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) VALUES($1,'session-retention-native','legacy-originless','tool','protected legacy','legacy-evidence','product','exact',clock_timestamp()-interval '3 days') ON CONFLICT DO NOTHING`, o)
		if err == nil {
			t.Fatal("legacy replay adopted mutable origin")
		}
		if countOp(`SELECT count(*) FROM zasp_retention_v1.event_origins WHERE event_id='legacy-originless'`) != 0 {
			t.Fatal("legacy origin fabricated")
		}
		cycle := strings.Repeat("1", 64)
		var raw json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_retention_v1.sweep($1::jsonb)`, fmt.Sprintf(`{"cycle_key":%q}`, cycle)).Scan(&raw); err != nil {
			t.Fatal("scope-bound sweep refused")
		}
		if countOp(`SELECT count(*) FROM zasp_retention_v1.event_origins WHERE event_id='bound-in-A' AND environment_id=$1`, e) != 1 || countOp(`SELECT count(*) FROM zasp_retention_v1.tombstones WHERE class='product_session_event' AND source_id='bound-in-A'`) != 0 {
			t.Fatal("B policy expired A origin")
		}
		exec(`UPDATE zasp_product_sessions SET environment_id=$1,authenticated_at=clock_timestamp() WHERE session_id='session-retention-native'`, e)
		identity, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "retention-native-session"})
		if err != nil {
			t.Fatal("restored source session refused")
		}
	})
	t.Run("audited_policy_expiry_and_idempotent_cycle", func(t *testing.T) {
		reconcile()
		mutation := administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: 1, DeletionEnabled: true, ExpectedVersion: 1, EnvironmentClass: "production", AuditID: automaticSourceID(99901)}
		if _, err := repo.MutateAdministration(checked("updateDataControls", nil), identity, mutation); err != nil {
			t.Fatal("actual audited policy update refused")
		}
		key := strings.Repeat("2", 64)
		request := fmt.Sprintf(`{"cycle_key":%q}`, key)
		var first, again json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_retention_v1.sweep($1::jsonb)`, request).Scan(&first); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("actual expiry refused")
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_retention_v1.sweep($1::jsonb)`, request).Scan(&again); err != nil || !bytes.Equal(first, again) {
			t.Fatal("cycle replay changed confirmed counters")
		}
		if countOp(`SELECT count(*) FROM public.zasp_runtime_session_events WHERE organization_id=$1`, o) != len(retainedIDs) || countOp(`SELECT count(*) FROM zasp_retention_v1.tombstones WHERE class='runtime_event'`) != len(expiredIDs) {
			t.Fatal("strict class cutoff lost or retained wrong source rows")
		}
		if countOp(`SELECT count(*) FROM zasp_retention_v1.pending_cleanup`) != 3*len(expiredIDs) {
			t.Fatal("three-family cleanup obligations missing")
		}
		if countOp(`SELECT count(*) FROM public.zasp_admin_audit WHERE id=$1 AND action='data_controls.update'`, mutation.AuditID) != 1 {
			t.Fatal("policy audit receipt lost")
		}
	})
	t.Run("mixed_replay_preserves_whole_receipts_without_resurrection", func(t *testing.T) {
		for _, c := range cases {
			query := `SELECT ` + c.entry + `($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
			var raw json.RawMessage
			if err := coordinator.QueryRow(ctx, query, c.args...).Scan(&raw); err != nil {
				connectorFixtureErrorDiagnostic(t, err)
				t.Fatal("mixed authentic replay refused", c.name)
			}
			if countOp(`SELECT cardinality(event_ids) FROM public.zasp_runtime_session_projection_receipts WHERE organization_id=$1 AND batch_id=$2`, o, c.args[3]) != 3 {
				t.Fatal("whole original receipt rewritten")
			}
		}
		if countOp(`SELECT count(*) FROM public.zasp_runtime_session_events WHERE organization_id=$1`, o) != len(retainedIDs) {
			t.Fatal("expired original IDs resurrected")
		}
	})
	t.Run("real_api_visibility_unknown_and_foreign_scope_denied", func(t *testing.T) {
		reconcile()
		visibility, err := NewRetentionEventVisibility(db, pin)
		if err != nil {
			t.Fatal(err)
		}
		states, err := visibility.VisibleEvents(checked("listSessions", nil), scope, allIDs)
		if err != nil {
			t.Fatal("actual current visibility refused")
		}
		for _, id := range retainedIDs {
			if !states[id] {
				t.Fatal("known live source suppressed")
			}
		}
		for _, id := range expiredIDs {
			if states[id] {
				t.Fatal("expired source exposed")
			}
		}
		if _, err = visibility.VisibleEvents(checked("listSessions", nil), scope, []string{automaticSourceID(99999)}); err == nil {
			t.Fatal("unknown source reported live")
		}
		foreign, err := domain.NewScope(scope.OrganizationID(), scope.WorkspaceID(), mustProductID(t, otherEnv))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = visibility.VisibleEvents(checked("listSessions", nil), foreign, allIDs); err == nil {
			t.Fatal("foreign scope reused proof")
		}
	})
	t.Run("independent_live_guard_drift_refuses_and_rolls_back", func(t *testing.T) {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;ALTER TABLE public.zasp_runtime_session_events DISABLE TRIGGER zasp_000_retention_v1_runtime_event`); err != nil {
			t.Fatal("owned drift fixture refused")
		}
		var ready bool
		if err = tx.QueryRow(ctx, `SELECT zasp_retention_v1.effective_catalog_ready($1)`, pin).Scan(&ready); err != nil || ready {
			t.Fatal("disabled guard accepted")
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if !boolOp(`SELECT zasp_retention_v1.effective_catalog_ready($1)`, pin) {
			t.Fatal("rollback did not restore live seal")
		}
	})
}

func seedRetentionMixedProjection(t *testing.T, ctx context.Context, connection *pgx.Conn, scope domain.Scope, agent string, sandbox, precise bool, identityBase int) ([]any, runtimeprojection.ProjectedBatch) {
	t.Helper()
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	batchID := mustProductID(t, "pid_96000001-0000-4000-8000-000000000001")
	sensorID, tokenID := "pid_96000002-0000-4000-8000-000000000002", "pid_96000003-0000-4000-8000-000000000003"
	tokenHash := bytes.Repeat([]byte{0x96}, 32)
	eventPrefix := ""
	archiveReference, artifactKey := "s3://zasp-evidence/runtime/sessions.json", "runtime/session-projection-fixture.json"
	correlationReference, projectedReference, completionReference := "s3://zasp-evidence/correlation.json", "s3://zasp-evidence/projected.json", "s3://zasp-evidence/completed.json"
	if identityBase != 0 {
		batchID = mustProductID(t, automaticSourceID(identityBase))
		sensorID, tokenID = automaticSourceID(identityBase+1), automaticSourceID(identityBase+2)
		uniqueToken := sha256.Sum256([]byte(tokenID))
		tokenHash = uniqueToken[:]
		eventPrefix = fmt.Sprintf("projection-%d-", identityBase)
		artifactKey = fmt.Sprintf("runtime/projection-%d/sessions.json", identityBase)
		archiveReference = "s3://zasp-evidence/" + artifactKey
		correlationReference = fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/correlation.json", identityBase)
		projectedReference = fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/projected.json", identityBase)
		completionReference = fmt.Sprintf("s3://zasp-evidence/runtime/projection-%d/completed.json", identityBase)
	}
	body := []byte(`{"source":"tetragon","events":[` + strings.Join([]string{
		`{"event_id":"late","class":"process","action":"exec","workload_id":"runtime-a","event_time":"` + time.Now().UTC().Add(-30*time.Minute).Format("2006-01-02T15:04:05.000Z") + `","evidence_id":"pid_96000004-0000-4000-8000-000000000004","content":{}}`,
		`{"event_id":"early","class":"process","action":"exec","workload_id":"runtime-a","event_time":"` + time.Now().UTC().Add(-48*time.Hour).Format("2006-01-02T15:04:05.000Z") + `","evidence_id":"pid_96000005-0000-4000-8000-000000000005","content":{}}`,
		`{"event_id":"unknown","class":"process","action":"exec","workload_id":"runtime-a","event_time":"` + time.Now().UTC().Add(-48*time.Hour).Format("2006-01-02T15:04:05.000Z") + `","evidence_id":"pid_96000006-0000-4000-8000-000000000006","content":{}}`,
	}, ",") + `]}`)
	if eventPrefix != "" {
		body = bytes.ReplaceAll(body, []byte(`"event_id":"`), []byte(`"event_id":"`+eventPrefix))
	}
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, body)
	if err != nil {
		t.Fatal(err)
	}
	if precise {
		var old struct {
			Source string
			Events []sensoradapter.RuntimeEvent
		}
		if err := json.Unmarshal(body, &old); err != nil {
			t.Fatal(err)
		}
		events := make([]sensoradapter.PreciseRuntimeEvent, len(old.Events))
		for i, event := range old.Events {
			events[i] = sensoradapter.PreciseRuntimeEvent{RuntimeEvent: event}
		}
		body, err = json.Marshal(struct {
			Version string                              `json:"version"`
			Source  string                              `json:"source"`
			Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
		}{"runtime-archive-v2", old.Source, events})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtimeevent.DecodePreciseArchivedBatch(scope, body); err != nil {
			t.Fatal(err)
		}
	}
	correlations := make([]runtimecorrelation.Result, len(decoded.Records))
	for index, record := range decoded.Records {
		confidence := domain.EvidenceConfidenceExact
		if record.SourceEventID == eventPrefix+"early" || precise {
			confidence = domain.EvidenceConfidenceStrong
		}
		correlations[index] = runtimecorrelation.Result{EventID: record.ID, SessionID: mustProductID(t, "pid_96000007-0000-4000-8000-000000000007"), AgentID: mustProductID(t, agent), Confidence: confidence}
		if record.SourceEventID == eventPrefix+"unknown" {
			correlations[index] = runtimecorrelation.Result{EventID: record.ID, Confidence: domain.EvidenceConfidenceUnattributed}
		} else if sandbox {
			correlations[index].SandboxID = "session-sandbox"
			correlations[index].SandboxSourceSensorID = mustProductID(t, sandboxSemantic)
		}
	}
	archiveDigest := sha256.Sum256(body)
	projector, projectionVersion, completionVersion := runtimeprojection.Project, "runtime-projection-v1", "runtime-complete-v1"
	if sandbox {
		projector, projectionVersion, completionVersion = runtimeprojection.ProjectSandbox, "runtime-projection-v2", "runtime-complete-v2"
	}
	encode := runtimeprojection.EncodeReceipt
	if precise {
		projector, projectionVersion, completionVersion, encode = runtimeprojection.ProjectPrecise, "runtime-projection-v3", "runtime-complete-v3", runtimeprojection.EncodePreciseReceipt
	}
	projected, err := projector(runtimeprojection.Batch{Scope: scope, BatchID: batchID, Generation: 1, ArchiveReference: archiveReference, ArchiveVersionID: "archive-v1", ArchiveDigest: archiveDigest, Body: body, Correlations: correlations})
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, receiptDigest, _, err := encode(runtimeprojection.Receipt{ImplementationVersion: projectionVersion, Scope: scope, BatchID: batchID, Generation: 1, InputReference: correlationReference, InputVersionID: "correlation-v1", InputDigest: archiveDigest, ArchiveReference: archiveReference, ArchiveVersionID: "archive-v1", ArchiveDigest: archiveDigest, EffectDigest: projected.ContentDigest, Items: projected.Items})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,'Session proof sensor','tetragon')`, []any{org, workspace, environment, sensorID}},
		{`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,decode(repeat('aa',16),'hex'),$6,transaction_timestamp()+interval '1 day')`, []any{org, workspace, environment, tokenID, sensorID, tokenHash}},
		{`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,$4,$5,'session-projection-fixture',$6,3,$7,100,'application/json','runtime-v1','processing')`, []any{org, workspace, environment, batchID.String(), sensorID, archiveDigest[:], archiveReference}},
		{`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$4,$5,$6,1,1,'session-projection-fixture',$7,$7,'tetragon','application/json','runtime-v1',100,3,$8,$9,'archive-v1',$7,100,'fixture-kms-reference',transaction_timestamp(),'processing')`, []any{org, workspace, environment, batchID.String(), sensorID, tokenID, archiveDigest[:], artifactKey, archiveReference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,1,'project',4,$8,$5,'succeeded',1,$6,$9,'projected-v1',$7,transaction_timestamp())`, []any{org, workspace, environment, batchID.String(), archiveDigest[:], projected.ContentDigest[:], receiptDigest[:], projectionVersion, projectedReference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,1,'complete',5,$6,$5,$5,'leased',1,'session-worker','session-lease-token-0001',transaction_timestamp()+interval '1 hour')`, []any{org, workspace, environment, batchID.String(), projected.ContentDigest[:], completionVersion}},
	} {
		if _, err := connection.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(fmt.Errorf("session completion fixture: %w", err))
		}
	}
	resultDigest := sha256.Sum256([]byte("completion"))
	return []any{org, workspace, environment, batchID.String(), int64(1), "session-worker", "session-lease-token-0001", 1, projected.ContentDigest[:], completionVersion, "succeeded", projected.ContentDigest[:], completionReference, "completed-v1", resultDigest[:], nil, 0, receiptBytes}, projected
}
