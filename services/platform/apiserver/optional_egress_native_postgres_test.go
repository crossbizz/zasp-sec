package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

// This group uses one admitted disposable PostgreSQL instance and the official
// local OpenFGA. Credentials/provider capability/pricing values are explicit
// fixture approvals; no Stytch/provider/deployment acceptance is inferred.
func TestOptionalEgressCurrentAuditNativePostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned local OpenFGA")
	}
	t.Setenv("ZASP_P7_AUDIT_TEST", "1")
	t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned PostgreSQL connection refused")
	}
	defer owner.Close(context.Background())
	runner := migrateIntegrationClientComposed(t, ctx, owner)
	exec := func(t *testing.T, q string, a ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, a...); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("native fixture operation refused")
		}
	}
	exec(t, `CREATE ROLE optional_native_api LOGIN;CREATE ROLE optional_native_worker LOGIN;CREATE ROLE optional_native_executor LOGIN;CREATE ROLE optional_native_compensation LOGIN;SELECT zasp_security_agent_register_principals(session_user,'optional_native_api','optional_native_worker');SELECT zasp_temporal68.register_principals('optional_native_executor','optional_native_compensation')`)
	deployment := authorization.IdentityDeployment{PublicOrigin: "https://console.example", ProviderBaseURL: "https://test.stytch.com", ProjectID: "project-test-optional-native", ConfiguredOrganization: "organization-optional-native", Mode: "saas"}
	audience, err := deployment.Audience()
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("optional-native-identity-fixture-01234567890123456789")
	sessionKey, err := authorization.NewIdentitySessionKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	webhookKey, err := authorization.NewIdentityWebhookKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	var epoch int64
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,'auth80_api','')`, sessionKey.Version(), sessionKey.Verifier(), audience, deployment.ProjectID).Scan(&epoch); err != nil || epoch < 1 {
		t.Fatal("actual identity session registration", err)
	}
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_identity.register_webhook($1,$2,$3,$4,'auth80_api','')`, webhookKey.Version(), webhookKey.Verifier(), audience, deployment.ProjectID).Scan(&epoch); err != nil || epoch < 1 {
		t.Fatal("actual identity webhook registration", err)
	}
	if err := runner.UpProductionAuthorizationWorkerAuditProfile(ctx); err != nil {
		t.Fatal("actual audit worker parent", err)
	}
	i := fixtureRequestIdentity(t)
	o, w, e, actor := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const finding = "pid_0e000001-0000-4000-8000-000000000001"
	const foreignO = "pid_0e000002-0000-4000-8000-000000000002"
	const foreignW = "pid_0e000003-0000-4000-8000-000000000003"
	const foreignE = "pid_0e000004-0000-4000-8000-000000000004"
	exec(t, `INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Optional native','optional.invalid'),($2,'Foreign optional','foreign-optional.invalid')`, o, foreignO)
	exec(t, `INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Selected'),($3,$4,'Foreign')`, o, w, foreignO, foreignW)
	exec(t, `INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production'),($4,$5,$6,'Foreign','production')`, o, w, e, foreignO, foreignW, foreignE)
	exec(t, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-optional-native','member-optional-native','organization_admin',true)`, actor, o)
	exec(t, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','[]',true)`, actor, o, w, e)
	exec(t, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('optional-native-session','sha256'),'session-optional-native',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, actor, o, w, e)
	exec(t, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','ownerless_agent','SECRET synthetic patient medical note never sent','high','open'),($5,$6,$7,$4,'posture','ownerless_agent','Foreign private title','high','open')`, o, w, e, finding, foreignO, foreignW, foreignE)
	connect := func(t *testing.T, login string) *pgx.Conn {
		t.Helper()
		cfg := owner.Config().Copy()
		cfg.User = login
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal("registered connection refused")
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	human, captured, planner := connect(t, "optional_native_api"), connect(t, "optional_native_compensation"), connect(t, "optional_native_executor")
	database := func(t *testing.T, c *pgx.Conn) *PostgresJSONDatabase {
		t.Helper()
		d, err := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: c})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	forwardDB, capturedDB := database(t, human), database(t, captured)
	authConn := connect(t, "auth80_api")
	authDB := database(t, authConn)
	if err := authDB.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	sessions, err := NewPostgresRepository(authDB)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sessions.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "optional-native-session"})
	if err != nil {
		t.Fatal("actual native browser credential authentication", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = "auth80_outbox"
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
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
	exec(t, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID)
	reconcile := func(t *testing.T) {
		t.Helper()
		r, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID)
		if err != nil || !r.Applied {
			t.Fatal("actual current tuple projection refused", err)
		}
	}
	reconcile(t)
	resolver, err := NewPostgresAuthorizationResolver(authDB)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	proofFor := func(operation string) (optionalegress.Proof, error) {
		route := RoutedOperation{OperationID: operation}
		if operation == "getFinding" {
			route.PathParameters = map[string]string{"id": finding}
		}
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, route)
		if err != nil {
			return nil, err
		}
		proof, err := authorizationProofJSON(grant)
		return optionalegress.Proof(proof), err
	}
	mustProof := func(t *testing.T, operation string) optionalegress.Proof {
		t.Helper()
		p, err := proofFor(operation)
		if err != nil {
			t.Fatal("current official Check refused", err)
		}
		return p
	}
	repo, err := NewOptionalEgressRepositoryForProfile(forwardDB, capturedDB, migrations.OptionalEgressAuditProfileChecksum())
	if err != nil {
		t.Fatal(err)
	}
	scope := optionalEgressScope{Organization: o, Workspace: w, Environment: e, Actor: actor}
	intent := optionalegress.Intent{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ActorID: actor, FindingID: finding, FindingVersion: 1, IdempotencyKey: "optional-native-intent-0001", Purpose: optionalegress.Purpose}
	var approved optionalegress.Profile
	now := time.Now().UTC()
	approved = optionalegress.Profile{ProfileID: "pid_0e000005-0000-4000-8000-000000000005", ProfileVersion: 1, Provider: "openrouter", Purpose: optionalegress.Purpose, Model: "fixture/model", Backend: "Fixture Provider", AccountID: "fixture_account", CredentialReference: "secret_ref_ai/" + o + "/" + w + "/" + e + "/fixture_credential", CredentialDigest: "sha256:" + strings.Repeat("1", 64), CapabilityDigest: "sha256:" + strings.Repeat("2", 64), PricingDigest: "sha256:" + strings.Repeat("3", 64), EffectiveAt: now.Add(-time.Minute).Format(optionalegress.TimeFormat), ExpiresAt: now.Add(time.Hour).Format(optionalegress.TimeFormat), InputTokenBound: 1000, OutputTokenCap: 100, PromptPriceNanoCreditsPerMillion: 1000000, CompletionPriceNanoCreditsPerMillion: 1000000, CostCeilingNanoCredits: 2000, MaximumOutstandingNanoCredits: 200000, MaximumConcurrency: 4, TimeoutMilliseconds: 30000, PolicyVersion: "fixture_policy_v1"}
	approved.ProfileDigest, err = optionalegress.ProfileDigest(approved)
	if err != nil {
		t.Fatal(err)
	}
	operatorProfile := func(t *testing.T, p optionalegress.Profile) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "profile": p})
		exec(t, `SELECT zasp_optional_egress_v1.register_profile($1::jsonb)`, raw)
	}
	snapshot := func(t *testing.T) string {
		t.Helper()
		var v string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('policies',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY flow_id),'[]') FROM zasp_optional_egress_v1.policies p),'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY request_id),'[]') FROM zasp_optional_egress_v1.requests r),'events',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY event_id),'[]') FROM zasp_optional_egress_v1.events a),'mutations',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY idempotency_key),'[]') FROM zasp_optional_egress_v1.mutations m))::text`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	sequence := 0
	binding := func(t *testing.T, key string) optionalegress.Binding {
		t.Helper()
		j := intent
		j.IdempotencyKey = key
		src, err := repo.Source(ctx, j, mustProof(t, "getFinding"))
		if err != nil {
			t.Fatal("actual source denied", err)
		}
		sequence++
		p, err := optionalegress.Prepare(j, src, fmt.Sprintf("pid_0e001000-0000-4000-8000-%012d", sequence), time.Now().UTC())
		if err != nil {
			t.Fatal("canonical preparation denied", err)
		}
		return p.Binding()
	}
	toggle := func(t *testing.T, enabled bool, version int64, key string) error {
		return repo.query(ctx, mustProof(t, "updateExternalDataFlows"), "update", struct {
			optionalEgressScope
			FlowID  string `json:"flow_id"`
			Enabled bool   `json:"enabled"`
			Version int64  `json:"expected_version"`
			Key     string `json:"idempotency_key"`
		}{scope, "openrouter", enabled, version, key}, new(json.RawMessage))
	}
	t.Run("compiled_audit_install_and_purpose_boundaries", func(t *testing.T) {
		if err := runner.UpProductionOptionalEgressAuditProfile(ctx); err != nil {
			t.Fatal("install audit optional authority", err)
		}
		if err := runner.UpProductionOptionalEgressAuditProfile(ctx); err != nil {
			t.Fatal("idempotent audit install", err)
		}
		if err := runner.UpProductionOptionalEgressProfile(ctx); err == nil {
			t.Fatal("standalone recipe replaced audit parent")
		}
		exec(t, `CREATE ROLE optional_native_unregistered LOGIN INHERIT;GRANT zasp_security_agent_api TO optional_native_unregistered`)
		if _, err := owner.Exec(ctx, `SELECT zasp_optional_egress_v1.register_principal('optional_native_unregistered','human-forward')`); err == nil {
			t.Fatal("sole role membership replaced original registered parent identity")
		}
		for _, registration := range [][2]string{{"optional_native_api", "human-forward"}, {"optional_native_executor", "planner-forward"}, {"optional_native_compensation", "captured-settlement"}} {
			exec(t, `SELECT zasp_optional_egress_v1.register_principal($1,$2)`, registration[0], registration[1])
		}
		if err := repo.Ready(ctx); err != nil {
			t.Fatal("registered distinct roles not ready", err)
		}
		var ready bool
		if err := planner.QueryRow(ctx, `SELECT zasp_optional_egress_v1.planner_ready()`).Scan(&ready); err != nil || !ready {
			t.Fatal("registered planner identity not ready")
		}
		if err := human.QueryRow(ctx, `SELECT zasp_optional_egress_v1.caller_ready('captured-settlement',$1)`, migrations.OptionalEgressAuditProfileChecksum()).Scan(&ready); err != nil || ready {
			t.Fatal("human login acquired captured purpose")
		}
		var count int
		if err := human.QueryRow(ctx, `SELECT count(*) FROM zasp_optional_egress_v1.requests`).Scan(&count); err == nil {
			t.Fatal("runtime login read private table")
		}
		var canonical int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_schema_versions`).Scan(&canonical); err != nil || canonical != 61 {
			t.Fatal("canonical ledger changed")
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `GRANT SELECT ON zasp_optional_egress_v1.requests TO optional_native_api`); err != nil {
			t.Fatal(err)
		}
		if err = tx.QueryRow(ctx, `SELECT zasp_optional_egress_v1.catalog_ready($1)`, migrations.OptionalEgressAuditProfileChecksum()).Scan(&ready); err != nil || ready {
			t.Fatal("catalog ACL drift accepted")
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		operatorProfile(t, approved)
	})
	t.Run("required_catalog_and_durable_optional_switch", func(t *testing.T) {
		var catalog struct {
			Items []struct {
				ID         string   `json:"id"`
				Name       string   `json:"name"`
				Required   bool     `json:"required"`
				Enabled    bool     `json:"enabled"`
				Version    int64    `json:"version"`
				Categories []string `json:"categories"`
				Available  bool     `json:"available"`
				Health     string   `json:"health"`
			} `json:"items"`
		}
		if err := repo.query(ctx, mustProof(t, "getExternalDataFlows"), "catalog", scope, &catalog); err != nil || len(catalog.Items) != 5 {
			t.Fatal("fixed catalog missing", err)
		}
		for n, row := range catalog.Items {
			if len(row.Categories) == 0 || row.Required != (n < 2) || row.Enabled != (n < 2) {
				t.Fatal("server required/optional defaults changed")
			}
		}
		before := snapshot(t)
		for _, id := range []string{"stytch", "neon"} {
			var receipt json.RawMessage
			err := repo.query(ctx, mustProof(t, "updateExternalDataFlows"), "update", map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": actor, "flow_id": id, "enabled": false, "expected_version": 1, "idempotency_key": "hostile-required-disable-" + id}, &receipt)
			if err == nil || snapshot(t) != before {
				t.Fatal("required disable mutated authority")
			}
		}
		if err := toggle(t, true, 1, "enable-openrouter-fixture-0001"); err != nil {
			t.Fatal("approved optional enable", err)
		}
		untouched := snapshot(t)
		if _, err := planner.Exec(ctx, `SELECT zasp_optional_egress_v1.admit_planner_dispatch('finding78',$1::jsonb)`, map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "operation": "start"}); err == nil || snapshot(t) != untouched {
			t.Fatal("enabled planner gate admitted missing original worker proof")
		}
		after := snapshot(t)
		if after == before {
			t.Fatal("enable did not persist audit/state")
		}
		if err := toggle(t, true, 1, "enable-openrouter-fixture-0001"); err != nil || snapshot(t) != after {
			t.Fatal("idempotent toggle duplicated mutation", err)
		}
		if err := toggle(t, false, 1, "stale-openrouter-fixture-0001"); err == nil || snapshot(t) != after {
			t.Fatal("stale policy version changed state")
		}
	})
	t.Run("canonical_source_and_tenant_profile_isolation", func(t *testing.T) {
		src, err := repo.Source(ctx, intent, mustProof(t, "getFinding"))
		if err != nil || src.Summary.FindingID != finding || src.Summary.Rule != "ownerless_agent" || src.Summary.EvidenceCount != 0 || src.Profile != approved {
			t.Fatal("actual source/profile binding", err)
		}
		encoded, _ := json.Marshal(src)
		if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "medical") || strings.Contains(string(encoded), "Foreign private") {
			t.Fatal("raw evidence/title entered canonical source")
		}
		before := snapshot(t)
		foreign := intent
		foreign.OrganizationID = foreignO
		foreign.WorkspaceID = foreignW
		foreign.EnvironmentID = foreignE
		if _, err := repo.Source(ctx, foreign, mustProof(t, "getFinding")); err == nil || snapshot(t) != before {
			t.Fatal("foreign scope consumed current proof")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_optional_egress_v1.approved_profiles SET profile=profile||'{"model":"unapproved/model"}' WHERE profile_id=$1`, approved.ProfileID); err == nil {
			t.Fatal("approved immutable profile changed")
		}
		var foreignEnabled bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.policies WHERE organization_id=$1 AND enabled)`, foreignO).Scan(&foreignEnabled); err != nil || foreignEnabled {
			t.Fatal("foreign tenant enabled by selected tenant mutation")
		}
	})
	var admitted optionalegress.DispatchResult
	var retainedUnknownCost int64
	t.Run("concurrent_dispatch_mints_exactly_one_claim", func(t *testing.T) {
		b := binding(t, "optional-native-concurrent-0001")
		reserved, err := repo.Reserve(ctx, b, mustProof(t, "getFinding"))
		if err != nil || !reserved.NewlyReserved || reserved.State != optionalegress.Reserved {
			t.Fatal("actual reservation", err)
		}
		again, err := repo.Reserve(ctx, b, mustProof(t, "getFinding"))
		if err != nil || again.NewlyReserved || again.Binding != b {
			t.Fatal("reservation replay changed intent", err)
		}
		wrong := b
		wrong.BodyDigest = "sha256:" + strings.Repeat("9", 64)
		before := snapshot(t)
		if _, err := repo.Reserve(ctx, wrong, mustProof(t, "getFinding")); err == nil || snapshot(t) != before {
			t.Fatal("same key adopted changed body")
		}
		second := connect(t, "optional_native_api")
		secondRepo, err := NewOptionalEgressRepositoryForProfile(database(t, second), capturedDB, migrations.OptionalEgressAuditProfileChecksum())
		if err != nil {
			t.Fatal(err)
		}
		proofs := []optionalegress.Proof{mustProof(t, "getFinding"), mustProof(t, "getFinding")}
		repos := []*OptionalEgressRepository{repo, secondRepo}
		var results [2]optionalegress.DispatchResult
		var failures [2]error
		var wg sync.WaitGroup
		for n := 0; n < 2; n++ {
			wg.Add(1)
			go func(n int) { defer wg.Done(); results[n], failures[n] = repos[n].Dispatch(ctx, b, proofs[n]) }(n)
		}
		wg.Wait()
		claims := 0
		for n, r := range results {
			if failures[n] != nil {
				t.Fatal("native concurrent dispatch refused", failures[n])
			}
			if r.NewlyStarted {
				claims++
				admitted = r
				if len(r.Nonce) != 64 {
					t.Fatal("new claim nonce absent")
				}
			} else if r.Nonce != "" {
				t.Fatal("replay received send nonce")
			}
		}
		if claims != 1 {
			t.Fatal("dispatch produced multiple/no new claims")
		}
		var started int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_optional_egress_v1.events WHERE request_id=$1 AND action='started'`, b.RequestID).Scan(&started); err != nil || started != 1 {
			t.Fatal("duplicate native start evidence")
		}
		replay, err := repo.Dispatch(ctx, b, mustProof(t, "getFinding"))
		if err != nil || replay.NewlyStarted || replay.Nonce != "" {
			t.Fatal("STARTED request gained a second send claim")
		}
	})
	t.Run("captured_settlement_survives_revoke_and_read_denies", func(t *testing.T) {
		// This capture owns a fresh genuine claim. The separate concurrency
		// replay may already have converged its original request to UNKNOWN.
		b := binding(t, "optional-native-captured-settlement-0001")
		reserved, err := repo.Reserve(ctx, b, mustProof(t, "getFinding"))
		if err != nil || !reserved.NewlyReserved || reserved.State != optionalegress.Reserved {
			t.Fatal("independent captured reservation", err)
		}
		admitted, err := repo.Dispatch(ctx, b, mustProof(t, "getFinding"))
		if err != nil || !admitted.NewlyStarted || admitted.State != optionalegress.Started || len(admitted.Nonce) != 64 {
			t.Fatal("independent captured dispatch", err)
		}
		stale := mustProof(t, "getFinding")
		exec(t, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, actor, o)
		before := snapshot(t)
		if _, err := repo.Replay(ctx, admitted.Binding.Intent, stale); err == nil || snapshot(t) != before {
			t.Fatal("pending/revoked old proof read metadata")
		}
		settle := optionalegress.Settlement{Claim: optionalegress.Claim{Binding: admitted.Binding, Nonce: admitted.Nonce}, State: optionalegress.Complete, ResultDigest: "sha256:" + strings.Repeat("4", 64), Usage: &optionalegress.Usage{InputTokens: 1, OutputTokens: 1, CostNanoCredits: 1}}
		bad := settle
		bad.Nonce = strings.Repeat("0", 64)
		if _, err := repo.Settle(ctx, bad); err == nil || snapshot(t) != before {
			t.Fatal("captured settlement accepted foreign nonce")
		}
		bad = settle
		bad.Usage = &optionalegress.Usage{InputTokens: 1, OutputTokens: 1, CostNanoCredits: 3}
		if _, err := repo.Settle(ctx, bad); err == nil || snapshot(t) != before {
			t.Fatal("usage above actual-token rate ceiling accepted")
		}
		completed, err := repo.Settle(ctx, settle)
		if err != nil || completed.State != optionalegress.Complete || completed.Usage == nil || completed.Usage.CostNanoCredits != 1 {
			t.Fatal("captured discounted settlement after revoke", err)
		}
		after := snapshot(t)
		if _, err := repo.Settle(ctx, settle); err != nil || snapshot(t) != after {
			t.Fatal("captured duplicate settlement changed first outcome", err)
		}
		reconcile(t)
		if _, err := proofFor("getFinding"); err == nil {
			t.Fatal("revoked member obtained a fresh Check")
		}
		exec(t, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1 AND organization_id=$2`, actor, o)
		reconcile(t)
		replay, err := repo.Replay(ctx, admitted.Binding.Intent, mustProof(t, "getFinding"))
		if err != nil || !replay.Found || replay.Receipt == nil || replay.Receipt.State != optionalegress.Complete {
			t.Fatal("current authorized metadata read", err)
		}
	})
	t.Run("disable_and_pending_projection_deny_new_dispatch", func(t *testing.T) {
		b := binding(t, "optional-native-disabled-0001")
		if _, err := repo.Reserve(ctx, b, mustProof(t, "getFinding")); err != nil {
			t.Fatal(err)
		}
		if err := toggle(t, false, 2, "disable-openrouter-fixture-0001"); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t)
		if _, err := repo.Dispatch(ctx, b, mustProof(t, "getFinding")); err == nil || snapshot(t) != before {
			t.Fatal("disabled switch admitted a reserved send")
		}
		if err := toggle(t, true, 3, "enable-openrouter-fixture-0002"); err != nil {
			t.Fatal(err)
		}
		stale := mustProof(t, "getFinding")
		exec(t, `SELECT zasp_authorization79.touch($1)`, o)
		before = snapshot(t)
		if _, err := repo.Dispatch(ctx, b, stale); err == nil || snapshot(t) != before {
			t.Fatal("pending projection admitted cached permission")
		}
		reconcile(t)
		d, err := repo.Dispatch(ctx, b, mustProof(t, "getFinding"))
		if err != nil || !d.NewlyStarted {
			t.Fatal("reconciled current dispatch", err)
		}
		retainedUnknownCost = b.CostCeilingNanoCredits
		u := optionalegress.Settlement{Claim: optionalegress.Claim{Binding: b, Nonce: d.Nonce}, State: optionalegress.Unknown, FailureCode: "provider_transport"}
		r, err := repo.Settle(ctx, u)
		if err != nil || r.State != optionalegress.Unknown || r.Usage != nil {
			t.Fatal("unknown outcome fabricated known/zero usage", err)
		}
		if again, err := repo.Dispatch(ctx, b, mustProof(t, "getFinding")); err != nil || again.NewlyStarted || again.Nonce != "" {
			t.Fatal("UNKNOWN acquired resend authority")
		}
		var retained bool
		if err := owner.QueryRow(ctx, `SELECT state='unknown' AND usage IS NULL AND(binding->>'cost_ceiling_nano_credits')::bigint>0 FROM zasp_optional_egress_v1.requests WHERE request_id=$1`, b.RequestID).Scan(&retained); err != nil || !retained {
			t.Fatal("unknown cost reservation lost")
		}
	})
	t.Run("mounted_expiry_converges_without_background_worker", func(t *testing.T) {
		reservedBinding := binding(t, "optional-native-expired-reserved-0001")
		startedBinding := binding(t, "optional-native-expired-started-0001")
		if _, err := repo.Reserve(ctx, reservedBinding, mustProof(t, "getFinding")); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Reserve(ctx, startedBinding, mustProof(t, "getFinding")); err != nil {
			t.Fatal(err)
		}
		d, err := repo.Dispatch(ctx, startedBinding, mustProof(t, "getFinding"))
		if err != nil || !d.NewlyStarted {
			t.Fatal("original started expiry claim", err)
		}
		end, err := time.Parse(optionalegress.TimeFormat, startedBinding.Deadline)
		if err != nil {
			t.Fatal(err)
		}
		concurrentDeadline, err := time.Parse(optionalegress.TimeFormat, admitted.Binding.Deadline)
		if err != nil || concurrentDeadline.After(end) {
			t.Fatal("concurrency claim did not precede original expiry wait", err)
		}
		if wait := time.Until(end) + 10*time.Millisecond; wait > 0 {
			if wait > 31*time.Second {
				t.Fatal("fixture escaped approved original deadline")
			}
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal("owned expiry wait canceled")
			}
		}
		for _, tc := range []struct {
			b     optionalegress.Binding
			state optionalegress.State
			code  string
		}{{reservedBinding, optionalegress.Failed, "expired_no_send"}, {startedBinding, optionalegress.Unknown, "deadline"}} {
			r, err := repo.Replay(ctx, tc.b.Intent, mustProof(t, "getFinding"))
			if err != nil || !r.Found || r.Receipt == nil || r.Receipt.Binding != tc.b || r.Receipt.State != tc.state || r.Receipt.FailureCode != tc.code || r.Receipt.Usage != nil {
				t.Fatal("mounted expiry did not converge exact no-send/unknown state", err)
			}
			after := snapshot(t)
			again, err := repo.Dispatch(ctx, tc.b, mustProof(t, "getFinding"))
			if err != nil || again.NewlyStarted || again.Nonce != "" || snapshot(t) != after {
				t.Fatal("expired request acquired a new send claim")
			}
		}
		// The independent concurrency claim retains its own original debt.
		// Converge it through the same real mounted read, never a fixture UPDATE.
		concurrent, err := repo.Replay(ctx, admitted.Binding.Intent, mustProof(t, "getFinding"))
		if err != nil || !concurrent.Found || concurrent.Receipt == nil || concurrent.Receipt.Binding != admitted.Binding || concurrent.Receipt.State != optionalegress.Unknown || concurrent.Receipt.FailureCode != "deadline" || concurrent.Receipt.Usage != nil {
			t.Fatal("concurrency claim lost exact unknown expiry debt", err)
		}
		var unknownCeiling int64
		if err := owner.QueryRow(ctx, `SELECT sum((binding->>'cost_ceiling_nano_credits')::bigint) FROM zasp_optional_egress_v1.requests WHERE state='unknown'`).Scan(&unknownCeiling); err != nil || retainedUnknownCost <= 0 || unknownCeiling != admitted.Binding.CostCeilingNanoCredits+retainedUnknownCost+startedBinding.CostCeilingNanoCredits {
			t.Fatal("expiry released unknown charges")
		}
	})
	t.Run("operator_rotation_preserves_captured_binding_and_no_raw_storage", func(t *testing.T) {
		b := binding(t, "optional-native-rotation-0001")
		if _, err := repo.Reserve(ctx, b, mustProof(t, "getFinding")); err != nil {
			t.Fatal(err)
		}
		version2 := approved
		version2.ProfileVersion = 2
		version2.PolicyVersion = "fixture_policy_v2"
		version2.ProfileDigest, err = optionalegress.ProfileDigest(version2)
		if err != nil {
			t.Fatal(err)
		}
		operatorProfile(t, version2)
		activation, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "profile_id": approved.ProfileID, "profile_version": 2, "expected_version": 4})
		if _, err := owner.Exec(ctx, `SELECT zasp_optional_egress_v1.activate_profile($1::jsonb)`, activation); err == nil {
			t.Fatal("enabled policy rotated operator profile")
		}
		if err := toggle(t, false, 4, "disable-openrouter-rotation-0001"); err != nil {
			t.Fatal(err)
		}
		activation, _ = json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "profile_id": approved.ProfileID, "profile_version": 2, "expected_version": 5})
		exec(t, `SELECT zasp_optional_egress_v1.activate_profile($1::jsonb)`, activation)
		if err := toggle(t, true, 6, "enable-openrouter-rotation-0001"); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t)
		if _, err := repo.Dispatch(ctx, b, mustProof(t, "getFinding")); err == nil || snapshot(t) != before {
			t.Fatal("old RESERVED adopted new approved profile")
		}
		var changed bool
		if err := owner.QueryRow(ctx, `SELECT binding->>'profile_digest'=$2 FROM zasp_optional_egress_v1.requests WHERE request_id=$1`, b.RequestID, approved.ProfileDigest).Scan(&changed); err != nil || !changed {
			t.Fatal("old immutable reservation profile changed")
		}
		if strings.Contains(snapshot(t), "SECRET") || strings.Contains(snapshot(t), "medical") || strings.Contains(snapshot(t), "Foreign private") {
			t.Fatal("private metadata retained raw title/evidence")
		}
		var forbidden bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='zasp_optional_egress_v1' AND column_name IN('prompt','response','request_body','raw_result','title','evidence'))`).Scan(&forbidden); err != nil || forbidden {
			t.Fatal("raw-content persistence column added")
		}
	})
}
