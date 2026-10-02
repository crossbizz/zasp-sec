package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches a private Temporal cutover that cannot coexist with registered61 and
// current API80 authority. No policy execution, provider or Temporal service runs.
func TestTemporalPolicyResponseComposedLineagePostgres(t *testing.T) {
	policyResponseLineage(t, "zasp_e2e", true)
}

func TestTemporalPolicyResponseDescendantPinsPostgres(t *testing.T) {
	policyResponseLineage(t, "zasp_e2e", false)
}

func TestTemporalPolicyResponseSupportedLineagePostgres(t *testing.T) {
	policyResponseLineage(t, "zasp_test", false)
}

func policyResponseLineage(t *testing.T, login string, includeAuthorization bool) {
	multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, api *pgx.Conn, o, w, e, _, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Minute)
		defer cancel()
		for _, role := range []struct {
			connection *pgx.Conn
			want       string
		}{{owner, login}, {api, "security_agent_v33_api_login"}} {
			var actual string
			if err := role.connection.QueryRow(ctx, `SELECT session_user`).Scan(&actual); err != nil || actual != role.want {
				t.Fatalf("actual migration/API principal=%s want=%s error=%v", actual, role.want, err)
			}
			t.Logf("session_user=%s", actual)
		}
		runner, err := migrations.NewRunner(&policyLineageDatabase{connection: owner, t: t})
		if err != nil {
			t.Fatal(err)
		}
		stages := []struct {
			name string
			up   func(context.Context) error
		}{
			{"56", runner.UpProductionCompliance}, {"57", runner.UpProductionSecurityAgentAttackLab}, {"58", runner.UpProductionSecurityAgentExports}, {"59", runner.UpProductionSecurityAgentWebhooks}, {"60", runner.UpProductionDiscoveryScheduleReplay}, {"61", runner.UpProductionSecurityAgentMultistep},
			{"67", runner.UpProductionTemporalDomain}, {"68", runner.UpProductionTemporalExecutor}, {"69", runner.UpProductionTemporalWorkflow}, {"70", runner.UpProductionTemporalCompatibility}, {"71", runner.UpProductionTemporalLegacyTests}, {"72", runner.UpProductionTemporalDiscovery}, {"73", runner.UpProductionTemporalAdmission}, {"74", runner.UpProductionTemporalTestExecutor}, {"75", runner.UpProductionTemporalTestSelector}, {"76", runner.UpProductionTemporalHumanAdmission}, {"77", runner.UpProductionTemporalAutomaticSources}, {"78", runner.UpProductionTemporalFindingResponse}, {"79", runner.UpProductionAuthorizationProjection}, {"80", runner.UpProductionAuthorizationEnforcement},
		}
		t.Logf("source checksums61=%s 67=%s 78=%s 79=%s 80=%s", migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalFindingResponseChecksum(), migrations.ProductionAuthorizationProjection().Checksum(), migrations.ProductionAuthorizationEnforcement().Checksum())
		const helperIdentity = `SELECT jsonb_agg(jsonb_build_object('signature',oid::regprocedure::text,'body_sha256',encode(digest(pg_get_functiondef(oid),'sha256'),'hex'),'owner',proowner::regrole::text,'acl',COALESCE(proacl::text,'')) ORDER BY oid::regprocedure::text)::text FROM pg_proc WHERE oid IN('public.zasp_valid_product_id(text)'::regprocedure,'public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)'::regprocedure)`
		var previousHelpers string
		if err := owner.QueryRow(ctx, helperIdentity).Scan(&previousHelpers); err != nil {
			t.Fatal(err)
		}
		for _, stage := range stages {
			if stage.name == "61" && login == "zasp_test" {
				continue
			}
			if stage.name == "79" {
				var ready bool
				if err := api.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()).Scan(&ready); err != nil || !ready {
					t.Fatalf("descendant78 API authority=%t error=%v", ready, err)
				}
				if !includeAuthorization {
					return
				}
			}
			if stage.name == "67" {
				if _, err := owner.Exec(ctx, `CREATE ROLE policy81_scheduler LOGIN INHERIT; CREATE ROLE policy81_risk LOGIN INHERIT; CREATE ROLE policy81_graph LOGIN INHERIT; CREATE ROLE policy81_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'policy81_scheduler','security_agent_v33_discovery_worker_login','policy81_risk','policy81_graph','policy81_search')`); err != nil {
					t.Fatal("registered execution prerequisites", err)
				}
			}
			if err := stage.up(ctx); err != nil {
				var count int
				var live, expected string
				var ready bool
				diagnostic := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_schema_versions),zasp_sa_multistep_registered_live_fingerprint(),$1::text,zasp_sa_multistep_readiness($2,$1)`, migrations.SecurityAgentMultistepRegisteredFingerprint(), migrations.ProductionSecurityAgentMultistep().Checksum()).Scan(&count, &live, &expected, &ready)
				t.Logf("failed stage=%s registered_rows=%d canonical61_ready=%t live61=%s expected61=%s diagnostic_error=%v", stage.name, count, ready, live, expected, diagnostic)
				t.Fatalf("composed lineage install%s: %v", stage.name, err)
			}
			t.Logf("installed stage=%s", stage.name)
			if includeAuthorization && (stage.name == "78" || stage.name == "79") {
				policyTemporalAncestry(t, ctx, owner, "after"+stage.name)
			}
			var currentHelpers string
			if err := owner.QueryRow(ctx, helperIdentity).Scan(&currentHelpers); err != nil {
				t.Fatal(err)
			}
			if currentHelpers != previousHelpers {
				t.Logf("helper identity change stage=%s before=%s after=%s", stage.name, previousHelpers, currentHelpers)
				previousHelpers = currentHelpers
			}
		}
		var ready bool
		if err := api.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2) AND zasp_authorization80.ready($3)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint(), migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
			t.Fatalf("composed API authority=%t error=%v", ready, err)
		}
		key := authorizationFixtureAttestor(t)
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
		identity := automaticSourceIdentity(t, o, w, e, actor)
		identity.CSRFToken = strings.Repeat("x", 32)
		const finding = "pid_f0810000-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$5,'posture','Lineage read','low','open'); INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('policy-lineage-session','sha256'),'policy-lineage-session',$4,$1,$2,$3,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor, finding); err != nil {
			t.Fatal(err)
		}
		var outbox string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
			t.Fatal("registered outbox lookup", err)
		}
		cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User = outbox
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		var actual string
		if err := pool.QueryRow(ctx, `SELECT session_user`).Scan(&actual); err != nil || actual != outbox {
			t.Fatal("registered projection principal", actual, err)
		}
		t.Logf("session_user=%s", actual)
		projection, err := authorization.NewPostgresProjectionRepository(pool)
		if err != nil {
			t.Fatal(err)
		}
		store, model := "01K00000000000000000000001", "01K00000000000000000000002"
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model); err != nil {
			t.Fatal(err)
		}
		if _, err := authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		resolver, err := NewPostgresAuthorizationResolver(db)
		if err != nil {
			t.Fatal(err)
		}
		authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: authorizationDecisionFixture{allow: map[string]bool{finding: true}, model: model}, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: key}
		binding := CredentialBinding{Kind: CredentialBrowserSession, ID: "policy-lineage-session", Digest: sha256.Sum256([]byte("policy-lineage-session"))}
		grant, err := authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": finding}})
		if err != nil {
			t.Fatal("current human authorization", err)
		}
		checked := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
		repo := &PostgresRepository{database: db, currentAuthorization: true}
		got, err := repo.GetRiskFinding(checked, identity.Scope, finding)
		if err != nil || got.ID != finding {
			t.Fatalf("retained finding read through current fence: id=%s error=%v", got.ID, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='policy-lineage-session'`); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.GetRiskFinding(checked, identity.Scope, finding); !errors.Is(err, ErrRepositoryConflict) {
			t.Fatalf("revoked current80 fence allowed stale proof: %v", err)
		}
		t.Log("composed78 authority and signed human80 retained finding read/revocation passed; FGA Check and projection transport controlled")
	}, func(t *testing.T) string { return startDisposablePostgresAs(t, login) })
}

// Test-only raw boundary diagnostics: statement hashes and boolean guard results,
// never SQL arguments, error detail or credential/body values.
type policyLineageDatabase struct {
	connection *pgx.Conn
	t          *testing.T
	capture72  func(context.Context, pgx.Tx)
}

func (d *policyLineageDatabase) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	return &policyLineageRow{row: d.connection.QueryRow(ctx, q, args...), q: q, t: d.t}
}
func (d *policyLineageDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &policyLineageTransaction{integrationMigrationTransaction: integrationMigrationTransaction{transaction: tx}, t: d.t, capture72: d.capture72}, nil
}

type policyLineageTransaction struct {
	integrationMigrationTransaction
	t         *testing.T
	capture72 func(context.Context, pgx.Tx)
}

func (tx *policyLineageTransaction) Exec(ctx context.Context, q string, args ...any) error {
	err := tx.integrationMigrationTransaction.Exec(ctx, q, args...)
	if err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) {
			tx.t.Logf("raw migration exec sha256=%x SQLSTATE=%s position=%d", sha256.Sum256([]byte(q)), p.Code, p.Position)
		}
	}
	return err
}
func (tx *policyLineageTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	r := &policyLineageRow{row: tx.transaction.QueryRow(ctx, q, args...), q: q, t: tx.t}
	if q == `SELECT zasp_authorization80.ready($1)` {
		r.onFalse = func() {
			var result string
			err := tx.transaction.QueryRow(ctx, `SELECT jsonb_build_object('ready80',zasp_authorization80.ready($1),'registration80_checksum',EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum=$1),'registration80_catalog',EXISTS(SELECT 1 FROM zasp_authorization80.registration WHERE checksum=$1 AND fingerprint=zasp_authorization80.fingerprint()),'live80',zasp_authorization80.fingerprint(),'ready79',zasp_authorization79.ready($2),'operator79',zasp_authorization79.operator(),'ready61',public.zasp_sa_multistep_readiness($3,$4),'live61',public.zasp_sa_multistep_registered_live_fingerprint(),'registered61_version',EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$3),'registered61_checksum',EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_multistep_checksum' AND value=$3),'registered61_fingerprint',EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_multistep_fingerprint' AND value=$4),'legacy61_metadata_absent',to_regclass('public.zasp_sa_multistep_metadata') IS NULL)::text`, migrations.ProductionAuthorizationEnforcement().Checksum(), migrations.ProductionAuthorizationProjection().Checksum(), migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&result)
			tx.t.Logf("same-transaction80 conjuncts=%s diagnostic_error=%v", result, err)
			policyTemporalAncestry(tx.t, ctx, tx.transaction, "inside80")
		}
	}
	for _, version := range []string{"73", "74", "75", "76", "77", "78"} {
		if q == "SELECT zasp_temporal"+version+".ready($1,$2)" {
			r.onResult = func() {
				var live string
				err := tx.transaction.QueryRow(ctx, "SELECT zasp_temporal"+version+".fingerprint()").Scan(&live)
				tx.t.Logf("descendant%s live_fingerprint=%s expected=%v diagnostic_error=%v", version, live, args[1], err)
			}
		}
	}
	if q == `SELECT zasp_temporal72.ready($1,$2)` {
		if tx.capture72 != nil {
			r.onResult = func() { tx.capture72(ctx, tx.transaction) }
		}
		r.onFalse = func() {
			var prior, registration, roles, catalog bool
			var count int
			var fingerprint, mismatches string
			err := tx.transaction.QueryRow(ctx, `SELECT zasp_temporal71.ready($3,$4),(SELECT count(*) FROM zasp_temporal72.registration),EXISTS(SELECT 1 FROM zasp_temporal72.registration WHERE checksum=$1 AND fingerprint=$2),zasp_temporal72.roles_ready(),zasp_temporal72.fingerprint()=$2,zasp_temporal72.fingerprint(),COALESCE((SELECT jsonb_agg(jsonb_build_object('signature',s.signature,'missing',p.oid IS NULL,'source_mismatch',s.signature NOT IN('zasp_production_runtime_precision_live_fingerprint()','zasp_execution_claim_jobs(text,text,integer,integer)','zasp_execution_live_fingerprint()','zasp_discovery_schedule_replay_function_identity(oid)') AND pg_get_functiondef(p.oid) IS DISTINCT FROM s.definition,'owner_mismatch',p.proowner::regrole::text IS DISTINCT FROM s.owner_name,'acl_mismatch',COALESCE(p.proacl::text,'') IS DISTINCT FROM s.acl))::text FROM zasp_temporal72.predecessor_functions s LEFT JOIN pg_proc p ON p.oid=to_regprocedure(s.signature) WHERE p.oid IS NULL OR (s.signature NOT IN('zasp_production_runtime_precision_live_fingerprint()','zasp_execution_claim_jobs(text,text,integer,integer)','zasp_execution_live_fingerprint()','zasp_discovery_schedule_replay_function_identity(oid)') AND pg_get_functiondef(p.oid) IS DISTINCT FROM s.definition) OR p.proowner::regrole::text IS DISTINCT FROM s.owner_name OR COALESCE(p.proacl::text,'') IS DISTINCT FROM s.acl),'[]')`, args[0], args[1], migrations.ProductionTemporalLegacyTests().Checksum(), migrations.TemporalLegacyTestsFingerprint()).Scan(&prior, &count, &registration, &roles, &catalog, &fingerprint, &mismatches)
			tx.t.Logf("same-transaction72 prior71=%t registration_count=%d registration_match=%t roles=%t catalog_match=%t live_catalog=%s predecessor_mismatches=%s diagnostic_error=%v", prior, count, registration, roles, catalog, fingerprint, mismatches, err)
		}
	}
	return r
}

func policyTemporalAncestry(t *testing.T, ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, stage string) {
	t.Helper()
	var result string
	err := db.QueryRow(ctx, `SELECT jsonb_build_object('ready61',public.zasp_sa_multistep_readiness($1,$2),'scope67',zasp_temporal67.scope_authority_ready(),'base67',zasp_temporal67.base_ready(),'base67_fingerprint',zasp_temporal67.base_fingerprint(),'ready68',zasp_temporal68.current_ready(),'fingerprint68',zasp_temporal68.fingerprint(),'ready72',zasp_temporal72.ready($3,$4),'fingerprint72',zasp_temporal72.fingerprint(),'domain72',zasp_temporal72.domain_catalog(),'ready78',zasp_temporal78.current_ready())::text`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), migrations.ProductionTemporalDiscovery().Checksum(), migrations.TemporalDiscoveryFingerprint()).Scan(&result)
	t.Logf("temporal ancestry stage=%s guards=%s diagnostic_error=%v", stage, result, err)
}

type policyLineageRow struct {
	row      pgx.Row
	q        string
	t        *testing.T
	onFalse  func()
	onResult func()
}

func (r *policyLineageRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	if err == nil && r.onResult != nil {
		r.onResult()
	}
	if err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) {
			r.t.Logf("raw migration query sha256=%x SQLSTATE=%s", sha256.Sum256([]byte(r.q)), p.Code)
		}
	}
	if len(dest) == 1 {
		if value, ok := dest[0].(*bool); ok && err == nil && !*value {
			r.t.Logf("false migration predicate=%s", r.q)
			if r.onFalse != nil {
				r.onFalse()
			}
		}
	}
	return err
}

// Retains the diagnostic identity comparison with both corrected profiles.
func TestTemporalPolicyResponseCatalogProfilesPostgres(t *testing.T) {
	profiles := map[string]map[string]string{}
	for _, profile := range []string{"clean60-zasp_test", "registered61-zasp_e2e"} {
		t.Run(profile, func(t *testing.T) {
			login := "zasp_test"
			if profile == "registered61-zasp_e2e" {
				login = "zasp_e2e"
			}
			multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, _ *pgx.Conn, o, w, e, testID, actor string) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Minute)
				defer cancel()
				var actual string
				if err := owner.QueryRow(ctx, `SELECT session_user`).Scan(&actual); err != nil || actual != login {
					t.Fatal("profile login", actual, err)
				}
				t.Logf("profile=%s session_user=%s", profile, actual)
				db := &policyLineageDatabase{connection: owner, t: t, capture72: func(ctx context.Context, tx pgx.Tx) {
					var fingerprint string
					var ready bool
					if err := tx.QueryRow(ctx, `SELECT zasp_temporal72.fingerprint(),zasp_temporal72.ready($1,$2)`, migrations.ProductionTemporalDiscovery().Checksum(), migrations.TemporalDiscoveryFingerprint()).Scan(&fingerprint, &ready); err != nil {
						t.Fatal(err)
					}
					t.Logf("profile=%s live72=%s ready72=%t", profile, fingerprint, ready)
					if fingerprint != migrations.TemporalDiscoveryFingerprint() || !ready {
						t.Fatal("supported control does not match accepted72 pin")
					}
					profiles[profile] = policyCatalogIdentityRows(t, ctx, tx)
				}}
				runner, err := migrations.NewRunner(db)
				if err != nil {
					t.Fatal(err)
				}
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
					if err := up(ctx); err != nil {
						t.Fatal("control prerequisites", err)
					}
				}
				if login == "zasp_e2e" {
					if err := runner.UpProductionSecurityAgentMultistep(ctx); err != nil {
						t.Fatal("canonical61", err)
					}
				}
				if _, err := owner.Exec(ctx, `CREATE ROLE policy81_scheduler LOGIN INHERIT;CREATE ROLE policy81_risk LOGIN INHERIT;CREATE ROLE policy81_graph LOGIN INHERIT;CREATE ROLE policy81_search LOGIN INHERIT;SELECT zasp_execution_register_principals(session_user,'policy81_scheduler','security_agent_v33_discovery_worker_login','policy81_risk','policy81_graph','policy81_search')`); err != nil {
					t.Fatal(err)
				}
				for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests} {
					if err := up(ctx); err != nil {
						t.Fatal("profile predecessor", err)
					}
				}
				err = runner.UpProductionTemporalDiscovery(ctx)
				if err != nil {
					t.Fatal("supported72 install", err)
				}
			}, func(t *testing.T) string { return startDisposablePostgresAs(t, login) })
		})
		if t.Failed() {
			return
		}
	}
	control, candidate := profiles["clean60-zasp_test"], profiles["registered61-zasp_e2e"]
	if len(control) == 0 || len(candidate) == 0 {
		t.Fatal("profile capture missing")
	}
	keys := map[string]bool{}
	for k := range control {
		keys[k] = true
	}
	for k := range candidate {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	differences := 0
	for _, k := range ordered {
		if control[k] != candidate[k] {
			differences++
			t.Logf("catalog_difference identity=%s supported=%s canonical=%s", k, control[k], candidate[k])
		}
	}
	t.Logf("identity comparison complete supported_rows=%d canonical_rows=%d changed_rows=%d; both72 profiles ready", len(control), len(candidate), differences)
	if differences == 0 {
		t.Fatal("different catalog hashes without captured identity difference")
	}
}

func policyCatalogIdentityRows(t *testing.T, ctx context.Context, tx pgx.Tx) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, fn := range []string{"zasp_temporal72.fingerprint()", "zasp_temporal72.domain_catalog()", "public.zasp_inventory_live_fingerprint()"} {
		var source string
		if err := tx.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid=$1::regprocedure`, fn).Scan(&source); err != nil {
			t.Fatal(err)
		}
		at := strings.LastIndex(source, ") SELECT ")
		if at < 0 {
			t.Fatal("catalog CTE shape changed", fn)
		}
		if fn == "public.zasp_inventory_live_fingerprint()" {
			rows, err := tx.Query(ctx, source[:at+1]+` SELECT kind,identity,definition FROM objects ORDER BY kind,identity,definition`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var kind, id string
				var value []byte
				if err := rows.Scan(&kind, &id, &value); err != nil {
					t.Fatal(err)
				}
				out[fn+"/"+kind+"/"+id] = fmt.Sprintf("sha256:%x", sha256.Sum256(value))
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		rows, err := tx.Query(ctx, source[:at+1]+` SELECT value FROM identities ORDER BY value`)
		if err != nil {
			t.Fatal(err)
		}
		groups := map[string][]string{}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(value, "|")
			n := 2
			switch parts[0] {
			case "function", "constraint", "policy", "trigger":
				n = 3
			case "column":
				n = 4
			case "foreign-key-trigger":
				n = 7
			case "domain-catalog", "inventory-catalog", "precision-handoff":
				n = 1
			}
			if n > len(parts) {
				n = len(parts)
			}
			key := strings.Join(parts[:n], "|")
			groups[key] = append(groups[key], fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		for key, values := range groups {
			sort.Strings(values)
			out[fn+"/"+key] = strings.Join(values, ",")
		}
	}
	// Attribute function deltas with static identities, owners, ACLs and hashes.
	rows, err := tx.Query(ctx, `SELECT p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex') FROM pg_proc p WHERE p.pronamespace='public'::regnamespace OR p.pronamespace='zasp_temporal72'::regnamespace ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, owner, acl, body string
		if err := rows.Scan(&id, &owner, &acl, &body); err != nil {
			t.Fatal(err)
		}
		value, _ := json.Marshal(map[string]string{"owner": owner, "acl": acl, "body_sha256": body})
		out["function-metadata/"+id] = string(value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTemporalPolicyResponseOwnerCompatibilityPostgres(t *testing.T) {
	for _, login := range []string{"zasp_test", "zasp_e2e"} {
		t.Run(login, func(t *testing.T) {
			multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Minute)
				defer cancel()
				var actual string
				if err := owner.QueryRow(ctx, `SELECT session_user`).Scan(&actual); err != nil || actual != login {
					t.Fatal(actual, err)
				}
				t.Logf("owner profile session_user=%s", actual)
				const originals = `SELECT jsonb_agg(jsonb_build_array(oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'')) ORDER BY oid::regprocedure::text)::text FROM pg_proc WHERE oid IN('public.zasp_valid_product_id(text)'::regprocedure,'public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)'::regprocedure)`
				var before string
				runner, err := migrations.NewRunner(&policyLineageDatabase{connection: owner, t: t, capture72: func(ctx context.Context, tx pgx.Tx) {
					var fp string
					if err := tx.QueryRow(ctx, `SELECT zasp_temporal72.fingerprint()`).Scan(&fp); err != nil {
						t.Fatal(err)
					}
					t.Logf("candidate72=%s", fp)
				}})
				if err != nil {
					t.Fatal(err)
				}
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if login == "zasp_e2e" {
					if err := runner.UpProductionSecurityAgentMultistep(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := owner.Exec(ctx, `CREATE ROLE policy81_scheduler LOGIN INHERIT;CREATE ROLE policy81_risk LOGIN INHERIT;CREATE ROLE policy81_graph LOGIN INHERIT;CREATE ROLE policy81_search LOGIN INHERIT;SELECT zasp_execution_register_principals(session_user,'policy81_scheduler','security_agent_v33_discovery_worker_login','policy81_risk','policy81_graph','policy81_search')`); err != nil {
					t.Fatal(err)
				}
				for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests} {
					if err := up(ctx); err != nil {
						t.Fatal("owner-compatible72 installation", err)
					}
				}
				if err := owner.QueryRow(ctx, originals).Scan(&before); err != nil {
					t.Fatal(err)
				}
				if err := runner.UpProductionTemporalDiscovery(ctx); err != nil {
					t.Fatal("owner-compatible72 installation", err)
				}
				var after string
				if err := owner.QueryRow(ctx, originals).Scan(&after); err != nil || after != before {
					t.Fatal("helper definition/owner/effective ACL changed", err)
				}
				var saved bool
				if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(s.definition=pg_get_functiondef(p.oid) AND s.owner_name=p.proowner::regrole::text AND s.acl=COALESCE(p.proacl::text,'')) FROM zasp_temporal72.predecessor_functions s JOIN pg_proc p ON p.oid=to_regprocedure(s.signature) WHERE s.signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)')`).Scan(&saved); err != nil || !saved {
					t.Fatal("raw saved helper identity changed", err)
				}
				if err := runner.UpProductionTemporalDiscovery(ctx); err != nil {
					t.Fatal("exact current reinstall", err)
				}
				config := owner.Config().Copy()
				config.User = "security_agent_v33_discovery_api_login"
				discovery, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer discovery.Close(context.Background())
				var ready bool
				if err := discovery.QueryRow(ctx, `SELECT session_user,zasp_temporal72.principal_ready('zasp_discovery_api')`).Scan(&actual, &ready); err != nil || actual != config.User || !ready {
					t.Fatal("registered discovery API", actual, ready, err)
				}
				var denied *pgconn.PgError
				if err := api.QueryRow(ctx, `SELECT zasp_temporal72.current_ready()`).Scan(&ready); !errors.As(err, &denied) || denied.Code != "42501" {
					t.Fatal("security-agent API borrowed discovery authority", err)
				}
				for _, mutation := range []struct{ name, sql string }{
					{"source", `CREATE OR REPLACE FUNCTION public.zasp_valid_product_id(value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT false'`},
					{"security", `ALTER FUNCTION public.zasp_valid_product_id(text) SECURITY DEFINER`},
					{"owner", `CREATE ROLE policy81_other NOLOGIN;ALTER FUNCTION public.zasp_valid_product_id(text) OWNER TO policy81_other`},
					{"extra_acl", `GRANT EXECUTE ON FUNCTION public.zasp_workflow_replay(text,text,text,text,text,text,jsonb) TO security_agent_v33_worker_login`},
					{"grant_option", `GRANT EXECUTE ON FUNCTION public.zasp_workflow_replay(text,text,text,text,text,text,jsonb) TO zasp_discovery_api WITH GRANT OPTION`},
					{"saved_owner", `ALTER TABLE zasp_temporal72.predecessor_functions DISABLE TRIGGER immutable;UPDATE zasp_temporal72.predecessor_functions SET owner_name='zasp_discovery_authority' WHERE signature='zasp_valid_product_id(text)';ALTER TABLE zasp_temporal72.predecessor_functions ENABLE TRIGGER immutable`},
					{"saved_acl", `ALTER TABLE zasp_temporal72.predecessor_functions DISABLE TRIGGER immutable;UPDATE zasp_temporal72.predecessor_functions SET acl='{}' WHERE signature='zasp_valid_product_id(text)';ALTER TABLE zasp_temporal72.predecessor_functions ENABLE TRIGGER immutable`},
					{"same_wrong_owner_saved_live", `CREATE ROLE policy81_other NOLOGIN;ALTER FUNCTION public.zasp_valid_product_id(text) OWNER TO policy81_other;ALTER TABLE zasp_temporal72.predecessor_functions DISABLE TRIGGER immutable;UPDATE zasp_temporal72.predecessor_functions SET owner_name='policy81_other' WHERE signature='zasp_valid_product_id(text)';ALTER TABLE zasp_temporal72.predecessor_functions ENABLE TRIGGER immutable`},
					{"unrelated", `ALTER FUNCTION public.zasp_discovery_canonical_id(text,text,text,text,text) VOLATILE`},
				} {
					t.Run(mutation.name, func(t *testing.T) {
						tx, err := owner.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer tx.Rollback(context.Background())
						if _, err := tx.Exec(ctx, mutation.sql); err != nil {
							t.Fatal("owned tamper setup", err)
						}
						var value bool
						if err := tx.QueryRow(ctx, `SELECT zasp_temporal72.ready($1,$2)`, migrations.ProductionTemporalDiscovery().Checksum(), migrations.TemporalDiscoveryFingerprint()).Scan(&value); err != nil || value {
							t.Fatalf("tampered72 readiness=%t error=%v", value, err)
						}
					})
				}
				const oldChecksum = "3e20d5ea41a47ae8e03540ecd08264748faea58fedf78544cc5f334e23e19d8c"
				// A disposable old registration is intentionally not upgraded in place.
				if _, err := owner.Exec(ctx, `ALTER TABLE zasp_temporal72.registration DISABLE TRIGGER immutable;UPDATE zasp_temporal72.registration SET checksum=$1;ALTER TABLE zasp_temporal72.registration ENABLE TRIGGER immutable`, pgx.QueryExecModeSimpleProtocol, oldChecksum); err != nil {
					t.Fatal(err)
				}
				if err := runner.UpProductionTemporalDiscovery(ctx); !errors.Is(err, migrations.ErrInvalidState) {
					t.Fatal("old registration did not refuse reinstall", err)
				}
				var retained string
				if err := owner.QueryRow(ctx, `SELECT checksum FROM zasp_temporal72.registration`).Scan(&retained); err != nil || retained != oldChecksum {
					t.Fatal("old registration rewritten", err)
				}
			}, func(t *testing.T) string { return startDisposablePostgresAs(t, login) })
		})
	}
}
