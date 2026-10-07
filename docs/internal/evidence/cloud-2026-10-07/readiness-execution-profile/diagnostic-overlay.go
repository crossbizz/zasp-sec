package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// This is installed native module acceptance, not the separate full runtime
// projection proof. The sensor credential uses the real registered issuer.
func TestP7CurrentRuntimeModuleFences(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		const sensorID = "pid_f0800000-0000-4000-8000-000000009001"
		const tokenID = "pid_f0800000-0000-4000-8000-000000009002"
		if _, err := owner.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'current-runtime-native','otlp')`, o, w, e, sensorID); err != nil {
			t.Fatal(err)
		}
		wire, locatorHash, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, 0xa4)
		if _, err := owner.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, o, w, e, sensorID, tokenID, locatorHash, salt, hash); err != nil {
			t.Fatal(err)
		}
		credential, err := sensor.ParseTokenCredential(wire)
		if err != nil {
			t.Fatal(err)
		}
		defer credential.Destroy()
		const preciseSensor = "pid_f0800000-0000-4000-8000-000000009003"
		const preciseToken = "pid_f0800000-0000-4000-8000-000000009004"
		if _, err := owner.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'current-runtime-precise','tetragon')`, o, w, e, preciseSensor); err != nil {
			t.Fatal(err)
		}
		preciseWire, preciseLocator, preciseSalt, preciseHash := envelopeLifecycleCredential(t, preciseToken, 1, 0xa5)
		if _, err := owner.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, o, w, e, preciseSensor, preciseToken, preciseLocator, preciseSalt, preciseHash); err != nil {
			t.Fatal(err)
		}
		installAutomaticSourceFixture(t, ctx, owner)
		runner, err := migrations.NewRunner(&runtimeObservedMigrationDatabase{workerObservedMigrationDatabase{integrationMigrationDatabase{connection: owner}, t}})
		if err != nil {
			t.Fatal(err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("current module installation", err)
			}
		}
		var current, historical, wrongRole bool
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_runtime.current_ready(),zasp_discovery_schedule_replay_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=60),(SELECT value FROM zasp_schema_metadata WHERE key='production_discovery_schedule_replay_fingerprint')),zasp_authorization80_runtime.ready($1,'zasp_runtime_ingest')`, migrations.AuthorizationRuntimeProfileChecksum()).Scan(&current, &historical, &wrongRole); err != nil || !current || historical || wrongRole {
			t.Fatal("current-only installed authority", current, historical, wrongRole, err)
		}
		var principal string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_runtime_ingest'`).Scan(&principal); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = principal
		ingest, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer ingest.Close(context.Background())
		repository, err := runtimeevent.NewPostgresCurrentRuntimeIngestRepository(runtimeProfileDiagnosticDatabase{connection: ingest, t: t})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repository.Authenticate(ctx, credential); err != nil {
			t.Fatal("registered current ingest authentication", err)
		}
		t.Run("ingest application pin and own login", func(t *testing.T) {
			for _, pin := range []any{migrations.AuthorizationRuntimeProfileChecksum(), "wrong", "", nil} {
				var matched bool
				if err := ingest.QueryRow(ctx, `SELECT zasp_authorization80_runtime.ingest_profile_identity($1)`, pin).Scan(&matched); err != nil || matched != (pin == migrations.AuthorizationRuntimeProfileChecksum()) {
					t.Fatal("compiled ingest pin", matched, err)
				}
			}
			var matched bool
			if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_runtime.ingest_profile_identity($1)`, migrations.AuthorizationRuntimeProfileChecksum()).Scan(&matched); err != nil || matched {
				t.Fatal("identity accepted wrong login", matched, err)
			}
			for _, mutation := range []string{
				`DELETE FROM zasp_authorization80_runtime.registration`,
				`UPDATE zasp_authorization80_runtime.registration SET checksum='wrong'`,
			} {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer tx.Rollback(ctx)
					if _, err := tx.Exec(ctx, `ALTER TABLE zasp_authorization80_runtime.registration DISABLE TRIGGER immutable;`+mutation); err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{principal}.Sanitize()); err != nil {
						t.Fatal(err)
					}
					for _, pin := range []string{migrations.AuthorizationRuntimeProfileChecksum(), "wrong"} {
						if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_runtime.ingest_profile_identity($1)`, pin).Scan(&matched); err != nil || matched {
							t.Fatal("missing or replaced registration accepted", matched, err)
						}
					}
				}()
			}
		})
		t.Run("readiness cost and installed catalog", func(t *testing.T) {
			for _, query := range []string{
				`SELECT zasp_temporal78.current_ready()`,
				`SELECT zasp_authorization80.ready($1)`,
				`SELECT zasp_authorization80_worker.catalog_ready()`,
				`SELECT zasp_authorization80_temporal.catalog_ready()`,
				`SELECT zasp_authorization80.runtime_identity_ready()`,
			} {
				for attempt := 0; attempt < 2; attempt++ {
					started := time.Now()
					var ready bool
					var args []any
					if strings.Contains(query, "$1") {
						args = []any{migrations.ProductionAuthorizationEnforcement().Checksum()}
					}
					if err := owner.QueryRow(ctx, query, args...).Scan(&ready); err != nil || !ready {
						t.Fatal("diagnostic readiness", query, ready, err)
					}
					t.Logf("readiness timing attempt=%d elapsed=%s query=%s", attempt, time.Since(started).Round(time.Millisecond), query)
				}
			}
			for _, signature := range []string{
				"public.zasp_runtime_authenticate_gateway_enrollment(bytea,bytea,text)",
				"public.zasp_runtime_gateway_advance_replay(text,bigint,bigint,bytea)",
				"public.zasp_runtime_gateway_record_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,timestamptz)",
				"public.zasp_runtime_gateway_record_event_v27(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamptz)",
				"public.zasp_runtime_data_plane_live_fingerprint()",
				"public.zasp_recovery_execution_live_fingerprint()",
			} {
				var definition, ownerName, acl string
				if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid=$1::regprocedure`, signature).Scan(&definition, &ownerName, &acl); err != nil {
					t.Fatal("catalog-only export", signature, err)
				}
				t.Logf("installed catalog signature=%s owner=%s acl=%s\n%s", signature, ownerName, acl, definition)
			}
		})
		t.Run("direct wrong login", func(t *testing.T) {
			locator, secret, err := credential.Parts()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(locator)
			defer clear(secret)
			var result json.RawMessage
			err = owner.QueryRow(ctx, `SELECT zasp_authorization80_runtime.runtime_authenticate_sensor($1,$2,'event-ingest')`, locator, secret).Scan(&result)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Error("private ingest accepted wrong registered authority", err)
			}
		})
		t.Run("readiness implication and private bodies", func(t *testing.T) {
			compare := func(t *testing.T, db interface {
				QueryRow(context.Context, string, ...any) pgx.Row
			}, want bool) {
				t.Helper()
				var original, candidate bool
				err := db.QueryRow(ctx, `SELECT COALESCE(zasp_temporal78.current_ready() AND zasp_authorization80.ready($1),false),COALESCE(zasp_temporal78.current_ready() AND zasp_authorization80.runtime_identity_ready(),false)`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&original, &candidate)
				if err != nil || original != want || candidate != want {
					t.Fatal("same-call readiness implication", original, candidate, want, err)
				}
			}
			compare(t, owner, true)
			for name, drift := range map[string]string{
				"80 predicate":      `CREATE OR REPLACE FUNCTION zasp_authorization80.ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT false $$`,
				"profile dispatch":  `CREATE OR REPLACE FUNCTION zasp_authorization80.runtime_profile_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT false $$`,
				"identity dispatch": `CREATE OR REPLACE FUNCTION zasp_authorization80.runtime_identity_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT false $$`,
				"61 predicate":      `CREATE OR REPLACE FUNCTION public.zasp_sa_multistep_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT false $$`,
				"68 predicate":      `CREATE OR REPLACE FUNCTION zasp_temporal68.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT false $$`,
				"80 ACL":            `GRANT EXECUTE ON FUNCTION zasp_authorization80.ready(text) TO zasp_runtime_ingest`,
				"profile ACL":       `GRANT EXECUTE ON FUNCTION zasp_authorization80.runtime_profile_ready() TO zasp_runtime_ingest`,
				"61 ACL":            `GRANT EXECUTE ON FUNCTION public.zasp_sa_multistep_readiness(text,text) TO zasp_runtime_ingest`,
			} {
				t.Run(name, func(t *testing.T) {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					if _, err := tx.Exec(ctx, drift); err != nil {
						t.Fatal(err)
					}
					compare(t, tx, false)
				})
			}
			t.Run("inner execution denied", func(t *testing.T) {
				for _, name := range []string{"inner_authenticate_sensor", "inner_reserve_batch_v15", "inner_finalize_batch_v15", "inner_commit_reserved_batch", "inner_reconcile_batch"} {
					var count, arguments int
					var closed bool
					err := owner.QueryRow(ctx, `SELECT count(*),COALESCE(max(pronargs),0),COALESCE(bool_and(p.proowner='zasp_discovery_authority'::regrole AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}' AND NOT has_function_privilege($1,p.oid,'EXECUTE')),false) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_runtime'::regnamespace AND p.proname=$2`, principal, name).Scan(&count, &arguments, &closed)
					if err != nil || count != 1 || !closed {
						t.Error("missing or executable inner body", name, count, closed, err)
						continue
					}
					var result json.RawMessage
					err = ingest.QueryRow(ctx, "SELECT zasp_authorization80_runtime."+name+"("+strings.TrimSuffix(strings.Repeat("NULL,", arguments), ",")+")").Scan(&result)
					var native *pgconn.PgError
					if !errors.As(err, &native) || native.Code != "42501" || !strings.Contains(native.Message, "permission denied for function") {
						t.Error("direct service call entered owner-only body", name, err)
					}
				}
			})
			t.Run("exact inner source delta", func(t *testing.T) {
				for original, inner := range map[string]string{
					"runtime_authenticate_sensor":         "inner_authenticate_sensor",
					"runtime_reserve_batch_v15_internal":  "inner_reserve_batch_v15",
					"runtime_finalize_batch_v15_internal": "inner_finalize_batch_v15",
					"runtime_commit_reserved_batch":       "inner_commit_reserved_batch",
					"runtime_reconcile_batch":             "inner_reconcile_batch",
				} {
					var source, actual string
					if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef(a.oid),pg_get_functiondef(b.oid) FROM pg_proc a CROSS JOIN pg_proc b WHERE a.pronamespace='zasp_authorization80_runtime'::regnamespace AND b.pronamespace=a.pronamespace AND a.proname=$1 AND b.proname=$2`, original, inner).Scan(&source, &actual); err != nil {
						t.Fatal(err)
					}
					expected := strings.Replace(source, "FUNCTION zasp_authorization80_runtime."+original+"(", "FUNCTION zasp_authorization80_runtime."+inner+"(", 1)
					expected = strings.ReplaceAll(expected, "PERFORM zasp_authorization80_runtime.require_current();", "")
					if original == "runtime_reserve_batch_v15_internal" || original == "runtime_finalize_batch_v15_internal" {
						expected = strings.Replace(expected, "zasp_authorization80_runtime.runtime_authenticate_sensor(", "zasp_authorization80_runtime.inner_authenticate_sensor(", 1)
					}
					if original == "runtime_finalize_batch_v15_internal" || original == "runtime_reconcile_batch" {
						expected = strings.Replace(expected, "zasp_authorization80_runtime.runtime_commit_reserved_batch(", "zasp_authorization80_runtime.inner_commit_reserved_batch(", 1)
					}
					if actual != expected {
						t.Error("inner body changed native validation or locks", inner)
					}
				}
			})
		})
		t.Run("installed return fences", func(t *testing.T) {
			rows, err := owner.Query(ctx, `SELECT p.proname,p.prosrc FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.pronamespace='zasp_authorization80_runtime'::regnamespace AND l.lanname='plpgsql' AND p.proname LIKE 'runtime_%' ORDER BY p.proname`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			returns := regexp.MustCompile(`\bRETURN\b`)
			for rows.Next() {
				var name, body string
				if err := rows.Scan(&name, &body); err != nil {
					t.Fatal(err)
				}
				if name == "runtime_precision_transport_ready" || name == "runtime_precision_reconciliation_ready" {
					if strings.Count(body, "zasp_authorization80_runtime.source_ready(51,") != 1 || len(returns.FindAllStringIndex(body, -1)) != 0 {
						t.Error("owner-only source gate changed", name)
					}
					continue
				}
				if strings.Count(body, "PERFORM zasp_authorization80_runtime.require_current();") < 1+len(returns.FindAllStringIndex(body, -1)) {
					t.Error("copied entry or compact return lacks current fence", name)
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("independent live catalog", func(t *testing.T) {
			for _, drift := range []string{
				`CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT true $$`,
				`CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT fingerprint FROM zasp_authorization80_runtime.registration $$`,
				`CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.require_current() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN RETURN; END $$`,
				`ALTER TABLE zasp_authorization80_runtime.predecessor_functions DISABLE TRIGGER immutable`,
			} {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, drift); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				var current, worker, temporal bool
				err = tx.QueryRow(ctx, `SELECT zasp_authorization80_runtime.current_ready(),zasp_authorization80_worker.catalog_ready(),zasp_temporal78.current_ready()`).Scan(&current, &worker, &temporal)
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					t.Fatal(rollbackErr)
				}
				if err != nil || current || worker || temporal {
					t.Fatal("changed live runtime catalog retained authority", current, worker, temporal, err)
				}
			}
		})
		t.Run("semantic HTTP intake", func(t *testing.T) {
			assertCurrentRuntimeSemanticIntake(t, ctx, owner, newCurrentRuntimeFixtureRepository(t, ctx, owner, principal), wire, sensorID)
		})
		t.Run("after wait fences", func(t *testing.T) {
			for _, mutation := range []string{"catalog", "credential"} {
				t.Run(mutation, func(t *testing.T) {
					assertCurrentRuntimeAfterWait(t, ctx, owner, principal, credential, o, w, e, sensorID, mutation)
				})
			}
		})
		t.Run("precise HTTP recovery", func(t *testing.T) {
			assertCurrentRuntimePreciseRecovery(t, ctx, owner, newCurrentRuntimeFixtureRepository(t, ctx, owner, principal), preciseWire, preciseSensor, automaticSourceIdentity(t, o, w, e, o).Scope)
		})
		t.Run("stage statement fences", func(t *testing.T) {
			assertCurrentRuntimeStageStatement(t, ctx, owner, principal, credential, o, w, e)
		})
	})
}

func assertCurrentRuntimeAfterWait(t *testing.T, parent context.Context, owner *pgx.Conn, principal string, credential *sensor.TokenCredential, o, w, e, sensorID, mutation string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	config := owner.Config().Copy()
	config.User = principal
	caller, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close(context.Background())
	var originalGate string
	if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_authorization80_runtime.require_current()'::regprocedure)`).Scan(&originalGate); err != nil {
		t.Fatal(err)
	}
	blocker, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM zasp_sensors WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4) FOR UPDATE`, o, w, e, sensorID); err != nil {
		t.Fatal(err)
	}
	locator, secret, err := credential.Parts()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(locator)
	defer clear(secret)
	done := make(chan error, 1)
	joined := false
	go func() {
		var result json.RawMessage
		err := caller.QueryRow(ctx, `SELECT zasp_authorization80_runtime.runtime_sensor_heartbeat($1,$2,'event-ingest',991,'healthy','["otlp"]'::jsonb,'native-test',false,1,0)`, locator, secret).Scan(&result)
		done <- err
	}()
	defer func() {
		cancel()
		_ = blocker.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	for {
		var waiting bool
		if err := blocker.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2))`, owner.PgConn().PID(), caller.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			joined = true
			t.Fatal("operation returned before held sensor lock", err)
		case <-ctx.Done():
			t.Fatal("operation never reached sensor lock", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if mutation == "catalog" {
		_, err = blocker.Exec(ctx, `CREATE OR REPLACE FUNCTION zasp_authorization80_runtime.require_current() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN IF NOT zasp_authorization80_runtime.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='changed catalog';END IF;END $$`)
	} else {
		_, err = blocker.Exec(ctx, `UPDATE zasp_sensors SET version=version+1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, sensorID)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	if mutation == "catalog" {
		if _, restoreErr := owner.Exec(parent, originalGate); restoreErr != nil {
			t.Fatal(restoreErr)
		}
	} else {
		if _, restoreErr := owner.Exec(parent, `UPDATE zasp_sensors SET version=version-1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, sensorID); restoreErr != nil {
			t.Fatal(restoreErr)
		}
	}
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != map[string]string{"catalog": "55000", "credential": "28000"}[mutation] {
		t.Error("post-wait mutation retained authority", mutation, err)
	}
	var rows int
	if err := owner.QueryRow(parent, `SELECT count(*) FROM zasp_sensor_heartbeats WHERE (organization_id,workspace_id,environment_id,sensor_id,sequence)=($1,$2,$3,$4,991)`, o, w, e, sensorID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("post-wait heartbeat was durable", rows, err)
	}
}

func newCurrentRuntimeFixtureRepository(t *testing.T, ctx context.Context, owner *pgx.Conn, principal string) *runtimeevent.PostgresProductionIngestRepository {
	t.Helper()
	config := owner.Config().Copy()
	config.User = principal
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(context.Background()) })
	repository, err := runtimeevent.NewPostgresCurrentRuntimeIngestRepository(runtimeProfileDiagnosticDatabase{connection: connection, t: t})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

type runtimeProfileDiagnosticDatabase struct {
	connection *pgx.Conn
	t          *testing.T
}

type runtimeObservedMigrationDatabase struct {
	workerObservedMigrationDatabase
}

func (d *runtimeObservedMigrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &runtimeObservedMigrationTransaction{workerObservedMigrationTransaction: workerObservedMigrationTransaction{integrationMigrationTransaction{transaction: tx}, d.t}}, nil
}

type runtimeObservedMigrationTransaction struct {
	workerObservedMigrationTransaction
	priorFingerprints map[string]string
}

func (tx *runtimeObservedMigrationTransaction) Exec(ctx context.Context, query string, args ...any) error {
	if strings.Contains(query, "CREATE SCHEMA zasp_authorization80_worker") {
		rows, err := tx.transaction.Query(ctx, `SELECT n.nspname,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.pronargs=0 AND p.prorettype='text'::regtype AND (n.nspname='public' AND p.proname LIKE 'zasp_%live_fingerprint' OR n.nspname='zasp_temporal67' AND p.proname='base_fingerprint') ORDER BY n.nspname,p.proname`)
		if err != nil {
			return err
		}
		var names []string
		for rows.Next() {
			var schema, name string
			if err := rows.Scan(&schema, &name); err != nil {
				rows.Close()
				return err
			}
			names = append(names, pgx.Identifier{schema, name}.Sanitize()+"()")
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		tx.priorFingerprints = make(map[string]string, len(names))
		for _, name := range names {
			var fingerprint string
			if err := tx.transaction.QueryRow(ctx, "SELECT "+name).Scan(&fingerprint); err != nil {
				return err
			}
			tx.priorFingerprints[name] = fingerprint
		}
		tx.t.Logf("captured %d pre-worker fingerprint outputs in installation transaction", len(names))
	}
	return tx.workerObservedMigrationTransaction.Exec(ctx, query, args...)
}

func (tx *runtimeObservedMigrationTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	return runtimeObservedMigrationRow{tx: tx, ctx: ctx, query: q, row: tx.transaction.QueryRow(ctx, q, args...)}
}

type runtimeObservedMigrationRow struct {
	tx    *runtimeObservedMigrationTransaction
	ctx   context.Context
	query string
	row   pgx.Row
}

func (r runtimeObservedMigrationRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	if err != nil || len(dest) != 1 {
		return err
	}
	value, ok := dest[0].(*bool)
	if !ok || *value || !strings.Contains(r.query, "AND zasp_authorization80_temporal.ready()") {
		return nil
	}
	r.tx.t.Log("composed final check refused", r.query)
	for name, before := range r.tx.priorFingerprints {
		var after string
		err := r.tx.transaction.QueryRow(r.ctx, "SELECT "+name).Scan(&after)
		if err != nil {
			r.tx.t.Logf("retained fingerprint comparison failed function=%s error=%v", name, err)
			break
		}
		if before != after {
			r.tx.t.Logf("retained fingerprint changed function=%s before=%s after=%s", name, before, after)
		}
	}
	queries := []string{`SELECT zasp_authorization80_worker.catalog_ready()`, `SELECT zasp_authorization80_runtime.catalog_ready()`, `SELECT zasp_authorization80_temporal.catalog_ready()`, `SELECT zasp_authorization80.runtime_identity_ready()`, `SELECT zasp_temporal68.base_ready()`}
	for _, version := range []string{"68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78"} {
		queries = append(queries, "SELECT zasp_temporal"+version+".fingerprint() IS NOT DISTINCT FROM (SELECT fingerprint FROM zasp_temporal"+version+".registration)")
	}
	for _, version := range []string{"68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78"} {
		queries = append(queries, "SELECT zasp_temporal"+version+".ready((SELECT checksum FROM zasp_temporal"+version+".registration),(SELECT fingerprint FROM zasp_temporal"+version+".registration))")
	}
	for _, query := range queries {
		var ready bool
		err := r.tx.transaction.QueryRow(r.ctx, query).Scan(&ready)
		r.tx.t.Logf("composed component ready=%t error=%v query=%s", ready, err, query)
		if err != nil {
			break
		}
	}
	for _, signature := range []string{"zasp_temporal68.ready(text,text)", "zasp_temporal68.predecessor_ready(text,text)", "zasp_temporal78.ready(text,text)", "zasp_temporal78.predecessor_ready(text,text)"} {
		var definition string
		if err := r.tx.transaction.QueryRow(r.ctx, `SELECT pg_get_functiondef(to_regprocedure($1))`, signature).Scan(&definition); err != nil {
			r.tx.t.Logf("readiness definition unavailable signature=%s error=%v", signature, err)
			continue
		}
		r.tx.t.Logf("installed readiness definition signature=%s definition=%s", signature, definition)
	}
	return nil
}

func (d runtimeProfileDiagnosticDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	started := time.Now()
	var result json.RawMessage
	err := d.connection.QueryRow(ctx, query, args...).Scan(&result)
	d.t.Logf("current runtime operation elapsed=%s deadline=%t statement=%s", time.Since(started).Round(time.Millisecond), errors.Is(ctx.Err(), context.DeadlineExceeded), query)
	var native *pgconn.PgError
	if errors.As(err, &native) {
		d.t.Logf("current runtime SQLSTATE=%s statement=%s context=%s", native.Code, query, native.Where)
	}
	return result, err
}

// Diagnostic only: EXPLAIN executes each fixed product SELECT once. No SQL body,
// role, catalog, cache, or original suite context is changed.
func TestOwnedCurrent80ReadinessCostDiagnostic(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		const sensorID = "pid_f0800000-0000-4000-8000-000000009001"
		const tokenID = "pid_f0800000-0000-4000-8000-000000009002"
		if _, err := owner.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'current-runtime-native','otlp')`, o, w, e, sensorID); err != nil {
			t.Fatal(err)
		}
		wire, locatorHash, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, 0xa4)
		if _, err := owner.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, o, w, e, sensorID, tokenID, locatorHash, salt, hash); err != nil {
			t.Fatal(err)
		}
		credential, err := sensor.ParseTokenCredential(wire)
		if err != nil {
			t.Fatal(err)
		}
		defer credential.Destroy()
		const preciseSensor = "pid_f0800000-0000-4000-8000-000000009003"
		const preciseToken = "pid_f0800000-0000-4000-8000-000000009004"
		if _, err := owner.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'current-runtime-precise','tetragon')`, o, w, e, preciseSensor); err != nil {
			t.Fatal(err)
		}
		preciseWire, preciseLocator, preciseSalt, preciseHash := envelopeLifecycleCredential(t, preciseToken, 1, 0xa5)
		_ = preciseWire // retained seed fixture; this diagnostic performs no precise ingestion
		if _, err := owner.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, o, w, e, preciseSensor, preciseToken, preciseLocator, preciseSalt, preciseHash); err != nil {
			t.Fatal(err)
		}
		installAutomaticSourceFixture(t, ctx, owner)
		runner, err := migrations.NewRunner(&runtimeObservedMigrationDatabase{workerObservedMigrationDatabase{integrationMigrationDatabase{connection: owner}, t}})
		if err != nil {
			t.Fatal(err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("current module installation", err)
			}
		}

		cases := []struct {
			name, query string
			args        []any
		}{
			{"temporal78", "SELECT zasp_temporal78.current_ready()", nil},
			{"authorization80", "SELECT zasp_authorization80.ready($1)", []any{migrations.ProductionAuthorizationEnforcement().Checksum()}},
			{"same-call-implication", "SELECT COALESCE(zasp_temporal78.current_ready() AND zasp_authorization80.ready($1),false),COALESCE(zasp_temporal78.current_ready() AND zasp_authorization80.runtime_identity_ready(),false)", []any{migrations.ProductionAuthorizationEnforcement().Checksum()}},
		}
		for _, c := range cases {
			started := time.Now()
			var plan json.RawMessage
			if err := owner.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+c.query, c.args...).Scan(&plan); err != nil {
				t.Fatal(c.name, "diagnostic explain", err)
			}
			if !json.Valid(plan) {
				t.Fatal(c.name, "invalid explain JSON")
			}
			t.Logf("READINESS_COST %s elapsed=%s plan=%s", c.name, time.Since(started), plan)
		}
	})
}
