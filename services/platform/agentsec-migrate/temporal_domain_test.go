package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catch a missing production dispatch or an install that still depends on
// release61's fixture-specific owner name. The fixture owner is zasp_test.
func TestTemporalDomainShippedCommandPostgres(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained65_%t", retained), func(t *testing.T) { runTemporalDomainCommand(t, retained) })
	}
}

func TestTemporalDomainPrincipalBeforeDDLPostgres(t *testing.T) {
	f := newScheduleReplayFixture(t)
	if err := runReleaseMigration(f.ctx, f.registered, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	wrong := *f.registered
	wrong.registration.migration = f.registration.securityAgentAPI
	if err := runReleaseMigration(f.ctx, &wrong, []string{"up-temporal-domain"}); err == nil {
		t.Fatal("mismatched deployment principal reached domain DDL")
	}
	var untouched bool
	if err := f.owner.QueryRow(f.ctx, `SELECT to_regnamespace('zasp_temporal67') IS NULL AND (SELECT count(*) FROM zasp_schema_versions)=60`).Scan(&untouched); err != nil || !untouched {
		t.Fatal("principal refusal left migration state", untouched, err)
	}
}

// Removing the permanence binding must make both readiness and the shipped
// replay command accept these mutations. Each probe uses only the owned DB.
func TestTemporalDomainPersistencePostgres(t *testing.T) {
	f := newScheduleReplayFixture(t)
	if err := runReleaseMigration(f.ctx, f.registered, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	runDomainCLI(t, f, false)
	for _, table := range []string{"registration", "predecessor_functions"} {
		t.Run(table, func(t *testing.T) {
			statement := `ALTER TABLE zasp_temporal67.` + pgx.Identifier{table}.Sanitize()
			tx, err := f.owner.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			if _, err := tx.Exec(f.ctx, statement+` SET UNLOGGED`); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal67.ready($1,$2)`, migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalDomainFingerprint()).Scan(&ready); err != nil {
				t.Fatal(err)
			} else if ready {
				t.Errorf("readiness accepted unlogged %s", table)
			}
			// The subprocess must observe committed drift, not block behind this
			// transaction and mistake a lock timeout for a readiness refusal.
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := f.owner.Exec(f.ctx, statement+` SET LOGGED`); err != nil {
					t.Fatal("restore permanent authority", err)
				}
				if err := f.runner.UpProductionTemporalDomain(f.ctx); err != nil {
					t.Fatal("restored permanent authority not ready", err)
				}
			})
			runDomainCLI(t, f, true)
		})
	}
}

func runTemporalDomainCommand(t *testing.T, retained bool) {
	f := newScheduleReplayFixture(t)
	if err := runReleaseMigration(f.ctx, f.registered, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	if retained {
		if err := f.runner.UpProductionTemporalOutbox(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	failed := false
	broken, _ := migrations.NewRunner(&domainFailedRegistrationDB{migrationDatabase: &migrationDatabase{connection: f.owner}, hit: &failed})
	if err := broken.UpProductionTemporalDomain(f.ctx); err == nil || !failed {
		t.Fatal("final registration failure not exercised", failed, err)
	}
	var intact bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_schema_versions)=60 AND to_regnamespace('zasp_temporal67') IS NULL AND to_regnamespace('zasp_temporal66') IS NULL AND to_regnamespace('zasp_ordered_public62') IS NULL AND public.zasp_discovery_schedule_replay_readiness($1,$2)`, migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&intact); err != nil || !intact {
		t.Fatal("failed67 left partial authority", intact, err)
	}
	runDomainCLI(t, f, false)
	if err := runReleaseMigration(f.ctx, f.registered, []string{"up-temporal-domain"}); err != nil {
		t.Fatal("domain replay", err)
	}
	if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-temporal-domain"}); err != nil {
		t.Fatal("domain command registration", err)
	}
	var old, ready bool
	if err := f.owner.QueryRow(f.ctx, `SELECT public.zasp_sa_multistep_readiness($1,$2),zasp_temporal67.ready($3,$4)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalDomainFingerprint()).Scan(&old, &ready); err != nil || old || !ready {
		t.Fatal("old61 false/new67 true", old, ready, err)
	}
	for _, role := range []string{f.registration.securityAgentAPI, f.registration.securityAgentWorker} {
		config := f.owner.Config().Copy()
		config.User = role
		connection, err := pgx.ConnectConfig(f.ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRow(f.ctx, `SELECT zasp_temporal67.ready($1,$2)`, migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalDomainFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("real role readiness", role, ready, err)
		}
		for _, q := range []string{`UPDATE zasp_temporal67.registration SET predecessor='registered66'`, `SELECT zasp_temporal67.api_transition('x','x','{}')`, `INSERT INTO zasp_temporal66.admission_routes VALUES('x','x','x','temporal')`} {
			if _, err := connection.Exec(f.ctx, q); err == nil {
				t.Fatal("runtime authority escaped", role, q)
			}
		}
		connection.Close(f.ctx)
	}
	assertDomainDrift(t, f)
	if _, err := f.owner.Exec(f.ctx, `GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.lock_scope(text,text,text,text) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	runDomainCLI(t, f, true)
	if _, err := f.owner.Exec(f.ctx, `REVOKE EXECUTE ON FUNCTION zasp_sa_multistep_prior.lock_scope(text,text,text,text) FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.UpProductionTemporalDomain(f.ctx); err != nil {
		t.Fatal("restored authority", err)
	}
	if err := f.runner.DownProductionTemporalOutbox(f.ctx); err == nil {
		t.Fatal("retained67 outbox authority was dropped")
	}
}

func runDomainCLI(t *testing.T, f scheduleReplayFixture, refused bool) {
	t.Helper()
	c := exec.CommandContext(f.ctx, "go", "run", ".", "up-temporal-domain")
	c.Env = append(os.Environ(), postgresDSNEnvironment+"="+f.owner.Config().ConnString(), migrationTimeoutEnvironment+"=30s")
	r := f.registration
	for _, b := range [][2]string{{migrationPrincipalEnvironment, r.migration}, {discoveryAPIPrincipalEnvironment, r.api}, {discoveryWorkerPrincipalEnvironment, r.discovery}, {runtimeIngestPrincipalEnvironment, r.ingest}, {runtimeWorkerPrincipalEnvironment, r.runtime}, {outboxWorkerPrincipalEnvironment, r.outbox}, {runtimeGatewayPrincipalEnvironment, r.gateway}, {discoverySchedulerPrincipalEnvironment, r.scheduler}, {projectionRiskPrincipalEnvironment, r.projectionRisk}, {projectionGraphPrincipalEnvironment, r.projectionGraph}, {projectionSearchPrincipalEnvironment, r.projectionSearch}, {runtimeCoordinatorPrincipalEnvironment, r.runtimeCoordinator}, {runtimeArchivePrincipalEnvironment, r.runtimeArchive}, {runtimeIndexPrincipalEnvironment, r.runtimeIndex}, {runtimeCorrelationPrincipalEnvironment, r.runtimeCorrelation}, {runtimeProjectionPrincipalEnvironment, r.runtimeProjection}, {gatewayControlPrincipalEnvironment, r.gatewayControl}, {securityAgentAPIPrincipalEnvironment, r.securityAgentAPI}, {securityAgentWorkerPrincipalEnvironment, r.securityAgentWorker}, {securityAgentActionPrincipalEnvironment, r.securityAgentAction}, {redTeamWorkerPrincipalEnvironment, r.redTeamWorker}, {redTeamOutboxPrincipalEnvironment, r.redTeamOutbox}, {redTeamAdapterPrincipalEnvironment, r.redTeamAdapter}, {attackLabControllerPrincipalEnvironment, r.attackLabController}, {attackLabOutboxPrincipalEnvironment, r.attackLabOutbox}, {attackLabProxyPrincipalEnvironment, r.attackLabProxy}, {recoveryWorkerPrincipalEnvironment, r.recoveryWorker}, {recoveryOutboxPrincipalEnvironment, r.recoveryOutbox}, {policyDeploymentPrincipalEnvironment, r.policyDeployment}} {
		c.Env = append(c.Env, b[0]+"="+b[1])
	}
	if output, err := c.CombinedOutput(); (err != nil) != refused {
		t.Fatalf("shipped domain CLI: %v %s", err, output)
	}
}

func assertDomainDrift(t *testing.T, f scheduleReplayFixture) {
	t.Helper()
	for _, mutation := range []string{
		`ALTER FUNCTION zasp_sa_multistep_prior.lock_scope(text,text,text,text) OWNER TO zasp_discovery_authority`,
		`GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.lock_scope(text,text,text,text) TO PUBLIC`,
		`GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.pricing_lock_scope(text,text,text,text) TO zasp_discovery_authority WITH GRANT OPTION`,
		`UPDATE pg_proc SET proacl=ARRAY['zasp_test=X/zasp_test','zasp_discovery_authority=X/zasp_discovery_authority']::aclitem[] WHERE oid='zasp_sa_multistep_prior.lock_scope(text,text,text,text)'::regprocedure`,
		`ALTER FUNCTION zasp_sa_multistep_prior.lock_scope(text,text,text,text) STABLE`,
		`UPDATE zasp_temporal65.registration SET predecessor=CASE predecessor WHEN 'legacy60' THEN 'ordered62' ELSE 'legacy60' END`,
		`UPDATE zasp_ordered_public62.registration SET fingerprint=repeat('0',64)`,
		`GRANT EXECUTE ON FUNCTION zasp_temporal67.api_transition(text,text,jsonb) TO zasp_security_agent_worker`,
		`ALTER TABLE zasp_temporal67.registration DISABLE TRIGGER immutable`,
		`ALTER FUNCTION zasp_temporal66.legacy_visible(text,text,text,text) IMMUTABLE`,
		`CREATE OR REPLACE FUNCTION zasp_temporal65.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT true'`,
	} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.ctx, mutation); err != nil {
			tx.Rollback(f.ctx)
			t.Fatal("drift fixture", mutation, err)
		}
		var ready bool
		if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal67.ready($1,$2)`, migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalDomainFingerprint()).Scan(&ready); err != nil || ready {
			tx.Rollback(f.ctx)
			t.Fatal("drift accepted", mutation, ready, err)
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
}

type domainFailedRegistrationDB struct {
	*migrationDatabase
	hit *bool
}

func (d *domainFailedRegistrationDB) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.migrationDatabase.Begin(ctx)
	return &domainFailedRegistrationTx{Transaction: tx, hit: d.hit}, err
}

type domainFailedRegistrationTx struct {
	migrations.Transaction
	hit *bool
}

func (d *domainFailedRegistrationTx) Exec(ctx context.Context, q string, args ...any) error {
	if strings.HasPrefix(q, "INSERT INTO zasp_temporal67.registration") {
		*d.hit = true
		return d.Transaction.Exec(ctx, `SELECT 1/0`)
	}
	return d.Transaction.Exec(ctx, q, args...)
}
