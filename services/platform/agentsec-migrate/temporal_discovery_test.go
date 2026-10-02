package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// A missing shipped dispatch, permissive catalog check, or membership-only
// permission must fail this group on the supported upgraded installation.
func TestTemporalDiscoveryInstalledAuthorityPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	assertDiscoveryCatalogPin(t, f)
	runDiscoveryCLI(t, f, false)
	runDiscoveryCLI(t, f, false)
	var ready bool
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_temporal72.current_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("installed discovery authority", ready, err)
	}
	for _, principal := range []string{f.registration.api, f.registration.discovery, f.registration.scheduler, f.registration.outbox} {
		cfg := f.owner.Config().Copy()
		cfg.User = principal
		connection, err := pgx.ConnectConfig(f.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRow(f.ctx, `SELECT zasp_temporal72.current_ready()`).Scan(&ready); err != nil || !ready {
			t.Fatal("registered runtime readiness", principal, ready, err)
		}
		if _, err := connection.Exec(f.ctx, `UPDATE zasp_temporal72.registration SET checksum=repeat('0',64)`); err == nil {
			t.Fatal("runtime modified authority", principal)
		}
		var applyAllowed bool
		if err := connection.QueryRow(f.ctx, `SELECT has_function_privilege(current_user,'zasp_temporal72.apply_retained_snapshot(text,text,text,text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb)','EXECUTE')`).Scan(&applyAllowed); err != nil || applyAllowed != (principal == f.registration.discovery) {
			t.Fatal("retained apply role grant", principal, applyAllowed, err)
		}
		for _, denied := range []string{`SELECT * FROM zasp_temporal72.runs`, `SELECT * FROM zasp_temporal72.retained_dispatches`, `SELECT zasp_temporal72.active_owners(NULL)`, `SELECT zasp_temporal72.require_principal('zasp_discovery_worker')`, `SELECT zasp_temporal72.require_actor(NULL,NULL,NULL,NULL)`} {
			if _, err := connection.Exec(f.ctx, denied); err == nil {
				t.Fatal("private authority exposed", principal, denied)
			}
		}
		connection.Close(f.ctx)
	}
	for _, mutation := range []string{`GRANT EXECUTE ON FUNCTION zasp_temporal72.current_ready() TO PUBLIC`, `ALTER TABLE zasp_temporal72.registration SET UNLOGGED`, `ALTER TABLE zasp_temporal72.registration DISABLE ROW LEVEL SECURITY`,
		`ALTER TABLE public.zasp_discovery_outbox DISABLE TRIGGER zasp_temporal72_outbox_guard`,
		`CREATE TRIGGER unrelated_outbox_trigger BEFORE UPDATE ON public.zasp_discovery_outbox FOR EACH ROW EXECUTE FUNCTION zasp_temporal72.outbox_guard()`,
		`CREATE OR REPLACE FUNCTION zasp_temporal72.outbox_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS 'BEGIN RETURN NEW;END'`,
		`CREATE OR REPLACE FUNCTION zasp_temporal72.retained_precision_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT repeat(''a'',64)'`,
		`CREATE OR REPLACE FUNCTION public.zasp_production_runtime_precision_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT repeat(''a'',64)'`,
		`ALTER TABLE public.zasp_discovery_jobs DISABLE TRIGGER zasp_temporal72_retained_claim`,
		`ALTER TABLE public.zasp_discovery_generation_reservations DISABLE TRIGGER zasp_temporal72_reservation`,
		`ALTER TABLE zasp_temporal72.retained_dispatches NO FORCE ROW LEVEL SECURITY`,
		`ALTER FUNCTION public.zasp_execution_claim_jobs(text,text,integer,integer) SECURITY INVOKER`,
		`ALTER FUNCTION public.zasp_execution_live_fingerprint() SECURITY INVOKER`,
		`ALTER FUNCTION public.zasp_discovery_schedule_replay_function_identity(oid) IMMUTABLE`,
		`ALTER TABLE zasp_temporal72.predecessor_functions DISABLE TRIGGER immutable; UPDATE zasp_temporal72.predecessor_functions SET definition=definition||' ' WHERE signature='zasp_execution_claim_jobs(text,text,integer,integer)'`,
		`CREATE FUNCTION public.zasp_execution_unrelated_drift() RETURNS boolean LANGUAGE sql AS 'SELECT true'`,
		`GRANT SELECT ON public.zasp_discovery_execution_quotas TO zasp_discovery_worker`,
		`ALTER FUNCTION zasp_temporal72.normalize_relationships(text,text,text,text,text,jsonb) SECURITY INVOKER`,
		`GRANT EXECUTE ON FUNCTION zasp_temporal72.apply_retained_snapshot(text,text,text,text,text,text,text,text,text,bigint,text,text,text,text,bytea,bigint,text,text,timestamptz,text,text,text,jsonb,jsonb,jsonb) TO zasp_discovery_scheduler`,
		`ALTER FUNCTION public.zasp_discovery_relationship_id(text,text,text,text,text,text,text) STABLE`,
	} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.ctx, mutation); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal72.current_ready()`).Scan(&ready); err != nil || ready {
			t.Fatal("catalog drift accepted", mutation, ready, err)
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_temporal71.current_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("retained71 unavailable", ready, err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal72.predecessor_functions SET definition='changed' WHERE signature='zasp_production_runtime_precision_live_fingerprint()'`); err == nil {
		t.Fatal("saved precision baseline mutable")
	}
	// Membership alone must not create another registered runtime principal.
	if _, err := f.owner.Exec(f.ctx, `CREATE ROLE discovery72_shadow LOGIN INHERIT; GRANT zasp_discovery_worker TO discovery72_shadow`); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = "discovery72_shadow"
	shadow, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close(f.ctx)
	var raw []byte
	if err := shadow.QueryRow(f.ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,clock_timestamp())`, replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration).Scan(&raw); err == nil {
		t.Fatal("unregistered role member admitted")
	}
}

// CLI configuration must match the exact existing registrations before DDL;
// losing final registration must roll back every72 object and imported row.
func TestTemporalDiscoveryInstallAtomicityPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	wrong := *f.registered
	wrong.registration.api = f.registration.discovery
	if err := runReleaseMigration(f.ctx, &wrong, []string{"up-temporal-discovery"}); err == nil {
		t.Fatal("mismatched API login reached DDL")
	}
	var intact bool
	if err := f.owner.QueryRow(f.ctx, `SELECT to_regnamespace('zasp_temporal72') IS NULL AND zasp_temporal71.current_ready()`).Scan(&intact); err != nil || !intact {
		t.Fatal("wrong principal changed installation", intact, err)
	}
	hit := false
	broken, _ := migrations.NewRunner(&discoveryFailedRegistrationDB{migrationDatabase: &migrationDatabase{connection: f.owner}, hit: &hit})
	if err := broken.UpProductionTemporalDiscovery(f.ctx); err == nil || !hit {
		t.Fatal("final registration fault not exercised", hit, err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT to_regnamespace('zasp_temporal72') IS NULL AND zasp_temporal71.current_ready()`).Scan(&intact); err != nil || !intact {
		t.Fatal("failed installation leaked authority", intact, err)
	}
}

type discoveryFailedRegistrationDB struct {
	*migrationDatabase
	hit *bool
}

func (d *discoveryFailedRegistrationDB) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.migrationDatabase.Begin(ctx)
	return &discoveryFailedRegistrationTx{Transaction: tx, hit: d.hit}, err
}

type discoveryFailedRegistrationTx struct {
	migrations.Transaction
	hit *bool
}

func (d *discoveryFailedRegistrationTx) Exec(ctx context.Context, q string, args ...any) error {
	if strings.HasPrefix(q, "INSERT INTO zasp_temporal72.registration") {
		*d.hit = true
		return d.Transaction.Exec(ctx, `SELECT 1/0`)
	}
	return d.Transaction.Exec(ctx, q, args...)
}

func temporalDiscoveryPredecessor(t *testing.T) scheduleReplayFixture {
	t.Helper()
	f := newScheduleReplayFixture(t)
	f.seedIntegration(t)
	for _, command := range []string{"up-to-60", "up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests"} {
		if err := runReleaseMigration(f.ctx, f.registered, []string{command}); err != nil {
			t.Fatal(command, err)
		}
		if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{command}); err != nil {
			t.Fatal(command, err)
		}
	}
	return f
}

func assertDiscoveryCatalogPin(t *testing.T, f scheduleReplayFixture) {
	t.Helper()
	// Compile the catalog in a rollback-only transaction, independently of the
	// installer registration. A source change requires a reviewed literal pin.
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, fn := range []string{"zasp_temporal67.base_fingerprint", "zasp_temporal67.fingerprint", "zasp_temporal68.fingerprint", "zasp_temporal69.fingerprint", "zasp_temporal70.fingerprint", "zasp_temporal71.fingerprint", "public.zasp_execution_live_fingerprint", "public.zasp_discovery_schedule_replay_live_fingerprint", "public.zasp_sa_webhook_live_fingerprint"} {
		var value string
		if err := tx.QueryRow(f.ctx, "SELECT "+fn+"()").Scan(&value); err != nil {
			t.Fatal(fn, err)
		}
		before[fn] = value
	}
	if _, err := tx.Exec(f.ctx, migrations.ProductionTemporalDiscovery().UpSQL()); err != nil {
		t.Fatalf("catalog compile: %#v", err)
	}
	var pin string
	if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal72.fingerprint()`).Scan(&pin); err != nil {
		t.Fatal(err)
	}
	if pin == migrations.TemporalDiscoveryFingerprint() {
		if _, err := tx.Exec(f.ctx, `INSERT INTO zasp_temporal72.registration(checksum,fingerprint) VALUES($1,$2)`, migrations.ProductionTemporalDiscovery().Checksum(), pin); err != nil {
			t.Fatal(err)
		}
		for fn, old := range before {
			var value string
			if err := tx.QueryRow(f.ctx, "SELECT "+fn+"()").Scan(&value); err != nil {
				t.Fatal(fn, err)
			}
			if value != old {
				t.Fatal("handoff changed unrelated predecessor", fn, old, value)
			}
		}
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if pin != migrations.TemporalDiscoveryFingerprint() {
		t.Fatalf("review catalog pin: %s", pin)
	}
}

// Catch wakeup-derived identity, non-atomic due advancement, foreign receipt
// admission, a72 legacy-job insertion, and creator-login dependency.
func TestTemporalDiscoveryAdmissionPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.scheduler
	scheduler, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close(f.ctx)
	var raw []byte
	query := `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,$6,$7)`
	var nominal time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT next_run_at FROM public.zasp_discovery_schedules WHERE id=$1`, replaySchedule).Scan(&nominal); err != nil {
		t.Fatal(err)
	}
	args := []any{replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration, int64(1), nominal}
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal("lease-free admission", err)
	}
	var admitted orchestration.DiscoveryAdmission
	if json.Unmarshal(raw, &admitted) != nil || admitted.Outcome != "admitted" || admitted.Start == nil || admitted.Start.Ref.OrganizationID != replayOrg {
		t.Fatalf("admission shape: %s", raw)
	}
	var valid bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_temporal72.runs)=1 AND (SELECT count(*) FROM zasp_discovery_jobs WHERE id=$1)=0 AND (SELECT count(*) FROM zasp_discovery_outbox WHERE payload->>'job_id'=$1)=1 AND (SELECT next_run_at>clock_timestamp() FROM zasp_temporal72.schedules WHERE id=$2)`, admitted.Start.Ref.RunID, replaySchedule).Scan(&valid); err != nil || !valid {
		t.Fatal("atomic due/run/outbox and no legacy job", valid, err)
	}
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var duplicate orchestration.DiscoveryAdmission
	if json.Unmarshal(raw, &duplicate) != nil || duplicate.Outcome != "not_due" || duplicate.Start != nil {
		t.Fatalf("duplicate admitted: %s", raw)
	}
	args[0] = replayWorkspace
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("foreign scope admitted")
	}
	args[0] = replayOrg
	args[5] = int64(2)
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("stale revision admitted")
	}
	args[5] = nil
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("NULL revision bypassed current schedule authority")
	}
	workerCfg := f.owner.Config().Copy()
	workerCfg.User = f.registration.discovery
	worker, err := pgx.ConnectConfig(f.ctx, workerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(f.ctx)
	if _, err := worker.Exec(f.ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'legacy', $5,60)`, replayOrg, replayWorkspace, replayEnvironment, admitted.Start.Ref.RunID, strings.Repeat("x", 32)); err == nil {
		t.Fatal("legacy claimant found72 job")
	}
	// A retained job still uses the unchanged old claimant. No mixed-batch72 row
	// can occupy its queue position because72 never creates a public job.
	legacyJob := "pid_72001001-0000-4000-8000-000000000001"
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,'pid_72001002-0000-4000-8000-000000000002',$6,'pid_72001003-0000-4000-8000-000000000003','retained-discovery-0001',decode(repeat('ab',32),'hex'),'manual','parser_v1','tool_v1')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, legacyJob).Scan(&raw); err != nil {
		t.Fatal("retained admission", err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'legacy', $5,60)`, replayOrg, replayWorkspace, replayEnvironment, legacyJob, strings.Repeat("y", 32)).Scan(&raw); err != nil {
		t.Fatal("retained claim", err)
	}
	var retained struct {
		Disposition string `json:"disposition"`
	}
	if json.Unmarshal(raw, &retained) != nil || retained.Disposition != "claimed" {
		t.Fatalf("retained job stranded: %s", raw)
	}
}

// Changing canonical identity to the wakeup, skipping oldest overdue work, or
// committing due advancement separately from the outbox breaks this scenario.
func TestTemporalDiscoveryCoalescingAtomicityPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	const due = "2020-01-02T03:04:05.1234Z"
	const job = "pid_064eee60-1c93-4bb4-8793-6cc5517dfff7"
	const syncID = "pid_0252503a-e36d-436d-8fca-fa11da8a2a67"
	const outbox = "pid_8d7d9ea0-478f-4856-89c4-8cf384502d69"
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal72.schedules SET cadence_seconds=86400,next_run_at=$1,anchor=$1`, due); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.scheduler
	scheduler, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close(f.ctx)
	query := `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,'2020-01-03T03:04:05.1234Z')`
	args := []any{replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration}
	var raw []byte
	// A preexisting conflicting outbox causes failure after run/sync insertion.
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest) VALUES($1,$2,$3,$4,'discovery-jobs','atomic-outbox-conflict-0001',1,'{}',decode(repeat('aa',32),'hex'))`, replayOrg, replayWorkspace, replayEnvironment, outbox); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("outbox conflict committed")
	}
	var valid bool
	if err := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal72.runs) AND NOT EXISTS(SELECT 1 FROM zasp_discovery_syncs) AND (SELECT next_run_at=$1::timestamptz FROM zasp_temporal72.schedules)`, due).Scan(&valid); err != nil || !valid {
		t.Fatal("admission rollback lost oldest due", valid, err)
	}
	if _, err := f.owner.Exec(f.ctx, `DELETE FROM zasp_discovery_outbox WHERE id=$1`, outbox); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var admitted orchestration.DiscoveryAdmission
	if json.Unmarshal(raw, &admitted) != nil || admitted.Start == nil || admitted.Start.Ref.RunID != job || admitted.Start.InputDigest != "d86ec346b73f326f25d335ad80302bd504d38f4f5533b04a5a7178c5d7aa5c6f" {
		t.Fatalf("oldest occurrence identity: %s", raw)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal72.runs WHERE job_id=$1 AND sync_id=$2 AND outbox_id=$3 AND scheduled_for=$4::timestamptz AND deadline=admitted_at+interval '24 hours') AND (SELECT next_run_at>clock_timestamp() AND next_run_at<=clock_timestamp()+interval '24 hours' AND mod(extract(epoch FROM next_run_at-anchor),86400)=0 FROM zasp_temporal72.schedules)`, job, syncID, outbox, due).Scan(&valid); err != nil || !valid {
		t.Fatal("coalesced due or persisted budget", valid, err)
	}
	if err := scheduler.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil || string(raw) != "{\"outcome\": \"not_due\"}" {
		t.Fatal("replayed wakeup", string(raw), err)
	}
}

// Missing API extraction, loss of durable desired revisions, or an actor
// authorization bypass fails here. Identity data is controlled local IO.
func TestTemporalDiscoveryManualAndDesiredChangePostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'discovery-org','discovery-member','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Discovery','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.api
	api, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(f.ctx)
	digest := sha256.Sum256([]byte("manual-discovery72"))
	args := []any{replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, "discovery72-manual-0001", int64(1), "pid_72000001-0000-4000-8000-000000000001", "pid_72000002-0000-4000-8000-000000000002", "pid_72000003-0000-4000-8000-000000000003", digest[:], "parser_v1", "tool_v1", "pid_72000004-0000-4000-8000-000000000004", "pid_72000005-0000-4000-8000-000000000005", "pid_72000006-0000-4000-8000-000000000006"}
	query := `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
	var raw []byte
	if err := api.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal("manual admission", err)
	}
	var first map[string]any
	if json.Unmarshal(raw, &first) != nil || first["replayed"] != false {
		t.Fatalf("manual receipt: %s", raw)
	}
	if err := api.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var replay map[string]any
	if json.Unmarshal(raw, &replay) != nil || replay["replayed"] != true {
		t.Fatalf("manual replay: %s", raw)
	}
	var valid bool
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_temporal72.runs)=1 AND (SELECT count(*) FROM zasp_discovery_jobs)=0 AND (SELECT count(*) FROM zasp_discovery_outbox WHERE topic='discovery-jobs')=1`).Scan(&valid); err != nil || !valid {
		t.Fatal("manual durable single start", valid, err)
	}
	put := `SELECT zasp_temporal72.public_put_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	putArgs := []any{replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, "discovery72-disable-0001", int64(1), 86400, "disabled", "pid_72000007-0000-4000-8000-000000000007", "pid_72000008-0000-4000-8000-000000000008", "pid_72000009-0000-4000-8000-000000000009"}
	if err := api.QueryRow(f.ctx, put, putArgs...).Scan(&raw); err != nil {
		t.Fatal("desired configuration", err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT state='disabled' AND version=2 AND delivered_revision<version FROM zasp_temporal72.schedules WHERE id=$1`, replaySchedule).Scan(&valid); err != nil || !valid {
		t.Fatal("durable desired revision missing", valid, err)
	}
	dsn := (&url.URL{Scheme: "postgres", User: url.User(f.registration.api), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	ids, _ := json.Marshal([]string{replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration})
	child := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledPublicMutations$", "-count=1", "-v")
	child.Env = append(os.Environ(), "ZASP_P4B_API_DSN="+dsn, "ZASP_P4B_MUTATION_IDS="+string(ids))
	output, childErr := child.CombinedOutput()
	t.Log(string(output))
	if childErr != nil {
		t.Fatal("installed public mutations", childErr)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_temporal72.runs)=2 AND (SELECT count(*) FROM zasp_discovery_jobs)=0 AND (SELECT state='deleted' AND version=4 AND delivered_revision<version FROM zasp_temporal72.schedules WHERE id=$1)`, replaySchedule).Scan(&valid); err != nil || !valid {
		t.Fatal("typed mutation authority", valid, err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("revoked human read replay")
	}
}

func runDiscoveryCLI(t *testing.T, f scheduleReplayFixture, refused bool) {
	t.Helper()
	c := exec.CommandContext(f.ctx, "go", "run", ".", "up-temporal-discovery")
	c.Env = append(os.Environ(), postgresDSNEnvironment+"="+f.owner.Config().ConnString(), migrationTimeoutEnvironment+"=30s")
	r := f.registration
	for _, b := range [][2]string{{migrationPrincipalEnvironment, r.migration}, {discoveryAPIPrincipalEnvironment, r.api}, {discoveryWorkerPrincipalEnvironment, r.discovery}, {runtimeIngestPrincipalEnvironment, r.ingest}, {runtimeWorkerPrincipalEnvironment, r.runtime}, {outboxWorkerPrincipalEnvironment, r.outbox}, {runtimeGatewayPrincipalEnvironment, r.gateway}, {discoverySchedulerPrincipalEnvironment, r.scheduler}, {projectionRiskPrincipalEnvironment, r.projectionRisk}, {projectionGraphPrincipalEnvironment, r.projectionGraph}, {projectionSearchPrincipalEnvironment, r.projectionSearch}, {runtimeCoordinatorPrincipalEnvironment, r.runtimeCoordinator}, {runtimeArchivePrincipalEnvironment, r.runtimeArchive}, {runtimeIndexPrincipalEnvironment, r.runtimeIndex}, {runtimeCorrelationPrincipalEnvironment, r.runtimeCorrelation}, {runtimeProjectionPrincipalEnvironment, r.runtimeProjection}, {gatewayControlPrincipalEnvironment, r.gatewayControl}, {securityAgentAPIPrincipalEnvironment, r.securityAgentAPI}, {securityAgentWorkerPrincipalEnvironment, r.securityAgentWorker}, {securityAgentActionPrincipalEnvironment, r.securityAgentAction}, {redTeamWorkerPrincipalEnvironment, r.redTeamWorker}, {redTeamOutboxPrincipalEnvironment, r.redTeamOutbox}, {redTeamAdapterPrincipalEnvironment, r.redTeamAdapter}, {attackLabControllerPrincipalEnvironment, r.attackLabController}, {attackLabOutboxPrincipalEnvironment, r.attackLabOutbox}, {attackLabProxyPrincipalEnvironment, r.attackLabProxy}, {recoveryWorkerPrincipalEnvironment, r.recoveryWorker}, {recoveryOutboxPrincipalEnvironment, r.recoveryOutbox}, {policyDeploymentPrincipalEnvironment, r.policyDeployment}} {
		c.Env = append(c.Env, b[0]+"="+b[1])
	}
	if output, err := c.CombinedOutput(); (err != nil) != refused {
		t.Fatalf("shipped discovery CLI: %v %s", err, output)
	}
}

// An identical command must never prepare another effect. Only a recorded,
// known-safe retry result can authorize a new effect without cursor movement.
func TestTemporalDiscoveryPageReceiptsPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	worker, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(f.ctx)
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,(SELECT '2020-01-01'::timestamptz))`, replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration).Scan(&raw); err == nil {
		t.Fatal("invalid wakeup admitted")
	}
	var nominal time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT anchor FROM zasp_temporal72.schedules WHERE id=$1`, replaySchedule).Scan(&nominal); err != nil {
		t.Fatal(err)
	}
	if nominal.Nanosecond() != 0 {
		nominal = nominal.Truncate(time.Second).Add(time.Second)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,$6)`, replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration, nominal).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var admission orchestration.DiscoveryAdmission
	if err := json.Unmarshal(raw, &admission); err != nil || admission.Start == nil {
		t.Fatal("admission", err)
	}
	start := admission.Start
	var deadline time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	prepare := `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	args := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, replayIntegration, start.InputDigest, deadline, int64(0), ""}
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal("prepare fresh product effect", err)
	}
	var first struct {
		EffectID string                       `json:"effect_id"`
		Input    map[string]any               `json:"input"`
		Page     *orchestration.DiscoveryPage `json:"page"`
	}
	if err := json.Unmarshal(raw, &first); err != nil || len(first.EffectID) != 64 || first.Input == nil || first.Page != nil {
		t.Fatalf("effect authority: %s %v", raw, err)
	}
	for _, key := range []string{"lease_expires_at", "attempt", "worker_id", "lease_token"} {
		if _, ok := first.Input[key]; ok {
			t.Fatal("legacy lease identity in product input", key)
		}
	}
	if first.Input["generation"] != float64(1) || first.Input["checkpoint_version"] != float64(0) {
		t.Fatalf("initial durable generation/cursor: %s", raw)
	}
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var replay struct {
		Page  orchestration.DiscoveryPage `json:"page"`
		Input map[string]any              `json:"input"`
	}
	if json.Unmarshal(raw, &replay) != nil || replay.Page.Outcome != "outcome_unknown" || replay.Input != nil {
		t.Fatalf("lost prepare response resent: %s", raw)
	}
	record := `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,$6::jsonb)`
	recordArgs := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, first.EffectID, `{"outcome":"retryable","retry_after_seconds":1}`}
	if err := worker.QueryRow(f.ctx, record, recordArgs...).Scan(&raw); err != nil {
		t.Fatal("record safe retry", err)
	}
	var retry orchestration.DiscoveryPage
	if json.Unmarshal(raw, &retry) != nil || retry.Outcome != "retryable" || retry.CheckpointVersion != 1 || len(retry.ReceiptDigest) != 64 {
		t.Fatalf("advancing retry receipt: %s", raw)
	}
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &replay) != nil || replay.Page != retry || replay.Input != nil {
		t.Fatalf("retry receipt did not replay: %s", raw)
	}
	args[7], args[8] = retry.CheckpointVersion, retry.ReceiptDigest
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err == nil {
		t.Fatal("retry-not-before bypassed")
	}
	time.Sleep(1100 * time.Millisecond)
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal("authorized next effect", err)
	}
	var next struct {
		EffectID string         `json:"effect_id"`
		Input    map[string]any `json:"input"`
	}
	if json.Unmarshal(raw, &next) != nil || next.EffectID == first.EffectID || next.Input["generation"] != float64(1) || next.Input["checkpoint_version"] != float64(0) || next.Input["cursor_value"] != nil {
		t.Fatalf("retry changed cursor/generation or reused effect: %s", raw)
	}
	recordArgs[4], recordArgs[5] = next.EffectID, `{"outcome":"outcome_unknown"}`
	if err := worker.QueryRow(f.ctx, record, recordArgs...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &replay) != nil || replay.Page.Outcome != "outcome_unknown" || replay.Input != nil {
		t.Fatalf("unknown effect resent: %s", raw)
	}
	args[7], args[8] = int64(2), strings.Repeat("a", 64)
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err == nil {
		t.Fatal("invented receipt authorized unknown retry")
	}
	args[7], args[8], args[6] = int64(0), "", deadline.Add(time.Hour)
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err == nil {
		t.Fatal("deadline extension accepted")
	}
}

func TestTemporalDiscoveryPartialCheckpointPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	prepare := `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	args := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, replayIntegration, start.InputDigest, deadline, int64(0), ""}
	var raw []byte
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		EffectID string         `json:"effect_id"`
		Input    map[string]any `json:"input"`
	}
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	key := "organizations/" + replayOrg + "/workspaces/" + replayWorkspace + "/environments/" + replayEnvironment + "/artifacts/pid_72002001-0000-4000-8000-000000000001"
	details := map[string]any{"outcome": "partial", "cursor": map[string]any{"provider": "aws", "version": "cursor_v1", "value": "provider-page-two"}, "manifest": map[string]any{"reference": "s3://zasp-evidence/" + key, "key": key, "version_id": "stored-version-1", "checksum": strings.Repeat("ab", 32), "size_bytes": 100, "media_type": "application/json", "schema_version": "manifest_v1", "parser_version": "parser_v1", "tool_version": "tool_v1"}}
	payload, _ := json.Marshal(details)
	record := `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,$6::jsonb)`
	if err := worker.QueryRow(f.ctx, record, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID, string(payload)).Scan(&raw); err != nil {
		t.Fatal("record persisted partial", err)
	}
	var page orchestration.DiscoveryPage
	if json.Unmarshal(raw, &page) != nil || page.Outcome != "partial" || page.CheckpointVersion != 1 {
		t.Fatalf("partial receipt: %s", raw)
	}
	firstEffect := prepared.EffectID
	args[7], args[8] = page.CheckpointVersion, page.ReceiptDigest
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &prepared) != nil || prepared.EffectID == firstEffect || prepared.Input["checkpoint_version"] != float64(1) || prepared.Input["cursor_value"] != "provider-page-two" || prepared.Input["checkpoint_manifest_version_id"] != "stored-version-1" || prepared.Input["generation"] != float64(1) {
		t.Fatalf("resume lost provider checkpoint: %s", raw)
	}
	if err := worker.QueryRow(f.ctx, record, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID, `{"outcome":"retryable","retry_after_seconds":1}`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &page) != nil || page.CheckpointVersion != 2 {
		t.Fatalf("retry receipt: %s", raw)
	}
	time.Sleep(1100 * time.Millisecond)
	args[7], args[8] = page.CheckpointVersion, page.ReceiptDigest
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &prepared) != nil || prepared.Input["checkpoint_version"] != float64(1) || prepared.Input["cursor_value"] != "provider-page-two" || prepared.Input["checkpoint_manifest_version_id"] != "stored-version-1" || prepared.Input["generation"] != float64(1) {
		t.Fatalf("safe retry advanced provider checkpoint: %s", raw)
	}
	if err := worker.QueryRow(f.ctx, record, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID, `{"outcome":"incomplete"}`).Scan(&raw); err != nil {
		t.Fatal("truthful cumulative exhaustion", err)
	}
	if json.Unmarshal(raw, &page) != nil || page.Outcome != "incomplete" || page.CheckpointVersion != 2 {
		t.Fatal("exhaustion changed checkpoint", string(raw))
	}
	var preserved bool
	if err := f.owner.QueryRow(f.ctx, `SELECT r.state='incomplete' AND c.cursor->>'value'='provider-page-two' AND c.version=1 AND (SELECT count(*) FROM zasp_discovery_snapshots)=0 FROM zasp_temporal72.runs r JOIN zasp_temporal72.checkpoints c USING(organization_id,workspace_id,environment_id,job_id) WHERE job_id=$1`, start.Ref.RunID).Scan(&preserved); err != nil || !preserved {
		t.Fatal("exhaustion changed last-good/provider cursor", preserved, err)
	}
}

func TestTemporalDiscoveryTemporalWakeupPrecisionPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	worker, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	var anchor time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT anchor FROM zasp_temporal72.schedules WHERE id=$1`, replaySchedule).Scan(&anchor); err != nil {
		t.Fatal(err)
	}
	if anchor.Nanosecond() == 0 {
		t.Fatal("fractional imported fixture required")
	}
	wakeup := anchor.Truncate(time.Second).Add(time.Second)
	query := `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,$6)`
	for _, bad := range []time.Time{anchor, anchor.Truncate(time.Second), wakeup.Add(time.Microsecond)} {
		tx, err := worker.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		err = tx.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration, bad).Scan(&raw)
		tx.Rollback(f.ctx)
		if err == nil {
			t.Fatal("noncanonical Temporal wakeup accepted", bad)
		}
	}
	var raw []byte
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration, wakeup).Scan(&raw); err != nil {
		t.Fatal("exact non-early Temporal wakeup", err)
	}
	var retained bool
	if err := f.owner.QueryRow(f.ctx, `SELECT scheduled_for=$1 AND (SELECT anchor FROM zasp_temporal72.schedules WHERE id=$2)=$1 FROM zasp_temporal72.runs`, anchor, replaySchedule).Scan(&retained); err != nil || !retained {
		t.Fatal("product identity rounded", retained, err)
	}
}

func temporalDiscoveryPageFixture(t *testing.T) (scheduleReplayFixture, *pgx.Conn, orchestration.DiscoveryStart, time.Time) {
	return temporalDiscoveryPageFixtureWith(t, nil)
}

func temporalDiscoveryPageFixtureWith(t *testing.T, prepare func(scheduleReplayFixture)) (scheduleReplayFixture, *pgx.Conn, orchestration.DiscoveryStart, time.Time) {
	t.Helper()
	f := temporalDiscoveryPredecessor(t)
	if prepare != nil {
		prepare(f)
	}
	runDiscoveryCLI(t, f, false)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	worker, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	var nominal, deadline time.Time
	if err := f.owner.QueryRow(f.ctx, `SELECT anchor FROM zasp_temporal72.schedules WHERE id=$1`, replaySchedule).Scan(&nominal); err != nil {
		t.Fatal(err)
	}
	if nominal.Nanosecond() != 0 {
		nominal = nominal.Truncate(time.Second).Add(time.Second)
	}
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.scheduled_admit($1,$2,$3,$4,$5,1,$6)`, replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration, nominal).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var admission orchestration.DiscoveryAdmission
	if json.Unmarshal(raw, &admission) != nil || admission.Start == nil {
		t.Fatalf("admission: %s", raw)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT deadline FROM zasp_temporal72.runs WHERE job_id=$1`, admission.Start.Ref.RunID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	return f, worker, *admission.Start, deadline
}

// Use actual inventory SQL and durable apply evidence. An empty typed snapshot
// isolates settlement; real provider-produced inventory belongs to runtime E2E.
func TestTemporalDiscoveryApplyEvidencePostgres(t *testing.T) {
	for _, mode := range []string{"committed", "unknown", "no_apply"} {
		t.Run(mode, func(t *testing.T) {
			f, worker, start, _ := temporalDiscoveryPageFixture(t)
			var deadline time.Time
			if err := f.owner.QueryRow(f.ctx, `WITH n AS(SELECT clock_timestamp() v) UPDATE zasp_temporal72.runs SET admitted_at=n.v-interval '24 hours'+interval '3 seconds',deadline=n.v+interval '3 seconds' FROM n WHERE job_id=$1 RETURNING deadline`, start.Ref.RunID).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			args := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, replayIntegration, start.InputDigest, deadline}
			var raw []byte
			if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,0,'')`, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var prepared struct {
				EffectID string `json:"effect_id"`
			}
			if json.Unmarshal(raw, &prepared) != nil {
				t.Fatal("prepare decode")
			}
			key := "organizations/" + replayOrg + "/workspaces/" + replayWorkspace + "/environments/" + replayEnvironment + "/artifacts/pid_72003001-0000-4000-8000-000000000001"
			details := map[string]any{"outcome": "complete", "cursor": map[string]any{"provider": "aws", "version": "cursor_v1", "value": "complete-cursor"}, "manifest": map[string]any{"reference": "s3://zasp-evidence/" + key, "key": key, "version_id": "stored-complete-1", "checksum": strings.Repeat("cd", 32), "size_bytes": 100, "media_type": "application/json", "schema_version": "manifest_v1", "parser_version": "parser_v1", "tool_version": "tool_v1"}, "candidate": map[string]any{"entities": []any{}, "relationships": []any{}, "evidence": []any{}}}
			payload, _ := json.Marshal(details)
			if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,$6::jsonb)`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID, string(payload)).Scan(&raw); err != nil {
				t.Fatal("complete receipt", err)
			}
			var complete orchestration.DiscoveryPage
			if json.Unmarshal(raw, &complete) != nil || complete.Outcome != "complete" {
				t.Fatalf("complete: %s", raw)
			}
			applyArgs := append(append([]any{}, args...), complete.ReceiptDigest)
			prepareApply := `SELECT zasp_temporal72.prepare_apply($1,$2,$3,$4,$5,$6,$7,$8)`
			var application struct {
				EffectID string                         `json:"effect_id"`
				Result   *orchestration.DiscoveryResult `json:"result"`
			}
			if mode != "no_apply" {
				if err := worker.QueryRow(f.ctx, prepareApply, applyArgs...).Scan(&raw); err != nil {
					t.Fatal("prepare application", err)
				}
				if json.Unmarshal(raw, &application) != nil || len(application.EffectID) != 64 || application.Result != nil {
					t.Fatalf("apply authority: %s", raw)
				}
				if err := worker.QueryRow(f.ctx, prepareApply, applyArgs...).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var duplicate struct {
					EffectID string                        `json:"effect_id"`
					Result   orchestration.DiscoveryResult `json:"result"`
				}
				if json.Unmarshal(raw, &duplicate) != nil || duplicate.EffectID != "" || duplicate.Result.Outcome != "outcome_unknown" {
					t.Fatalf("ambiguous application resent: %s", raw)
				}
			}
			commitArgs := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, application.EffectID, deadline}
			commit := `SELECT zasp_temporal72.commit_apply($1,$2,$3,$4,$5,$6)`
			if mode == "committed" {
				if err := worker.QueryRow(f.ctx, commit, commitArgs...).Scan(&raw); err != nil {
					t.Fatal("actual typed application", err)
				}
			}
			time.Sleep(time.Until(deadline) + 20*time.Millisecond)
			if mode == "unknown" {
				if err := worker.QueryRow(f.ctx, commit, commitArgs...).Scan(&raw); err == nil {
					t.Fatal("expired application dispatched")
				}
			}
			if mode == "no_apply" {
				if err := worker.QueryRow(f.ctx, prepareApply, applyArgs...).Scan(&raw); err == nil {
					t.Fatal("expired fresh application prepared")
				}
			}
			settle := `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,'cancelled','')`
			if err := worker.QueryRow(f.ctx, settle, args...).Scan(&raw); err != nil {
				t.Fatal("evidence-only settlement", err)
			}
			var result orchestration.DiscoveryResult
			want := map[string]string{"committed": "succeeded", "unknown": "outcome_unknown", "no_apply": "incomplete"}[mode]
			if json.Unmarshal(raw, &result) != nil || result.Outcome != want || mode == "committed" && len(result.ReceiptDigest) != 64 {
				t.Fatalf("settlement: %s want %s", raw, want)
			}
			var snapshots int
			if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_discovery_snapshots WHERE complete`).Scan(&snapshots); err != nil {
				t.Fatal(err)
			}
			if mode == "committed" && snapshots != 1 || mode != "committed" && snapshots != 0 {
				t.Fatal("settlement fabricated inventory", snapshots)
			}
		})
	}
}

func TestTemporalDiscoveryRealCollectorPostgres(t *testing.T) {
	f, _, start, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
		// Older SQL-only fixtures use ref:owned. The actual AWS collector requires
		// a provider-bound reference; update fixture connector authority BEFORE
		// admission, never rewrite the persisted run's immutable input.
		for _, q := range []string{
			`UPDATE zasp_integrations SET configuration=jsonb_set(configuration,'{external_id_reference}','"ref:aws/external-id/customer-0001"') WHERE id=$1`,
			`UPDATE zasp_integration_connections SET connection_reference='ref:aws/external-id/customer-0001' WHERE integration_id=$1`,
			`UPDATE zasp_discovery_connection_subjects SET configuration_digest=(SELECT digest(convert_to(configuration::text,'UTF8'),'sha256') FROM zasp_integrations WHERE id=$1) WHERE integration_id=$1`,
		} {
			if _, err := f.owner.Exec(f.ctx, q, replayIntegration); err != nil {
				t.Fatal(err)
			}
		}
	})
	start.Continuation = &orchestration.DiscoveryContinuation{Deadline: deadline}
	raw, _ := json.Marshal(start)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	command := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledCollector$", "-count=1", "-v")
	dsn := (&url.URL{Scheme: "postgres", User: url.User(cfg.User), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	command.Env = append(os.Environ(), "ZASP_P4B_WORKER_DSN="+dsn, "ZASP_P4B_START="+string(raw))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("real collector child", err)
	}
	var entities, inputs, projections int
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_inventory_entities),(SELECT count(*) FROM zasp_discovery_snapshot_inputs),(SELECT count(*) FROM zasp_projection_work WHERE input_digest IS NOT NULL)`).Scan(&entities, &inputs, &projections); err != nil {
		t.Fatal(err)
	}
	if entities < 1 || inputs != 1 || projections != 3 {
		t.Fatalf("nonempty typed inventory missing: entities=%d inputs=%d projections=%d", entities, inputs, projections)
	}
	var syncID string
	if err := f.owner.QueryRow(f.ctx, `SELECT sync_id FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID).Scan(&syncID); err != nil {
		t.Fatal(err)
	}
	discoveryTypedReadback(t, f, syncID, "succeeded", 1, false)
}

func TestTemporalDiscoveryInventoryRulePinPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(f.ctx, `UPDATE public.zasp_inventory_identity_rules SET freshness_seconds=freshness_seconds+1 WHERE provider='aws'`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal72.current_ready()`).Scan(&ready); err != nil || ready {
		t.Fatal("mutable rule catalog accepted", ready, err)
	}
}

func TestTemporalDiscoveryOutboxOwnershipPostgres(t *testing.T) {
	f, _, _, _ := temporalDiscoveryPageFixture(t)
	if _, err := f.owner.Exec(f.ctx, `CREATE ROLE discovery72_old_outbox LOGIN INHERIT;GRANT zasp_outbox_worker TO discovery72_old_outbox`); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = "discovery72_old_outbox"
	shadow, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close(context.Background())
	var raw []byte
	if err := shadow.QueryRow(f.ctx, `SELECT public.zasp_execution_claim_outbox('discovery-jobs','legacy-transport','legacy-transport-token-0001',30,1)`).Scan(&raw); err == nil {
		t.Fatal("unregistered legacy transport claimed72-owned row")
	}
	cfg.User = f.registration.outbox
	transport, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close(context.Background())
	if err := transport.QueryRow(f.ctx, `SELECT zasp_temporal72.claim_outbox('discovery-jobs','registered-transport','registered-token-000000001',30,1)`).Scan(&raw); err != nil {
		t.Fatal("registered72 transport", err)
	}
	var envelope struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Items) != 1 {
		t.Fatalf("owned outbox claim: %s", raw)
	}
	id := envelope.Items[0].ID
	for _, q := range []string{
		`SELECT public.zasp_execution_heartbeat_outbox('discovery-jobs','registered-transport','registered-token-000000001',30,1)`,
		`SELECT public.zasp_execution_ack_outbox('discovery-jobs',$1,$2,$3,$4,'registered-transport','registered-token-000000001','sha256:'||repeat('a',64))`,
		`SELECT public.zasp_execution_retry_outbox('discovery-jobs',$1,$2,$3,$4,'registered-transport','registered-token-000000001',1,'queue_publish_unknown')`,
	} {
		args := []any{}
		if strings.Contains(q, "$1") {
			args = []any{replayOrg, replayWorkspace, replayEnvironment, id}
		}
		if err := shadow.QueryRow(f.ctx, q, args...).Scan(&raw); err == nil {
			t.Fatal("legacy transport mutated72-owned lease")
		}
	}
	if err := transport.QueryRow(f.ctx, `SELECT zasp_temporal72.ack_outbox('discovery-jobs',$1,$2,$3,$4,'registered-transport','registered-token-000000001','sha256:'||repeat('a',64))`, replayOrg, replayWorkspace, replayEnvironment, id).Scan(&raw); err != nil {
		t.Fatal("registered72 acknowledge", err)
	}
	// A row without72 run ownership keeps its old transport route.
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest) VALUES($1,$2,$3,'pid_72009999-0000-4000-8000-000000000001','discovery-jobs','retained-transport-key-0001',1,'{}',digest(convert_to('{}','UTF8'),'sha256'))`, replayOrg, replayWorkspace, replayEnvironment); err != nil {
		t.Fatal(err)
	}
	if err := shadow.QueryRow(f.ctx, `SELECT public.zasp_execution_claim_outbox('discovery-jobs','legacy-transport','legacy-transport-token-0002',30,1)`).Scan(&raw); err != nil {
		t.Fatal("retained outbox route", err)
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Items) != 1 || envelope.Items[0].ID != "pid_72009999-0000-4000-8000-000000000001" {
		t.Fatalf("retained row missing: %s", raw)
	}
}

func TestTemporalDiscoveryScheduleDeliveryPostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	runDiscoveryCLI(t, f, false)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.scheduler
	scheduler, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Close(f.ctx)
	args := []any{replayOrg, replayWorkspace, replayEnvironment, replaySchedule, replayIntegration}
	var raw []byte
	current := `SELECT zasp_temporal72.schedule_current($1,$2,$3,$4,$5)`
	ack := `SELECT zasp_temporal72.schedule_ack($1,$2,$3,$4,$5,$6)`
	due := `SELECT zasp_temporal72.reconcile_due($1,$2,$3,$4,$5)`
	if err := scheduler.QueryRow(f.ctx, current, args...).Scan(&raw); err != nil {
		t.Fatal("current desired", err)
	}
	if err := scheduler.QueryRow(f.ctx, due, args...).Scan(&raw); err == nil {
		t.Fatal("unacknowledged desired admitted")
	}
	if err := scheduler.QueryRow(f.ctx, ack, append(args, int64(2))...).Scan(&raw); err == nil {
		t.Fatal("foreign revision acknowledged")
	}
	if err := scheduler.QueryRow(f.ctx, ack, append(args, int64(1))...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.QueryRow(f.ctx, due, args...).Scan(&raw); err != nil {
		t.Fatal("startup oldest due repair", err)
	}
	if err := scheduler.QueryRow(f.ctx, due, args...).Scan(&raw); err != nil {
		t.Fatal("duplicate repair", err)
	}
	var count int
	var delivered int64
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_temporal72.runs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("repair admission count", count, err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT delivered_revision FROM zasp_temporal72.schedules WHERE id=$1`, replaySchedule).Scan(&delivered); err != nil || delivered != 1 {
		t.Fatal("repair not acknowledged", delivered, err)
	}
	// Begin another RPC then lose its response. Durable pending must survive
	// even though this same revision was previously delivered successfully.
	if err := scheduler.QueryRow(f.ctx, current, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT delivered_revision FROM zasp_temporal72.schedules WHERE id=$1`, replaySchedule).Scan(&delivered); err != nil || delivered != 0 {
		t.Fatal("ambiguous repeat lost pending repair", delivered, err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal72.schedules SET state='disabled',version=2 WHERE id=$1`, replaySchedule); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.QueryRow(f.ctx, ack, append(args, int64(1))...).Scan(&raw); err == nil {
		t.Fatal("stale response acknowledged current revision")
	}
	if err := scheduler.QueryRow(f.ctx, current, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.QueryRow(f.ctx, ack, append(args, int64(2))...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.QueryRow(f.ctx, due, args...).Scan(&raw); err != nil {
		t.Fatal("disabled repair", err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_temporal72.runs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("disabled repair admitted", count, err)
	}
	foreign := append([]any(nil), args...)
	foreign[2] = "pid_72009999-0000-4000-8000-000000000099"
	if err := scheduler.QueryRow(f.ctx, current, foreign...).Scan(&raw); err == nil {
		t.Fatal("foreign schedule read")
	}
	ref := orchestration.DiscoveryScheduleRef{OrganizationID: replayOrg, WorkspaceID: replayWorkspace, EnvironmentID: replayEnvironment, ScheduleID: replaySchedule, IntegrationID: replayIntegration}
	refRaw, _ := json.Marshal(ref)
	dsn := (&url.URL{Scheme: "postgres", User: url.User(cfg.User), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	command := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledScheduleSource$", "-count=1", "-v")
	command.Env = append(os.Environ(), "ZASP_P4B_SCHEDULER_DSN="+dsn, "ZASP_P4B_SCHEDULE_REF="+string(refRaw))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("installed schedule source", err)
	}
}

func TestTemporalDiscoveryStartDeliveryPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	var payload, raw []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT payload FROM public.zasp_discovery_outbox WHERE payload->>'job_id'=$1`, start.Ref.RunID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	args := []any{start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID, payload}
	query := `SELECT zasp_temporal72.start_delivery($1,$2,$3,$4,$5::jsonb)`
	if err := worker.QueryRow(f.ctx, query, args...).Scan(&raw); err != nil {
		t.Fatal("load queued start", err)
	}
	var got orchestration.DiscoveryStart
	if json.Unmarshal(raw, &got) != nil || got.Continuation == nil || !got.Continuation.Deadline.Equal(deadline) || got.Ref != start.Ref || got.InputDigest != start.InputDigest {
		t.Fatal("start changed scope or budget", string(raw))
	}
	args[4] = []byte(strings.Replace(string(payload), start.IntegrationID, "pid_72009999-0000-4000-8000-000000000099", 1))
	if err := worker.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("foreign queued input accepted")
	}
	args[4] = payload
	args[2] = "pid_72009999-0000-4000-8000-000000000099"
	if err := worker.QueryRow(f.ctx, query, args...).Scan(&raw); err == nil {
		t.Fatal("cross tenant queued input accepted")
	}
	start.Continuation = &orchestration.DiscoveryContinuation{Deadline: deadline}
	startRaw, _ := json.Marshal(start)
	cfg := f.owner.Config().Copy()
	cfg.User = f.registration.discovery
	dsn := (&url.URL{Scheme: "postgres", User: url.User(cfg.User), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	command := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledStartProcessor$", "-count=1", "-v")
	command.Env = append(os.Environ(), "ZASP_P4B_WORKER_DSN="+dsn, "ZASP_P4B_START="+string(startRaw), "ZASP_P4B_PAYLOAD="+string(payload))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("installed start processor", err)
	}
}

func discoveryTypedReadback(t *testing.T, f scheduleReplayFixture, syncID, state string, attempt int, retry bool) {
	t.Helper()
	cfg := f.owner.Config()
	dsn := (&url.URL{Scheme: "postgres", User: url.User(f.registration.api), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	ids, _ := json.Marshal([]string{replayOrg, replayWorkspace, replayEnvironment, replayIntegration, syncID})
	c := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledReadback$", "-count=1", "-v")
	c.Env = append(os.Environ(), "ZASP_P4B_API_DSN="+dsn, "ZASP_P4B_READBACK_IDS="+string(ids), "ZASP_P4B_EXPECT_STATUS="+state, "ZASP_P4B_EXPECT_ATTEMPT="+strconv.Itoa(attempt), "ZASP_P4B_EXPECT_RETRY="+strconv.FormatBool(retry))
	output, err := c.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("installed typed readback", err)
	}
}

func TestTemporalDiscoveryPublicReadbackPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	var syncID string
	if err := f.owner.QueryRow(f.ctx, `SELECT sync_id FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID).Scan(&syncID); err != nil {
		t.Fatal(err)
	}
	discoveryTypedReadback(t, f, syncID, "queued", 0, false)
	args := []any{replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, start.IntegrationID, start.InputDigest, deadline, int64(0), ""}
	var raw []byte
	prepare := `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		EffectID string `json:"effect_id"`
	}
	if json.Unmarshal(raw, &prepared) != nil || prepared.EffectID == "" {
		t.Fatal(string(raw))
	}
	discoveryTypedReadback(t, f, syncID, "running", 1, false)
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,'{"outcome":"retryable","retry_after_seconds":1}')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		CheckpointVersion int64  `json:"checkpoint_version"`
		ReceiptDigest     string `json:"receipt_digest"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		t.Fatal(string(raw))
	}
	discoveryTypedReadback(t, f, syncID, "queued", 1, true)
	args[7], args[8] = receipt.CheckpointVersion, receipt.ReceiptDigest
	// Child API checks take longer than the persisted one-second not-before.
	if err := worker.QueryRow(f.ctx, prepare, args...).Scan(&raw); err != nil {
		t.Fatal("fresh safe retry", err)
	}
	discoveryTypedReadback(t, f, syncID, "running", 1, false)
	if json.Unmarshal(raw, &prepared) != nil || prepared.EffectID == "" {
		t.Fatal(string(raw))
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.record_page($1,$2,$3,$4,$5,'{"outcome":"terminal"}')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, prepared.EffectID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,'terminal','')`, args[:7]...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	discoveryTypedReadback(t, f, syncID, "failed", 1, false)
}

func TestTemporalDiscoveryPreDispatchReadbackPostgres(t *testing.T) {
	f, worker, start, deadline := temporalDiscoveryPageFixture(t)
	var syncID string
	if err := f.owner.QueryRow(f.ctx, `SELECT sync_id FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID).Scan(&syncID); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.settle($1,$2,$3,$4,$5,$6,$7,'cancelled','')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, start.IntegrationID, start.InputDigest, deadline).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	discoveryTypedReadback(t, f, syncID, "failed", 0, false)
}

func TestTemporalDiscoveryCoexistencePostgres(t *testing.T) {
	f, worker, start, _ := temporalDiscoveryPageFixture(t)
	var payload, raw []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT payload FROM zasp_discovery_outbox WHERE payload->>'job_id'=$1`, start.Ref.RunID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	query := `SELECT zasp_temporal72.delivery_route($1,$2,$3,$4,$5::jsonb)`
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, payload).Scan(&raw); err != nil {
		t.Fatal("owned route", err)
	}
	var route struct {
		Ownership string                        `json:"ownership"`
		Start     *orchestration.DiscoveryStart `json:"start"`
	}
	if json.Unmarshal(raw, &route) != nil || route.Ownership != "temporal" || route.Start == nil {
		t.Fatal("72 ownership", string(raw))
	}
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, "pid_72809999-0000-4000-8000-000000000099", payload).Scan(&raw); err == nil {
		t.Fatal("missing ownership routed")
	}
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) SELECT organization_id,workspace_id,environment_id,job_id,'discovery',sync_id,'fixture-dual-ownership-728',request_digest FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID); err != nil {
		t.Fatal("dual ownership fixture", err)
	}
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, payload).Scan(&raw); err == nil {
		t.Fatal("ambiguous ownership routed")
	}
	if _, err := f.owner.Exec(f.ctx, `DELETE FROM zasp_discovery_jobs WHERE id=$1`, start.Ref.RunID); err != nil {
		t.Fatal(err)
	}
	legacyJob := "pid_72800002-0000-4000-8000-000000000002"
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,'pid_72800001-0000-4000-8000-000000000001',$6,'pid_72800003-0000-4000-8000-000000000003','retained-discovery-728',decode(repeat('ab',32),'hex'),'manual','parser_v1','tool_v1')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, legacyJob).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT payload FROM zasp_discovery_outbox WHERE payload->>'job_id'=$1`, legacyJob).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, legacyJob, payload).Scan(&raw); err != nil {
		t.Fatal("retained route", err)
	}
	route.Start = nil
	if json.Unmarshal(raw, &route) != nil || route.Ownership != "legacy" || route.Start != nil {
		t.Fatal("legacy ownership", string(raw))
	}
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, payload).Scan(&raw); err == nil {
		t.Fatal("foreign envelope routed")
	}
	cfg := f.owner.Config()
	dsns := map[string]string{}
	for role, login := range map[string]string{"zasp_discovery_worker": f.registration.discovery, "zasp_projection_risk_worker": f.registration.projectionRisk, "zasp_projection_graph_worker": f.registration.projectionGraph, "zasp_projection_search_worker": f.registration.projectionSearch, "zasp_outbox_worker": f.registration.outbox} {
		dsns[role] = (&url.URL{Scheme: "postgres", User: url.User(login), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	}
	encoded, _ := json.Marshal(dsns)
	child := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledRetainedAuthority$", "-count=1", "-v")
	child.Env = append(os.Environ(), "ZASP_P4B_RETAINED_DSNS="+string(encoded))
	output, err := child.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("retained constructor child", err)
	}
	if _, err := f.owner.Exec(f.ctx, `CREATE ROLE discovery72_projection_shadow LOGIN INHERIT;GRANT zasp_projection_risk_worker TO discovery72_projection_shadow`); err != nil {
		t.Fatal(err)
	}
	shadowConfig := f.owner.Config().Copy()
	shadowConfig.User = "discovery72_projection_shadow"
	shadow, err := pgx.ConnectConfig(f.ctx, shadowConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close(context.Background())
	var ready bool
	if err := shadow.QueryRow(f.ctx, `SELECT zasp_temporal72.retained_principal_ready('zasp_projection_risk_worker')`).Scan(&ready); err == nil && ready {
		t.Fatal("unregistered projection role accepted")
	}
	graphConfig := f.owner.Config().Copy()
	graphConfig.User = f.registration.projectionGraph
	graph, err := pgx.ConnectConfig(f.ctx, graphConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close(context.Background())
	if err := graph.QueryRow(f.ctx, `SELECT zasp_temporal72.retained_principal_ready('zasp_projection_risk_worker')`).Scan(&ready); err == nil && ready {
		t.Fatal("wrong registered projection role accepted")
	}
	if _, err := graph.Exec(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,clock_timestamp(),0,'')`, replayOrg, replayWorkspace, replayEnvironment, start.Ref.RunID, start.IntegrationID, start.InputDigest); err == nil {
		t.Fatal("projection role gained page authority")
	}
	if _, err := f.owner.Exec(f.ctx, `ALTER FUNCTION zasp_temporal72.delivery_route(text,text,text,text,jsonb) SECURITY INVOKER`); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(f.ctx, query, replayOrg, replayWorkspace, replayEnvironment, legacyJob, payload).Scan(&raw); err == nil {
		t.Fatal("invalid72 routed legacy job")
	}
	child = exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryInstalledRetainedAuthority$", "-count=1", "-v")
	child.Env = append(os.Environ(), "ZASP_P4B_RETAINED_DSNS="+string(encoded), "ZASP_P4B_EXPECT_REFUSED=true")
	output, err = child.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("invalid72 fallback child", err)
	}
}

func TestTemporalDiscoveryContinuationPostgres(t *testing.T) {
	f, _, start, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
		for _, q := range []string{
			`DELETE FROM zasp_discovery_connection_subjects WHERE integration_id=$1`,
			`UPDATE zasp_integrations SET kind='kubernetes',configuration='{"connection_reference":"ref:kubernetes/connection/customer-0001"}' WHERE id=$1`,
			`UPDATE zasp_integration_connections SET provider='kubernetes',connection_reference='ref:kubernetes/connection/customer-0001' WHERE integration_id=$1`,
			`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT i.organization_id,i.workspace_id,i.environment_id,i.id,c.id,'kubernetes','kubernetes_cluster','example.com/customer',c.version,digest(convert_to(i.configuration::text,'UTF8'),'sha256'),'reference' FROM zasp_integrations i JOIN zasp_integration_connections c ON c.integration_id=i.id WHERE i.id=$1`,
		} {
			if _, err := f.owner.Exec(f.ctx, q, replayIntegration); err != nil {
				t.Fatal("Kubernetes owned fixture", err)
			}
		}
	})
	// The bounded scale scenario owns a longer test context, not a new product
	// budget. Its persisted admission deadline remains exactly the original24h.
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Minute)
	defer cancel()
	start.Continuation = &orchestration.DiscoveryContinuation{Deadline: deadline}
	encoded, _ := json.Marshal(start)
	cfg := f.owner.Config()
	dsn := func(login string) string {
		return (&url.URL{Scheme: "postgres", User: url.User(login), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	}
	child := exec.CommandContext(ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryShippedContinuation$", "-count=1", "-timeout", "31m", "-v")
	child.Env = append(os.Environ(), "ZASP_P4B_CONTINUATION=true", "ZASP_P4B_WORKER_DSN="+dsn(f.registration.discovery), "ZASP_P4B_OUTBOX_DSN="+dsn(f.registration.outbox), "ZASP_P4B_START="+string(encoded))
	child.Stdout, child.Stderr = os.Stdout, os.Stdout
	err := child.Run()
	var state []byte
	diagnosticCtx, diagnosticCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer diagnosticCancel()
	if qerr := f.owner.QueryRow(diagnosticCtx, `SELECT jsonb_build_object('run',(SELECT jsonb_build_object('state',state,'checkpoint',checkpoint_version,'deadline',deadline) FROM zasp_temporal72.runs WHERE job_id=$1),'pages',(SELECT count(*) FROM zasp_temporal72.page_effects WHERE job_id=$1),'checkpoint',(SELECT jsonb_build_object('version',version,'cursor',cursor,'generation',(SELECT generation FROM zasp_discovery_generation_reservations WHERE sync_id=(SELECT sync_id FROM zasp_temporal72.runs WHERE job_id=$1))) FROM zasp_temporal72.checkpoints WHERE job_id=$1))`, start.Ref.RunID).Scan(&state); qerr == nil {
		t.Log("continuation persisted state", string(state))
	}
	if err != nil {
		t.Fatal("real continuation child", err)
	}
	var valid bool
	if err := f.owner.QueryRow(ctx, `SELECT r.state='succeeded' AND r.deadline=$2 AND r.checkpoint_version=266 AND c.version=267 AND c.cursor->>'value' LIKE 'kubernetes:complete:%' AND (SELECT count(DISTINCT effect_id) FROM zasp_temporal72.page_effects WHERE job_id=$1)=267 AND (SELECT count(*) FROM zasp_discovery_jobs)=0 AND (SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE generation=1 AND jsonb_array_length(entities)=258)=1 AND (SELECT count(*) FROM zasp_projection_work WHERE input_digest IS NOT NULL)=3 FROM zasp_temporal72.runs r JOIN zasp_temporal72.checkpoints c USING(organization_id,workspace_id,environment_id,job_id) WHERE r.job_id=$1`, start.Ref.RunID, deadline).Scan(&valid); err != nil || !valid {
		t.Fatal("persisted continuation/cursor/generation", valid, err)
	}
}

func TestTemporalDiscoveryShippedRuntimePostgres(t *testing.T) {
	temporalDiscoveryShippedRuntime(t, false)
}

func TestTemporalDiscoveryTenantIsolationPostgres(t *testing.T) {
	temporalDiscoveryShippedRuntime(t, true)
}

func temporalDiscoveryShippedRuntime(t *testing.T, isolation bool) {
	t.Helper()
	f, _, start, deadline := temporalDiscoveryPageFixtureWith(t, func(f scheduleReplayFixture) {
		for _, q := range []string{`UPDATE zasp_integrations SET configuration=jsonb_set(configuration,'{external_id_reference}','"ref:aws/external-id/customer-0001"') WHERE id=$1`, `UPDATE zasp_integration_connections SET connection_reference='ref:aws/external-id/customer-0001' WHERE integration_id=$1`, `UPDATE zasp_discovery_connection_subjects SET configuration_digest=(SELECT digest(convert_to(configuration::text,'UTF8'),'sha256') FROM zasp_integrations WHERE id=$1) WHERE integration_id=$1`} {
			if _, err := f.owner.Exec(f.ctx, q, replayIntegration); err != nil {
				t.Fatal(err)
			}
		}
	})
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'discovery-org','discovery-member','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Discovery','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	foreignOrg, foreignPrincipal := "pid_60000009-0000-4000-8000-000000000009", "pid_60000008-0000-4000-8000-000000000008"
	if isolation {
		// Same connector name AND integration/connection/schedule IDs in another
		// tenant. Only full scoped identity may separate these durable records.
		for _, q := range []string{
			`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) SELECT $2,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state FROM zasp_integrations WHERE organization_id=$1`,
			`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,verified_at) SELECT $2,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,verified_at FROM zasp_integration_connections WHERE organization_id=$1`,
			`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT $2,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source FROM zasp_discovery_connection_subjects WHERE organization_id=$1`,
			`INSERT INTO zasp_discovery_schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at) SELECT $2,workspace_id,environment_id,id,integration_id,cadence_seconds,'disabled',next_run_at FROM zasp_discovery_schedules WHERE organization_id=$1`,
			`INSERT INTO zasp_temporal72.schedules(organization_id,workspace_id,environment_id,id,integration_id,cadence_seconds,state,next_run_at,anchor,version,created_at,updated_at) SELECT $2,workspace_id,environment_id,id,integration_id,cadence_seconds,'disabled',next_run_at,anchor,version,created_at,updated_at FROM zasp_temporal72.schedules WHERE organization_id=$1`,
		} {
			if _, err := f.owner.Exec(f.ctx, q, replayOrg, foreignOrg); err != nil {
				t.Fatal("identically named tenant fixture", err)
			}
		}
		if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'discovery-other-org','discovery-other-member','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Discovery','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, foreignOrg, replayWorkspace, replayEnvironment, foreignPrincipal); err != nil {
			t.Fatal(err)
		}
	}
	// An imported historical schedule whose next cadence falls shortly ahead.
	// Keep the nonzero microsecond phase to exercise actual Schedule evidence.
	if _, err := f.owner.Exec(f.ctx, `WITH due AS(SELECT date_trunc('second',clock_timestamp())+interval '45 seconds 123456 microseconds' v) UPDATE zasp_temporal72.schedules SET cadence_seconds=300,anchor=due.v-interval '300 seconds',next_run_at=due.v FROM due WHERE id=$1 AND organization_id=$2`, replaySchedule, replayOrg); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT payload FROM zasp_discovery_outbox WHERE payload->>'job_id'=$1`, start.Ref.RunID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	start.Continuation = &orchestration.DiscoveryContinuation{Deadline: deadline}
	encoded, _ := json.Marshal(start)
	cfg := f.owner.Config()
	dsn := (&url.URL{Scheme: "postgres", User: url.User(f.registration.discovery), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	child := exec.CommandContext(f.ctx, "go", "test", "../agentsec-worker", "-run", "^TestProductDiscoveryShippedTemporalRuntime$", "-count=1", "-v")
	outboxDSN := (&url.URL{Scheme: "postgres", User: url.User(f.registration.outbox), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	apiDSN := (&url.URL{Scheme: "postgres", User: url.User(f.registration.api), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	schedulerDSN := (&url.URL{Scheme: "postgres", User: url.User(f.registration.scheduler), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	ids, _ := json.Marshal([]string{replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration})
	child.Env = append(os.Environ(), "ZASP_P4B_WORKER_DSN="+dsn, "ZASP_P4B_OUTBOX_DSN="+outboxDSN, "ZASP_P4B_API_DSN="+apiDSN, "ZASP_P4B_SCHEDULER_DSN="+schedulerDSN, "ZASP_P4B_SCHEDULE_ID="+replaySchedule, "ZASP_P4B_MUTATION_IDS="+string(ids), "ZASP_P4B_START="+string(encoded), "ZASP_P4B_PAYLOAD="+string(payload))
	if isolation {
		foreignIDs, _ := json.Marshal([]string{foreignOrg, replayWorkspace, replayEnvironment, foreignPrincipal, replayIntegration})
		child.Env = append(child.Env, "ZASP_P4B_FOREIGN_IDS="+string(foreignIDs))
	}
	child.Stdout, child.Stderr = os.Stdout, os.Stdout
	err := child.Run()
	if err != nil {
		var diagnostic []byte
		if queryErr := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('runs',(SELECT jsonb_agg(jsonb_build_object('job',job_id,'state',state,'checkpoint',checkpoint_version)) FROM zasp_temporal72.runs),'pages',(SELECT jsonb_agg(jsonb_build_object('job',job_id,'result',result)) FROM zasp_temporal72.page_effects),'apply',(SELECT jsonb_agg(jsonb_build_object('job',job_id,'result',result)) FROM zasp_temporal72.apply_effects))`).Scan(&diagnostic); queryErr == nil {
			t.Log("owned receipt diagnostics", string(diagnostic))
		}
		t.Fatal("shipped runtime child", err)
	}
	var valid bool
	var counts []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('syncs',(SELECT jsonb_agg(jsonb_build_object('id',id,'state',state,'attempt',attempt,'discovered_count',discovered_count,'snapshot_id',snapshot_id,'trigger',trigger_kind)) FROM zasp_discovery_syncs),'snapshots',(SELECT jsonb_agg(jsonb_build_object('id',snapshot_id,'entities',jsonb_array_length(entities),'generation',generation)) FROM zasp_discovery_snapshot_inputs),'projections',(SELECT count(*) FROM zasp_projection_work WHERE input_digest IS NOT NULL),'outbox',(SELECT jsonb_agg(jsonb_build_object('id',id,'job',payload->>'job_id','state',state)) FROM zasp_discovery_outbox),'jobs',(SELECT count(*) FROM zasp_discovery_jobs))`).Scan(&counts); err != nil {
		t.Fatal("persisted final diagnostics", err)
	}
	t.Log("persisted final receipt identities/counts", string(counts))
	wantRuns, wantManual, wantProjections := 3, 1, 9
	if isolation {
		wantRuns, wantManual, wantProjections = 4, 2, 12
	}
	if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_discovery_jobs)=0 AND (SELECT count(*) FROM zasp_discovery_syncs WHERE state='succeeded' AND attempt=1)=$1 AND (SELECT count(*) FROM zasp_discovery_syncs WHERE trigger_kind='manual')=$2 AND (SELECT count(*) FROM zasp_discovery_syncs WHERE discovered_count=0)=2 AND (SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE jsonb_array_length(entities)=3)=$1 AND (SELECT count(*) FROM zasp_projection_work WHERE input_digest IS NOT NULL)=$3 AND (SELECT count(*) FROM zasp_discovery_outbox WHERE state='published')=$1`, wantRuns, wantManual, wantProjections).Scan(&valid); err != nil || !valid {
		t.Fatal("shipped typed inventory/evidence", valid, err)
	}
	if isolation {
		if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(DISTINCT display_name) FROM zasp_integrations)=1 AND (SELECT count(DISTINCT id) FROM zasp_temporal72.schedules)=1 AND (SELECT count(*) FROM zasp_temporal72.schedules)=2 AND (SELECT count(*) FROM zasp_discovery_snapshots WHERE organization_id=$1 AND generation=1)=1 AND (SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE organization_id=$1 AND jsonb_array_length(entities)=3)=1 AND (SELECT count(*) FROM zasp_temporal72.runs WHERE organization_id=$1)=1`, foreignOrg).Scan(&valid); err != nil || !valid {
			t.Fatal("tenant projection alias", valid, err)
		}
	}
}
