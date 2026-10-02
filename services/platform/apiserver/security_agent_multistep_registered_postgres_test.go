package apiserver

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

// Saved restoration definitions are executable migration evidence. A writer
// must finish before retry/down checks readiness, not while down drops them.
func TestSecurityAgentMultistepRegisteredSavedDefinitionWaitPostgres(t *testing.T) {
	for _, direction := range []string{"down", "retry"} {
		t.Run(direction, func(t *testing.T) {
			multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, _, _, _, _, _ string) {
				runner := precisionMigrationRunner(t, owner)
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				writer, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Rollback(ctx)
				if _, err = writer.Exec(ctx, `UPDATE zasp_sa_multistep_prior.functions SET definition=definition||E'\n-- concurrent saved-definition drift' WHERE signature='public.zasp_sa_multistep_readiness(text,text)'`); err != nil {
					t.Fatal(err)
				}
				const savedRowsSQL = `SELECT jsonb_agg(to_jsonb(f) ORDER BY signature)::text FROM zasp_sa_multistep_prior.functions f`
				var savedRows string
				if err = writer.QueryRow(ctx, savedRowsSQL).Scan(&savedRows); err != nil {
					t.Fatal(err)
				}
				contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				attemptCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				var pid int32
				if err = contender.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					t.Fatal(err)
				}
				migration := precisionMigrationRunner(t, contender)
				done := make(chan error, 1)
				go func() {
					if direction == "down" {
						done <- migration.DownProductionSecurityAgentMultistep(attemptCtx)
					} else {
						done <- migration.UpProductionSecurityAgentMultistep(attemptCtx)
					}
				}()
				joined := false
				defer func() {
					cancel()
					if !joined {
						<-done
					}
					contender.Close(ctx)
				}()
				waiting := false
				var waitQuery string
				var result error
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					select {
					case result = <-done:
						joined = true
					default:
					}
					if joined {
						break
					}
					if err = writer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_sa_multistep_prior.functions'::regclass AND mode IN('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock') AND NOT granted)`, pid).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						if err = writer.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waitQuery); err != nil {
							t.Fatal(err)
						}
						break
					}
				}
				if !waiting || !strings.HasPrefix(waitQuery, "LOCK TABLE ") || !strings.Contains(waitQuery, "zasp_sa_multistep_prior.functions") {
					t.Errorf("%s did not wait for saved evidence before readiness (waiting=%t completed=%t)", direction, waiting, joined)
				}
				if err = writer.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if !joined {
					result = <-done
					joined = true
				}
				if !errors.Is(result, migrations.ErrInvalidState) {
					t.Errorf("%s accepted committed saved-definition drift: %v", direction, result)
				}
				if version, err := runner.Version(ctx); err != nil || version != 61 {
					t.Errorf("registered identity lost: version=%d err=%v", version, err)
				}
				var present bool
				if err = owner.QueryRow(ctx, `SELECT to_regclass('zasp_sa_multistep_prior.functions') IS NOT NULL AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_security_agent_multistep_checksum' AND value=$1) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_security_agent_multistep_fingerprint' AND value=$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&present); err != nil || !present {
					t.Fatal("registered restoration evidence or metadata discarded", present, err)
				}
				var actualRows string
				if err = owner.QueryRow(ctx, savedRowsSQL).Scan(&actualRows); err != nil || actualRows != savedRows {
					t.Fatal("committed saved definitions changed or discarded", err)
				}
			})
		})
	}
}

type registeredMultistepRunner interface {
	UpProductionSecurityAgentMultistep(context.Context) error
	DownProductionSecurityAgentMultistep(context.Context) error
}

type registeredMultistepDatabase struct {
	connection *pgx.Conn
	t          *testing.T
	isolation  pgx.TxIsoLevel
	outer      pgx.Tx
}

func (d *registeredMultistepDatabase) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	if d.outer != nil {
		return d.outer.QueryRow(ctx, q, args...)
	}
	return d.connection.QueryRow(ctx, q, args...)
}
func (d *registeredMultistepDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	var tx pgx.Tx
	var err error
	if d.outer != nil {
		tx, err = d.outer.Begin(ctx)
	} else {
		tx, err = d.connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: d.isolation})
	}
	if err != nil {
		return nil, err
	}
	return &registeredMultistepTransaction{integrationMigrationTransaction: integrationMigrationTransaction{transaction: tx}, t: d.t}, nil
}

type registeredMultistepTransaction struct {
	integrationMigrationTransaction
	t *testing.T
}

func (tx *registeredMultistepTransaction) Exec(ctx context.Context, q string, args ...any) error {
	err := tx.integrationMigrationTransaction.Exec(ctx, q, args...)
	if err != nil {
		tx.t.Log("migration SQL refusal:", err)
	}
	return err
}
func TestSecurityAgentMultistepRegisteredPostgres(t *testing.T) {
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, o, w, e, _, _ string) {
		runner, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t})
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		methods, ok := any(runner).(registeredMultistepRunner)
		if !ok {
			t.Fatal("release61 Runner unregistered")
		}
		m := migrations.ProductionSecurityAgentMultistep()
		snapshot := func() string {
			t.Helper()
			var result string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) ORDER BY n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind='f' AND (n.nspname LIKE 'zasp_%' OR n.nspname='public' AND p.proname LIKE 'zasp_%')),'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY version) FROM zasp_schema_versions v),'metadata',(SELECT jsonb_agg(to_jsonb(m) ORDER BY key) FROM zasp_schema_metadata m))::text`).Scan(&result); err != nil {
				t.Fatal(err)
			}
			return result
		}
		before := snapshot()
		for name, drift := range map[string]string{
			"up-predecessor-checksum": `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=60`,
			"up-predecessor-metadata": `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_discovery_schedule_replay_checksum'`,
			"up-missing-predecessor":  `DELETE FROM zasp_schema_versions WHERE version=60`,
		} {
			t.Run(name, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, drift); err != nil {
					t.Fatal(err)
				}
				r, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, outer: tx})
				if err = r.UpProductionSecurityAgentMultistep(ctx); err == nil {
					t.Fatal("inexact predecessor accepted")
				}
				var absent bool
				if err = tx.QueryRow(ctx, `SELECT to_regclass('zasp_sa_multistep_receipts') IS NULL`).Scan(&absent); err != nil || !absent {
					t.Fatal("failed up left candidate", err)
				}
			})
		}
		var registered string
		for i := 0; i < 2; i++ {
			if err := methods.UpProductionSecurityAgentMultistep(ctx); err != nil {
				t.Fatal("registered up/retry", err)
			}
			if i == 0 {
				registered = snapshot()
			} else if snapshot() != registered {
				t.Fatal("retry changed registered function/ACL/identity bytes")
			}
		}
		for _, pair := range [][2]string{{strings.Repeat("0", 64), migrations.SecurityAgentMultistepRegisteredFingerprint()}, {m.Checksum(), migrations.SecurityAgentMultistepFingerprint()}} {
			var got bool
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, pair[0], pair[1]).Scan(&got); err != nil || got {
				t.Fatal("wrong caller identity ready", got, err)
			}
		}
		var ready, legacy, single bool
		var fp string
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2),zasp_discovery_schedule_replay_readiness($3,$4),to_regclass('zasp_sa_multistep_metadata') IS NULL AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_security_agent_multistep_checksum' AND value=$1) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_security_agent_multistep_fingerprint' AND value=$2),zasp_sa_multistep_registered_live_fingerprint()`, m.Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&ready, &legacy, &single, &fp); err != nil || !ready || legacy || !single {
			t.Fatalf("readiness=%t legacy=%t single=%t fp=%s err=%v", ready, legacy, single, fp, err)
		}
		if v, err := runner.Version(ctx); err != nil || v != 61 {
			t.Fatal("version", v, err)
		}
		if err := runner.DownProductionDiscoveryScheduleReplay(ctx); err == nil {
			t.Fatal("release60 rollback accepted61")
		}
		t.Run("retry-locks-retained-evidence", func(t *testing.T) {
			blocker, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(ctx)
			if _, err = blocker.Exec(ctx, `LOCK TABLE zasp_sa_multistep_receipts IN ACCESS SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer contender.Close(ctx)
			r := precisionMigrationRunner(t, contender)
			if err = r.UpProductionSecurityAgentMultistep(ctx); err == nil {
				t.Fatal("retry skipped evidence lock")
			}
		})
		for _, isolation := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.Serializable} {
			r, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, isolation: isolation})
			if err := r.UpProductionSecurityAgentMultistep(ctx); err == nil {
				t.Fatal("retry can retain a stale pre-lock snapshot", isolation)
			}
			if err := r.DownProductionSecurityAgentMultistep(ctx); err == nil {
				t.Fatal("unsafe isolation accepted", isolation)
			}
		}
		for _, direction := range []string{"up", "down"} {
			t.Run(direction+"-rechecks-after-advisory-wait", func(t *testing.T) {
				blocker, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(ctx)
				if _, err = blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`); err != nil {
					t.Fatal(err)
				}
				contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer contender.Close(ctx)
				var pid int32
				if err = contender.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					t.Fatal(err)
				}
				r := precisionMigrationRunner(t, contender)
				done := make(chan error, 1)
				go func() {
					if direction == "up" {
						done <- r.UpProductionSecurityAgentMultistep(ctx)
					} else {
						done <- r.DownProductionSecurityAgentMultistep(ctx)
					}
				}()
				waiting := false
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					if err = blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
				}
				if !waiting {
					t.Fatal("contender did not wait for schema admission")
				}
				if err = blocker.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err == nil {
					t.Fatal("post-wait drift accepted")
				}
				if _, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_multistep_checksum'`, m.Checksum()); err != nil {
					t.Fatal(err)
				}
			})
		}
		for name, drift := range map[string]string{
			"current-checksum":     `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`,
			"current-name":         `UPDATE zasp_schema_versions SET name='drift' WHERE version=61`,
			"predecessor-checksum": `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=60`,
			"later-release":        `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(62,'later',repeat('0',64))`,
			"shared-checksum":      `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`,
			"shared-fingerprint":   `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_fingerprint'`,
			"ancestry-snapshot":    `UPDATE zasp_sa_multistep_prior.functions SET definition=definition||E'\n-- drift' WHERE signature='public.zasp_sa_multistep_readiness(text,text)'`,
			"ancestry-live":        `ALTER FUNCTION zasp_schedule_replay_prior.predecessor_ready(text,text) IMMUTABLE`,
			"predecessor-object":   `ALTER TABLE zasp_discovery_schedule_runs ADD COLUMN drift text`,
			"receipt-rls":          `ALTER TABLE zasp_sa_multistep_receipts DISABLE ROW LEVEL SECURITY`,
			"receipt-grant":        `GRANT SELECT ON zasp_sa_multistep_receipts TO PUBLIC`,
			"candidate-identity":   `CREATE TABLE zasp_sa_multistep_metadata(singleton boolean,checksum text,fingerprint text)`,
		} {
			t.Run(name, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, drift); err != nil {
					t.Fatal(err)
				}
				var got bool
				if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, m.Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&got); err != nil || got {
					t.Fatal("drift readiness", got, err)
				}
				r, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, outer: tx})
				if err = r.UpProductionSecurityAgentMultistep(ctx); err == nil {
					t.Fatal("drift retry accepted")
				}
				if err = r.DownProductionSecurityAgentMultistep(ctx); err == nil {
					t.Fatal("drift down accepted")
				}
			})
		}
		// Seed one retained class at a time. Owner-only replica mode bypasses FK
		// prerequisites and insertion triggers without changing catalog identity;
		// another marker must not mask the class under test.
		for name, seed := range map[string]string{
			"definition-marker":  `INSERT INTO zasp_sa_multistep_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version) VALUES('o','w','e','d',1)`,
			"run-marker":         `INSERT INTO zasp_sa_multistep_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,plan_hash) VALUES('o','w','e','r','d',1,decode(repeat('11',32),'hex'))`,
			"dependency":         `INSERT INTO zasp_sa_multistep_dependencies(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,step_index,input_digest,predecessor_step_id,predecessor_step_index,predecessor_input_digest,required_receipt_kind) VALUES('o','w','e','r',decode(repeat('11',32),'hex'),'s1',1,decode(repeat('44',32),'hex'),'s0',0,decode(repeat('33',32),'hex'),'temporary_policy_applied.v1')`,
			"policy-receipt":     `INSERT INTO zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body) VALUES('o','w','e','r',decode(repeat('11',32),'hex'),'s0','create_temporary_policy',decode(repeat('33',32),'hex'),decode(repeat('55',32),'hex'),'temporary_policy_applied.v1',1,'{"deployment_id":"d","control_id":"c","control_version":1,"outcome_id":"o","applied_at":"2026-09-20T01:00:00Z","expires_at":"2026-09-20T02:00:00Z"}')`,
			"test-receipt":       `INSERT INTO zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body) VALUES('o','w','e','r',decode(repeat('11',32),'hex'),'s1','run_test',decode(repeat('44',32),'hex'),decode(repeat('66',32),'hex'),'existing_test_settled.v1',1,jsonb_build_object('invocation_id','i','snapshot_digest',repeat('a',64),'proof_digest',repeat('b',64),'settlement_generation',1,'outcome','not_reproduced'))`,
			"definition-config":  `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version,body,plan_catalog_version) VALUES('o','w','e','d',1,'{"max_steps":2}','v1')`,
			"definition-history": `INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) VALUES('o','w','e','d',1,'draft','{"max_steps":2}',decode(repeat('11',32),'hex'),'actor')`,
			"plan-evidence":      `INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES('o','w','e','r','d',1,decode(repeat('22',32),'hex'),'v1','{"steps":[{},{}]}',decode(repeat('11',32),'hex'),now()+interval '1 hour')`,
			"step-evidence":      `INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES('o','w','e','r','s1',1,'run_test',decode(repeat('44',32),'hex'),'allow','queued')`,
			"completed-audit":    `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES('o','w','e','audit','correlation','actor','ordered_plan_completed',decode(repeat('ab',32),'hex'),'{"contract_version":61}')`,
		} {
			t.Run(name, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				seed = strings.NewReplacer("'o'", "'"+o+"'", "'w'", "'"+w+"'", "'e'", "'"+e+"'").Replace(seed)
				if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica;`+seed+`;SET LOCAL session_replication_role=origin`); err != nil {
					t.Fatal(err)
				}
				var got bool
				if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, m.Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&got); err != nil || !got {
					t.Fatal("fixture schema drifted", got, err)
				}
				r, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, outer: tx})
				if err = r.DownProductionSecurityAgentMultistep(ctx); err == nil {
					t.Fatal("retained evidence discarded")
				}
				if v, err := r.Version(ctx); err != nil || v != 61 {
					t.Fatal("refusal lost registered identity", v, err)
				}
			})
		}
		if err := methods.DownProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal("registered down", err)
		}
		if snapshot() != before {
			t.Fatal("clean down did not restore exact release60 function/ACL/identity bytes")
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_discovery_schedule_replay_readiness($1,$2),zasp_discovery_schedule_replay_live_fingerprint(),to_regclass('zasp_sa_multistep_receipts') IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key LIKE 'production_security_agent_multistep_%')`, migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&ready, &fp, &single); err != nil || !ready || !single || fp != migrations.DiscoveryScheduleReplayFingerprint() {
			t.Fatal("release60 not restored", ready, single, fp, err)
		}
	})
}
