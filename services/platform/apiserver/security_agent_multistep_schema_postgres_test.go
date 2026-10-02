package apiserver

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentMultistepSchemaPostgres(t *testing.T) {
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, o, w, e, _, _ string) {
		scopeSQL := strings.NewReplacer("'o'", "'"+o+"'", "'w'", "'"+w+"'", "'e'", "'"+e+"'").Replace
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if err := runner.UpProductionDiscoveryScheduleReplay(ctx); err != nil {
			t.Fatal(err)
		}
		candidate := migrations.ProductionSecurityAgentMultistep()
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, scopeSQL(q), args...); err != nil {
				t.Fatal(err)
			}
		}
		apply := func(q string) error {
			tx, err := owner.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, scopeSQL(q)); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
		requireRefusal := func(err error, codes ...string) {
			t.Helper()
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || !slices.Contains(codes, pg.Code) {
				t.Fatalf("wrong refusal, expected %v: %v", codes, err)
			}
		}
		ready := func(want bool) {
			t.Helper()
			var got bool
			var fp string
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_live_fingerprint(),zasp_sa_multistep_readiness($1,$2)`, candidate.Checksum(), migrations.SecurityAgentMultistepFingerprint()).Scan(&fp, &got); err != nil || got != want {
				t.Fatalf("candidate readiness=%t want=%t fingerprint=%s error=%v", got, want, fp, err)
			}
		}
		if err := apply(candidate.UpSQL()); err != nil {
			t.Fatal("candidate install", err)
		}
		ready(true)
		var legacy bool
		var version int
		if err := owner.QueryRow(ctx, `SELECT zasp_discovery_schedule_replay_readiness($1,$2),(SELECT max(version) FROM zasp_schema_versions)`, migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&legacy, &version); err != nil || !legacy || version != 60 {
			t.Fatal("candidate changed predecessor", legacy, version, err)
		}
		for _, pair := range [][2]string{{strings.Repeat("0", 64), migrations.SecurityAgentMultistepFingerprint()}, {candidate.Checksum(), strings.Repeat("0", 64)}} {
			var got bool
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, pair[0], pair[1]).Scan(&got); err != nil || got {
				t.Fatal("caller identity accepted", err)
			}
		}
		for _, table := range []string{"metadata", "definitions", "runs", "dependencies", "receipts"} {
			var secured bool
			if err := owner.QueryRow(ctx, `SELECT relowner='zasp_discovery_authority'::regrole AND relrowsecurity AND relforcerowsecurity AND NOT has_table_privilege('zasp_security_agent_api',oid,'SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('zasp_security_agent_worker',oid,'SELECT,INSERT,UPDATE,DELETE') FROM pg_class WHERE oid=$1::regclass`, "zasp_sa_multistep_"+table).Scan(&secured); err != nil || !secured {
				t.Fatal("unsafe table", table, err)
			}
		}
		for _, drift := range []string{`ALTER TABLE zasp_sa_multistep_receipts DISABLE ROW LEVEL SECURITY`, `GRANT SELECT ON zasp_sa_multistep_receipts TO PUBLIC`, `ALTER TABLE zasp_sa_multistep_dependencies ADD COLUMN unexpected text`, `ALTER TABLE zasp_sa_multistep_receipts DISABLE TRIGGER USER`, `UPDATE zasp_sa_multistep_metadata SET checksum=repeat('0',64)`, `UPDATE zasp_schema_metadata SET value='drift' WHERE key='production_discovery_schedule_replay_checksum'`} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, drift); err != nil {
				t.Fatal(err)
			}
			var got bool
			if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, candidate.Checksum(), migrations.SecurityAgentMultistepFingerprint()).Scan(&got); err != nil || got {
				t.Fatal("drift ready", drift, err)
			}
			if _, err = tx.Exec(ctx, candidate.DownSQL()); err == nil {
				t.Fatal("drift rollback accepted", drift)
			}
			requireRefusal(err, "55000")
			tx.Rollback(ctx)
		}
		for _, retained := range []string{
			`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version,body,plan_catalog_version) VALUES('o','w','e','unused',1,'{}','v1'); INSERT INTO zasp_sa_multistep_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version) VALUES('o','w','e','unused',1)`,
			`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version,body,plan_catalog_version) VALUES('o','w','e','configured',1,'{"max_steps":2}','v1')`,
			`INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES('o','w','e','audit','correlation','actor','ordered_plan_completed',decode(repeat('ab',32),'hex'),'{"contract_version":61}')`,
		} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, scopeSQL(retained)); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, candidate.DownSQL())
			tx.Rollback(ctx)
			if err == nil {
				t.Fatal("isolated retained marker/configuration/evidence discarded", retained)
			}
			requireRefusal(err, "55000")
		}
		// A competing schema owner must fence rollback before any object is removed.
		blocker, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			t.Fatal(err)
		}
		contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := contender.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = attempt.Exec(ctx, candidate.DownSQL())
		attempt.Rollback(ctx)
		contender.Close(ctx)
		blocker.Rollback(ctx)
		requireRefusal(err, "55P03")
		ready(true)
		if err := apply(candidate.DownSQL()); err != nil {
			t.Fatal("clean down", err)
		}
		var removed bool
		if err := owner.QueryRow(ctx, `SELECT to_regclass('public.zasp_sa_multistep_receipts') IS NULL AND to_regclass('public.zasp_sa_multistep_metadata') IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key LIKE 'production_security_agent_multistep_%')`).Scan(&removed); err != nil || !removed {
			t.Fatal("candidate residue", err)
		}
		if err := apply(candidate.UpSQL()); err != nil {
			t.Fatal("second install", err)
		}
		// These owner-seeded rows exercise persistence constraints, not public execution proof.
		exec(`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version,body,plan_catalog_version) VALUES('o','w','e','d',1,'{}','v1');
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,plan_hash) VALUES('o','w','e','r','d',1,'t','actor','running',decode(repeat('11',32),'hex'));
 INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES('o','w','e','r','d',1,decode(repeat('22',32),'hex'),'v1','{"steps":[{},{}]}',decode(repeat('11',32),'hex'),now()+interval '1 hour');
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES('o','w','e','r','s0',0,'create_temporary_policy',decode(repeat('33',32),'hex'),'allow','authorized'),('o','w','e','r','s1',1,'run_test',decode(repeat('44',32),'hex'),'approval_required','queued')`)
		for _, state := range []string{"running", "remediated"} {
			exec(`UPDATE zasp_security_agent_runs SET state=$1 WHERE run_id='r'`, state)
			if err := apply(candidate.DownSQL()); err == nil {
				t.Fatal("retained multistep work discarded", state)
			}
		}
		exec(`INSERT INTO zasp_sa_multistep_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version) VALUES('o','w','e','d',1)`)
		if err := apply(candidate.DownSQL()); err == nil {
			t.Fatal("configured contract discarded")
		}
		exec(`INSERT INTO zasp_sa_multistep_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,plan_hash) VALUES('o','w','e','r','d',1,decode(repeat('11',32),'hex'))`)
		dependency := `INSERT INTO zasp_sa_multistep_dependencies(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,step_index,input_digest,predecessor_step_id,predecessor_step_index,predecessor_input_digest,required_receipt_kind) VALUES('o','w','e','r',decode(repeat('11',32),'hex'),'s1',1,decode(repeat('44',32),'hex'),'s0',0,decode(repeat('33',32),'hex'),'temporary_policy_applied.v1')`
		for _, bad := range []string{strings.Replace(dependency, "repeat('33'", "repeat('55'", 1), strings.Replace(dependency, "'s0',0", "'s1',0", 1), strings.Replace(dependency, "'o','w','e','r'", "'foreign','w','e','r'", 1), strings.Replace(dependency, "temporary_policy_applied.v1", "existing_test_settled.v1", 1), strings.Replace(dependency, "'s1',1", "'s1',2", 1), strings.Replace(dependency, "repeat('11'", "repeat('55'", 1)} {
			requireRefusal(apply(bad), "23503", "23514")
		}
		exec(dependency)
		policyBody := `{"deployment_id":"deployment","control_id":"control","control_version":1,"outcome_id":"outcome","applied_at":"2026-09-20T01:00:00Z","expires_at":"2026-09-20T02:00:00Z"}`
		receipt := `INSERT INTO zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body) VALUES('o','w','e','r',decode(repeat('11',32),'hex'),'s0','create_temporary_policy',decode(repeat('33',32),'hex'),decode(repeat('55',32),'hex'),'temporary_policy_applied.v1',1,'` + policyBody + `')`
		for _, bad := range []string{strings.Replace(receipt, policyBody, `{}`, 1), strings.Replace(receipt, `"control_version":1`, `"control_version":null`, 1), strings.Replace(receipt, `"control_version":1`, `"control_version":"1"`, 1), strings.Replace(receipt, "temporary_policy_applied.v1", "existing_test_settled.v1", 1), strings.Replace(receipt, "repeat('33'", "repeat('44'", 1), strings.Replace(receipt, `02:00:00Z`, `00:00:00Z`, 1), strings.Replace(receipt, policyBody, `{"state":"succeeded"}`, 1), strings.Replace(receipt, `"deployment_id":"deployment"`, `"deployment_id":"`+strings.Repeat("x", 9000)+`"`, 1), strings.Replace(receipt, `"control_version":1`, `"extra":true,"control_version":1`, 1), strings.Replace(receipt, `v1',1,`, `v1',2,`, 1)} {
			requireRefusal(apply(bad), "23503", "23514")
		}
		exec(receipt)
		for _, body := range []string{`{"invocation_id":"i","snapshot_digest":"` + strings.Repeat("a", 64) + `","proof_digest":"` + strings.Repeat("b", 64) + `","settlement_generation":1,"outcome":"succeeded"}`, `{"invocation_id":"i","snapshot_digest":null,"proof_digest":"` + strings.Repeat("b", 64) + `","settlement_generation":1,"outcome":"unknown"}`} {
			var valid bool
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_body_valid('existing_test_settled.v1',$1::jsonb)`, body).Scan(&valid); err != nil || valid {
				t.Fatal("invalid settlement body accepted", err)
			}
		}
		exec(`INSERT INTO zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body) VALUES('o','w','e','r',decode(repeat('11',32),'hex'),'s1','run_test',decode(repeat('44',32),'hex'),decode(repeat('66',32),'hex'),'existing_test_settled.v1',1,'{"invocation_id":"invocation","snapshot_digest":"` + strings.Repeat("a", 64) + `","proof_digest":"` + strings.Repeat("b", 64) + `","settlement_generation":1,"outcome":"not_reproduced"}')`)
		for _, table := range []string{"definitions", "runs", "dependencies", "receipts"} {
			for _, statement := range []string{"DELETE FROM ", "UPDATE ", "TRUNCATE "} {
				query := statement + "zasp_sa_multistep_" + table
				if statement == "UPDATE " {
					query += " SET organization_id='other'"
				}
				requireRefusal(apply(query), "55000", "0A000")
			}
		}
		if err := apply(candidate.DownSQL()); err == nil {
			t.Fatal("retained receipts discarded")
		}
		exec(`CREATE ROLE multistep_foreign NOLOGIN INHERIT; GRANT zasp_discovery_authority TO multistep_foreign`)
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE multistep_foreign`); err != nil {
			t.Fatal(err)
		}
		var visible int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM zasp_sa_multistep_receipts`).Scan(&visible); err != nil || visible != 0 {
			t.Fatal("forced RLS leaked foreign tenant evidence", visible, err)
		}
		tx.Rollback(ctx)
		exec(`REVOKE zasp_discovery_authority FROM multistep_foreign`)
		for _, role := range []string{"zasp_security_agent_api", "zasp_security_agent_worker", "zasp_security_agent_action_worker"} {
			requireRefusal(apply(`SET LOCAL ROLE `+role+`; SELECT * FROM zasp_sa_multistep_receipts`), "42501")
		}
		ready(true)
	})
}

func runMultistepReviewFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, string, string, string)) {
	t.Helper()
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, o, w, e, _, _ string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, migrations.ProductionSecurityAgentMultistep().UpSQL()); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var ready bool
		var fingerprint string
		if err = owner.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2),zasp_sa_multistep_live_fingerprint()`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepFingerprint()).Scan(&ready, &fingerprint); err != nil || !ready {
			t.Fatalf("candidate not ready: %t fingerprint=%s error=%v", ready, fingerprint, err)
		}
		exercise(ctx, owner, o, w, e)
	})
}

// The advisory-lock SELECT takes a transaction snapshot before evidence locks.
// A repeatable-read rollback must not drop rows committed during that wait.
func TestSecurityAgentMultistepRollbackSnapshotPostgres(t *testing.T) {
	for _, isolation := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.ReadCommitted} {
		t.Run(string(isolation), func(t *testing.T) {
			runMultistepReviewFixture(t, func(ctx context.Context, owner *pgx.Conn, o, w, e string) {
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,'concurrent-marker',1,'{}','v1')`, o, w, e); err != nil {
					t.Fatal(err)
				}
				writer, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Rollback(ctx)
				if _, err = writer.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
					t.Fatal(err)
				}
				contender, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer contender.Close(ctx)
				attempt, err := contender.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
				if err != nil {
					t.Fatal(err)
				}
				defer attempt.Rollback(ctx)
				finished := make(chan error, 1)
				go func() {
					_, err := attempt.Exec(ctx, migrations.ProductionSecurityAgentMultistep().DownSQL())
					if err == nil {
						err = attempt.Commit(ctx)
					} else {
						attempt.Rollback(ctx)
					}
					finished <- err
				}()
				waiting := false
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
					if err = writer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, contender.PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !waiting {
					t.Fatal("rollback did not reach advisory-lock snapshot barrier")
				}
				if _, err = writer.Exec(ctx, `INSERT INTO zasp_sa_multistep_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version) VALUES($1,$2,$3,'concurrent-marker',1)`, o, w, e); err != nil {
					t.Fatal(err)
				}
				if err = writer.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				err = <-finished
				var pg *pgconn.PgError
				wantCode := "55000"
				if isolation == pgx.RepeatableRead {
					wantCode = "25001"
				}
				if !errors.As(err, &pg) || pg.Code != wantCode {
					t.Errorf("rollback accepted stale snapshot or wrong refusal: isolation=%s want=%s error=%v", isolation, wantCode, err)
				}
				var exists bool
				if err = owner.QueryRow(ctx, `SELECT to_regclass('public.zasp_sa_multistep_definitions') IS NOT NULL`).Scan(&exists); err != nil || !exists {
					t.Fatalf("rollback dropped concurrently committed evidence: exists=%t error=%v", exists, err)
				}
				var count int
				if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_sa_multistep_definitions WHERE definition_id='concurrent-marker'`).Scan(&count); err != nil || count != 1 {
					t.Fatal("rollback lost concurrent marker", count, err)
				}
			})
		})
	}
}

// Fingerprinting only user triggers misses PostgreSQL's actual FK enforcers.
func TestSecurityAgentMultistepForeignKeyTriggerDriftPostgres(t *testing.T) {
	runMultistepReviewFixture(t, func(ctx context.Context, owner *pgx.Conn, _, _, _ string) {
		for _, side := range []string{"child", "referenced"} {
			t.Run(side, func(t *testing.T) {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				var table, name string
				if err = tx.QueryRow(ctx, `SELECT t.tgrelid::regclass::text,t.tgname FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint WHERE k.conrelid='public.zasp_sa_multistep_definitions'::regclass AND k.contype='f' AND t.tgisinternal AND CASE WHEN $1='child' THEN t.tgrelid=k.conrelid ELSE t.tgrelid=k.confrelid END ORDER BY t.tgtype LIMIT 1`, side).Scan(&table, &name); err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(ctx, `ALTER TABLE `+table+` DISABLE TRIGGER `+pgx.Identifier{name}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				var ready bool
				if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepFingerprint()).Scan(&ready); err != nil {
					t.Fatal(err)
				} else if ready {
					t.Errorf("readiness ignored disabled %s FK enforcement trigger", side)
				}
				_, err = tx.Exec(ctx, migrations.ProductionSecurityAgentMultistep().DownSQL())
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "55000" {
					t.Errorf("rollback ignored disabled %s FK enforcement trigger: %v", side, err)
				}
			})
		}
	})
}
