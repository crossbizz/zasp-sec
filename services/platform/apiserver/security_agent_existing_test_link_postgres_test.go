package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This exercises the private persistence layer with owner-seeded authorized
// intent. It does not prove planner, budget admission or worker dispatch.
func exerciseSecurityAgentExistingTestLink(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, testID, target, actor string) {
	t.Helper()
	const run = "pid_89000021-0000-4000-8000-000000000001"
	const step = "pid_89000022-0000-4000-8000-000000000002"
	const correlation = "pid_89000023-0000-4000-8000-000000000003"
	var private bool
	if err := owner.QueryRow(ctx, `SELECT NOT has_function_privilege('public','public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)','EXECUTE')`).Scan(&private); err != nil || !private {
		t.Fatalf("private link enqueue unavailable: %v", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='autonomous',body=body||jsonb_build_object('enabled',true,'autonomy','autonomous','allowed_actions',jsonb_build_array('run_test'),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$4,'definition_version',1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$7 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)
 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET actor_id=excluded.actor_id,definition=excluded.definition,definition_digest=excluded.definition_digest;
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state)
 SELECT organization_id,workspace_id,environment_id,$5,definition_id,version,$4,$7,'planning' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,decode(repeat('cd',32),'hex'),'security-agent-actions-v1',p,digest(convert_to(p::text,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour'
 FROM zasp_security_agent_runs CROSS JOIN LATERAL (SELECT jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('step_id',$6,'index',0,'action','run_test','target_id',$4,'test_definition_version',1,'test_target_id',$8,'test_target_kind','agent_endpoint','authorization','autonomous'))) AS p) document WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5);
 UPDATE zasp_security_agent_runs SET plan_hash=(SELECT plan_hash FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)) WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5);
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
 SELECT $1,$2,$3,$5,$6,0,'run_test',digest(convert_to((plan->'steps'->0)::text,'UTF8'),'sha256'),'autonomous','authorized' FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5);
 INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state)
 SELECT $1,$2,$3,$5,$6,'run_test',input_digest,'pending' FROM zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$5,$6)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, testID, run, step, actor, target); err != nil {
		t.Fatal(err)
	}
	const query = `SELECT zasp_security_agent_test_link_enqueue($1,$2,$3,$4,$5,$6)`
	t.Run("cannot_adopt_preexisting_test", func(t *testing.T) {
		if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(context.Background(), "ROLLBACK")
		var collision string
		if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_test_run',$4||chr(31)||$5||chr(31)||'run_test')`, org, ws, env, run, step).Scan(&collision); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_security_agent_test_enqueue_core($1,$2,$3,$4,$5,$6,1,$7,$8)`, org, ws, env, actor, "agent-step:"+collision, testID, collision, correlation); err != nil {
			t.Fatal(err)
		}
		_, err := owner.Exec(ctx, query, org, ws, env, run, step, correlation)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("adopted preexisting test as new agent execution: %v", err)
		}
	})
	read := func() json.RawMessage {
		t.Helper()
		var value json.RawMessage
		if err := owner.QueryRow(ctx, query, org, ws, env, run, step, correlation).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, blocker := range []string{"actor", "enqueue_advisory"} {
		t.Run("expiry_after_"+blocker+"_wait", func(t *testing.T) {
			other, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close(context.Background())
			var deadline time.Time
			if err := owner.QueryRow(ctx, `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING fresh_until`, target).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, target)
				if err != nil {
					t.Error(err)
				}
			}()
			if _, err := other.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			defer other.Exec(context.Background(), "ROLLBACK")
			if blocker == "actor" {
				_, err = other.Exec(ctx, `SELECT 1 FROM zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) FOR UPDATE`, org, ws, env)
			} else {
				_, err = other.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),$1::text,$2::text,$3::text,$4::text,'runTest','agent-step:'||zasp_discovery_canonical_id($1::text,$2::text,$3::text,'security_agent_test_run',$5::text||chr(31)||$6::text||chr(31)||'run_test')),0))`, org, ws, env, actor, run, step)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			defer owner.Exec(context.Background(), "ROLLBACK")
			pid := owner.PgConn().PID()
			done := make(chan error, 1)
			go func() { _, err := owner.Exec(ctx, query, org, ws, env, run, step, correlation); done <- err }()
			defer func() { other.Exec(context.Background(), "ROLLBACK"); <-done }()
			observed := false
			for time.Now().Before(deadline) {
				if err := other.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND clock_timestamp()<$2::timestamptz`, pid, deadline).Scan(&observed); err != nil {
					t.Fatal(err)
				}
				if observed {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !observed {
				t.Fatal("expected blocker not observed before expiry")
			}
			for {
				var expired bool
				if err := other.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := other.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			err = <-done
			done <- err
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("expired authority enqueued after %s wait: %v", blocker, err)
			}
		})
	}
	// An enclosing admission transaction that aborts must leave no linked work.
	if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	rolledBack := read()
	if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_test_links WHERE run_id=$1`, run).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back link retained: %d %v", count, err)
	}
	var rolledBackID string
	if err := owner.QueryRow(ctx, `SELECT $1::jsonb->>'test_run_id'`, rolledBack).Scan(&rolledBackID); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_red_team_runs WHERE run_id=$1)+(SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1)+(SELECT count(*) FROM zasp_red_team_request_receipts WHERE resource_id=$1)+(SELECT count(*) FROM zasp_red_team_audit WHERE body::text LIKE '%'||$1::text||'%')`, rolledBackID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback left test work/audit: %d %v", count, err)
	}
	if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	first := read()
	peer, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		owner.Exec(context.Background(), "ROLLBACK")
		t.Fatal(err)
	}
	defer peer.Close(context.Background())
	type linkReply struct {
		body json.RawMessage
		err  error
	}
	peerDone := make(chan linkReply, 1)
	peerPID := peer.PgConn().PID()
	go func() {
		var reply linkReply
		reply.err = peer.QueryRow(ctx, query, org, ws, env, run, step, correlation).Scan(&reply.body)
		peerDone <- reply
	}()
	joined := false
	defer func() {
		if !joined {
			owner.Exec(context.Background(), "ROLLBACK")
			<-peerDone
		}
	}()
	contended := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if err := owner.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, peerPID).Scan(&contended); err != nil {
			t.Fatal(err)
		}
		if contended {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !contended {
		t.Fatal("duplicate enqueue did not wait for first transaction")
	}
	if _, err := owner.Exec(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	peerResult := <-peerDone
	joined = true
	if peerResult.err != nil {
		t.Fatal(peerResult.err)
	}
	replay := peerResult.body
	var linked struct {
		TestRunID         string `json:"test_run_id"`
		DefinitionID      string `json:"definition_id"`
		DefinitionVersion int64  `json:"definition_version"`
		State             string `json:"state"`
		Replayed          bool   `json:"replayed"`
	}
	if decodeStrictDiscovery(first, &linked) != nil || !validProductID(linked.TestRunID) || linked.DefinitionID != testID || linked.DefinitionVersion != 1 || linked.State != "pending" || linked.Replayed {
		t.Fatalf("invalid link: %s", first)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT ($1::jsonb-'replayed')=($2::jsonb-'replayed') AND $2::jsonb->'replayed'='true'::jsonb`, first, replay).Scan(&exact); err != nil || !exact {
		t.Fatalf("link replay differs: %v", err)
	}
	// Durable step identity, not the expiring human/API receipt, owns replay.
	if _, err := owner.Exec(ctx, `DELETE FROM zasp_red_team_request_receipts WHERE resource_id=$1`, linked.TestRunID); err != nil {
		t.Fatal(err)
	}
	read()
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1`, linked.TestRunID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate outbox after durable replay: %d %v", count, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_definition_id,test_definition_version,test_run_id,target_id) = ($1,$2,$3,$4,$5,$6,1,$7,$8)`, org, ws, env, run, step, testID, linked.TestRunID, target).Scan(&count); err != nil || count != 1 {
		t.Fatalf("wrong persisted link: %d %v", count, err)
	}
	t.Run("changed_step_replay", func(t *testing.T) {
		if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(context.Background(), "ROLLBACK")
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_steps SET input_digest=decode(repeat('cd',32),'hex') WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, org, ws, env, run, step); err != nil {
			t.Fatal(err)
		}
		_, err := owner.Exec(ctx, query, org, ws, env, run, step, correlation)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("changed step replay accepted: %v", err)
		}
	})
}
