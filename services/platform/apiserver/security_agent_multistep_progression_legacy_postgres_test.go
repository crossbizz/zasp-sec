package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepProgressionLegacyDecisionFencePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for index, function := range []string{"zasp_security_agent_decide_approval_v22", "zasp_security_agent_decide_approval_v23", "zasp_security_agent_decide_approval_v24", "zasp_security_agent_decide_approval"} {
			t.Run(function, func(t *testing.T) {
				request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 400+index)
				r := request["run_id"].(string)
				admitted, err := orderedProgressionCall(ctx, worker, "admit", request)
				if err != nil {
					t.Fatal(err)
				}
				before := orderedAdmissionSnapshot(t, ctx, owner, r)
				var result json.RawMessage
				err = api.QueryRow(ctx, `SELECT `+function+`($1,$2,$3,$4,$5,$9,1,'approved',clock_timestamp(),$6,$7,$8)`, o, w, e, admitted["approval_id"], orderedProgressionApprover, r, request["definition_id"], request["trigger_id"], "ordered-legacy-"+r).Scan(&result)
				if err == nil {
					t.Error("legacy lane decided release61 approval", string(result))
				}
				if orderedAdmissionSnapshot(t, ctx, owner, r) != before {
					t.Error("legacy lane mutated ordered run/step/approval/audit")
				}
			})
		}
	})
}

func TestSecurityAgentMultistepProgressionLegacySingleStepPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for index, function := range []string{"zasp_security_agent_decide_approval_v22", "zasp_security_agent_decide_approval_v23", "zasp_security_agent_decide_approval_v24", "expire"} {
			t.Run(function, func(t *testing.T) {
				request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 430+index)
				r := request["run_id"].(string)
				// This is an owner-seeded legacy single-step approval, not a release61
				// admission. Expiry must also work for pre-budget historical rows.
				if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_provider_reservations WHERE run_id=$4;
 DELETE FROM zasp_security_agent_run_budgets WHERE run_id=$4;
 UPDATE zasp_security_agent_definitions SET body=jsonb_set(jsonb_set(body,'{allowed_actions}','["create_temporary_policy"]'),'{max_steps}','1') WHERE definition_id=$5;
 INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES($1,$2,$3,$4,$5,1,decode(repeat('cd',32),'hex'),'security-agent-actions-v1',jsonb_build_object('evidence_ids',jsonb_build_array($6),'steps',jsonb_build_array(jsonb_build_object('step_id',$4,'action','create_temporary_policy','ttl_seconds',600))),digest(convert_to($4,'UTF8'),'sha256'),clock_timestamp()+CASE WHEN $8 THEN interval '-1 minute' ELSE interval '1 hour' END);
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES($1,$2,$3,$4,$4,0,'create_temporary_policy',digest(convert_to($4,'UTF8'),'sha256'),'approval_required','waiting_approval');
 INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) SELECT $1,$2,$3,$5,$4,$4,plan_hash,'pending',$7,expires_at FROM zasp_security_agent_plans WHERE run_id=$4;
 UPDATE zasp_security_agent_runs SET state='waiting_approval',plan_hash=digest(convert_to($4,'UTF8'),'sha256'),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, request["definition_id"], request["trigger_id"], actor, function == "expire"); err != nil {
					t.Fatal(err)
				}
				var result json.RawMessage
				wantRun, wantStep, wantApproval := "queued", "authorized", "approved"
				if function == "expire" {
					if err := worker.QueryRow(ctx, `SELECT zasp_security_agent_expire_approvals_v28('ordered-legacy-expiry',25)`).Scan(&result); err != nil || string(result) != `{"expired": 1}` {
						t.Fatal("legacy expiry changed", string(result), err)
					}
					wantRun, wantStep, wantApproval = "needs_human", "cancelled", "expired"
				} else if err := api.QueryRow(ctx, `SELECT `+function+`($1,$2,$3,$4,$5,$6,1,'approved',clock_timestamp(),$7,$8,$7)`, o, w, e, request["definition_id"], orderedProgressionApprover, "single-step-"+r, r, request["trigger_id"]).Scan(&result); err != nil {
					t.Fatal("legacy decision changed", err)
				}
				var valid bool
				if err := owner.QueryRow(ctx, `SELECT (SELECT state=$2 AND version=3 FROM zasp_security_agent_runs WHERE run_id=$1) AND (SELECT state=$3 AND version=2 FROM zasp_security_agent_steps WHERE run_id=$1) AND (SELECT state=$4 AND version=2 FROM zasp_security_agent_approvals WHERE run_id=$1)`, r, wantRun, wantStep, wantApproval).Scan(&valid); err != nil || !valid {
					t.Fatal("legacy single-step post-state", valid, err)
				}
			})
		}
	})
}

func TestSecurityAgentMultistepProgressionLegacyFenceFingerprintPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		for _, name := range []string{"zasp_security_agent_decide_approval", "zasp_security_agent_decide_approval_v22", "zasp_security_agent_decide_approval_v23", "zasp_security_agent_decide_approval_v24", "zasp_security_agent_expire_approvals_v28"} {
			for _, drift := range []string{"definition", "acl", "saved_definition", "saved_acl"} {
				t.Run(name+"/"+drift, func(t *testing.T) {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					var signature, definition string
					if err = tx.QueryRow(ctx, `SELECT signature,definition FROM zasp_sa_multistep_prior.functions WHERE split_part(signature,'(',1)=$1`, "public."+name).Scan(&signature, &definition); err != nil {
						t.Fatal("missing exact restoration snapshot", err)
					}
					switch drift {
					case "definition":
						_, err = tx.Exec(ctx, definition)
					case "acl":
						_, err = tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+signature+` TO PUBLIC`)
					case "saved_definition":
						_, err = tx.Exec(ctx, `UPDATE zasp_sa_multistep_prior.functions SET definition=definition||E'\n-- unsafe saved body' WHERE signature=$1`, signature)
					case "saved_acl":
						_, err = tx.Exec(ctx, `UPDATE zasp_sa_multistep_prior.functions SET acl='[]' WHERE signature=$1`, signature)
					}
					if err != nil {
						t.Fatal(err)
					}
					var ready bool
					if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready); err != nil || ready {
						t.Fatal("unfingerprinted legacy approval fence", ready, err)
					}
				})
			}
		}
	})
}

func TestSecurityAgentMultistepProgressionLegacyExpiryWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 410)
		r := request["run_id"].(string)
		// Admission owns the resulting immutable plan expiry. No receipt or plan
		// is forged to simulate time passing.
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1`, r); err != nil {
			t.Fatal(err)
		}
		admitted, err := orderedProgressionCall(ctx, worker, "admit", request)
		if err != nil {
			t.Fatal(err)
		}
		for {
			var expired bool
			if err = owner.QueryRow(ctx, `SELECT expires_at<=clock_timestamp() FROM zasp_security_agent_plans WHERE run_id=$1`, r).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if expired {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if _, err = owner.Exec(ctx, `BEGIN; SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `ROLLBACK`)
		done := make(chan error, 1)
		cancelRequest := orderedProgressionRequest(o, w, e, r, admitted["step_ids"].([]any)[1].(string), "cancel", orderedProgressionApprover, 3)
		go func() { _, callErr := orderedProgressionCall(ctx, api, "transition", cancelRequest); done <- callErr }()
		joined := false
		defer func() {
			owner.Exec(ctx, `ROLLBACK`)
			if !joined {
				<-done
			}
		}()
		waitOrderedProgressionBlocked(t, ctx, owner, api)
		// An ordered transition holds its Organization/budget fence and waits
		// for this run. Expiry must neither take its approval nor wait for run.
		expiryCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		var result json.RawMessage
		err = worker.QueryRow(expiryCtx, `SELECT zasp_security_agent_expire_approvals_v28('ordered-expiry-worker',25)`).Scan(&result)
		if err != nil || string(result) != `{"expired": 0}` {
			t.Errorf("legacy expiry touched or waited on release61: result=%s err=%v", result, err)
		}
		if _, err = owner.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		if err != nil {
			t.Fatal("ordered cancellation lost to legacy expiry", err)
		}
		var safe bool
		if err = owner.QueryRow(ctx, `SELECT (SELECT state='cancelled' FROM zasp_security_agent_runs WHERE run_id=$1) AND (SELECT count(*)=1 AND bool_and(state='cancelled') FROM zasp_security_agent_approvals WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1)`, r).Scan(&safe); err != nil || !safe {
			t.Fatal("expiry/transition left unsafe ordered state", safe, err)
		}
	})
}
