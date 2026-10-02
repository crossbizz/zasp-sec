package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// The source and deployment are authority-produced. Expiring a lease simulates
// worker loss after the acknowledgement commit, not proof of provider success.
func TestSecurityAgentMultistepApplicationAcknowledgedRestartPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 800, true)
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedApplication(t, ctx, owner, key, stored)
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, r); err != nil {
			t.Fatal(err)
		}
		restart, err := pgx.ConnectConfig(ctx, action.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restart.Close(ctx)
		request := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 5, 2)
		request["lease_token"] = "ordered-recovered-action"
		recovered, err := orderedApplicationCall(ctx, restart, request, keys)
		if err != nil || recovered["reservation_id"] != claim["reservation_id"] || recovered["attempt"] != float64(2) {
			t.Fatal("acknowledged restart", recovered, err)
		}
		request = orderedApplicationRequest(o, w, e, r, steps[0], "complete", 6, 3)
		request["lease_token"] = "ordered-recovered-action"
		complete, err := orderedApplicationCall(ctx, restart, request, keys)
		if err != nil || complete["effect_state"] != "cleanup_pending" || complete["run_version"] != float64(7) {
			t.Fatal("recovered application", complete, err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 1, 1)
	})
}

func TestSecurityAgentMultistepApplicationShortDeploymentRefusesPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 860, true)
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedApplication(t, ctx, owner, key, stored, true)
		before := orderedApplicationSnapshot(t, ctx, owner, r)
		if got, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, 2), keys); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
			t.Fatal("short deployment overstated control lifetime", got, err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
	})
}

func TestSecurityAgentMultistepApplicationProvisionalWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		for i, mode := range []string{"claim_readiness", "claim_deadline", "heartbeat_lease", "complete_lease"} {
			t.Run(mode, func(t *testing.T) {
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 810+i, true)
				request := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)
				count := 0
				if mode == "heartbeat_lease" || mode == "complete_lease" {
					claim, err := orderedProgressionCall(ctx, action, "application", request)
					if err != nil {
						t.Fatal(err)
					}
					count = 1
					request = orderedApplicationRequest(o, w, e, r, steps[0], "heartbeat", 5, 1)
					if mode == "complete_lease" {
						_, key, _ := ed25519.GenerateKey(rand.Reader)
						stored, err := orderedProgressionCall(ctx, action, "application", orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key))
						if err != nil {
							t.Fatal(err)
						}
						deployOrderedApplication(t, ctx, owner, key, stored)
						request = orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, 2)
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1`, r); err != nil {
						t.Fatal(err)
					}
				} else if mode == "claim_deadline" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1`, r); err != nil {
						t.Fatal(err)
					}
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Close(ctx)
				if _, err = blocker.Exec(ctx, `BEGIN; LOCK TABLE zasp_security_agent_audit IN SHARE MODE`); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, callErr := orderedProgressionCall(ctx, action, "application", request); done <- callErr }()
				joined := false
				defer func() {
					if !joined {
						blocker.Exec(ctx, `ROLLBACK`)
						<-done
					}
				}()
				waitOrderedProgressionBlocked(t, ctx, blocker, action)
				if mode == "claim_readiness" {
					if _, err = blocker.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err = blocker.Exec(ctx, `SELECT pg_sleep(2.05)`); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				err = <-done
				joined = true
				if err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
					t.Fatal("provisional effect escaped expired authority", mode, err)
				}
				assertOrderedApplicationCounts(t, ctx, owner, r, count, count, 0, 1)
				if mode == "claim_readiness" {
					if _, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_multistep_checksum'`, migrations.ProductionSecurityAgentMultistep().Checksum()); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	})
}
