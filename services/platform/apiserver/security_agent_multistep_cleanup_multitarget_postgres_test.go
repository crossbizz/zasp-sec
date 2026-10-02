package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentMultistepCleanupEveryTargetPostgres(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "complete"
		if partial {
			name = "partial_recovery"
		}
		t.Run(name, func(t *testing.T) {
			exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 4, 0), keys)
				if err != nil {
					t.Fatal(err)
				}
				if len(claim["targets"].([]any)) != 2 {
					t.Fatal("fixture lacks two real application acknowledgements")
				}
				stored := claim
				for _, target := range claim["targets"].([]any) {
					selected := cloneOrderedApplicationRequest(t, stored)
					selected["targets"] = []any{target}
					q := orderedCleanupStoreRequest(t, o, w, e, r, steps[0], selected, key)
					stored, err = orderedCleanupCall(ctx, action, q, keys)
					if err != nil {
						t.Fatal(err)
					}
				}
				selected := cloneOrderedApplicationRequest(t, stored)
				selected["targets"] = []any{stored["targets"].([]any)[0]}
				deployOrderedCleanup(t, ctx, owner, key, selected)
				complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 7, 3)
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				if _, err = orderedCleanupCall(ctx, action, complete, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Fatal("one acknowledgement removed two-target control", err)
				}
				want := "remediated"
				if partial {
					if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
						t.Fatal(err)
					}
					q := orderedCleanupRequest(o, w, e, r, steps[0], "reconcile", 10, 7, 3)
					got, err := orderedCleanupCall(ctx, action, q, keys)
					if err != nil || got["reason"] != "partial_acknowledgement" || got["run_state"] != "needs_human" {
						t.Fatal("partial acknowledgement recovery", got, err)
					}
					q = orderedCleanupRequest(o, w, e, r, steps[0], "claim", 11, 8, 4)
					q["lease_token"] = "ordered-cleanup-partial-retry"
					stored, err = orderedCleanupCall(ctx, action, q, keys)
					if err != nil {
						t.Fatal(err)
					}
					stored["cleanup_lease_token"] = "ordered-cleanup-partial-retry"
					complete = orderedCleanupRequest(o, w, e, r, steps[0], "complete", 11, 9, 5)
					complete["lease_token"] = "ordered-cleanup-partial-retry"
					want = "needs_human"
				}
				selected = cloneOrderedApplicationRequest(t, stored)
				selected["targets"] = []any{stored["targets"].([]any)[1]}
				deployOrderedCleanup(t, ctx, owner, key, selected)
				got, err := orderedCleanupCall(ctx, action, complete, keys)
				if err != nil || got["run_state"] != want || len(got["receipt"].(map[string]any)["targets"].([]any)) != 2 {
					t.Fatal("every-target cleanup incomplete", got, err)
				}
			}, "cleanup_many")
		})
	}
}

func TestSecurityAgentMultistepCleanupCancellationPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), keys)
		if err != nil {
			t.Fatal("cancelled parent suppressed retained cleanup", err)
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		got, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2), keys)
		if err != nil || got["run_state"] != "cancelled" || got["state"] != "cleaned" {
			t.Fatal("cancelled cleanup claimed remediation", got, err)
		}
		var leaked bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind LIKE 'ordered_cleanup%' AND (body::text LIKE '%'||$2||'%' OR body::text LIKE '%'||$3||'%' OR body::text LIKE '%ordered-cleanup-lease%'))`, r, strings.Repeat("a", 32), hex.EncodeToString([]byte(strings.Repeat("a", 32)))).Scan(&leaked); err != nil || leaked {
			t.Fatal("cleanup copied retained worker credential into audit", leaked, err)
		}
	}, "cancel")
}
