package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepPricingLookupRefusalsPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		req := orderedPricingAdminRequest(o, w, e, actor)
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", req)
		if err != nil {
			t.Fatal(err)
		}
		base := orderedPricingLookupRequest(o, w, e, req["policy"].(map[string]any), created)
		for _, mode := range []string{"foreign_scope", "provider", "model", "profile", "unit", "credential", "credential_digest", "policy_version", "policy_digest", "account_version", "policy_id", "account_id", "request_policy", "token_limit", "body_digest", "body_model", "body_token", "body_unknown", "body_duplicate", "body_nested_duplicate", "body_messages", "body_schema", "body_large", "unknown", "null"} {
			t.Run(mode, func(t *testing.T) {
				q := cloneOrderedApplicationRequest(t, base)
				switch mode {
				case "foreign_scope":
					q["environment_id"] = actor
				case "provider":
					q["provider"] = "other"
				case "model":
					q["model"] = "openai/other"
				case "profile":
					q["account_profile"] = "other"
				case "unit":
					q["cost_unit"] = "usd"
				case "credential":
					q["credential_reference"] = q["credential_reference"].(string) + "-rotated"
				case "credential_digest", "policy_digest", "body_digest":
					q[mode] = "sha256:" + strings.Repeat("cd", 32)
				case "policy_version", "account_version":
					q[mode] = 2
				case "policy_id", "account_id":
					q[mode] = actor
				case "request_policy":
					q["request_policy_version"] = "other-v1"
				case "token_limit":
					q["request_token_limit"] = 512
				case "body_model":
					q["body"] = strings.Replace(q["body"].(string), "openai/gpt-5-mini", "openai/other", 1)
				case "body_token":
					q["body"] = strings.Replace(q["body"].(string), "256", "512", 1)
				case "body_unknown":
					q["body"] = `{"unreviewed":true,` + q["body"].(string)[1:]
				case "body_duplicate":
					q["body"] = `{"model":"openai/other",` + q["body"].(string)[1:]
				case "body_nested_duplicate":
					q["body"] = strings.Replace(q["body"].(string), `"data_collection":"deny"`, `"data_collection":"allow","data_collection":"deny"`, 1)
				case "body_messages":
					q["body"] = strings.Replace(q["body"].(string), `"role":"system"`, `"role":"tool"`, 1)
				case "body_schema":
					q["body"] = strings.Replace(q["body"].(string), `"strict":true`, `"strict":false`, 1)
				case "body_large":
					q["body"] = q["body"].(string) + strings.Repeat(" ", 65536)
				case "unknown":
					q["verified"] = true
				case "null":
					q["body"] = nil
				}
				if strings.HasPrefix(mode, "body_") && mode != "body_digest" {
					digest := sha256.Sum256([]byte(q["body"].(string)))
					q["body_digest"] = "sha256:" + hex.EncodeToString(digest[:])
				}
				before := orderedPricingSnapshot(t, ctx, owner)
				if _, err := orderedPricingCall(ctx, worker, "pricing_lookup", q); err == nil {
					t.Error("lookup accepted mismatched or noncanonical prepared request")
				}
				if orderedPricingSnapshot(t, ctx, owner) != before {
					t.Error("refused lookup mutated authority")
				}
			})
		}
	})
}

func TestSecurityAgentMultistepPricingAdminRefusalsPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		for _, mode := range []string{"worker", "foreign_actor", "foreign_environment", "stale_auth", "future_auth", "inactive", "non_admin", "permission", "unknown", "null", "negative_version", "large_version", "model", "unit", "provider", "zero_tokens", "large_tokens", "zero_cost", "large_cost", "token_limit", "credential_scope", "credential_empty", "credential_wildcard", "credential_digest", "expired", "long_validity", "future_policy", "changed_replay"} {
			t.Run(mode, func(t *testing.T) {
				q := orderedPricingAdminRequest(o, w, e, actor)
				q["idempotency_key"] = "pricing-admin-refusal-" + mode
				p := q["policy"].(map[string]any)
				p["account_profile"] = "local-" + mode
				connection := admin
				var restore string
				switch mode {
				case "worker":
					connection = worker
				case "foreign_actor":
					q["actor_id"] = e
				case "foreign_environment":
					q["environment_id"] = actor
				case "stale_auth":
					q["fresh_auth_at"] = time.Now().UTC().Add(-6 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
				case "future_auth":
					q["fresh_auth_at"] = time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05.000000Z")
				case "inactive":
					_, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor)
					if err != nil {
						t.Fatal(err)
					}
					restore = `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`
				case "non_admin":
					_, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_engineer' WHERE principal_id=$1`, actor)
					if err != nil {
						t.Fatal(err)
					}
					restore = `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1`
				case "permission":
					_, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view"]' WHERE principal_id=$1`, actor)
					if err != nil {
						t.Fatal(err)
					}
					restore = `UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity"]' WHERE principal_id=$1`
				case "unknown":
					q["approved"] = true
				case "null":
					p["maximum_tokens"] = nil
				case "negative_version":
					q["expected_version"] = -1
				case "large_version":
					q["expected_version"] = 1000000
				case "model":
					p["model"] = strings.Repeat("a", 129)
				case "unit":
					p["cost_unit"] = "usd"
				case "provider":
					p["provider"] = "other"
				case "zero_tokens":
					p["maximum_tokens"] = 0
				case "large_tokens":
					p["maximum_tokens"] = 12001
				case "zero_cost":
					p["maximum_cost_nano_credits"] = 0
				case "large_cost":
					p["maximum_cost_nano_credits"] = int64(1000000000001)
				case "token_limit":
					p["request_token_limit"] = 1001
				case "credential_scope":
					p["credential_reference"] = "secret_ref_planner/global"
				case "credential_empty":
					p["credential_reference"] = "secret_ref_planner/" + o + "/" + w + "/" + e + "/"
				case "credential_wildcard":
					p["credential_reference"] = strings.Replace(p["credential_reference"].(string), "pid_", "pidx", 1)
				case "credential_digest":
					p["credential_digest"] = "secret-material"
				case "expired":
					p["expires_at"] = time.Now().UTC().Add(-time.Second).Format("2006-01-02T15:04:05.000000Z")
				case "long_validity":
					p["expires_at"] = time.Now().UTC().Add(31 * 24 * time.Hour).Format("2006-01-02T15:04:05.000000Z")
				case "future_policy":
					p["effective_at"] = time.Now().UTC().Add(30 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
				case "changed_replay":
					if _, err := orderedPricingCall(ctx, admin, "pricing_admin", q); err != nil {
						t.Fatal(err)
					}
					p["maximum_tokens"] = 1001
				}
				defer func() {
					if restore != "" {
						if _, err := owner.Exec(ctx, restore, actor); err != nil {
							t.Error(err)
						}
					}
				}()
				before := orderedPricingSnapshot(t, ctx, owner)
				response, err := orderedPricingCall(ctx, connection, "pricing_admin", q)
				if mode == "future_policy" {
					if err != nil {
						t.Fatal("valid future policy not stored", err)
					}
					if _, err = orderedPricingCall(ctx, worker, "pricing_lookup", orderedPricingLookupRequest(o, w, e, p, response)); err == nil {
						t.Fatal("future policy authorized lookup")
					}
					return
				}
				if err == nil {
					t.Error("unauthorized admin write accepted")
				}
				if orderedPricingSnapshot(t, ctx, owner) != before {
					t.Error("refused admin write changed authority")
				}
			})
		}
	})
}

func TestSecurityAgentMultistepPricingVersionDisablePostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		q := orderedPricingAdminRequest(o, w, e, actor)
		first, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		lookup := orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), first)
		q["operation"] = "version"
		q["expected_version"] = 1
		q["expected_account_version"] = 1
		q["idempotency_key"] = "pricing-version-0002"
		q["policy"].(map[string]any)["credential_digest"] = "sha256:" + strings.Repeat("cd", 32)
		second, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil || second["version"] != float64(2) || second["account_version"] != float64(2) || second["policy_id"] != first["policy_id"] {
			t.Fatal("version/rotation", second, err)
		}
		if _, err = orderedPricingCall(ctx, worker, "pricing_lookup", lookup); err == nil {
			t.Fatal("old credential or policy revived")
		}
		lookup = orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), second)
		if _, err = orderedPricingCall(ctx, worker, "pricing_lookup", lookup); err != nil {
			t.Fatal("rotated authority refused", err)
		}
		q["operation"] = "disable"
		q["expected_version"] = 2
		q["expected_account_version"] = 2
		q["idempotency_key"] = "pricing-disable-0003"
		third, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil || third["version"] != float64(3) || third["account_version"] != float64(2) || third["disabled"] != true {
			t.Fatal("disable", third, err)
		}
		before := orderedPricingSnapshot(t, ctx, owner)
		if _, err = orderedPricingCall(ctx, worker, "pricing_lookup", lookup); err == nil {
			t.Fatal("disabled policy resolved")
		}
		if replay, err := orderedPricingCall(ctx, admin, "pricing_admin", q); err != nil || !jsonEqualMaps(replay, third) || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("disable replay", replay, err)
		}
		var counts []int64
		if err = owner.QueryRow(ctx, `SELECT ARRAY[(SELECT count(*) FROM zasp_sa_multistep_prior.pricing_policies),(SELECT count(*) FROM zasp_sa_multistep_prior.pricing_accounts),(SELECT count(*) FROM zasp_sa_multistep_prior.pricing_mutations),(SELECT count(*) FROM zasp_admin_audit WHERE action LIKE 'security_agent.pricing.%')]`).Scan(&counts); err != nil || len(counts) != 4 || counts[0] != 3 || counts[1] != 2 || counts[2] != 3 || counts[3] != 3 {
			t.Fatal("append-only history/audit", counts, err)
		}
		for _, table := range []string{"pricing_policies", "pricing_accounts", "pricing_mutations"} {
			for _, command := range []string{"UPDATE zasp_sa_multistep_prior." + table + " SET organization_id=organization_id", "DELETE FROM zasp_sa_multistep_prior." + table, "TRUNCATE zasp_sa_multistep_prior." + table} {
				if _, err = owner.Exec(ctx, command); err == nil {
					t.Error("retained history mutated", command)
				}
			}
		}
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("history mutation changed bytes")
		}
	})
}

func TestSecurityAgentMultistepPricingCrossModelRotationPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		q := orderedPricingAdminRequest(o, w, e, actor)
		first, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		other := cloneOrderedApplicationRequest(t, q)
		other["idempotency_key"] = "cross-model-account-rotation"
		other["expected_account_version"] = 1
		other["policy"].(map[string]any)["model"] = "openai/other"
		other["policy"].(map[string]any)["credential_digest"] = "sha256:" + strings.Repeat("cd", 32)
		rotated, err := orderedPricingCall(ctx, admin, "pricing_admin", other)
		if err != nil || rotated["account_version"] != float64(2) || rotated["account_id"] != first["account_id"] {
			t.Fatal("shared account did not rotate exactly", rotated, err)
		}
		before := orderedPricingSnapshot(t, ctx, owner)
		if _, err = orderedPricingCall(ctx, worker, "pricing_lookup", orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), first)); err == nil {
			t.Fatal("old model retained authorization after account rotation")
		}
		q["operation"] = "disable"
		q["idempotency_key"] = "cross-model-stale-disable"
		q["expected_version"] = 1
		q["expected_account_version"] = 2
		if _, err = orderedPricingCall(ctx, admin, "pricing_admin", q); err == nil {
			t.Error("disable attached old credential contents to a new account revision")
		}
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Error("rejected stale-account disable changed history")
		}
		q["operation"] = "version"
		q["idempotency_key"] = "cross-model-rebind-current"
		q["policy"].(map[string]any)["credential_digest"] = "sha256:" + strings.Repeat("cd", 32)
		rebound, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil || rebound["version"] != float64(2) || rebound["account_version"] != float64(2) {
			t.Fatal("rebind to current account", rebound, err)
		}
		q["operation"] = "disable"
		q["idempotency_key"] = "cross-model-disable-current"
		q["expected_version"] = 2
		disabled, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil || disabled["version"] != float64(3) || disabled["account_version"] != float64(2) || disabled["disabled"] != true {
			t.Fatal("current account disable", disabled, err)
		}
	})
}
