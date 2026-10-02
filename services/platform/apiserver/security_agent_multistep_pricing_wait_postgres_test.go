package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepPricingEffectiveReplayPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, _ *pgx.Conn, o, w, e, actor string) {
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: admin})
		repo, err := multisteppricing.New(db, "admin")
		if err != nil {
			t.Fatal(err)
		}
		q := orderedPricingAdminRequest(o, w, e, actor)
		var createdAt time.Time
		if err = owner.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&createdAt); err != nil {
			t.Fatal(err)
		}
		deadline := createdAt.UTC().Add(2 * time.Second).Truncate(time.Microsecond)
		q["policy"].(map[string]any)["effective_at"] = deadline.Add(-5 * time.Minute).Format(multisteppricing.TimeFormat)
		raw, _ := json.Marshal(q)
		const command = `SELECT zasp_sa_multistep_prior.pricing_admin($1,$2,$3::jsonb)`
		var first, replay []byte
		if err = admin.QueryRow(ctx, command, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&first); err != nil {
			t.Fatal("near-threshold SQL create", err)
		}
		before := orderedPricingSnapshot(t, ctx, owner)
		// Wait only until the saved request's actual effective-time threshold.
		// Both clocks are real; no policy row or clock is fault-injected.
		if _, err = owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)`, deadline); err != nil {
			t.Fatal(err)
		}
		var crossed bool
		if err = owner.QueryRow(ctx, `SELECT clock_timestamp()>$1`, deadline).Scan(&crossed); err != nil || !crossed || !time.Now().After(deadline) {
			t.Fatal("effective-time threshold not crossed", crossed, err)
		}
		if err = admin.QueryRow(ctx, command, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&replay); err != nil || !bytes.Equal(first, replay) || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("SQL saved replay changed after threshold", err)
		}
		var expected multisteppricing.AdminReceipt
		if err = json.Unmarshal(first, &expected); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Admin(ctx, raw)
		expectedJSON, _ := json.Marshal(expected)
		gotJSON, _ := json.Marshal(got)
		if err != nil || !bytes.Equal(expectedJSON, gotJSON) || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Error("Go exact replay rejected or changed after effective threshold", err)
		}
		for _, operation := range []string{"create", "version"} {
			t.Run("new_"+operation, func(t *testing.T) {
				freshMutation := cloneOrderedApplicationRequest(t, q)
				freshMutation["idempotency_key"] = "effective-threshold-new-" + operation
				if operation == "create" {
					freshMutation["policy"].(map[string]any)["account_profile"] = "effective-threshold-new-account"
				} else {
					freshMutation["operation"], freshMutation["expected_version"], freshMutation["expected_account_version"] = "version", 1, 1
				}
				if _, err := orderedPricingCall(ctx, admin, "pricing_admin", freshMutation); err == nil {
					t.Error("SQL permitted new mutation with stale effective time")
				}
				mutationRaw, _ := json.Marshal(freshMutation)
				if _, err := repo.Admin(ctx, mutationRaw); err == nil || orderedPricingSnapshot(t, ctx, owner) != before {
					t.Fatal("new stale-effective mutation was not refused unchanged", err)
				}
			})
		}
	})
}

func TestSecurityAgentMultistepPricingConcurrentPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		q := orderedPricingAdminRequest(o, w, e, actor)
		first, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		other, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		q["operation"] = "version"
		q["expected_version"] = 1
		q["expected_account_version"] = 1
		q["idempotency_key"] = "concurrent-pricing-version-1"
		q["policy"].(map[string]any)["maximum_tokens"] = 1001
		second := cloneOrderedApplicationRequest(t, q)
		second["idempotency_key"] = "concurrent-pricing-version-2"
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		winning, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := orderedPricingCall(ctx, other, "pricing_admin", second); done <- err }()
		joined := false
		defer func() {
			tx.Rollback(context.Background())
			if !joined {
				<-done
			}
		}()
		waitOrderedProgressionBlocked(t, ctx, admin, other)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		err = <-done
		joined = true
		if err == nil {
			t.Fatal("two writers used the same expected version")
		}
		if winning["version"] != float64(2) || winning["account_version"] != float64(1) || winning["policy_id"] != first["policy_id"] {
			t.Fatal("concurrent version identity", winning)
		}
		before := orderedPricingSnapshot(t, ctx, owner)
		if replay, err := orderedPricingCall(ctx, other, "pricing_admin", q); err != nil || !jsonEqualMaps(replay, winning) || orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("winning restart duplicated version", err, replay)
		}
		var n int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_sa_multistep_prior.pricing_policies`).Scan(&n); err != nil || n != 2 {
			t.Fatal("duplicate policy revision", n, err)
		}
	})
}

func TestSecurityAgentMultistepPricingWaitPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		for _, mode := range []string{"expiry", "disable", "rotation", "readiness", "admin_auth", "admin_policy_expiry", "admin_revoke"} {
			t.Run(mode, func(t *testing.T) {
				q := orderedPricingAdminRequest(o, w, e, actor)
				q["idempotency_key"] = "pricing-wait-create-" + mode
				q["policy"].(map[string]any)["account_profile"] = "wait-" + mode
				adminCase := strings.HasPrefix(mode, "admin_")
				if mode == "expiry" || mode == "admin_policy_expiry" {
					q["policy"].(map[string]any)["expires_at"] = time.Now().UTC().Add(2 * time.Second).Format("2006-01-02T15:04:05.000000Z")
				}
				if mode == "admin_auth" {
					q["fresh_auth_at"] = time.Now().UTC().Add(-5*time.Minute + 2*time.Second).Format("2006-01-02T15:04:05.000000Z")
				}
				var lookup map[string]any
				if !adminCase {
					created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
					if err != nil {
						t.Fatal(err)
					}
					lookup = orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), created)
				}
				blocker := owner
				if mode == "disable" || mode == "rotation" {
					blocker = admin
				}
				before := orderedPricingSnapshot(t, ctx, owner)
				tx, err := blocker.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if mode == "disable" || mode == "rotation" {
					q["operation"] = "disable"
					if mode == "rotation" {
						q["operation"] = "version"
						q["policy"].(map[string]any)["credential_digest"] = "sha256:" + strings.Repeat("cd", 32)
					}
					q["expected_version"] = 1
					q["expected_account_version"] = 1
					q["idempotency_key"] = "pricing-wait-change-" + mode
					if _, err = orderedPricingCall(ctx, admin, "pricing_admin", q); err != nil {
						t.Fatal(err)
					}
				} else if mode == "admin_auth" || mode == "admin_policy_expiry" {
					if _, err = tx.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,zasp_discovery_canonical_id($1,$2,$3,'security_agent_pricing_mutation',$4||chr(31)||$5),$4,'fixture.wait',$4,'succeeded','{}')`, o, w, e, actor, q["idempotency_key"]); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
						t.Fatal(err)
					}
				}
				caller := worker
				function := "pricing_lookup"
				request := lookup
				if adminCase {
					caller = admin
					function = "pricing_admin"
					request = q
				}
				callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := orderedPricingCall(callCtx, caller, function, request); done <- err }()
				joined := false
				defer func() {
					cancel()
					tx.Rollback(context.Background())
					if !joined {
						<-done
					}
				}()
				waitOrderedProgressionBlocked(t, ctx, blocker, caller)
				if mode == "expiry" || mode == "admin_policy_expiry" || mode == "admin_auth" {
					until, _ := time.Parse(time.RFC3339Nano, q["policy"].(map[string]any)["expires_at"].(string))
					if mode == "admin_auth" {
						until, _ = time.Parse(time.RFC3339Nano, q["fresh_auth_at"].(string))
						until = until.Add(5 * time.Minute)
					}
					for time.Now().Before(until.Add(5 * time.Millisecond)) {
						time.Sleep(5 * time.Millisecond)
					}
				}
				if mode == "readiness" {
					if _, err = tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_fingerprint'`); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "admin_revoke" {
					if _, err = tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
						t.Fatal(err)
					}
				}
				// The audit blocker is not evidence. Its rollback lets the contender
				// reach its last guard, which must roll its entire write back.
				if mode == "admin_auth" || mode == "admin_policy_expiry" {
					err = tx.Rollback(ctx)
				} else {
					err = tx.Commit(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				err = <-done
				joined = true
				if err == nil {
					t.Error("expired/revoked post-wait authority accepted")
				}
				if mode == "readiness" {
					if _, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_multistep_fingerprint'`, migrations.SecurityAgentMultistepRegisteredFingerprint()); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "admin_revoke" {
					if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
						t.Fatal(err)
					}
				}
				if adminCase {
					if orderedPricingSnapshot(t, ctx, owner) != before {
						t.Fatal("refused admin wait changed immutable pricing history")
					}
					var n int
					if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_sa_multistep_prior.pricing_mutations WHERE request->>'idempotency_key'=$1)+(SELECT count(*) FROM zasp_sa_multistep_prior.pricing_policies WHERE policy->>'account_profile'=$2)+(SELECT count(*) FROM zasp_sa_multistep_prior.pricing_accounts WHERE account_profile=$2)+(SELECT count(*) FROM zasp_admin_audit WHERE id=zasp_discovery_canonical_id($3,$4,$5,'security_agent_pricing_mutation',$6||chr(31)||$1))`, q["idempotency_key"], q["policy"].(map[string]any)["account_profile"], o, w, e, actor).Scan(&n); err != nil || n != 0 {
						t.Fatal("refused wait left partial policy/account/audit", n, err)
					}
				}
			})
		}
	})
}

func TestSecurityAgentMultistepPricingAmbiguityPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		q := orderedPricingAdminRequest(o, w, e, actor)
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		lookup := orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), created)
		// Fault fixture only: an extra noncanonical policy identity must not be
		// silently ignored when resolving the exact model/account tuple.
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_sa_multistep_prior.pricing_policies SELECT organization_id,workspace_id,environment_id,$1,version,account_id,account_version,policy,policy_digest,disabled,actor_id,fresh_auth_at,created_at FROM zasp_sa_multistep_prior.pricing_policies`, actor); err != nil {
			t.Fatal(err)
		}
		before := orderedPricingSnapshot(t, ctx, owner)
		if _, err = orderedPricingCall(ctx, worker, "pricing_lookup", lookup); err == nil {
			t.Fatal("ambiguous policy silently selected")
		}
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("ambiguity changed authority")
		}
	})
}
