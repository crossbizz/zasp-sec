package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepPricingSecurityPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		var secure bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=3 AND bool_and(relrowsecurity AND relforcerowsecurity AND relowner='zasp_discovery_authority'::regrole) FROM pg_class WHERE relnamespace='zasp_sa_multistep_prior'::regnamespace AND relname IN('pricing_policies','pricing_accounts','pricing_mutations')) AND has_function_privilege('zasp_discovery_api','zasp_sa_multistep_prior.pricing_admin(text,text,jsonb)','EXECUTE') AND NOT has_function_privilege('zasp_security_agent_worker','zasp_sa_multistep_prior.pricing_admin(text,text,jsonb)','EXECUTE') AND has_function_privilege('zasp_security_agent_worker','zasp_sa_multistep_prior.pricing_lookup(text,text,jsonb)','EXECUTE') AND NOT has_function_privilege('zasp_discovery_api','zasp_sa_multistep_prior.pricing_lookup(text,text,jsonb)','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_sa_multistep_prior'::regnamespace AND p.proname LIKE 'pricing_%' AND a.grantee=0)`).Scan(&secure); err != nil || !secure {
			t.Fatal("least privilege", secure, err)
		}
		q := orderedPricingAdminRequest(o, w, e, actor)
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		for _, connection := range []*pgx.Conn{worker, admin} {
			for _, table := range []string{"pricing_policies", "pricing_accounts", "pricing_mutations"} {
				if _, err := connection.Exec(ctx, `SELECT * FROM zasp_sa_multistep_prior.`+table); err == nil {
					t.Fatal("direct authority table read granted", table)
				}
			}
		}
		for _, mutation := range []string{`ALTER TABLE zasp_sa_multistep_prior.pricing_policies DISABLE ROW LEVEL SECURITY`, `ALTER TABLE zasp_sa_multistep_prior.pricing_accounts DISABLE TRIGGER immutable`, `GRANT SELECT ON zasp_sa_multistep_prior.pricing_mutations TO zasp_security_agent_worker`, `ALTER FUNCTION zasp_sa_multistep_prior.pricing_lookup(text,text,jsonb) SET search_path=public`, `ALTER TABLE zasp_sa_multistep_prior.pricing_policies ADD COLUMN drift text`} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, mutation); err != nil {
				tx.Rollback(ctx)
				t.Fatal(err)
			}
			var ready bool
			err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready)
			tx.Rollback(ctx)
			if err != nil || ready {
				t.Fatal("pricing drift remained ready", mutation, ready, err)
			}
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `GRANT SELECT ON zasp_sa_multistep_prior.pricing_policies TO zasp_security_agent_worker; SET LOCAL ROLE zasp_security_agent_worker`); err != nil {
			t.Fatal(err)
		}
		var rows int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM zasp_sa_multistep_prior.pricing_policies`).Scan(&rows); err != nil || rows != 0 {
			t.Fatal("RLS leaked pricing history", rows, err)
		}
		tx.Rollback(ctx)
		before := orderedPricingSnapshot(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		if err = runner.DownProductionSecurityAgentMultistep(ctx); err == nil {
			t.Fatal("rollback discarded pricing approval history")
		}
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("refused down changed authority")
		}
		lookup := orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), created)
		raw, _ := json.Marshal(lookup)
		var result []byte
		if err = worker.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.pricing_lookup($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), strings.Repeat("0", 64), raw).Scan(&result); err == nil {
			t.Fatal("stale compiled pin accepted")
		}
		if _, err = orderedPricingCall(ctx, admin, "pricing_lookup", lookup); err == nil {
			t.Fatal("admin became worker")
		}
		if _, err = orderedPricingCall(ctx, owner, "pricing_admin", q); err == nil {
			t.Fatal("owner bypassed bound admin principal")
		}
	})
}

func TestSecurityAgentMultistepPricingEmptyRoundTripPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, _, _, _, _ string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.DownProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal("unused pricing down", err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_sa_multistep_prior') IS NULL AND max(version)=60 FROM zasp_schema_versions`).Scan(&absent); err != nil || !absent {
			t.Fatal("private pricing did not demote exactly", absent, err)
		}
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if _, err := multisteppricing.New(db, "worker"); err == nil {
			t.Fatal("private pricing accepted60")
		}
		if err := runner.UpProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal("pricing repromote", err)
		}
		if _, err := multisteppricing.New(db, "worker"); err != nil {
			t.Fatal("repromoted worker", err)
		}
	})
}

func TestSecurityAgentMultistepPricingBodyBoundaryPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		q := orderedPricingAdminRequest(o, w, e, actor)
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
		if err != nil {
			t.Fatal(err)
		}
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		repository, err := multisteppricing.New(db, "worker")
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{65536, 65537} {
			lookup := orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), created)
			body := lookup["body"].(string)
			body += strings.Repeat(" ", size-len(body))
			sum := sha256.Sum256([]byte(body))
			lookup["body"] = body
			lookup["body_digest"] = "sha256:" + hex.EncodeToString(sum[:])
			before := orderedPricingSnapshot(t, ctx, owner)
			_, sqlErr := orderedPricingCall(ctx, worker, "pricing_lookup", lookup)
			raw, _ := json.Marshal(lookup)
			_, goErr := repository.Lookup(ctx, raw)
			if (sqlErr == nil) != (size == 65536) || (goErr == nil) != (size == 65536) {
				t.Fatal("SQL/Go body limit mismatch", size, sqlErr, goErr)
			}
			if orderedPricingSnapshot(t, ctx, owner) != before {
				t.Fatal("boundary lookup mutated authority")
			}
		}
	})
}

func TestSecurityAgentMultistepPricingIdentityWriterPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, _ *pgx.Conn, o, w, e, actor string) {
		q := orderedPricingAdminRequest(o, w, e, actor)
		before := orderedPricingSnapshot(t, ctx, owner)
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		callCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if _, err = orderedPricingCall(callCtx, admin, "pricing_admin", q); err == nil || callCtx.Err() != nil {
			t.Fatal("identity safety writer blocked or admin accepted", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal("identity writer aborted", err)
		}
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("refused admin changed authority")
		}
	})
}

func TestSecurityAgentMultistepPricingDurationBoundaryPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, actor string) {
		if _, err := owner.Exec(ctx, `SET TIME ZONE 'America/New_York'`); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(context.Background(), `SET TIME ZONE 'UTC'`)
		// Literal UTC durations cross the DST transitions. The ceiling is an
		// elapsed 720 hours, independent of the database session's time zone.
		for _, tc := range []struct {
			effective, expires string
			want               bool
		}{
			{"2026-03-01T00:00:00.000000Z", "2026-03-31T00:00:00.000000Z", true},
			{"2026-10-15T00:00:00.000000Z", "2026-11-14T00:00:00.000001Z", false},
		} {
			p := orderedPricingAdminRequest(o, w, e, actor)["policy"].(map[string]any)
			p["effective_at"], p["expires_at"] = tc.effective, tc.expires
			raw, _ := json.Marshal(p)
			var valid bool
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.pricing_policy_valid($1::jsonb)`, raw).Scan(&valid); err != nil || valid != tc.want {
				t.Errorf("UTC duration validation effective=%s valid=%v want=%v err=%v", tc.effective, valid, tc.want, err)
			}
		}
	})
}

func TestSecurityAgentMultistepPricingRevisionCeilingPostgres(t *testing.T) {
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		adminDB, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: admin})
		adminRepo, err := multisteppricing.New(adminDB, "admin")
		if err != nil {
			t.Fatal(err)
		}
		workerDB, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		workerRepo, err := multisteppricing.New(workerDB, "worker")
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"account_version", "account_disable", "account_rotate", "policy_active_last", "policy_disable_last", "storage_active_last"} {
			t.Run(mode, func(t *testing.T) {
				q := orderedPricingAdminRequest(o, w, e, actor)
				q["idempotency_key"] = "ceiling-create-" + mode
				q["policy"].(map[string]any)["account_profile"] = "ceiling-" + mode
				created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
				if err != nil {
					t.Fatal(err)
				}
				// Owner-inserted boundary-state fixture, not a million real
				// revisions. No retained row or immutable trigger is changed.
				policyVersion, accountVersion := int64(999999), int64(1)
				if strings.HasPrefix(mode, "account_") {
					policyVersion, accountVersion = 2, 1000000
					if _, err = owner.Exec(ctx, `INSERT INTO zasp_sa_multistep_prior.pricing_accounts SELECT (jsonb_populate_record(NULL::zasp_sa_multistep_prior.pricing_accounts,to_jsonb(a)||'{"version":1000000}'::jsonb)).* FROM zasp_sa_multistep_prior.pricing_accounts a WHERE account_id=$1 AND version=1`, created["account_id"]); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = owner.Exec(ctx, `WITH boundary AS (SELECT jsonb_populate_record(NULL::zasp_sa_multistep_prior.pricing_policies,to_jsonb(p)||jsonb_build_object('version',$2::bigint,'account_version',$3::bigint)) AS p FROM zasp_sa_multistep_prior.pricing_policies p WHERE policy_id=$1 AND version=1) INSERT INTO zasp_sa_multistep_prior.pricing_policies SELECT (jsonb_populate_record(NULL::zasp_sa_multistep_prior.pricing_policies,to_jsonb(p)||jsonb_build_object('policy_digest',zasp_sa_multistep_prior.pricing_digest(p)))).* FROM boundary`, created["policy_id"], policyVersion, accountVersion); err != nil {
					t.Fatal(err)
				}
				q["operation"], q["idempotency_key"] = "version", "ceiling-mutation-"+mode
				q["expected_version"], q["expected_account_version"] = policyVersion, accountVersion
				if strings.Contains(mode, "disable") {
					q["operation"] = "disable"
				}
				if mode == "account_rotate" {
					q["policy"].(map[string]any)["credential_digest"] = "sha256:" + strings.Repeat("cd", 32)
				}
				before := orderedPricingSnapshot(t, ctx, owner)
				if mode == "storage_active_last" {
					_, err = owner.Exec(ctx, `WITH boundary AS (SELECT jsonb_populate_record(NULL::zasp_sa_multistep_prior.pricing_policies,to_jsonb(p)||'{"version":1000000}'::jsonb) AS p FROM zasp_sa_multistep_prior.pricing_policies p WHERE policy_id=$1 AND version=999999) INSERT INTO zasp_sa_multistep_prior.pricing_policies SELECT (jsonb_populate_record(NULL::zasp_sa_multistep_prior.pricing_policies,to_jsonb(p)||jsonb_build_object('policy_digest',zasp_sa_multistep_prior.pricing_digest(p)))).* FROM boundary`, created["policy_id"])
					if err == nil || orderedPricingSnapshot(t, ctx, owner) != before {
						t.Fatal("storage accepted active final revision reserved for disable", err)
					}
					return
				}
				result, sqlErr := orderedPricingCall(ctx, admin, "pricing_admin", q)
				afterSQL := orderedPricingSnapshot(t, ctx, owner)
				raw, _ := json.Marshal(q)
				replayed, goErr := adminRepo.Admin(ctx, raw)
				if mode == "account_rotate" || mode == "policy_active_last" {
					if sqlErr == nil || goErr == nil || orderedPricingSnapshot(t, ctx, owner) != before {
						t.Fatal("ceiling mutation did not refuse byte-identically", sqlErr, goErr)
					}
					return
				}
				if sqlErr != nil || goErr != nil || result["version"] != float64(policyVersion+1) || result["account_version"] != float64(accountVersion) || result["disabled"] != (q["operation"] == "disable") {
					t.Fatal("ceiling blocked safe non-rotating mutation", result, sqlErr, goErr)
				}
				replayRaw, _ := json.Marshal(replayed)
				var replayMap map[string]any
				if json.Unmarshal(replayRaw, &replayMap) != nil || !jsonEqualMaps(result, replayMap) || orderedPricingSnapshot(t, ctx, owner) != afterSQL {
					t.Fatal("SQL/Go exact replay changed receipt")
				}
				after := orderedPricingSnapshot(t, ctx, owner)
				if again, err := orderedPricingCall(ctx, admin, "pricing_admin", q); err != nil || !jsonEqualMaps(again, result) || orderedPricingSnapshot(t, ctx, owner) != after {
					t.Fatal("final revision replay duplicated authority", again, err)
				}
				lookup := orderedPricingLookupRequest(o, w, e, q["policy"].(map[string]any), result)
				lookupRaw, _ := json.Marshal(lookup)
				_, sqlErr = orderedPricingCall(ctx, worker, "pricing_lookup", lookup)
				_, goErr = workerRepo.Lookup(ctx, lookupRaw)
				wantLookup := mode == "account_version"
				if (sqlErr == nil) != wantLookup || (goErr == nil) != wantLookup || orderedPricingSnapshot(t, ctx, owner) != after {
					t.Fatal("ceiling SQL/Go active lookup disagreement", sqlErr, goErr)
				}
			})
		}
	})
}
