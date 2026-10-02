package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Exercise budget behavior through the actual forward migration chain and
// fresh registered repositories. Local fixture data is not live rollout proof.
func runSecurityAgentBudgetFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, string), starters ...func(*testing.T) string) {
	t.Helper()
	runSecurityAgentAttackPathFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		for index, apply := range []func(context.Context) error{
			runner.UpProductionIntegrationSetup,
			runner.UpProductionIntegrationWebhook,
			runner.UpProductionRuntimeQueueReplay,
			runner.UpProductionRedTeamSafety,
			runner.UpProductionRedTeamInvocation,
			runner.UpProductionRedTeamArtifacts,
			runner.UpProductionRuntimeSessions,
			runner.UpProductionRuntimeSessionReads,
			runner.UpProductionRuntimeSessionSearch,
			runner.UpProductionRuntimeSessionQuery,
			runner.UpProductionRuntimeSessionEvidence,
			runner.UpProductionRuntimeEnrollmentPairing,
			runner.UpProductionReconciliationLanePlan,
			runner.UpProductionRuntimeCandidateAuthority,
			runner.UpProductionRuntimeAcceptance,
			runner.UpProductionRuntimeCorrelationRouting,
			runner.UpProductionRuntimeSandboxBinding,
			runner.UpProductionRuntimePrecision,
			runner.UpProductionAuditExports,
			runner.UpProductionSecurityAgentBudgets,
		} {
			if err := apply(ctx); err != nil {
				t.Fatalf("budget fixture migration%d: %v", 34+index, err)
			}
		}
		if version, err := runner.Version(ctx); err != nil || version != 53 {
			t.Fatalf("budget fixture release=%d: %v", version, err)
		}
		exercise(ctx, owner, dsn)
	}, starters...)
}

func installSecurityAgentBudgetFragment(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	fragment, err := os.ReadFile("../migrations/sql/fragments/security_agent_budget_admission.sql")
	if err != nil {
		t.Fatal(err)
	}
	starts, err := os.ReadFile("../migrations/sql/fragments/security_agent_budget_starts.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, string(fragment)+"\n"+string(starts)); err != nil {
		t.Fatalf("install pending budget authority fragment: %v", err)
	}
}

func TestProductionSecurityAgentBudgetLegacyUsageCannotReset(t *testing.T) {
	for _, name := range []string{"known_limits_unknown_usage", "historical_limits_unknown_usage", "unavailable_limits_unknown_usage", "malformed_limits_unknown_usage"} {
		missingLimits := name == "unavailable_limits_unknown_usage" || name == "malformed_limits_unknown_usage"
		t.Run(name, func(t *testing.T) {
			runSecurityAgentAttackPathFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				config, err := pgx.ParseConfig(dsn)
				if err != nil {
					t.Fatal(err)
				}
				config.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
				if err != nil {
					t.Fatal(err)
				}
				repository, err := NewSecurityAgentWorkerRepository(database)
				if err != nil {
					t.Fatal(err)
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "budget-upgrade-worker", 1); err != nil || count != 1 {
					t.Fatalf("schedule count=%d err=%v", count, err)
				}
				if claims, err := repository.ClaimSecurityAgentRuns(ctx, "budget-upgrade-worker", "budget-upgrade-old-lease", 60, 1); err != nil || len(claims) != 1 {
					t.Fatalf("pre-upgrade claim count=%d err=%v", len(claims), err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET created_at=clock_timestamp()-interval '100 seconds' WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				if name == "historical_limits_unknown_usage" {
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definition_versions
(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),'budget-upgrade-history'
FROM zasp_security_agent_definitions WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				if name == "historical_limits_unknown_usage" || name == "unavailable_limits_unknown_usage" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET version=version+1,body='{}'::jsonb WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				} else if name == "malformed_limits_unknown_usage" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body='{"max_steps":"bad","max_duration_seconds":"999999999999999999999999999","ai_token_budget":-1,"concurrency_limit":99,"max_ai_cost_nano_credits":"NaN"}'::jsonb WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				// Fixture-owned cleanup row tests preservation only, not a live
				// policy effect or proof that the cleanup worker executed it.
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_controls
(organization_id,workspace_id,environment_id,control_id,run_id,step_id,action_key,target_id,state,expires_at)
SELECT organization_id,workspace_id,environment_id,'pid_6a000020-0000-4000-8000-000000000020',run_id,'pid_6a000021-0000-4000-8000-000000000021','create_temporary_policy',environment_id,'active',clock_timestamp()+interval '10 minutes'
FROM zasp_security_agent_runs WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				var controlsBefore string
				if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(c))::text FROM zasp_security_agent_controls c`).Scan(&controlsBefore); err != nil {
					t.Fatal(err)
				}
				installSecurityAgentBudgetFragment(t, ctx, owner)
				var stopped bool
				if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.last_error_code='budget_usage_unknown' AND r.lease_token IS NULL
 AND EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id)
 AND b.stop_reason='budget_usage_unknown' AND b.started_at=r.created_at)
FROM zasp_security_agent_runs r WHERE r.organization_id=$1`, organization).Scan(&stopped); err != nil || !stopped {
					t.Fatalf("legacy usage was given fresh authority: stopped=%t err=%v", stopped, err)
				}
				var correctLimits bool
				if err := owner.QueryRow(ctx, `SELECT max_cost_nano_credits IS NULL AND CASE WHEN $2::boolean
THEN deadline_at IS NULL AND max_steps IS NULL AND max_tokens IS NULL AND concurrency_limit IS NULL
ELSE deadline_at-started_at=interval '300 seconds' AND max_steps=1 AND max_tokens=1000 AND concurrency_limit=1 END
FROM zasp_security_agent_run_budgets WHERE organization_id=$1`, organization, missingLimits).Scan(&correctLimits); err != nil || !correctLimits {
					t.Fatalf("backfill invented or changed limits: valid=%t err=%v", correctLimits, err)
				}
				if missingLimits {
					_, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET stop_reason=NULL WHERE organization_id=$1`, organization)
					var pgError *pgconn.PgError
					if !errors.As(err, &pgError) || pgError.Code != "23514" {
						t.Fatalf("unknown limits could become active: %v", err)
					}
				}
				var controlsAfter string
				if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(c))::text FROM zasp_security_agent_controls c`).Scan(&controlsAfter); err != nil || controlsAfter != controlsBefore {
					t.Fatalf("upgrade changed cleanup work: err=%v", err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='queued' WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				if claims, err := repository.ClaimSecurityAgentRuns(ctx, "budget-upgrade-worker", "budget-upgrade-new-lease", 60, 1); err != nil || len(claims) != 0 {
					t.Fatalf("legacy requeue escaped stop: claims=%d err=%v", len(claims), err)
				}
			})
		})
	}
}

func TestProductionSecurityAgentBudgetCrossOrganizationProgress(t *testing.T) {
	for _, lockKind := range []string{"none", "organization", "expired_run", "expired_budget", "definition"} {
		locked := lockKind != "none"
		name := "oldest_organization_work_first"
		if locked {
			name = "locked_" + lockKind + "_does_not_block_other_tenant"
		}
		t.Run(name, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const firstOrganization = "pid_6a000001-0000-4000-8000-000000000001"
				const secondOrganization = "pid_9a000001-0000-4000-8000-000000000001"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1`); err != nil {
					t.Fatal(err)
				}
				config, err := pgx.ParseConfig(dsn)
				if err != nil {
					t.Fatal(err)
				}
				config.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
				if err != nil {
					t.Fatal(err)
				}
				repository, err := NewSecurityAgentWorkerRepository(database)
				if err != nil {
					t.Fatal(err)
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "budget-progress-worker", 25); err != nil || count != 2 {
					t.Fatalf("schedule count=%d err=%v", count, err)
				}
				oldest := secondOrganization
				if locked {
					oldest = firstOrganization
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET available_at=clock_timestamp()-CASE WHEN organization_id=$1 THEN interval '1 hour' ELSE interval '1 minute' END`, oldest); err != nil {
					t.Fatal(err)
				}
				if locked {
					if lockKind == "expired_run" || lockKind == "expired_budget" {
						claims, err := repository.ClaimSecurityAgentRuns(ctx, "budget-blocked-worker", "budget-blocked-lease-token", 60, 1)
						if err != nil || len(claims) != 1 || claims[0].OrganizationID != firstOrganization {
							t.Fatalf("initial blocked tenant claim=%#v err=%v", claims, err)
						}
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, firstOrganization); err != nil {
							t.Fatal(err)
						}
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, firstOrganization); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, firstOrganization); err != nil {
						t.Fatal(err)
					}
					transaction, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer transaction.Rollback(context.Background())
					lockQuery := `SELECT 1 FROM zasp_security_agent_org_admissions WHERE organization_id=$1 FOR UPDATE`
					if lockKind == "expired_run" {
						lockQuery = `SELECT 1 FROM zasp_security_agent_runs WHERE organization_id=$1 FOR UPDATE`
					} else if lockKind == "expired_budget" {
						lockQuery = `SELECT 1 FROM zasp_security_agent_run_budgets WHERE organization_id=$1 FOR UPDATE`
					} else if lockKind == "definition" {
						lockQuery = `SELECT 1 FROM zasp_security_agent_definitions WHERE organization_id=$1 FOR UPDATE`
					}
					if _, err := transaction.Exec(ctx, lockQuery, firstOrganization); err != nil {
						t.Fatal(err)
					}
				}
				// The timeout detects head-of-line waiting on a lock already held
				// deterministically. It is not a sleep or overlap timing heuristic.
				claimContext, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				claims, err := repository.ClaimSecurityAgentRuns(claimContext, "budget-progress-worker", "budget-progress-lease-token", 60, 1)
				if err != nil || len(claims) != 1 || claims[0].OrganizationID != secondOrganization {
					t.Fatalf("independent tenant progress: claims=%#v err=%v; want one second-organization claim", claims, err)
				}
			})
		})
	}
}

func TestProductionSecurityAgentBudgetSnapshotsAndLegacyClaims(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		const organization = "pid_6a000001-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
			t.Fatal(err)
		}
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "budget-snapshot-worker", 1); err != nil || count != 1 {
			t.Fatalf("schedule count=%d err=%v", count, err)
		}
		if claims, err := repository.ClaimSecurityAgentRuns(ctx, "budget-snapshot-worker", "budget-snapshot-first-lease", 60, 1); err != nil || len(claims) != 1 {
			t.Fatalf("initial claims=%d err=%v", len(claims), err)
		}
		for _, query := range []string{
			`SELECT * FROM zasp_security_agent_run_budgets`,
			`UPDATE zasp_security_agent_run_budgets SET stop_reason=NULL`,
			`SELECT * FROM zasp_security_agent_org_admissions`,
			`DELETE FROM zasp_security_agent_org_admissions`,
		} {
			_, err := worker.Exec(ctx, query)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || pgError.Code != "42501" {
				t.Fatalf("direct authority access must be denied: query=%s err=%v", query, err)
			}
		}
		var before string
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(b)::text FROM zasp_security_agent_run_budgets b WHERE organization_id=$1`, organization).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET version=version+1,body=body||'{"max_duration_seconds":86400,"max_steps":100,"ai_token_budget":12000,"concurrency_limit":10}'::jsonb WHERE organization_id=$1`, organization); err != nil {
			t.Fatal(err)
		}
		// Exercise every previously granted claim route. None may reset the
		// budget when the definition changes or a new worker takes over.
		entryPoints := []string{
			`SELECT zasp_security_agent_claim_runs('budget-legacy-worker','budget-legacy-lease-token',60,1)`,
			`SELECT zasp_security_agent_claim_runs_v22('budget-legacy-worker','budget-legacy-lease-token',60,1)`,
			`SELECT zasp_security_agent_claim_runs_v23('budget-legacy-worker','budget-legacy-lease-token',60,1)`,
		}
		for _, query := range entryPoints {
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
				t.Fatal(err)
			}
			var result struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := worker.QueryRow(ctx, query).Scan(&result); err != nil || len(result.Items) != 1 {
				t.Fatalf("legacy claim=%s items=%d err=%v", query, len(result.Items), err)
			}
			var after string
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(b)::text FROM zasp_security_agent_run_budgets b WHERE organization_id=$1`, organization).Scan(&after); err != nil || after != before {
				t.Fatalf("reclaim changed immutable budget: err=%v", err)
			}
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
			t.Fatal(err)
		}
		for _, query := range entryPoints {
			// A persisted stop survives even a legacy requeue. Only the fixture
			// owner can perform this direct state mutation.
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='queued',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE organization_id=$1`, organization); err != nil {
				t.Fatal(err)
			}
			var result struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := worker.QueryRow(ctx, query).Scan(&result); err != nil || len(result.Items) != 0 {
				t.Fatalf("legacy route bypassed stop: query=%s items=%d err=%v", query, len(result.Items), err)
			}
			var stopped bool
			if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.last_error_code='budget_deadline_exceeded' AND r.lease_token IS NULL AND b.stop_reason='budget_deadline_exceeded'
FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&stopped); err != nil || !stopped {
				t.Fatalf("stop not durable: stopped=%t err=%v", stopped, err)
			}
		}
	})
}

// A definition-local counter must not let two workers exceed one organization's
// limit. Separate organizations, however, must each retain their own capacity.
func TestProductionSecurityAgentBudgetOrganizationAdmission(t *testing.T) {
	for _, separateOrganizations := range []bool{false, true} {
		name := "two_definitions_share_organization_capacity"
		if separateOrganizations {
			name = "different_organizations_have_independent_capacity"
		}
		t.Run(name, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				if separateOrganizations {
					if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1`); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					// Same tenant, separate definition, both with concurrency_limit=1.
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions
(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
SELECT organization_id,workspace_id,environment_id,'pid_6a000004-0000-4000-8000-000000000014',activation,version,definition_version,
jsonb_set(body,'{id}','"pid_6a000004-0000-4000-8000-000000000014"'),plan_catalog_version
FROM zasp_security_agent_definitions WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				repositories := make([]*SecurityAgentWorkerRepository, 2)
				for i := range repositories {
					config, err := pgx.ParseConfig(dsn)
					if err != nil {
						t.Fatal(err)
					}
					config.User = "security_agent_v33_worker_login"
					connection, err := pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer connection.Close(context.Background())
					database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
					if err != nil {
						t.Fatal(err)
					}
					repositories[i], err = NewSecurityAgentWorkerRepository(database)
					if err != nil {
						t.Fatal(err)
					}
				}
				// Both queued runs are eligible; admission, not scheduling, is the
				// execution boundary. Each connection attempts to claim one run.
				if count, err := repositories[0].ScheduleSecurityAgentTriggers(ctx, "budget-admission-scheduler", 25); err != nil || count != 2 {
					t.Fatalf("schedule count=%d err=%v; want two eligible runs", count, err)
				}
				type result struct {
					count int
					err   error
				}
				start := make(chan struct{})
				results := make(chan result, 2)
				for i, repository := range repositories {
					go func() {
						<-start
						claims, err := repository.ClaimSecurityAgentRuns(ctx, fmt.Sprintf("budget-admission-worker-%d", i), fmt.Sprintf("budget-admission-lease-%04d", i), 60, 1)
						results <- result{count: len(claims), err: err}
					}()
				}
				close(start)
				claims := 0
				// Join both operations before any Fatal or fixture cleanup.
				first, second := <-results, <-results
				for _, outcome := range []result{first, second} {
					if outcome.err != nil {
						t.Fatalf("claim: %v", outcome.err)
					}
					claims += outcome.count
				}
				wantClaims := 1
				if separateOrganizations {
					wantClaims = 2
				}
				var planning, queued, organizations, effects int
				if err := owner.QueryRow(ctx, `SELECT
count(*) FILTER (WHERE state='planning'),count(*) FILTER (WHERE state='queued'),
count(DISTINCT organization_id) FILTER (WHERE state='planning'),
(SELECT count(*) FROM zasp_security_agent_effects)
FROM zasp_security_agent_runs`).Scan(&planning, &queued, &organizations, &effects); err != nil {
					t.Fatal(err)
				}
				if claims != wantClaims || planning != wantClaims || queued != 2-wantClaims || organizations != wantClaims || effects != 0 {
					t.Fatalf("organization admission: claims=%d planning=%d queued=%d organizations=%d effects=%d; want claims=%d queued=%d", claims, planning, queued, organizations, effects, wantClaims, 2-wantClaims)
				}
			})
		})
	}
}

// An expired run must never be handed to a planner, even after process restart.
// This intentionally exercises durable SQL authority, not BudgetManager memory.
func TestProductionSecurityAgentBudgetDeadlineStopsClaim(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "fresh_run_can_start"
		if expired {
			name = "expired_run_stops_before_replanning"
		}
		t.Run(name, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				config, err := pgx.ParseConfig(dsn)
				if err != nil {
					t.Fatal(err)
				}
				config.User = "security_agent_v33_worker_login"
				connection, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close(context.Background())
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
				if err != nil {
					t.Fatal(err)
				}
				repository, err := NewSecurityAgentWorkerRepository(database)
				if err != nil {
					t.Fatal(err)
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "budget-deadline-worker", 1); err != nil || count != 1 {
					t.Fatalf("schedule count=%d err=%v", count, err)
				}
				if expired {
					initial, err := repository.ClaimSecurityAgentRuns(ctx, "budget-deadline-worker", "budget-deadline-first-lease", 60, 1)
					if err != nil || len(initial) != 1 {
						t.Fatalf("initial planning claim count=%d err=%v", len(initial), err)
					}
					// Controlled fixture clock input, not a sleep or production override.
					// The run already started planning and its worker lease expired.
					// Reclaim must not reset the definition's 300-second wall clock.
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=transaction_timestamp()-interval '301 seconds',deadline_at=transaction_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				claims, err := repository.ClaimSecurityAgentRuns(ctx, "budget-deadline-worker", "budget-deadline-lease-0001", 60, 1)
				if err != nil {
					t.Fatal(err)
				}
				wantClaims, wantState := 1, "planning"
				if expired {
					wantClaims, wantState = 0, "needs_human"
				}
				var state string
				var plans, steps, approvals, effects int
				if err := owner.QueryRow(ctx, `SELECT state,
 (SELECT count(*) FROM zasp_security_agent_plans),
 (SELECT count(*) FROM zasp_security_agent_steps),
 (SELECT count(*) FROM zasp_security_agent_approvals),
 (SELECT count(*) FROM zasp_security_agent_effects)
FROM zasp_security_agent_runs WHERE organization_id=$1`, organization).Scan(&state, &plans, &steps, &approvals, &effects); err != nil {
					t.Fatal(err)
				}
				if len(claims) != wantClaims || state != wantState || plans != 0 || steps != 0 || approvals != 0 || effects != 0 {
					t.Fatalf("deadline enforcement: expired=%t claims=%d state=%s plans=%d steps=%d approvals=%d effects=%d; want claims=%d state=%s", expired, len(claims), state, plans, steps, approvals, effects, wantClaims, wantState)
				}
			})
		})
	}
}
