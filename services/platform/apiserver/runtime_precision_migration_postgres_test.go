package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func precisionMigrationRunner(t *testing.T, admin *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: admin})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestRuntimePrecisionMigrationRefusesContention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	migrator, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	runner := precisionMigrationRunner(t, migrator)
	for _, direction := range []struct {
		name          string
		run           func(context.Context) error
		before, after int64
	}{{"up", runner.UpProductionRuntimePrecision, 50, 51}, {"down", runner.DownProductionRuntimePrecision, 51, 50}} {
		for _, table := range []string{"zasp_schema_versions", "zasp_schema_metadata", "zasp_runtime_stage_work", "zasp_runtime_sandbox_search_outbox", "zasp_discovery_outbox", "zasp_discovery_outbox_topic_fairness", "zasp_runtime_deliveries"} {
			t.Run(direction.name+"/"+table, func(t *testing.T) {
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, `LOCK TABLE `+pgx.Identifier{table}.Sanitize()+` IN ACCESS SHARE MODE`); err != nil {
					t.Fatal(err)
				}
				bounded, stop := context.WithTimeout(ctx, 2*time.Second)
				err = direction.run(bounded)
				expired := bounded.Err() != nil
				stop()
				if expired || !errors.Is(err, migrations.ErrDatabase) {
					t.Fatal("migration did not release contention promptly", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if version, err := runner.Version(ctx); err != nil || version != direction.before {
					t.Fatal("contended migration changed registry", version, err)
				}
			})
		}
		if err := direction.run(ctx); err != nil {
			t.Fatal(direction.name, err)
		}
		if version, err := runner.Version(ctx); err != nil || version != direction.after {
			t.Fatal("uncontended migration registry", version, err)
		}
	}
}

func TestRuntimePrecisionMigrationClaimsAndRollbackFence(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		for _, state := range []string{"pending", "expired leased", "exhausted", "final attempt"} {
			t.Run(stage+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, _ := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				runner := installRuntimePrecision(t, ctx, admin)
				version, old, newName := "runtime-projection-v3", "zasp_runtime_claim_projection_v2", "zasp_runtime_claim_projection_v3"
				if stage == "complete" {
					version, old, newName = "runtime-complete-v3", "zasp_runtime_claim_completion_v2", "zasp_runtime_claim_completion_v3"
				}
				args := seedSandboxStageClaim(t, ctx, admin, stage, version, state)
				before := sandboxStageState(t, ctx, admin)
				worker := sandboxStageWorker(t, ctx, admin, stage)
				var body []byte
				if err := worker.QueryRow(ctx, `SELECT `+old+`('old-worker','old-worker-lease-01',60,10)`).Scan(&body); err != nil || string(body) != "[]" || sandboxStageState(t, ctx, admin) != before {
					t.Fatal("old claim changed precise work", string(body), err)
				}
				if err := worker.QueryRow(ctx, `SELECT `+newName+`('new-worker','new-worker-lease-01',60,10)`).Scan(&body); err != nil {
					t.Fatal("precise claim", err)
				}
				var leases []struct {
					Batch   string `json:"batch_id"`
					Version string `json:"implementation_version"`
					Attempt int    `json:"attempt"`
				}
				if err := json.Unmarshal(body, &leases); err != nil {
					t.Fatal(err)
				}
				if state == "exhausted" {
					if len(leases) != 0 {
						t.Fatal("exhausted leased", string(body))
					}
					var terminal bool
					if err := admin.QueryRow(ctx, `SELECT state='failed' AND last_error_class='exhausted' AND attempt=100 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, args[3], stage).Scan(&terminal); err != nil || !terminal {
						t.Fatal("exhaustion not retained", err)
					}
				} else if len(leases) != 1 || leases[0].Batch != args[3] || leases[0].Version != version {
					t.Fatal("wrong lease", string(body))
				}
				if err := runner.DownProductionRuntimePrecision(ctx); !errors.Is(err, migrations.ErrDatabase) {
					t.Fatal("rollback discarded precise work", err)
				}
			})
		}
	}
}

func TestRuntimePrecisionMigrationSearchVersionReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	worker := sandboxSessionCoordinator(t, ctx, admin)
	var body []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "candidate_index"
	index, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close(context.Background())
	if err := index.QueryRow(ctx, `SELECT COALESCE(zasp_runtime_sandbox_search_claim('old-search','old-search-token-01',30),'null'::jsonb)`).Scan(&body); err != nil || string(body) != "null" {
		t.Fatal("old search consumed precise receipt", string(body), err)
	}
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_precise_search_claim('new-search','new-search-token-01',30)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Version string `json:"projection_implementation_version"`
		Attempt int    `json:"attempt"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.Version != "runtime-projection-v3" || receipt.Attempt != 1 {
		t.Fatal("search claim lost receipt codec", string(body), err)
	}
}

func installRuntimePrecision(t *testing.T, ctx context.Context, admin *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := precisionMigrationRunner(t, admin)
	if err := runner.UpProductionRuntimePrecision(ctx); err != nil {
		tx, diagnosticErr := admin.Begin(ctx)
		if diagnosticErr == nil {
			_, diagnosticErr = tx.Exec(ctx, migrations.ProductionRuntimePrecision().UpSQL())
			var provider *pgconn.PgError
			if errors.As(diagnosticErr, &provider) {
				t.Log("position", provider.Position, "internal", provider.InternalPosition, "where", provider.Where, "query", provider.InternalQuery)
			}
			if diagnosticErr == nil {
				var fingerprint string
				var secure bool
				diagnosticErr = tx.QueryRow(ctx, `SELECT zasp_production_runtime_precision_live_fingerprint(),zasp_production_runtime_sandbox_binding_security_ready()`).Scan(&fingerprint, &secure)
				t.Log("live precision fingerprint", fingerprint, "secure", secure)
			}
			_ = tx.Rollback(context.Background())
		}
		t.Fatal("install precision", err, "diagnostic", diagnosticErr)
	}
	return runner
}

// Missing a fragment, grant, trigger identity, or reversal must break a real
// registered install. Readiness must reject catalog drift before rollback.
func TestRuntimePrecisionMigrationRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	var before string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_live_fingerprint()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	runner := installRuntimePrecision(t, ctx, admin)
	metadata := migrations.ProductionRuntimePrecision()
	t.Log("release51 checksum", metadata.Checksum(), "semantic fingerprint", migrations.ProductionRuntimePrecisionSemanticFingerprint())
	if version, err := runner.Version(ctx); err != nil || version != 51 {
		t.Fatal("release not registered", version, err)
	}
	var ready bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("complete precision readiness", ready, err)
	}
	for signature, role := range map[string]string{
		"zasp_runtime_claim_outbox_v2(text,text,text,integer,integer)":                                                "zasp_outbox_worker",
		"zasp_runtime_claim_reconciliation_v2(text,text,integer,integer)":                                             "zasp_runtime_ingest",
		"zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea)": "zasp_runtime_correlation_worker",
		preciseCompletionSignature:                                     "zasp_runtime_coordinator",
		"zasp_runtime_claim_archive_v2(text,text,integer,integer)":     "zasp_runtime_archive_worker",
		"zasp_runtime_claim_index_v2(text,text,integer,integer)":       "zasp_runtime_index_worker",
		"zasp_runtime_claim_correlation_v4(text,text,integer,integer)": "zasp_runtime_correlation_worker",
		"zasp_runtime_claim_projection_v3(text,text,integer,integer)":  "zasp_runtime_projection_worker",
		"zasp_runtime_claim_completion_v3(text,text,integer,integer)":  "zasp_runtime_coordinator",
		"zasp_runtime_precise_search_claim(text,text,integer)":         "zasp_runtime_index_worker",
	} {
		var allowed, public bool
		if err := admin.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE'),has_function_privilege('public',$2,'EXECUTE')`, role, signature).Scan(&allowed, &public); err != nil || !allowed || public {
			t.Fatal("grant boundary", signature, allowed, public, err)
		}
	}
	if err := runner.DownProductionRuntimePrecision(ctx); err != nil {
		t.Fatal("safe rollback", err)
	}
	var after string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_live_fingerprint()`).Scan(&after); err != nil || before != after {
		t.Fatal("exact predecessor restoration", before, after, err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 50 {
		t.Fatal("rollback registry", version, err)
	}
	if err := runner.UpProductionRuntimePrecision(ctx); err != nil {
		t.Fatal("reinstall", err)
	}
	for _, drift := range []string{
		`REVOKE EXECUTE ON FUNCTION zasp_runtime_freeze_precise_candidates(text,text,text,text,bigint,text,text,integer,text,bytea,bytea,bytea) FROM zasp_runtime_correlation_worker`,
		`CREATE OR REPLACE FUNCTION zasp_runtime_precise_epoch(value text) RETURNS numeric LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog,public AS 'SELECT 1::numeric'`,
		`ALTER TRIGGER zasp_runtime_precision_claim_version ON zasp_runtime_stage_work RENAME TO zasp_test_changed_trigger_identity`,
	} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, drift); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatal("drift accepted", drift, ready, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimePrecision(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatal("drift rollback accepted", err)
	}
}

func TestRuntimePrecisionMigrationSearchCachedClaimAndExhaustion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	worker := sandboxSessionCoordinator(t, ctx, admin)
	var body []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	index := precisionStageWorker(t, ctx, admin, "index")
	var oldBody string
	if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_runtime_sandbox_search_claim(text,text,integer)'::regprocedure)`).Scan(&oldBody); err != nil {
		t.Fatal(err)
	}
	// Reproduce the cached pre-version-filter body, keeping its real lock,
	// worker, scope and lease checks. Only the missing version filter differs.
	oldBody = strings.Replace(oldBody, "FUNCTION public.zasp_runtime_sandbox_search_claim(", "FUNCTION public.zasp_test_cached_search(", 1)
	oldBody = strings.ReplaceAll(oldBody, "project.implementation_version IN('runtime-projection-v1','runtime-projection-v2')", "true")
	if _, err := admin.Exec(ctx, oldBody+`; ALTER FUNCTION zasp_test_cached_search(text,text,integer) OWNER TO zasp_discovery_authority; REVOKE ALL ON FUNCTION zasp_test_cached_search(text,text,integer) FROM PUBLIC; GRANT EXECUTE ON FUNCTION zasp_test_cached_search(text,text,integer) TO zasp_runtime_index_worker`); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "expired", "exhausted"} {
		t.Run(state, func(t *testing.T) {
			var saved string
			if err := admin.QueryRow(ctx, `SELECT to_jsonb(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			patch := `{"state":"pending","attempt":0,"worker_id":null,"lease_digest":null,"lease_until":null}`
			if state == "expired" {
				patch = `{"state":"leased","attempt":1,"worker_id":"prior-worker","lease_digest":"\\xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lease_until":"2020-01-01T00:00:00Z"}`
			}
			if state == "exhausted" {
				patch = `{"state":"pending","attempt":100,"worker_id":null,"lease_digest":null,"lease_until":null}`
			}
			// Insert a historical queue fixture without changing a claim's attempt
			// through the very mutation fence this test is supposed to exercise.
			if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_sandbox_search_outbox`); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_sandbox_search_outbox SELECT (jsonb_populate_record(NULL::zasp_runtime_sandbox_search_outbox,$1::jsonb||$2::jsonb)).*`, saved, patch); err != nil {
				t.Fatal(err)
			}
			var before, after string
			if err := admin.QueryRow(ctx, `SELECT to_jsonb(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			err := index.QueryRow(ctx, `SELECT zasp_test_cached_search('cached-search','cached-search-token-01',30)`).Scan(&body)
			requireSandboxSQLState(t, err, "42501")
			if err := index.QueryRow(ctx, `SELECT COALESCE(zasp_runtime_sandbox_search_claim('old-search','old-search-token-01',30),'null'::jsonb)`).Scan(&body); err != nil || string(body) != "null" {
				t.Fatal("old search touched V3", err)
			}
			if err := admin.QueryRow(ctx, `SELECT to_jsonb(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&after); err != nil || before != after {
				t.Fatal("cached or old search mutated precise row", err)
			}
			if err := index.QueryRow(ctx, `SELECT COALESCE(zasp_runtime_precise_search_claim('new-search','new-search-token-01',30),'null'::jsonb)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if state == "exhausted" {
				var quarantined bool
				if err := admin.QueryRow(ctx, `SELECT state='quarantined' AND attempt=100 AND lease_until IS NULL FROM zasp_runtime_sandbox_search_outbox`).Scan(&quarantined); err != nil || !quarantined || string(body) != "null" {
					t.Fatal("precise exhaustion", string(body), err)
				}
			} else if string(body) == "null" {
				t.Fatal("precise claim absent")
			}
		})
	}
}

func TestRuntimePrecisionMigrationRejectsUnexpectedTriggers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	metadata := migrations.ProductionRuntimePrecision()
	for _, table := range []string{"zasp_runtime_stage_work", "zasp_runtime_batch_authorities", "zasp_runtime_ingest_reconciliation_work", "zasp_runtime_ingest_reconciliation_state", "zasp_discovery_outbox", "zasp_discovery_outbox_topic_fairness", "zasp_runtime_deliveries"} {
		t.Run(table, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			// This trigger really changes insert/update behavior, but its arbitrary
			// name is outside the precision migration's original four-name list.
			if _, err := tx.Exec(ctx, `CREATE TRIGGER unrelated_runtime_guard BEFORE INSERT OR UPDATE ON `+pgx.Identifier{table}.Sanitize()+` FOR EACH ROW EXECUTE FUNCTION zasp_runtime_pairing_immutable()`); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("unexpected trigger accepted by complete readiness", table, ready, err)
			}
		})
	}
}
