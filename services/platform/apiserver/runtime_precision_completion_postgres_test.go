package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"os"
	"testing"
	"time"
)

const preciseCompletionSignature = "public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)"

func TestRuntimePrecisionCompletionReachesItemAndEnqueueGuardsAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	fragment, err := os.ReadFile("../migrations/sql/fragments/runtime_precision_completion.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(fragment)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+preciseCompletionSignature+` TO zasp_runtime_coordinator`); err != nil {
		t.Fatal(err)
	}
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, projected := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	original := args[17].([]byte)
	for _, scenario := range []string{"final source", "exact", "valid receipt"} {
		t.Run(scenario, func(t *testing.T) {
			body := original
			if scenario != "valid receipt" {
				var wire map[string]any
				if err := json.Unmarshal(original, &wire); err != nil {
					t.Fatal(err)
				}
				items := wire["items"].([]any)
				if scenario == "final source" {
					items[len(items)-1].(map[string]any)["source"] = "otlp"
				} else {
					for _, value := range items {
						item := value.(map[string]any)
						if item["sandbox_id"] != nil {
							item["confidence"] = "exact"
							break
						}
					}
				}
				body, err = json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Independently forged provider bytes are deliberately supplied directly
			// to SQL. The matching predecessor SHA must not bypass item validation.
			digest := sha256.Sum256(body)
			if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET result_digest=$1 WHERE batch_id=$2 AND stage='project'`, digest[:], args[3]); err != nil {
				t.Fatal(err)
			}
			args[17] = body
			var result []byte
			err := coordinator.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...).Scan(&result)
			if scenario == "valid receipt" {
				if err != nil {
					t.Fatal("valid precise completion rejected", err)
				}
				if err := coordinator.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...).Scan(&result); err != nil {
					t.Fatal("precise replay rejected", err)
				}
				var state string
				var events, receipts, legacyQueue, preciseQueue int
				if err := admin.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_runtime_session_events),(SELECT count(*) FROM zasp_runtime_session_projection_receipts),(SELECT count(*) FROM zasp_runtime_session_search_outbox),(SELECT count(*) FROM zasp_runtime_sandbox_search_outbox) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, args[3]).Scan(&state, &events, &receipts, &legacyQueue, &preciseQueue); err != nil || state != "succeeded" || events != 3 || receipts != 1 || legacyQueue != 0 || preciseQueue != 1 {
					t.Fatal("precise completion/queue mismatch", err, state, events, receipts, legacyQueue, preciseQueue)
				}
				for _, item := range projected.Items {
					var sandbox, source string
					if err := admin.QueryRow(ctx, `SELECT COALESCE(sandbox_id,''),COALESCE(sandbox_source_sensor_id,'') FROM zasp_runtime_session_events WHERE event_id=$1`, item.EventID.String()).Scan(&sandbox, &source); err != nil || sandbox != item.SandboxID || source != item.SandboxSourceSensorID.String() {
						t.Fatal("persisted binding drift", err)
					}
				}
				// A cached old enqueue body still cannot insert unsupported V3 work.
				_, err = admin.Exec(ctx, `INSERT INTO zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids) SELECT organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids FROM zasp_runtime_sandbox_search_outbox`)
				requireSandboxSQLState(t, err, "22023")
				return
			}
			var provider *pgconn.PgError
			want := "runtime precise session source rejected"
			if !errors.As(err, &provider) || provider.Code != "22023" || provider.Message != want {
				t.Fatalf("guard=%v want=%s", err, want)
			}
			requireSandboxSessionUnfinished(t, ctx, admin, args[3], 0)
			var count int
			if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_session_search_outbox)+(SELECT count(*) FROM zasp_runtime_sandbox_search_outbox)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("partial search enqueue", count, err)
			}
		})
	}
}

func TestRuntimePrecisionCompletionPrivateAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	var historicalBefore string
	if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure)`).Scan(&historicalBefore); err != nil {
		t.Fatal(err)
	}
	fragment, err := os.ReadFile("../migrations/sql/fragments/runtime_precision_completion.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(fragment)); err != nil {
		t.Fatal(err)
	}
	var installed bool
	if err := admin.QueryRow(ctx, `SELECT to_regprocedure($1) IS NOT NULL`, preciseCompletionSignature).Scan(&installed); err != nil || !installed {
		t.Fatal("precise completion authority absent", err)
	}
	for _, role := range []string{"public", "zasp_runtime_coordinator", "zasp_runtime_projection_worker", "zasp_runtime_correlation_worker", "zasp_discovery_api"} {
		var allowed bool
		if err := admin.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE')`, role, preciseCompletionSignature).Scan(&allowed); err != nil || allowed {
			t.Fatal("draft execution permission exposed", role, err)
		}
	}
	var historicalAfter string
	if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)'::regprocedure)`).Scan(&historicalAfter); err != nil || historicalBefore != historicalAfter {
		t.Fatal("historical finisher mutated", err)
	}
	var output []byte
	err = worker.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`).Scan(&output)
	if err == nil {
		t.Fatal("ungranted worker executed precise completion")
	}
	requireSandboxSQLState(t, err, "42501")
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	if _, err := admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+preciseCompletionSignature+` TO zasp_runtime_coordinator`); err != nil {
		t.Fatal(err)
	}
	call := `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	// A valid historical V2 request cannot use the precise completion authority.
	err = coordinator.QueryRow(ctx, call, args...).Scan(&output)
	if err == nil {
		t.Fatal("precise authority accepted V2 completion")
	}
	requireSandboxSQLState(t, err, "22023")
	requireSandboxSessionUnfinished(t, ctx, admin, args[3], 0)
	// Changing only the claimed version cannot bypass its predecessor fence.
	args[9] = "runtime-complete-v3"
	err = coordinator.QueryRow(ctx, call, args...).Scan(&output)
	if err == nil {
		t.Fatal("precise authority accepted V2 predecessor")
	}
	requireSandboxSQLState(t, err, "22023")
	requireSandboxSessionUnfinished(t, ctx, admin, args[3], 0)
	var stateReady bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=50),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_fingerprint'))`).Scan(&stateReady); err != nil || !stateReady {
		t.Fatal("private draft changed predecessor readiness", err)
	}
}
