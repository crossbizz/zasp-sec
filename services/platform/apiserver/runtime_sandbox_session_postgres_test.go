package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

const sandboxSessionFinishSQL = `SELECT zasp_runtime_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`

func sandboxSessionCoordinator(t *testing.T, ctx context.Context, admin *pgx.Conn) *pgx.Conn {
	t.Helper()
	config := admin.Config().Copy()
	config.User = "candidate_coordinator"
	coordinator, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { coordinator.Close(context.Background()) })
	return coordinator
}

func TestRuntimeSandboxSessionCompletionPersistsBindingAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, other := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, projected := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	var output json.RawMessage
	if err := other.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&output); err == nil {
		t.Fatal("wrong principal completed sandbox work")
	} else {
		requireSandboxSQLState(t, err, "42501")
	}
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&output); err == nil {
		t.Fatal("old completion accepted new receipt")
	} else {
		requireSandboxSQLState(t, err, "22023")
	}
	for _, item := range projected.Items {
		if item.SandboxID == "" {
			continue
		}
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time,sandbox_id,sandbox_source_sensor_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'conflicting-sandbox',$14)`, args[0], args[1], args[2], item.EventID.String(), item.SessionID.String(), item.AgentID.String(), item.Confidence.String(), item.Source, item.EventClass, item.Action, item.Title, item.EvidenceID.String(), item.EventTime, sandboxSemantic); err != nil {
			t.Fatal(err)
		}
		requireSandboxSQLState(t, coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&output), "23505")
		requireSandboxSessionUnfinished(t, ctx, admin, args[3], 1)
		if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_session_events WHERE event_id=$1`, item.EventID.String()); err != nil {
			t.Fatal(err)
		}
		break
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: coordinator})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	var inputDigest, resultDigest [sha256.Size]byte
	copy(inputDigest[:], args[8].([]byte))
	copy(resultDigest[:], args[14].([]byte))
	request := runtimeevent.StageFinishRequest{Lease: runtimeevent.StageLease{Scope: fixtureRequestIdentity(t).Scope, BatchID: mustProductID(t, args[3].(string)), Generation: 1, Stage: runtimeevent.RuntimeStageComplete, Attempt: 1, ImplementationVersion: "runtime-complete-v2", InputDigest: inputDigest, PredecessorDigest: &inputDigest, InputReference: "s3://zasp-evidence/projected.json", InputVersionID: "projected-v1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}, WorkerID: args[5].(string), LeaseToken: args[6].(string), Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: inputDigest, ResultReference: args[12].(string), ResultVersionID: args[13].(string), ResultDigest: resultDigest, ProjectionReceipt: string(args[17].([]byte))}
	if _, err := repository.FinishStage(ctx, request); err != nil {
		t.Fatal("sandbox completion repository rejected", err)
	}
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&output); err != nil {
		t.Fatal("sandbox replay rejected", err)
	}
	for _, item := range projected.Items {
		var sandbox, source *string
		if err := admin.QueryRow(ctx, `SELECT sandbox_id,sandbox_source_sensor_id FROM zasp_runtime_session_events WHERE event_id=$1`, item.EventID.String()).Scan(&sandbox, &source); err != nil {
			t.Fatal(err)
		}
		if item.SandboxID == "" {
			if sandbox != nil || source != nil {
				t.Fatal("invented ambiguous binding")
			}
		} else if sandbox == nil || *sandbox != "session-sandbox" || source == nil || *source != sandboxSemantic {
			t.Fatal("lost source-qualified binding")
		}
	}
	var state string
	var events, receipts int
	if err := admin.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_runtime_session_events),(SELECT count(*) FROM zasp_runtime_session_projection_receipts) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, args[3]).Scan(&state, &events, &receipts); err != nil || state != "succeeded" || events != 3 || receipts != 1 {
		t.Fatal("completion persistence mismatch", err, state, events, receipts)
	}
}

func requireSandboxSessionUnfinished(t *testing.T, ctx context.Context, admin *pgx.Conn, batch any, events int) {
	t.Helper()
	var state string
	var count, receipts int
	if err := admin.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_runtime_session_events),(SELECT count(*) FROM zasp_runtime_session_projection_receipts) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, batch).Scan(&state, &count, &receipts); err != nil || state != "leased" || count != events || receipts != 0 {
		t.Fatal("non-atomic sandbox completion", err, state, count, receipts)
	}
}

func TestRuntimeSandboxSessionRejectsMalformedBindingAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	for _, scenario := range []struct{ name, code string }{{"missing-source", "22023"}, {"null-source", "22023"}, {"numeric-sandbox", "22023"}, {"missing-exact", "22023"}, {"empty", "23514"}, {"oversize", "23514"}, {"whitespace", "23514"}, {"weak-binding", "23514"}, {"same-identity", "22023"}, {"invalid-source", "23514"}} {
		t.Run(scenario.name, func(t *testing.T) {
			var receipt map[string]any
			if err := json.Unmarshal(args[17].([]byte), &receipt); err != nil {
				t.Fatal(err)
			}
			items := receipt["items"].([]any)
			// Corrupt the final item, after earlier valid inserts. A failure must
			// roll back both those inserts and the preceding terminal stage update.
			item := items[len(items)-1].(map[string]any)
			item["confidence"], item["agent_id"], item["session_id"] = "exact", invocationTarget, "pid_96000007-0000-4000-8000-000000000007"
			item["sandbox_id"], item["sandbox_source_sensor_id"] = "session-sandbox", sandboxSemantic
			switch scenario.name {
			case "missing-source":
				delete(item, "sandbox_source_sensor_id")
			case "null-source":
				item["sandbox_source_sensor_id"] = nil
			case "numeric-sandbox":
				item["sandbox_id"] = 7
			case "missing-exact":
				delete(item, "sandbox_id")
				delete(item, "sandbox_source_sensor_id")
			case "empty":
				item["sandbox_id"] = ""
			case "oversize":
				item["sandbox_id"] = strings.Repeat("a", 257)
			case "whitespace":
				item["sandbox_id"] = "\u00a0sandbox"
			case "weak-binding":
				item["confidence"] = "probable"
				delete(item, "agent_id")
				delete(item, "session_id")
			case "same-identity":
				item["session_id"] = item["agent_id"]
			case "invalid-source":
				item["sandbox_source_sensor_id"] = "not-a-product-id"
			}
			body, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET result_digest=$2 WHERE batch_id=$1 AND stage='project'`, args[3], digest[:]); err != nil {
				t.Fatal(err)
			}
			wrong := append([]any(nil), args...)
			wrong[17] = body
			var output json.RawMessage
			err = coordinator.QueryRow(ctx, sandboxSessionFinishSQL, wrong...).Scan(&output)
			requireSandboxSQLState(t, err, scenario.code)
			requireSandboxSessionUnfinished(t, ctx, admin, args[3], 0)
		})
	}
}

func TestRuntimeSandboxSessionLegacyRowsSurviveRollbackReinstall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var output json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&output); err != nil {
		t.Fatal(err)
	}
	var before, after string
	const snapshot = `SELECT jsonb_agg(to_jsonb(e)-'sandbox_id'-'sandbox_source_sensor_id' ORDER BY event_id)::text FROM zasp_runtime_session_events e`
	if err := admin.QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		installRuntimeSandboxDraft(t, ctx, admin)
		if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&output); err != nil {
			t.Fatal("legacy replay after column addition", err)
		}
		var known int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events WHERE sandbox_id IS NOT NULL OR sandbox_source_sensor_id IS NOT NULL`).Scan(&known); err != nil || known != 0 {
			t.Fatal("historical binding invented", err)
		}
		if err := rollbackRuntimeSandboxDraft(ctx, admin); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
			t.Fatal("historical event rows changed", err)
		}
	}
}

func TestRuntimeSandboxSessionReadinessDriftAfterLockWaitRollsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	lock, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err := lock.Exec(ctx, `SELECT 1 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete' FOR UPDATE`, args[3]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var output json.RawMessage
		done <- coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&output)
	}()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		var blocked bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, coordinator.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			waiting = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("completion never reached controlled lock wait")
	}
	if _, err := observer.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('b',64) WHERE key='production_runtime_sandbox_binding_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	requireSandboxSQLState(t, <-done, "55000")
	requireSandboxSessionUnfinished(t, ctx, admin, args[3], 0)
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_sandbox_binding_fingerprint'`, migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()); err != nil {
		t.Fatal(err)
	}
}
