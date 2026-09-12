package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimePrecisionRepositoryRegisteredCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	runner := installRuntimePrecision(t, ctx, admin)
	args, projected := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
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
	request := runtimeevent.StageFinishRequest{Lease: runtimeevent.StageLease{Scope: fixtureRequestIdentity(t).Scope, BatchID: mustProductID(t, args[3].(string)), Generation: 1, Stage: runtimeevent.RuntimeStageComplete, Attempt: 1, ImplementationVersion: "runtime-complete-v3", InputDigest: inputDigest, PredecessorDigest: &inputDigest, InputReference: "s3://zasp-evidence/projected.json", InputVersionID: "projected-v1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}, WorkerID: args[5].(string), LeaseToken: args[6].(string), Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: inputDigest, ResultReference: args[12].(string), ResultVersionID: args[13].(string), ResultDigest: resultDigest, ProjectionReceipt: string(args[17].([]byte))}
	var committed string
	for replay := 0; replay < 2; replay++ {
		result, err := repository.FinishStage(ctx, request)
		if err != nil || result.State != runtimeevent.StageOutcomeSucceeded || result.ImplementationVersion != "runtime-complete-v3" {
			t.Fatal("registered precise repository completion", result, err)
		}
		after := preciseCompletionRows(t, ctx, admin)
		if replay == 1 && after != committed {
			t.Fatal("registered completion replay changed retained atomic rows")
		}
		committed = after
	}
	var events, receipts, legacyQueue, newQueue int
	var state string
	if err := admin.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_runtime_session_events),(SELECT count(*) FROM zasp_runtime_session_projection_receipts),(SELECT count(*) FROM zasp_runtime_session_search_outbox),(SELECT count(*) FROM zasp_runtime_sandbox_search_outbox) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, args[3]).Scan(&state, &events, &receipts, &legacyQueue, &newQueue); err != nil || state != "succeeded" || events != len(projected.Items) || receipts != 1 || legacyQueue != 0 || newQueue != 1 {
		t.Fatal("atomic/replay persistence", err, state, events, receipts, legacyQueue, newQueue)
	}
	for _, item := range projected.Items {
		var body []byte
		var eventTime time.Time
		if err := admin.QueryRow(ctx, `SELECT to_jsonb(e)-'projected_at'-'event_time',event_time FROM zasp_runtime_session_events e WHERE event_id=$1`, item.EventID.String()).Scan(&body, &eventTime); err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		nullable := func(value string) any {
			if value == "" {
				return nil
			}
			return value
		}
		want := map[string]any{"organization_id": args[0], "workspace_id": args[1], "environment_id": args[2], "event_id": item.EventID.String(), "agent_id": nullable(item.AgentID.String()), "session_id": nullable(item.SessionID.String()), "evidence_id": item.EvidenceID.String(), "confidence": item.Confidence.String(), "source": item.Source, "event_class": item.EventClass, "action": item.Action, "title": item.Title, "sandbox_id": nullable(item.SandboxID), "sandbox_source_sensor_id": nullable(item.SandboxSourceSensorID.String())}
		wantTime, err := time.Parse(time.RFC3339Nano, item.EventTime)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) || !eventTime.Equal(wantTime) {
			t.Fatalf("persisted event differs from committed projection: got=%v want=%v time=%v wantTime=%v", got, want, eventTime, item.EventTime)
		}
	}
	receiptDigest := sha256.Sum256(args[17].([]byte))
	// The stage completion identity binds the caller, lease, outcome and exact
	// result artifact independently of the receipt's SHA256.
	completionDigest := sha256.Sum256([]byte(strings.Join([]string{args[0].(string), args[1].(string), args[2].(string), args[3].(string), "1", "complete", args[5].(string), args[6].(string), "1", hex.EncodeToString(inputDigest[:]), "runtime-complete-v3", "succeeded", hex.EncodeToString(inputDigest[:]), args[12].(string), args[13].(string), hex.EncodeToString(resultDigest[:]), "", "0"}, "\x1f")))
	var persistedReceipt, queuedReceipt, predecessorReceipt, stageCompletion, batchCompletion, stageResult, batchResult []byte
	var eventIDs []string
	if err := admin.QueryRow(ctx, `SELECT r.receipt_digest,q.receipt_digest,p.result_digest,s.completion_digest,b.completion_digest,s.result_digest,b.terminal_result_digest,r.event_ids FROM zasp_runtime_session_projection_receipts r JOIN zasp_runtime_sandbox_search_outbox q USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) JOIN zasp_runtime_stage_work s USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) JOIN zasp_runtime_stage_work p USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE r.batch_id=$1 AND s.stage='complete' AND p.stage='project'`, args[3]).Scan(&persistedReceipt, &queuedReceipt, &predecessorReceipt, &stageCompletion, &batchCompletion, &stageResult, &batchResult, &eventIDs); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"receipt": persistedReceipt, "queue": queuedReceipt, "predecessor": predecessorReceipt} {
		if !bytes.Equal(got, receiptDigest[:]) {
			t.Fatal("persisted receipt SHA mismatch", name)
		}
	}
	for name, got := range map[string][]byte{"stage": stageCompletion, "batch": batchCompletion} {
		if !bytes.Equal(got, completionDigest[:]) {
			t.Fatal("persisted completion identity mismatch", name)
		}
	}
	if !bytes.Equal(stageResult, resultDigest[:]) || !bytes.Equal(batchResult, resultDigest[:]) {
		t.Fatal("persisted result digest mismatch")
	}
	wantIDs := make([]string, len(projected.Items))
	for i, item := range projected.Items {
		wantIDs[i] = item.EventID.String()
	}
	if !reflect.DeepEqual(eventIDs, wantIDs) {
		t.Fatal("receipt event membership mismatch", eventIDs, wantIDs)
	}
	if err := runner.DownProductionRuntimePrecision(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatal("rollback erased retained precision evidence", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 51 {
		t.Fatal("rejected rollback changed release", version, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_events`).Scan(&events); err != nil || events != len(projected.Items) {
		t.Fatal("rejected rollback changed retained events", events, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FinishStage(ctx, request); !errors.Is(err, runtimeevent.ErrProductionPipelineUnavailable) {
		t.Fatal("replay ignored readiness drift", err)
	}
}

// Snapshot whole rows, including timestamps and lease state, so a refused call
// cannot pass by leaving the same counts while altering prior evidence.
func preciseCompletionRows(t *testing.T, ctx context.Context, admin *pgx.Conn) string {
	t.Helper()
	var snapshot string
	if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'events',(SELECT jsonb_agg(to_jsonb(r) ORDER BY event_id) FROM zasp_runtime_session_events r),
 'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id,batch_generation) FROM zasp_runtime_session_projection_receipts r),
 'stages',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id,stage_order) FROM zasp_runtime_stage_work r),
 'authorities',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id) FROM zasp_runtime_batch_authorities r),
 'batches',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM zasp_runtime_batches r),
 'jobs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM zasp_discovery_jobs r),
 'deliveries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id) FROM zasp_runtime_deliveries r),
 'legacy_queue',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id) FROM zasp_runtime_session_search_outbox r),
 'sandbox_queue',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id) FROM zasp_runtime_sandbox_search_outbox r))::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestRuntimePrecisionRegisteredCompletionRejectsAlteredAuthorityAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, other := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	const query = `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	mutations := []struct {
		name  string
		index int
		value any
		code  string
	}{
		{"organization", 0, invocationTarget, "22023"}, {"workspace", 1, invocationTarget, "22023"}, {"environment", 2, invocationTarget, "22023"},
		{"batch", 3, invocationTarget, "22023"}, {"generation", 4, int64(2), "22023"}, {"attempt", 7, 2, "P0002"},
		{"worker", 5, "foreign-worker", "P0002"}, {"lease-token", 6, "foreign-lease-token-0001", "P0002"},
		{"receipt-bytes", 17, append(append([]byte(nil), args[17].([]byte)...), ' '), "22023"},
		{"input-digest", 8, bytes.Repeat([]byte{0x71}, 32), "22023"},
	}
	for _, phase := range []string{"leased", "succeeded"} {
		if phase == "succeeded" {
			var result []byte
			if err := coordinator.QueryRow(ctx, query, args...).Scan(&result); err != nil {
				t.Fatal("valid completion after rejected calls", err)
			}
		}
		for _, mutation := range mutations {
			t.Run(phase+"/"+mutation.name, func(t *testing.T) {
				before := preciseCompletionRows(t, ctx, admin)
				wrong := append([]any(nil), args...)
				wrong[mutation.index] = mutation.value
				var result []byte
				requireSandboxSQLState(t, coordinator.QueryRow(ctx, query, wrong...).Scan(&result), mutation.code)
				if after := preciseCompletionRows(t, ctx, admin); after != before {
					t.Fatal("rejected completion changed atomic rows", mutation.name)
				}
			})
		}
		if phase == "succeeded" {
			continue
		}
		for _, mutation := range []string{"wrong-principal", "expired-lease", "predecessor-version", "malformed-final-item"} {
			t.Run(phase+"/"+mutation, func(t *testing.T) {
				caller := coordinator
				wrong := append([]any(nil), args...)
				code := "22023"
				if mutation == "wrong-principal" {
					caller = other
					code = "42501"
				}
				if mutation == "expired-lease" {
					code = "P0002"
					if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE batch_id=$1 AND stage='complete'`, args[3]); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "predecessor-version" {
					if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-projection-v2' WHERE batch_id=$1 AND stage='project'`, args[3]); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "malformed-final-item" {
					var wire map[string]any
					if err := json.Unmarshal(args[17].([]byte), &wire); err != nil {
						t.Fatal(err)
					}
					items := wire["items"].([]any)
					items[len(items)-1].(map[string]any)["source"] = "otlp"
					body, err := json.Marshal(wire)
					if err != nil {
						t.Fatal(err)
					}
					wrong[17] = body
					digest := sha256.Sum256(body)
					// A matching forged predecessor SHA must reach the item guard,
					// after earlier inserts and the terminal stage update.
					if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET result_digest=$1 WHERE batch_id=$2 AND stage='project'`, digest[:], args[3]); err != nil {
						t.Fatal(err)
					}
				}
				before := preciseCompletionRows(t, ctx, admin)
				var result []byte
				requireSandboxSQLState(t, caller.QueryRow(ctx, query, wrong...).Scan(&result), code)
				if after := preciseCompletionRows(t, ctx, admin); after != before {
					t.Fatal("rejected completion changed atomic rows", mutation)
				}
				if mutation == "expired-lease" {
					if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=transaction_timestamp()+interval '1 hour' WHERE batch_id=$1 AND stage='complete'`, args[3]); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "predecessor-version" {
					if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-projection-v3' WHERE batch_id=$1 AND stage='project'`, args[3]); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "malformed-final-item" {
					digest := sha256.Sum256(args[17].([]byte))
					if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET result_digest=$1 WHERE batch_id=$2 AND stage='project'`, digest[:], args[3]); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
