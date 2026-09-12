package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type semanticRoutingReservation struct {
	batch, key      string
	locator, secret []byte
}

// Actual enrolled-source reservation. Only payload bytes/storage are fixtures;
// source/schema authority and all commit transitions use registered SQL roles.
func reserveSemanticRouting(t *testing.T, ctx context.Context, admin, ingest *pgx.Conn, ordinal int, source, schema string) semanticRoutingReservation {
	t.Helper()
	credentialIndex := 1
	if source == "tetragon" {
		credentialIndex = 2
	}
	token := fmt.Sprintf("pid_76510001-0000-4000-8000-%012d", credentialIndex)
	locator, secret, salt := bytes.Repeat([]byte{byte(credentialIndex)}, 16), bytes.Repeat([]byte{0xd2}, 32), bytes.Repeat([]byte{0xd3}, 32)
	credential, err := sensor.NewTokenCredential(locator, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	locatorHash, _ := credential.LocatorDigest()
	tokenHash, _ := credential.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, token), 1, salt)
	sensorID := sandboxSemantic
	if source == "tetragon" {
		sensorID = sandboxAnchor
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token(organization_id,workspace_id,environment_id,id,$2,1,1,$3,$4,$5,transaction_timestamp()+interval '1 day') FROM zasp_sensors WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM zasp_runtime_batch_authorities WHERE sensor_id=$1)`, sensorID, token, locatorHash[:], salt, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	r := semanticRoutingReservation{batch: fmt.Sprintf("pid_76510002-0000-4000-8000-%012d", ordinal), locator: locator, secret: secret}
	var body []byte
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_reserve_batch($1,$2,'event-ingest',$3,$4,$5,$6,'application/json',$7,1,1)`, locator, secret, r.batch, fmt.Sprintf("semantic-routing-%04d", ordinal), bytes.Repeat([]byte{0xd4}, 32), source, schema).Scan(&body); err != nil {
		t.Fatal("reserve", err)
	}
	if err := admin.QueryRow(ctx, `SELECT raw_artifact_key FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, r.batch).Scan(&r.key); err != nil {
		t.Fatal(err)
	}
	return r
}

func semanticRoutingFinalize(r semanticRoutingReservation) (string, []any) {
	return `SELECT zasp_runtime_finalize_batch($1,$2,'event-ingest',$3,$4,$5,$6,$7,'semantic-routing-version',$8,1,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh')`, []any{r.locator, r.secret, r.batch, r.batch, "pid_76510003" + r.batch[len("pid_76510002"):], "s3://zasp-evidence/" + r.key, r.key, bytes.Repeat([]byte{0xd4}, 32)}
}

func semanticRoutingVersions(t *testing.T, ctx context.Context, admin *pgx.Conn, batch string) []string {
	t.Helper()
	var versions []string
	if err := admin.QueryRow(ctx, `SELECT array_agg(implementation_version ORDER BY stage_order) FROM zasp_runtime_stage_work WHERE batch_id=$1`, batch).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	return versions
}

func TestRuntimePrecisionSemanticRoutingUsesPersistedSourceWithoutRewritingReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	old := reserveSemanticRouting(t, ctx, admin, ingest, 1, "otlp", "runtime-event-v1")
	query, args := semanticRoutingFinalize(old)
	var body json.RawMessage
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	legacy := []string{"runtime-archive-v1", "runtime-index-v1", "runtime-correlation-v2", "runtime-projection-v1", "runtime-complete-v1"}
	if got := semanticRoutingVersions(t, ctx, admin, old.batch); !reflect.DeepEqual(got, legacy) {
		t.Fatal("predecessor route", got)
	}
	installRuntimePrecision(t, ctx, admin)
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
		t.Fatal("accepted replay", err)
	}
	if got := semanticRoutingVersions(t, ctx, admin, old.batch); !reflect.DeepEqual(got, legacy) {
		t.Fatal("rewritten accepted tuple", got)
	}
	for i, scenario := range []struct {
		source, schema string
		want           []string
	}{
		{"otlp", "runtime-event-v1", []string{"runtime-archive-v1", "runtime-index-v1", "runtime-correlation-v3", "runtime-projection-v2", "runtime-complete-v2"}},
		{"tetragon", "runtime-event-v1", legacy},
		{"tetragon", "runtime-event-v2", []string{"runtime-archive-v2", "runtime-index-v2", "runtime-correlation-v4", "runtime-projection-v3", "runtime-complete-v3"}},
	} {
		r := reserveSemanticRouting(t, ctx, admin, ingest, i+2, scenario.source, scenario.schema)
		query, args := semanticRoutingFinalize(r)
		if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
			t.Fatal("new finalize", err)
		}
		if got := semanticRoutingVersions(t, ctx, admin, r.batch); !reflect.DeepEqual(got, scenario.want) {
			t.Fatal("fresh persisted source routed incorrectly", scenario.source, scenario.schema, got)
		}
		if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
			t.Fatal("new replay", err)
		}
		if got := semanticRoutingVersions(t, ctx, admin, r.batch); !reflect.DeepEqual(got, scenario.want) {
			t.Fatal("new replay relabelled work", got)
		}
	}
}

func TestRuntimePrecisionSemanticRoutingRollbackRefusesPendingWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	runner := installRuntimePrecision(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	r := reserveSemanticRouting(t, ctx, admin, ingest, 1, "otlp", "runtime-event-v1")
	query, args := semanticRoutingFinalize(r)
	var body []byte
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	before := semanticRoutingVersions(t, ctx, admin, r.batch)
	if err := runner.DownProductionRuntimePrecision(ctx); err == nil {
		t.Fatal("rollback accepted pending fresh semantic work that schema50 manifests cannot drain")
	}
	if got := semanticRoutingVersions(t, ctx, admin, r.batch); !reflect.DeepEqual(got, before) {
		t.Fatal("failed rollback mutated work", got)
	}
}

func TestRuntimePrecisionSemanticRoutingRejectsCachedCommitAndPostWaitDrift(t *testing.T) {
	for _, mode := range []string{"cached", "postwait", "cached-postwait"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			ingest := precisionRecoveryIngest(t, ctx, admin)
			r := reserveSemanticRouting(t, ctx, admin, ingest, 1, "otlp", "runtime-event-v1")
			var body []byte
			if mode == "cached" {
				// The private archived predecessor is the exact old commit body,
				// invoked as fixture owner, not granted to an application role.
				// Its actual stage INSERT must still encounter the new row guard.
				err := admin.QueryRow(ctx, `SELECT zasp_precision_predecessor.zasp_runtime_commit_reserved_batch(organization_id,workspace_id,environment_id,batch_id,batch_generation,request_digest,batch_id,$2,$3,raw_artifact_key,'semantic-routing-version',content_digest,payload_size_bytes,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh') FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, r.batch, "pid_76510003"+r.batch[len("pid_76510002"):], "s3://zasp-evidence/"+r.key).Scan(&body)
				requireSandboxSQLState(t, err, "22023")
			} else {
				observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer observer.Close(context.Background())
				query, args := semanticRoutingFinalize(r)
				if mode == "cached-postwait" {
					// Retain the saved body, but execute it on a separate owner
					// connection so its own batch lock really waits. No worker
					// gains EXECUTE on the private predecessor schema.
					cached, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
					if err != nil {
						t.Fatal(err)
					}
					defer cached.Close(context.Background())
					ingest = cached
					query = `SELECT zasp_precision_predecessor.zasp_runtime_commit_reserved_batch(organization_id,workspace_id,environment_id,batch_id,batch_generation,request_digest,$4,$5,$6,$7,'semantic-routing-version',$8,1,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh') FROM zasp_runtime_batch_authorities WHERE batch_id=$3 AND octet_length($1::bytea||$2::bytea)>0`
				}
				// blockedRuntimeCandidateStatement locks args[3], which is the
				// deliberately batch-shaped job ID in this fixture.
				err = blockedRuntimeCandidateStatement(t, ctx, admin, ingest, observer, args, query, `SELECT 1 FROM zasp_runtime_batch_authorities WHERE batch_id=$1 FOR UPDATE`, func(tx pgx.Tx) {
					if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
						t.Fatal(err)
					}
				})
				requireSandboxSQLState(t, err, "55000")
			}
			var unchanged bool
			if err := admin.QueryRow(ctx, `SELECT state='uploading' AND NOT EXISTS(SELECT 1 FROM zasp_runtime_stage_work WHERE batch_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_runtime_batches WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_discovery_jobs WHERE authority_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1) FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, r.batch).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("rejected commit left partial authority", unchanged, err)
			}
		})
	}
}

func TestRuntimePrecisionSemanticRoutingRecoveryFinalAttemptAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	// Reservation predates51 but has never committed any stage/evidence.
	r := reserveSemanticRouting(t, ctx, admin, ingest, 1, "otlp", "runtime-event-v1")
	installRuntimePrecision(t, ctx, admin)
	// Declare an interrupted upload at its last available recovery attempt.
	if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_runtime_ingest_reconciliation_work WHERE batch_id=$1 RETURNING *) INSERT INTO zasp_runtime_ingest_reconciliation_work SELECT (jsonb_populate_record(NULL::zasp_runtime_ingest_reconciliation_work,to_jsonb(removed)||jsonb_build_object('attempt',99,'available_at',transaction_timestamp()-interval '1 hour'))).* FROM removed`, r.batch); err != nil {
		t.Fatal(err)
	}
	var body []byte
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation('semantic-recovery','semantic-recovery-lease',60,1)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var claims []struct {
		Batch   string `json:"batch_id"`
		Attempt int    `json:"attempt"`
	}
	if err := json.Unmarshal(body, &claims); err != nil || len(claims) != 1 || claims[0].Batch != r.batch || claims[0].Attempt != 100 {
		t.Fatal("historical V1 recovery lost final attempt", string(body), err)
	}
	scope := fixtureRequestIdentity(t).Scope
	query := `SELECT zasp_runtime_finish_reconciliation($1,$2,$3,$4,1,'semantic-recovery','semantic-recovery-lease',$4,$5,$6,$7,'semantic-routing-version',$8,1,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh')`
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), r.batch, "pid_76510003" + r.batch[len("pid_76510002"):], "s3://zasp-evidence/" + r.key, r.key, bytes.Repeat([]byte{0xd4}, 32)}
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
		t.Fatal("semantic recovery finish", err)
	}
	want := []string{"runtime-archive-v1", "runtime-index-v1", "runtime-correlation-v3", "runtime-projection-v2", "runtime-complete-v2"}
	if got := semanticRoutingVersions(t, ctx, admin, r.batch); !reflect.DeepEqual(got, want) {
		t.Fatal("recovery bypassed semantic routing", got)
	}
	before := precisionRecoveryState(t, ctx, admin, r.batch)
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil || before != precisionRecoveryState(t, ctx, admin, r.batch) {
		t.Fatal("recovery replay changed authority", err)
	}
	query, args = semanticRoutingFinalize(r)
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
		t.Fatal("authenticated replay after recovery", err)
	}
}

func TestRuntimePrecisionSemanticRoutingOldReadersCannotExhaustFreshWork(t *testing.T) {
	for _, stage := range []string{"correlate", "project", "complete"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, correlation := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			ingest := precisionRecoveryIngest(t, ctx, admin)
			r := reserveSemanticRouting(t, ctx, admin, ingest, 1, "otlp", "runtime-event-v1")
			query, args := semanticRoutingFinalize(r)
			var body []byte
			if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
				t.Fatal(err)
			}
			// Preserve the actual committed source/version tuple; fixture only
			// its final-attempt schedule. No successful stages are fabricated.
			if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2 RETURNING *) INSERT INTO zasp_runtime_stage_work SELECT (jsonb_populate_record(NULL::zasp_runtime_stage_work,to_jsonb(removed)||jsonb_build_object('attempt',100))).* FROM removed`, r.batch, stage); err != nil {
				t.Fatal(err)
			}
			worker := correlation
			old, newName := "zasp_runtime_claim_correlation_v2", "zasp_runtime_claim_correlation_v4"
			if stage != "correlate" {
				worker = sandboxStageWorker(t, ctx, admin, stage)
				old = "zasp_runtime_claim_stage"
				newName = "zasp_runtime_claim_projection_v3"
				if stage == "complete" {
					newName = "zasp_runtime_claim_completion_v3"
				}
			}
			before := sandboxStageState(t, ctx, admin)
			if err := worker.QueryRow(ctx, `SELECT `+old+`('old-semantic','old-semantic-lease',60,10)`).Scan(&body); err != nil || string(body) != "[]" || before != sandboxStageState(t, ctx, admin) {
				t.Fatal("old reader consumed or exhausted fresh semantic work", string(body), err)
			}
			if err := worker.QueryRow(ctx, `SELECT `+newName+`('new-semantic','new-semantic-lease',60,10)`).Scan(&body); err != nil {
				t.Fatal("superset reader failed", err)
			}
			var exhausted bool
			if err := admin.QueryRow(ctx, `SELECT state='failed' AND last_error_class='exhausted' AND attempt=100 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, r.batch, stage).Scan(&exhausted); err != nil || !exhausted {
				t.Fatal("superset reader did not own exhausted transition", exhausted, err)
			}
		})
	}
}

func TestRuntimePrecisionSemanticRoutingRollbackKeepsCompletedSandboxEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	var body []byte
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var result string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id) FROM zasp_runtime_session_events e),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id) FROM zasp_runtime_session_projection_receipts r),'queue',(SELECT jsonb_agg(to_jsonb(q) ORDER BY batch_id) FROM zasp_runtime_sandbox_search_outbox q))::text`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	runner := installRuntimePrecision(t, ctx, admin)
	if err := runner.DownProductionRuntimePrecision(ctx); err != nil {
		t.Fatal("completed50-compatible evidence blocked rollback", err)
	}
	if before != snapshot() {
		t.Fatal("rollback rewrote retained sandbox evidence/checkpoint")
	}
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&body); err != nil || before != snapshot() {
		t.Fatal("retained completion replay after rollback", err)
	}
	if err := runner.UpProductionRuntimePrecision(ctx); err != nil {
		t.Fatal("reinstall after retained evidence", err)
	}
}
