package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// These are controlled local archive/provider artifacts, never a real index
// deletion or deployment receipt. All database transitions use registered logins.
type retentionNativeProjection struct {
	args    []any
	archive []byte
}
type retentionNativeRaw struct {
	batch     domain.ProductID
	body      []byte
	reference string
	digest    [32]byte
}

// Seed only original producer source authority and a pending index stage before
// the fixture owner is demoted. No successful index/partition/cleanup is seeded.
func seedRetentionNativeRaw(t *testing.T, ctx context.Context, owner *pgx.Conn, scope domain.Scope, archive []byte) retentionNativeRaw {
	t.Helper()
	if _, err := runtimeevent.DecodePreciseArchivedBatch(scope, archive); err != nil {
		t.Fatal("whole precise raw fixture rejected")
	}
	raw := retentionNativeRaw{batch: mustProductID(t, automaticSourceID(99100)), body: append([]byte(nil), archive...), reference: "s3://zasp-evidence/runtime/retention-index-native.json", digest: sha256.Sum256(archive)}
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	sensor, token := automaticSourceID(99101), automaticSourceID(99102)
	tokenDigest := sha256.Sum256([]byte(token))
	queries := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,'Retention index native','tetragon')`, []any{o, w, e, sensor}},
		{`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,decode(repeat('aa',16),'hex'),$6,clock_timestamp()+interval '1 day')`, []any{o, w, e, token, sensor, tokenDigest[:]}},
		{`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,$4,$5,'retention-index-native',$6,3,$7,$8,'application/json','runtime-event-v2','processing')`, []any{o, w, e, raw.batch.String(), sensor, raw.digest[:], raw.reference, len(archive)}},
		{`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$4,$5,$6,1,1,'retention-index-native',$7,$7,'tetragon','application/json','runtime-event-v2',$8,3,'runtime/retention-index-native.json',$9,'archive-v1',$7,$8,'fixture-kms-reference',clock_timestamp(),'processing')`, []any{o, w, e, raw.batch.String(), sensor, token, raw.digest[:], len(archive), raw.reference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,1,'archive',1,'runtime-archive-v2',$5,'succeeded',1,$5,$6,'archive-v1',$5,clock_timestamp())`, []any{o, w, e, raw.batch.String(), raw.digest[:], raw.reference}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt) VALUES($1,$2,$3,$4,1,'index',2,'runtime-index-v2',$5,$5,'pending',0)`, []any{o, w, e, raw.batch.String(), raw.digest[:]}},
		{`INSERT INTO zasp_runtime_deliveries(organization_id,workspace_id,environment_id,batch_id,batch_generation,message_id,message_digest,receive_count,disposition,lease_owner,lease_token,lease_expires_at,visibility_deadline) VALUES($1,$2,$3,$4,1,$4,$5,1,'held','retention-native-coordinator','retention-native-delivery-token',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour')`, []any{o, w, e, raw.batch.String(), raw.digest[:]}},
	}
	for _, q := range queries {
		if _, err := owner.Exec(ctx, q.sql, q.args...); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("original raw producer fixture refused")
		}
	}
	return raw
}

// Publication of every returned capability waits for a confirmed READ COMMITTED
// commit. A rollback/error never publishes a usable admission to a provider.
type retentionNativeDatabase struct{ connection *pgx.Conn }

func (d retentionNativeDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	tx, err := d.connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var body json.RawMessage
	if err = tx.QueryRow(ctx, q, args...).Scan(&body); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return body, nil
}
func retentionNativeJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("native fixture encoding refused")
	}
	return body
}
func retentionNativeQuery(t *testing.T, ctx context.Context, db retentionNativeDatabase, q string, args ...any) json.RawMessage {
	t.Helper()
	body, err := db.QueryJSON(ctx, q, args...)
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal("registered native retention operation refused")
	}
	return body
}
func retentionNativeObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if json.Unmarshal(body, &value) != nil || value == nil {
		t.Fatal("native retention object malformed")
	}
	return value
}
func retentionNativeCopy(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func retentionNativeDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func retentionNativeArtifact(t *testing.T, name string, body []byte) {
	t.Helper()
	path := t.TempDir() + "/" + name
	if os.WriteFile(path, body, 0600) != nil {
		t.Fatal("controlled artifact persistence refused")
	}
	again, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("controlled artifact readback refused")
	}
}

func retentionNativeAdmission(t *testing.T, body []byte, eventIDs []string) (string, map[string]bool) {
	t.Helper()
	var result struct {
		Admission string `json:"admission_id"`
		Items     []struct {
			ID      string `json:"event_id"`
			Visible bool   `json:"visible"`
		} `json:"items"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || len(result.Admission) != 64 || len(result.Items) != len(eventIDs) {
		t.Fatal("native durable admission malformed")
	}
	if decoded, err := hex.DecodeString(result.Admission); err != nil || len(decoded) != 32 {
		t.Fatal("native admission nonce malformed")
	}
	states := map[string]bool{}
	for i, item := range result.Items {
		if item.ID != eventIDs[i] {
			t.Fatal("native admission identity order changed")
		}
		states[item.ID] = item.Visible
	}
	return result.Admission, states
}
func retentionNativeClaim(t *testing.T, ctx context.Context, db retentionNativeDatabase) map[string]any {
	t.Helper()
	body := retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.cleanup_claim($1::jsonb)`, retentionNativeJSON(t, map[string]any{"worker_id": "retention-native-cleanup"}))
	var envelope struct {
		Found bool           `json:"found"`
		Claim map[string]any `json:"claim"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Found != (envelope.Claim != nil) {
		t.Fatal("native cleanup envelope malformed")
	}
	if envelope.Found && len(envelope.Claim) != 10 {
		t.Fatal("native server-selected cleanup binding incomplete")
	}
	return envelope.Claim
}
func retentionNativeAuthorized(t *testing.T, ctx context.Context, db retentionNativeDatabase, claim map[string]any) bool {
	t.Helper()
	value := retentionNativeObject(t, retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.cleanup_authorize($1::jsonb)`, retentionNativeJSON(t, claim)))
	result, ok := value["authorized"].(bool)
	if !ok || len(value) != 1 {
		t.Fatal("native cleanup authorization malformed")
	}
	return result
}
func retentionNativeObservation(claim map[string]any) map[string]any {
	q := retentionNativeCopy(claim)
	q["index_observed_empty"], q["documents_checked"], q["absent"] = true, 0, 0
	return q
}

// One fixed native child uses internal assertions. No nested child names alter
// the strict evidence roster. SQL capabilities are bearer nonces; private
// execution ownership is enforced by the separately tested application collector.
func runRetentionIndexNativeAcceptance(t *testing.T, ctx context.Context, index, api *pgx.Conn, scope domain.Scope, pin string, raw retentionNativeRaw, projections []retentionNativeProjection, count func(string, ...any) int) {
	t.Helper()
	db := retentionNativeDatabase{index}
	apiDB := retentionNativeDatabase{api}
	failClosed := func(q string, request map[string]any, principal retentionNativeDatabase) {
		t.Helper()
		before := count(`SELECT count(*) FROM zasp_retention_v1.index_admissions`)
		if _, err := principal.QueryJSON(ctx, q, retentionNativeJSON(t, request)); err == nil {
			t.Fatal("invalid native retention binding accepted")
		}
		if count(`SELECT count(*) FROM zasp_retention_v1.index_admissions`) != before {
			t.Fatal("rejected binding published admission")
		}
	}
	// Consume actual sandbox-v2 claims, authenticating each whole receipt/archive.
	// Legacy-v1 attempt0 work remains untouched, rather than impersonated/completed.
	seen := map[string]bool{}
	var knownSessionNonce string
	for range projections {
		body := retentionNativeQuery(t, ctx, db, `SELECT COALESCE(zasp_authorization80_runtime.runtime_precise_search_claim($1,$2,$3),'null'::jsonb)`, "retention-native-session", "retention-native-session-token", 300)
		q := retentionNativeObject(t, body)
		batch, ok := q["batch_id"].(string)
		if !ok || seen[batch] {
			t.Fatal("actual session claim missing or repeated")
		}
		seen[batch] = true
		var fixture *retentionNativeProjection
		for i := range projections {
			if projections[i].args[3] == batch {
				fixture = &projections[i]
				break
			}
		}
		if fixture == nil {
			t.Fatal("claim has no authentic original fixture")
		}
		receiptBody := fixture.args[17].([]byte)
		digest := sha256.Sum256(receiptBody)
		if q["receipt_digest"] != hex.EncodeToString(digest[:]) {
			t.Fatal("actual session claim digest changed")
		}
		binding := sessionsearch.ReceiptBinding{Scope: scope, BatchID: mustProductID(t, batch), Generation: 1, ReceiptDigest: digest}
		build := sessionsearch.BuildDocuments
		if q["projection_implementation_version"] == "runtime-projection-v3" {
			build = sessionsearch.BuildPreciseDocuments
		}
		docs, err := build(binding, receiptBody, fixture.archive)
		if err != nil {
			t.Fatal("whole original session archive/receipt rejected")
		}
		ids, events := make([]string, len(docs)), make([]string, len(docs))
		for i, doc := range docs {
			ids[i], events[i] = doc.DocumentID, doc.EventID
		}
		if !reflect.DeepEqual(q["document_ids"], retentionNativeObject(t, retentionNativeJSON(t, map[string]any{"ids": ids}))["ids"]) {
			t.Fatal("full original claimed document IDs changed")
		}
		q["class"], q["event_ids"], q["worker_id"], q["lease_token"], q["index_family"] = "runtime_event", events, "retention-native-session", "retention-native-session-token", "sandbox-v2"
		admissionSQL := `SELECT zasp_retention_v1.session_index_visibility($1::jsonb)`
		failClosed(admissionSQL, q, apiDB)
		foreign := retentionNativeCopy(q)
		foreign["environment_id"] = "pid_98000001-0000-4000-8000-000000000001"
		failClosed(admissionSQL, foreign, db)
		badToken := retentionNativeCopy(q)
		badToken["lease_token"] = "retention-wrong-session-token"
		failClosed(admissionSQL, badToken, db)
		badMember := retentionNativeCopy(q)
		badMember["event_ids"] = []string{automaticSourceID(99999)}
		failClosed(admissionSQL, badMember, db)
		nonce, states := retentionNativeAdmission(t, retentionNativeQuery(t, ctx, db, admissionSQL, retentionNativeJSON(t, q)), events)
		knownSessionNonce = nonce
		written, suppressed := []string{}, []string{}
		selected := []sessionsearch.Document{}
		for _, doc := range docs {
			if states[doc.EventID] {
				written = append(written, doc.DocumentID)
				selected = append(selected, doc)
			} else {
				suppressed = append(suppressed, doc.DocumentID)
			}
		}
		if len(written) != 1 || len(suppressed) != 2 {
			t.Fatal("actual mixed-age session mask did not preserve cutoff")
		}
		fullBytes, providerBytes := retentionNativeJSON(t, docs), retentionNativeJSON(t, selected)
		retentionNativeArtifact(t, "controlled-session-provider.json", providerBytes)
		partition := retentionNativeCopy(q)
		partition["full_document_ids"], partition["written_document_ids"], partition["suppressed_document_ids"] = ids, written, suppressed
		partition["original_content_digest"], partition["provider_content_digest"], partition["admission_ids"] = retentionNativeDigest(fullBytes), retentionNativeDigest(providerBytes), []string{nonce}
		receipt := retentionNativeObject(t, retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.record_session_index_partition($1::jsonb)`, retentionNativeJSON(t, partition)))
		if len(receipt) != 1 || len(fmt.Sprint(receipt["partition_digest"])) != 64 {
			t.Fatal("session partition receipt malformed")
		}
		retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.current_sandbox_search_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch, int64(1), "retention-native-session", "retention-native-session-token", int(q["attempt"].(float64)), digest[:], "indexed", ids, 0)
	}
	// Pending raw attempt0 permits cleanup; claiming the real original work changes
	// the captured writer epoch before any controlled provider observation.
	stale := retentionNativeClaim(t, ctx, db)
	if stale == nil || !retentionNativeAuthorized(t, ctx, db, stale) {
		t.Fatal("stable original writer history did not admit cleanup")
	}
	repository, err := runtimeevent.NewPostgresRetentionRuntimePipelineRepository(db, runtimeevent.ProductionPipelineAuthorityIndex, pin)
	if err != nil {
		t.Fatal("actual retained pipeline constructor refused")
	}
	const worker, token = "retention-native-index", "retention-native-index-token"
	leases, err := repository.ClaimStages(ctx, worker, token, 300, 1)
	if err != nil || len(leases) != 1 || leases[0].BatchID != raw.batch {
		t.Fatal("actual original raw index claim refused")
	}
	lease := leases[0]
	if retentionNativeAuthorized(t, ctx, db, stale) {
		t.Fatal("changed writer history retained stale forward authorization")
	}
	if retentionNativeClaim(t, ctx, db) != nil {
		t.Fatal("in-flight original writer permitted cleanup")
	}
	// Construct full original document IDs/content digest through the actual codec;
	// the driver below is explicitly a controlled fixture artifact, not OpenSearch.
	driver := &retentionNativeCapture{}
	store, err := runtimeindex.New(driver, runtimeindex.Config{MaximumBatchBytes: 4 << 20, MaximumDocuments: 1000})
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.ApplyPrecise(ctx, runtimeindex.Batch{Scope: scope, BatchID: raw.batch, Generation: lease.Generation, InputDigest: lease.InputDigest, ArchiveReference: lease.InputReference, ArchiveVersionID: lease.InputVersionID, Body: raw.body})
	if err != nil {
		t.Fatal("whole original raw archive codec refused")
	}
	events := make([]string, len(driver.batch.Documents))
	for i, doc := range driver.batch.Documents {
		events[i] = doc.EventID
	}
	q := map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "class": "runtime_event", "event_ids": events, "batch_id": raw.batch.String(), "generation": lease.Generation, "stage": "index", "attempt": lease.Attempt, "implementation_version": lease.ImplementationVersion, "predecessor_digest": nil, "input_digest": hex.EncodeToString(lease.InputDigest[:]), "input_reference": lease.InputReference, "input_version_id": lease.InputVersionID, "lease_expires_at": lease.LeaseExpiresAt, "worker_id": worker, "lease_token": token}
	if lease.PredecessorDigest != nil {
		q["predecessor_digest"] = hex.EncodeToString(lease.PredecessorDigest[:])
	}
	const admitSQL = `SELECT zasp_retention_v1.index_visibility($1::jsonb)`
	failClosed(admitSQL, q, apiDB)
	bad := retentionNativeCopy(q)
	bad["attempt"] = lease.Attempt + 1
	failClosed(admitSQL, bad, db)
	// Rollback an issued value without publishing it to any fixture provider.
	tx, err := index.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	var rolled json.RawMessage
	if err = tx.QueryRow(ctx, admitSQL, retentionNativeJSON(t, q)).Scan(&rolled); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("rollback admission fixture refused")
	}
	rolledNonce, _ := retentionNativeAdmission(t, rolled, events)
	if tx.Rollback(ctx) != nil {
		t.Fatal("admission rollback refused")
	}
	if count(`SELECT count(*) FROM zasp_retention_v1.index_admissions WHERE admission_id=$1`, rolledNonce) != 0 {
		t.Fatal("rolled-back admission persisted")
	}
	nonceA, states := retentionNativeAdmission(t, retentionNativeQuery(t, ctx, db, admitSQL, retentionNativeJSON(t, q)), events)
	nonceB, _ := retentionNativeAdmission(t, retentionNativeQuery(t, ctx, db, admitSQL, retentionNativeJSON(t, q)), events)
	if nonceA == nonceB {
		t.Fatal("same-lease admissions did not mint independent capabilities")
	}
	selected := driver.batch
	selected.Documents = nil
	written, suppressed := []string{}, []string{}
	for _, doc := range driver.batch.Documents {
		if states[doc.EventID] {
			selected.Documents = append(selected.Documents, doc)
			written = append(written, doc.DocumentID)
		} else {
			suppressed = append(suppressed, doc.DocumentID)
		}
	}
	if len(written) != 1 || len(suppressed) != 2 {
		t.Fatal("raw resurrection mask changed")
	}
	providerBytes := retentionNativeJSON(t, selected)
	retentionNativeArtifact(t, "controlled-raw-provider.json", providerBytes)
	partition := retentionNativeCopy(q)
	partition["full_document_ids"], partition["written_document_ids"], partition["suppressed_document_ids"] = result.DocumentIDs, written, suppressed
	partition["original_content_digest"], partition["provider_content_digest"], partition["admission_ids"] = hex.EncodeToString(result.ContentDigest[:]), retentionNativeDigest(providerBytes), []string{nonceB}
	const recordSQL = `SELECT zasp_retention_v1.record_index_partition($1::jsonb)`
	// A valid bearer capability from a different original family/lease cannot
	// be substituted for this raw execution. Known same-lease capabilities are
	// intentionally not treated as separate SQL execution identities.
	wrongFamily := retentionNativeCopy(partition)
	wrongFamily["admission_ids"] = []string{knownSessionNonce}
	beforePartitions := count(`SELECT count(*) FROM zasp_retention_v1.index_partitions`)
	if _, err = db.QueryJSON(ctx, recordSQL, retentionNativeJSON(t, wrongFamily)); err == nil {
		t.Fatal("foreign original-family admission accepted")
	}
	if count(`SELECT count(*) FROM zasp_retention_v1.index_partitions`) != beforePartitions {
		t.Fatal("foreign capability changed durable partitions")
	}
	unknown := retentionNativeCopy(partition)
	unknown["admission_ids"] = []string{rolledNonce}
	if _, err = db.QueryJSON(ctx, recordSQL, retentionNativeJSON(t, unknown)); err == nil {
		t.Fatal("rolled-back capability settled a partition")
	}
	receiptB := retentionNativeQuery(t, ctx, db, recordSQL, retentionNativeJSON(t, partition))
	if count(`SELECT count(*) FROM zasp_retention_v1.admission_settlements WHERE admission_id=$1`, nonceB) != 1 || count(`SELECT count(*) FROM zasp_retention_v1.admission_settlements WHERE admission_id=$1`, nonceA) != 0 {
		t.Fatal("B-only accounting consumed unrelated admission A")
	}
	if retentionNativeClaim(t, ctx, db) != nil {
		t.Fatal("outstanding original execution permitted cleanup")
	}
	// A is still held by its original live fixture execution. This is not orphan
	// recovery: recording requires the original live lease, before native finish.
	partition["admission_ids"] = []string{nonceA}
	receiptA := retentionNativeQuery(t, ctx, db, recordSQL, retentionNativeJSON(t, partition))
	if !bytes.Equal(receiptA, receiptB) {
		t.Fatal("exact partition replay changed with explicit nonce list")
	}
	itemIDs := append([]string(nil), result.DocumentIDs...)
	sort.Strings(itemIDs)
	receiptBody, receiptDigest, reference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: lease.ImplementationVersion, Scope: scope, BatchID: raw.batch, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: lease.InputReference, ArchiveVersionID: lease.InputVersionID, ArchiveDigest: raw.digest, EffectDigest: result.ContentDigest, ItemIDs: itemIDs})
	if err != nil {
		t.Fatal("whole original raw stage receipt rejected")
	}
	retentionNativeArtifact(t, "whole-original-index-receipt.json", receiptBody)
	retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.current_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), raw.batch.String(), lease.Generation, worker, token, lease.Attempt, lease.InputDigest[:], lease.ImplementationVersion, "succeeded", result.ContentDigest[:], "s3://zasp-evidence/retention/"+reference.String(), "fixture-index-v1", receiptDigest[:], nil, 0)
	// An old zero observation cannot become valid after a different epoch finishes.
	staleObservation := retentionNativeObservation(stale)
	staleResult := retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`, retentionNativeJSON(t, staleObservation))
	outcome := retentionNativeObject(t, staleResult)
	if outcome["recorded"] != true || outcome["drained"] != false || outcome["complete"] != false {
		t.Fatal("stale epoch observation was promoted after writer completion")
	}
	again := retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`, retentionNativeJSON(t, staleObservation))
	if !bytes.Equal(staleResult, again) {
		t.Fatal("stale captured outcome was rewritten")
	}
	fresh := retentionNativeClaim(t, ctx, db)
	if fresh == nil || !retentionNativeAuthorized(t, ctx, db, fresh) {
		t.Fatal("fresh accounted writer epoch unavailable")
	}
	observation := retentionNativeObservation(fresh)
	settled := retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`, retentionNativeJSON(t, observation))
	outcome = retentionNativeObject(t, settled)
	if outcome["recorded"] != true || outcome["drained"] != true || outcome["complete"] != true {
		t.Fatal("controlled same-epoch SQL settlement refused")
	}
	again = retentionNativeQuery(t, ctx, db, `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`, retentionNativeJSON(t, observation))
	if !bytes.Equal(settled, again) {
		t.Fatal("captured successful settlement replay changed")
	}
	changed := retentionNativeCopy(observation)
	changed["documents_checked"], changed["absent"] = 1, 1
	if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`, retentionNativeJSON(t, changed)); err == nil {
		t.Fatal("immutable observation accepted changed replay")
	}
	foreign := retentionNativeCopy(observation)
	foreign["lease_token"] = fmt.Sprintf("%064x", 1)
	if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`, retentionNativeJSON(t, foreign)); err == nil {
		t.Fatal("foreign captured claim binding accepted")
	}
	if count(`SELECT count(*) FROM zasp_retention_v1.index_admissions a LEFT JOIN zasp_retention_v1.admission_settlements s USING(admission_id) WHERE s.admission_id IS NULL`) != 0 {
		t.Fatal("fixture original admissions remain unaccounted")
	}
}

type retentionNativeCapture struct{ batch runtimeindex.DriverBatch }

func (d *retentionNativeCapture) Apply(_ context.Context, b runtimeindex.DriverBatch) (runtimeindex.DriverResult, error) {
	d.batch = b
	ids := make([]string, len(b.Documents))
	for i, doc := range b.Documents {
		ids[i] = doc.DocumentID
	}
	return runtimeindex.DriverResult{BatchID: b.BatchID, Generation: b.Generation, InputDigest: b.InputDigest, ContentDigest: b.ContentDigest, DocumentIDs: ids}, nil
}
