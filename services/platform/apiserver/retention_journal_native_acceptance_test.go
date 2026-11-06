package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"testing"
)

func seedRetentionJournalNativeRaw(t *testing.T, ctx context.Context, owner *pgx.Conn, scope domain.Scope, archive []byte) retentionNativeRaw {
	t.Helper()
	if _, err := runtimeevent.DecodePreciseArchivedBatch(scope, archive); err != nil {
		t.Fatal("whole precise raw fixture rejected")
	}
	raw := retentionNativeRaw{batch: mustProductID(t, automaticSourceID(99200)), body: append([]byte(nil), archive...), reference: "s3://zasp-evidence/runtime/retention-journal-native.json", digest: sha256.Sum256(archive)}
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	sensor, token := automaticSourceID(99201), automaticSourceID(99202)
	tokenDigest := sha256.Sum256([]byte(token))
	queries := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,'Retention index native','tetragon')`, []any{o, w, e, sensor}},
		{`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,decode(repeat('aa',16),'hex'),$6,clock_timestamp()+interval '1 day')`, []any{o, w, e, token, sensor, tokenDigest[:]}},
		{`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,$4,$5,'retention-journal-native',$6,3,$7,$8,'application/json','runtime-event-v2','processing')`, []any{o, w, e, raw.batch.String(), sensor, raw.digest[:], raw.reference, len(archive)}},
		{`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$4,$5,$6,1,1,'retention-journal-native',$7,$7,'tetragon','application/json','runtime-event-v2',$8,3,'runtime/retention-journal-native.json',$9,'archive-v1',$7,$8,'fixture-kms-reference',clock_timestamp(),'processing')`, []any{o, w, e, raw.batch.String(), sensor, token, raw.digest[:], len(archive), raw.reference}},
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

// This fixture proves SQL enforcement using controlled local response artifacts.
// It does not attest real provider HTTP/S3 or historical writer resolution.
func runRetentionJournalNativeAcceptance(t *testing.T, ctx context.Context, bootstrap, owner, index *pgx.Conn, scope domain.Scope, parentPin string, archive []byte) {
	t.Helper()
	raw := seedRetentionJournalNativeRaw(t, ctx, bootstrap, scope, archive)
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: owner})
	if err != nil {
		t.Fatal("journal native runner refused")
	}
	// Explicit hostile defaults test only the newly created journal objects;
	// the installer must not change these global default rules themselves.
	defaultTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal("owned default ACL fixture refused")
	}
	if _, err = defaultTx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO auth80_api;ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO auth80_api`); err != nil {
		_ = defaultTx.Rollback(ctx)
		t.Fatal("owned default ACL grants refused")
	}
	if defaultTx.Commit(ctx) != nil {
		t.Fatal("owned default ACL fixture commit refused")
	}
	defer func() {
		cleanup, err := owner.Begin(ctx)
		if err == nil {
			defer cleanup.Rollback(context.Background())
			if _, err = cleanup.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM auth80_api;ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM auth80_api`); err == nil {
				_ = cleanup.Commit(ctx)
			}
		}
	}()
	if err = runner.UpProductionRetentionJournalProfile(ctx); err != nil {
		t.Fatal("journal native install refused", err)
	}
	if err = runner.UpProductionRetentionJournalProfile(ctx); err != nil {
		t.Fatal("journal native exact install replay refused")
	}
	var privateACL bool
	if err = bootstrap.QueryRow(ctx, `SELECT NOT has_table_privilege('auth80_api','zasp_retention_journal_v1.executions','SELECT') AND NOT has_function_privilege('auth80_api','zasp_retention_journal_v1.require_execution(jsonb,boolean)','EXECUTE') AND EXISTS(SELECT 1 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE d.defaclrole='zasp_discovery_authority'::regrole AND a.grantee='auth80_api'::regrole)`).Scan(&privateACL); err != nil || !privateACL {
		t.Fatal("journal inherited default ACL leaked private authority or installer changed global defaults")
	}
	pin := migrations.RetentionJournalProfileChecksum()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal("journal native operator refused")
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal("journal original operator role refused")
	}
	var ok bool
	if err = tx.QueryRow(ctx, `SELECT zasp_retention_journal_v1.enroll_scope($1,$2,$3,$4)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), pin).Scan(&ok); err != nil || !ok {
		t.Fatal("journal scope enrollment refused")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("journal scope enrollment commit refused")
	}
	// Original immutable settlement replay must remain a no-op after enrollment.
	replay, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal("owned historical replay fixture refused")
	}
	defer replay.Rollback(context.Background())
	if _, err = replay.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal("historical replay operator refused")
	}
	tag, err := replay.Exec(ctx, `INSERT INTO zasp_retention_v1.admission_settlements SELECT settled.* FROM zasp_retention_v1.admission_settlements settled JOIN zasp_retention_v1.index_admissions a USING(admission_id) WHERE(a.binding->>'organization_id',a.binding->>'workspace_id',a.binding->>'environment_id')=($1,$2,$3) LIMIT 1 ON CONFLICT DO NOTHING`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil || tag.RowsAffected() != 0 {
		t.Fatal("exact historical immutable settlement replay changed evidence")
	}
	if replay.Rollback(ctx) != nil {
		t.Fatal("historical replay rollback refused")
	}
	db := retentionNativeDatabase{index}
	repo, err := runtimeevent.NewPostgresRetentionRuntimePipelineRepository(db, runtimeevent.ProductionPipelineAuthorityIndex, parentPin)
	if err != nil {
		t.Fatal("journal original claim repository refused")
	}
	const worker, token = "retention-journal-native-index", "retention-journal-native-token"
	leases, err := repo.ClaimStages(ctx, worker, token, 300, 1)
	if err != nil || len(leases) != 1 || leases[0].BatchID != raw.batch {
		t.Fatal("journal original raw claim refused")
	}
	lease := leases[0]
	capture := &retentionNativeCapture{}
	store, err := runtimeindex.New(capture, runtimeindex.Config{MaximumBatchBytes: 4 << 20, MaximumDocuments: 1000})
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.ApplyPrecise(ctx, runtimeindex.Batch{Scope: scope, BatchID: raw.batch, Generation: lease.Generation, InputDigest: lease.InputDigest, ArchiveReference: lease.InputReference, ArchiveVersionID: lease.InputVersionID, Body: raw.body})
	if err != nil {
		t.Fatal("journal whole original archive refused")
	}
	events := make([]string, len(capture.batch.Documents))
	for n, d := range capture.batch.Documents {
		events[n] = d.EventID
	}
	binding := map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "class": "runtime_event", "event_ids": events, "batch_id": raw.batch.String(), "generation": lease.Generation, "stage": "index", "attempt": lease.Attempt, "implementation_version": lease.ImplementationVersion, "predecessor_digest": nil, "input_digest": hex.EncodeToString(lease.InputDigest[:]), "input_reference": lease.InputReference, "input_version_id": lease.InputVersionID, "lease_expires_at": lease.LeaseExpiresAt, "worker_id": worker, "lease_token": token}
	if lease.PredecessorDigest != nil {
		binding["predecessor_digest"] = hex.EncodeToString(lease.PredecessorDigest[:])
	}
	if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_v1.index_visibility($1::jsonb)`, retentionNativeJSON(t, binding)); err == nil {
		t.Fatal("direct legacy admission bypassed journal enrollment hook")
	}
	randomHex := func() string {
		t.Helper()
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal("native private identity entropy unavailable")
		}
		return hex.EncodeToString(b[:])
	}
	execution, capability := randomHex(), randomHex()
	base := map[string]any{"execution_id": execution, "capability": capability}
	call := func(name string, q map[string]any) map[string]any {
		t.Helper()
		var statement string
		switch name {
		case "begin_execution":
			statement = `SELECT zasp_retention_journal_v1.begin_execution($1::jsonb)`
		case "admit_execution":
			statement = `SELECT zasp_retention_journal_v1.admit_execution($1::jsonb)`
		case "execution_status":
			statement = `SELECT zasp_retention_journal_v1.execution_status($1::jsonb)`
		case "reserve_request":
			statement = `SELECT zasp_retention_journal_v1.reserve_request($1::jsonb)`
		case "claim_send":
			statement = `SELECT zasp_retention_journal_v1.claim_send($1::jsonb)`
		case "append_terminal":
			statement = `SELECT zasp_retention_journal_v1.append_terminal($1::jsonb)`
		case "close_inventory":
			statement = `SELECT zasp_retention_journal_v1.close_inventory($1::jsonb)`
		case "seal_partition":
			statement = `SELECT zasp_retention_journal_v1.seal_partition($1::jsonb)`
		default:
			t.Fatal("native closed journal operation rejected")
		}
		return retentionNativeObject(t, retentionNativeQuery(t, ctx, db, statement, retentionNativeJSON(t, q)))
	}
	begin := retentionNativeCopy(base)
	begin["kind"], begin["binding"] = "raw-index", binding
	call("begin_execution", begin)
	admit := retentionNativeCopy(base)
	admit["binding"], admit["admission_key"] = binding, randomHex()
	admitted := call("admit_execution", admit)
	nonce, states := retentionNativeAdmission(t, retentionNativeJSON(t, admitted), events)
	selected := capture.batch
	selected.Documents = nil
	written, suppressed, selectedEvents := []string{}, []string{}, []string{}
	for _, d := range capture.batch.Documents {
		if states[d.EventID] {
			selected.Documents = append(selected.Documents, d)
			written = append(written, d.DocumentID)
			selectedEvents = append(selectedEvents, d.EventID)
		} else {
			suppressed = append(suppressed, d.DocumentID)
		}
	}
	provider := retentionNativeJSON(t, selected)
	partition := retentionNativeCopy(binding)
	partition["full_document_ids"], partition["written_document_ids"], partition["suppressed_document_ids"] = result.DocumentIDs, written, suppressed
	partition["original_content_digest"], partition["provider_content_digest"], partition["admission_ids"] = hex.EncodeToString(result.ContentDigest[:]), retentionNativeDigest(provider), []string{nonce}
	if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_v1.record_index_partition($1::jsonb)`, retentionNativeJSON(t, partition)); err == nil {
		t.Fatal("direct legacy settlement bypassed mandatory journal hook")
	}
	// A public execution identifier never supplies its separate private capability.
	wrong := retentionNativeCopy(base)
	wrong["capability"] = randomHex()
	if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_journal_v1.execution_status($1::jsonb)`, retentionNativeJSON(t, wrong)); err == nil {
		t.Fatal("public execution acquired private state")
	}
	descriptor := map[string]any{"ordinal": 0, "method": "POST", "target": "zasp-runtime-events-v1", "path": "/zasp-runtime-events-v1/_bulk", "query": "refresh=wait_for&timeout=10s", "media_type": "application/x-ndjson", "body_sha256": retentionNativeDigest(provider), "body_length": len(provider), "document_ids": written, "event_ids": selectedEvents, "admission_ids": []string{nonce}, "original_reference": lease.InputReference, "original_version_id": lease.InputVersionID, "original_digest": hex.EncodeToString(lease.InputDigest[:]), "serializer_profile": "runtime-retained-bulk-v1"}
	reserve := retentionNativeCopy(base)
	reserve["binding"], reserve["descriptor"] = binding, descriptor
	reserved := call("reserve_request", reserve)
	claim := retentionNativeCopy(base)
	claim["binding"], claim["reservation_digest"] = binding, reserved["reservation_digest"]
	sent := call("claim_send", claim)
	if sent["send_permitted"] != true {
		t.Fatal("first confirmed send claim absent")
	}
	if call("claim_send", claim)["send_permitted"] != false {
		t.Fatal("send claim replay reissued permit")
	}
	if call("execution_status", base)["send_permitted"] != false {
		t.Fatal("lookup reissued volatile permit")
	}
	closeQ := retentionNativeCopy(base)
	closeQ["binding"], closeQ["admission_ids"], closeQ["request_count"] = binding, []string{nonce}, 1
	if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_journal_v1.close_inventory($1::jsonb)`, retentionNativeJSON(t, closeQ)); err == nil {
		t.Fatal("unknown dispatched HTTP acquired closed inventory")
	}
	// Controlled fixture terminal custody checks SQL binding only, not provider proof.
	items := make([]any, len(written))
	for n, id := range written {
		items[n] = map[string]any{"create": map[string]any{"_index": "zasp-runtime-events-v1", "_id": id, "status": 201, "_version": 1, "result": "created", "_seq_no": n, "_primary_term": 1, "_shards": map[string]any{"total": 1, "successful": 1, "failed": 0}}}
	}
	terminalBytes := retentionNativeJSON(t, map[string]any{"took": 1, "errors": false, "items": items})
	retentionNativeArtifact(t, "controlled-journal-terminal.json", terminalBytes)
	observation := map[string]any{"reservation_digest": reserved["reservation_digest"], "dispatch_digest": sent["dispatch_digest"], "reference": "s3://zasp-evidence/organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + automaticSourceID(99203), "version_id": "controlled-native-v1", "sha256": retentionNativeDigest(terminalBytes), "length": len(terminalBytes), "http_status": 200, "validator_profile": "runtime-retained-terminal-v1"}
	canonicalReference := observation["reference"].(string)
	for _, badReference := range []string{"s3://foreign-bucket" + canonicalReference[len("s3://zasp-evidence"):], canonicalReference + "/suffix", canonicalReference + "?versionId=other", canonicalReference + "#fragment", "s3://zasp-evidence/not-a-receipt/" + canonicalReference[len("s3://zasp-evidence/"):]} {
		badObservation := retentionNativeCopy(observation)
		badObservation["reference"] = badReference
		badTerminal := retentionNativeCopy(base)
		badTerminal["observation"] = badObservation
		if _, err = db.QueryJSON(ctx, `SELECT zasp_retention_journal_v1.append_terminal($1::jsonb)`, retentionNativeJSON(t, badTerminal)); err == nil {
			t.Fatal("foreign or noncanonical terminal artifact accepted")
		}
	}
	terminal := retentionNativeCopy(base)
	terminal["observation"] = observation
	call("append_terminal", terminal)
	call("close_inventory", closeQ)
	seal := retentionNativeCopy(base)
	seal["partition"] = partition
	sealed := call("seal_partition", seal)
	if sealed["partition_digest"] == nil || call("execution_status", base)["state"] != "sealed" {
		t.Fatal("exact journal transaction did not seal original partition")
	}
	if err = index.QueryRow(ctx, `SELECT zasp_retention_journal_v1.ready($1)`, pin).Scan(&ok); err != nil || !ok {
		t.Fatal("journal current readiness refused after exact original partition")
	}
	// The original work is still leased: no partition-only physical drain claim.
	if err = bootstrap.QueryRow(ctx, `SELECT NOT zasp_retention_v1.writers_drained($1,$2,$3)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&ok); err != nil || !ok {
		t.Fatal("component journal manufactured original writer completion")
	}
	drift, err := bootstrap.Begin(ctx)
	if err != nil {
		t.Fatal("owned journal drift transaction refused")
	}
	defer drift.Rollback(context.Background())
	if _, err = drift.Exec(ctx, `ALTER TABLE zasp_retention_v1.admission_settlements DISABLE TRIGGER zasp_retention_journal_v1_settlement`); err != nil {
		t.Fatal("owned hook drift refused")
	}
	if err = drift.QueryRow(ctx, `SELECT NOT zasp_retention_journal_v1.raw_ready($1)`, pin).Scan(&ok); err != nil || !ok {
		t.Fatal("disabled mandatory hook preserved independent seal")
	}
	if drift.Rollback(ctx) != nil {
		t.Fatal("owned journal drift rollback refused")
	}
}
