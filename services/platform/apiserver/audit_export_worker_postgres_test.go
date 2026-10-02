//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuditExportWorkerPostgresCaptureFrozenPagesResume(t *testing.T) {
	auditExportWorkerCaptureAndResume(t, false, false)
}

func TestAuditExportWorkerPostgresChunkReceiptsResume(t *testing.T) {
	auditExportWorkerCaptureAndResume(t, true, false)
}

func TestAuditExportWorkerPostgresCompletedSDK(t *testing.T) {
	auditExportWorkerCaptureAndResume(t, false, true)
}

func auditExportWorkerCaptureAndResume(t *testing.T, recordChunks, complete bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	auditExportWorkerConnections(t, ctx, f)
	args := f.createArgs()
	var descriptor json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&descriptor); err != nil {
		t.Fatal("create durable export", err)
	}
	expected, fixturePath := auditExportPrepareWorkerSource(t, ctx, f, args)
	if complete {
		auditExportCaptureWorkerChild(t, ctx, f, args, fixturePath, "complete")
		auditExportAssertCompletedSDK(t, ctx, f, args, expected, fixturePath+".objects.json")
		return
	}
	firstPhase, resumePhase := "capture", "resume"
	if recordChunks {
		firstPhase, resumePhase = "record", "record-resume"
	}
	auditExportCaptureWorkerChild(t, ctx, f, args, fixturePath, firstPhase)
	var firstReceipt string
	if recordChunks {
		firstReceipt = auditExportAssertWorkerChunkReceipts(t, ctx, f, args, 1)
	}
	// Compare persisted bytes independently, not only hashes returned to Go.
	rows, err := f.admin.Query(ctx, `SELECT canonical_event FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if index >= len(expected) || !bytes.Equal(raw, expected[index]) {
			rows.Close()
			t.Fatal("persisted canonical snapshot differs", index)
		}
		index++
	}
	rows.Close()
	if rows.Err() != nil || index != len(expected) {
		t.Fatal("persisted snapshot incomplete", rows.Err())
	}
	snapshot := func() string {
		var digest string
		err := f.admin.QueryRow(ctx, `SELECT encode(digest(convert_to(jsonb_build_object('job',(SELECT to_jsonb(j)-ARRAY['lease_worker','lease_token_digest','lease_expires_at','attempt','generation'] FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY ordinal) FROM zasp_audit_export_events e WHERE organization_id=$1 AND export_id=$2),'chunks',(SELECT jsonb_agg(to_jsonb(c) ORDER BY ordinal) FROM zasp_audit_export_chunks c WHERE organization_id=$1 AND export_id=$2))::text,'UTF8'),'sha256'),'hex')`, args[0], args[7]).Scan(&digest)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	before := snapshot()
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{"counter":999}' WHERE organization_id=$1 AND action='integration.webhook'`, args[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1 AND id='pid_53000000-0000-4000-8000-000000000001'`, args[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_53000000-0000-4000-8000-000000009999',$4,'late.backdated','excluded post-capture','succeeded','{}','2020-01-01T00:00:00Z')`, args[0], args[1], args[2], args[3]); err != nil {
		t.Fatal(err)
	}
	// Owner-only fixture expiry simulates process loss; it is not a fabricated
	// successful receipt, capture or terminal transition.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_audit_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND id=$2`, args[0], args[7]); err != nil {
		t.Fatal(err)
	}
	auditExportCaptureWorkerChild(t, ctx, f, args, fixturePath, resumePhase)
	if recordChunks && auditExportAssertWorkerChunkReceipts(t, ctx, f, args, 2) != firstReceipt {
		t.Fatal("new generation changed the first immutable receipt or intent")
	}
	if snapshot() != before {
		t.Fatal("process resume/source changes rewrote captured snapshot or plan")
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='processing' AND captured AND attempt=2 AND generation=2 AND event_count=1006 AND chunk_count=2 AND reserved_bytes=chunk_bytes+octet_length(manifest_bytes) AND completion_audit_id IS NULL AND completed_at IS NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("capture resume invented terminal state or lost quota", err)
	}
	var completions int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'`).Scan(&completions); err != nil || completions != 0 {
		t.Fatal("read-only capture fabricated completion", err)
	}
	if recordChunks {
		t.Log("actual Go registered PG prepared and recorded two canonical chunks across recreated-process generation2; exact persisted intents/receipts and source snapshot retained; supplied SQL version fixtures, no S3/manifest/Finish/outbox proof")
	} else {
		t.Log("actual Go registered PG capture and recreated-process resume preserved1006 canonical events/two-chunk chain despite source update/delete/backdated append; no provider/intent/receipt/finish proof")
	}
}

func auditExportAssertWorkerChunkReceipts(t *testing.T, ctx context.Context, f auditExportPG, args []any, count int) string {
	t.Helper()
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM zasp_audit_export_intents)=$5 AND
 (SELECT count(*) FROM zasp_audit_export_receipts)=$5 AND
 (SELECT count(*) FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) JOIN zasp_audit_export_chunks c USING(organization_id,export_id,ordinal)
 WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.export_id=$4 AND i.capture_id=c.capture_id AND i.kind='chunk'
 AND i.sha256=c.sha256 AND i.size_bytes=c.size_bytes AND r.sha256=i.sha256 AND r.size_bytes=i.size_bytes
 AND r.version_id='owned-sql-only-chunk-version-'||i.ordinal::text
 AND i.object_reference='s3://'||$6||'/organizations/'||$1||'/workspaces/'||$2||'/environments/'||$3||'/exports/'||i.artifact_id)=$5`, args[0], args[1], args[2], args[7], count, auditExportTestPolicy().Bucket).Scan(&exact); err != nil || !exact {
		t.Fatal("persisted SQL receipt/intent lost exact scope, plan, version or byte pins", err)
	}
	var first string
	if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object('intent',to_jsonb(i),'receipt',to_jsonb(r))::text FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.export_id=$2 AND i.kind='chunk' AND i.ordinal=1`, args[0], args[7]).Scan(&first); err != nil {
		t.Fatal(err)
	}
	return first
}

func auditExportCaptureWorkerChild(t *testing.T, ctx context.Context, f auditExportPG, args []any, expectedPath, phase string) {
	t.Helper()
	fixtureURL, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || fixtureURL.Scheme != "postgres" {
		t.Fatal("owned fixture URL")
	}
	fixtureURL.User = url.User("audit_export_worker_fixture")
	testName, marker := "TestAuditExportAuthorityCapturePostgres", "registered PostgreSQL Go capture/page proven:"
	if phase == "record" || phase == "record-resume" {
		testName, marker = "TestAuditExportAuthorityChunksPostgres", "registered PostgreSQL Go chunk receipt proven:"
	}
	if phase == "complete" {
		testName, marker = "TestAuditExportCompletedWorkerPostgres", "registered PostgreSQL completed export through actual production worker"
	}
	command := exec.Command("go", "test", "-race", "../agentsec-worker", "-run", "^"+testName+"$", "-count=1", "-v")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_WORKER_TEST_DSN="+fixtureURL.String(), "ZASP_AUDIT_EXPORT_WORKER_TEST_ORG="+args[0].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_WORKSPACE="+args[1].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_ENVIRONMENT="+args[2].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_EXPORT="+args[7].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_PHASE="+phase, "ZASP_AUDIT_EXPORT_WORKER_TEST_EXPECTED="+expectedPath)
	output, err := runSandboxWorkerCommand(ctx, command)
	if err != nil {
		t.Fatalf("owned capture child failed: %v\n%s", err, output)
	}
	if phase != "complete" {
		marker = fmt.Sprintf("%s phase=%s", marker, phase)
	}
	if !strings.Contains(string(output), marker) || strings.Contains(string(output), "--- SKIP:") {
		t.Fatal("capture child omitted real acceptance")
	}
	t.Logf("owned capture child:\n%s", output)
}

func auditExportAssertCompletedSDK(t *testing.T, ctx context.Context, f auditExportPG, args []any, events []json.RawMessage, path string) {
	t.Helper()
	objects := auditExportReadWorkerObjects(t, path)
	binding := audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string)}
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&binding.CaptureID); err != nil {
		t.Fatal(err)
	}
	// Expected bytes are independently constructed from the pre-capture source,
	// not copied from a provider response or persisted intent's claimed digest.
	expected := map[string][]byte{}
	previous := audit.ExportZeroDigest
	var chunkBytes int64
	for ordinal := int64(1); ordinal <= 2; ordinal++ {
		first, last := int((ordinal-1)*1000), min(int(ordinal*1000), len(events))
		chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: ordinal, FirstEvent: int64(first + 1), EventCount: int64(last - first), PreviousDigest: previous}
		for _, raw := range events[first:last] {
			event, err := audit.DecodeExportEvent(raw)
			if err != nil {
				t.Fatal(err)
			}
			chunk.Events = append(chunk.Events, event)
		}
		body, err := audit.EncodeExportChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		expected[fmt.Sprintf("chunk:%d", ordinal)] = body
		sum := sha256.Sum256(body)
		previous = hex.EncodeToString(sum[:])
		chunkBytes += int64(len(body))
	}
	manifest, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1006, ChunkCount: 2, ChunkBytes: chunkBytes, ChainRoot: previous})
	if err != nil {
		t.Fatal(err)
	}
	expected["manifest:0"] = manifest
	rows, err := f.admin.Query(ctx, `SELECT i.kind,i.ordinal,i.artifact_id,i.object_reference,i.sha256,i.size_bytes,r.version_id,r.sha256,r.size_bytes FROM zasp_audit_export_intents i JOIN zasp_audit_export_receipts r USING(organization_id,export_id,kind,ordinal) WHERE i.organization_id=$1 AND i.workspace_id=$2 AND i.environment_id=$3 AND i.export_id=$4 AND i.capture_id=$5 ORDER BY i.kind,i.ordinal`, args[0], args[1], args[2], args[7], binding.CaptureID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var kind, id, reference, version string
		var ordinal, size, receiptSize int64
		var digest, receiptDigest []byte
		if err := rows.Scan(&kind, &ordinal, &id, &reference, &digest, &size, &version, &receiptDigest, &receiptSize); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		body, ok := expected[fmt.Sprintf("%s:%d", kind, ordinal)]
		object, exists := objects[reference]
		sum := sha256.Sum256(body)
		versionNumber := ordinal
		if kind == "manifest" {
			versionNumber = 3
		}
		wantRef := fmt.Sprintf("s3://%s/organizations/%s/workspaces/%s/environments/%s/exports/%s", auditExportTestPolicy().Bucket, args[0], args[1], args[2], id)
		if !ok || !exists || reference != wantRef || !bytes.Equal(body, object.Body) || version != fmt.Sprintf("owned-TLS-version-%d", versionNumber) || object.Version != version || size != int64(len(body)) || receiptSize != size || !bytes.Equal(sum[:], digest) || !bytes.Equal(digest, receiptDigest) {
			rows.Close()
			t.Fatal("SQL receipt/provider differs from independent exact export bytes")
		}
		delete(expected, fmt.Sprintf("%s:%d", kind, ordinal))
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != 3 || len(expected) != 0 {
		t.Fatal("missing completed artifact authority", rows.Err())
	}
	manifestHash := sha256.Sum256(manifest)
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT status='ready' AND captured AND attempt=1 AND generation=1 AND event_count=1006 AND chunk_count=2 AND chunk_bytes=$3 AND chain_root=$4 AND manifest_bytes=$5 AND reserved_bytes=$3+octet_length($5::bytea) AND lease_worker IS NULL AND lease_token_digest IS NULL AND lease_expires_at IS NULL AND completion_audit_id IS NOT NULL AND completed_at>=captured_at AND (SELECT count(*) FROM zasp_audit_export_intents)=3 AND (SELECT count(*) FROM zasp_audit_export_receipts)=3 AND (SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete')=1 AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.organization_id=j.organization_id AND a.workspace_id=j.workspace_id AND a.environment_id=j.environment_id AND a.id=j.completion_audit_id AND a.actor_id=j.principal_id AND a.action='audit_export.complete' AND a.target_id=j.id AND a.outcome='succeeded' AND a.occurred_at=j.completed_at AND a.metadata=jsonb_build_object('event_count',1006,'chunk_count',2,'chunk_bytes',$3::bigint,'manifest_sha256',$6::text)) FROM zasp_audit_export_jobs j WHERE organization_id=$1 AND id=$2`, args[0], args[7], chunkBytes, mustDecodeAuditWorkerHex(t, previous), manifest, hex.EncodeToString(manifestHash[:])).Scan(&exact); err != nil || !exact {
		t.Fatal("ready job/completion audit differs from actual provider output", err)
	}
	var envelope json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportGetSQL, args[0], args[1], args[2], args[3], args[4], args[5], args[7], int64(1), nil, args[11], args[12]).Scan(&envelope); err != nil {
		t.Fatal("registered API ready retrieval", err)
	}
	var page struct {
		Export json.RawMessage `json:"export"`
	}
	if json.Unmarshal(envelope, &page) != nil {
		t.Fatal("ready envelope")
	}
	descriptor, err := audit.DecodeExportDescriptor(page.Export)
	if err != nil || descriptor.Status != "ready" || descriptor.ID != binding.ExportID || descriptor.OrganizationID != binding.OrganizationID || descriptor.WorkspaceID != binding.WorkspaceID || descriptor.EnvironmentID != binding.EnvironmentID || descriptor.EventCount == nil || *descriptor.EventCount != 1006 || descriptor.ChunkCount == nil || *descriptor.ChunkCount != 2 || descriptor.ChunkBytes == nil || *descriptor.ChunkBytes != chunkBytes || descriptor.ManifestSHA256 != hex.EncodeToString(manifestHash[:]) {
		t.Fatal("registered ready descriptor lost exact provider pins", err)
	}
	t.Log("actual production Go worker/SDK completion matches independently reconstructed1006-event/two-chunk/manifest bytes and registered ready descriptor, exact provider versions, one completion audit; no durable outbox or live AWS proof")
}

func mustDecodeAuditWorkerHex(t *testing.T, value string) []byte {
	t.Helper()
	body, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAuditExportWorkerPostgresClaimHeartbeatRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	auditExportWorkerConnections(t, ctx, f)
	args := f.createArgs()
	var body json.RawMessage
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&body); err != nil {
		t.Fatal("create durable job", err)
	}
	fixtureURL, err := url.Parse(f.admin.Config().ConnString())
	if err != nil || fixtureURL.Scheme != "postgres" {
		t.Fatal("invalid owned fixture URL")
	}
	fixtureURL.User = url.User("audit_export_worker_fixture")
	command := exec.Command("go", "test", "-race", "../agentsec-worker", "-run", "^TestAuditExportAuthorityPostgres$", "-count=1", "-v")
	// No ambient product or libpq/database settings reach the child. Its only
	// database target is the explicitly registered, disposable local fixture.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "ZASP_AUDIT_EXPORT_WORKER_TEST_DSN="+fixtureURL.String(), "ZASP_AUDIT_EXPORT_WORKER_TEST_ORG="+args[0].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_WORKSPACE="+args[1].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_ENVIRONMENT="+args[2].(string), "ZASP_AUDIT_EXPORT_WORKER_TEST_EXPORT="+args[7].(string))
	output, err := runSandboxWorkerCommand(ctx, command)
	if err != nil {
		t.Fatalf("owned worker authority child failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "registered PostgreSQL Go export authority proven:") || strings.Contains(string(output), "--- SKIP:") {
		t.Fatal("child did not execute registered acceptance")
	}
	t.Logf("owned worker child:\n%s", output)
	var state, worker, tokenDigest string
	var attempt, generation int64
	var captured bool
	if err := f.admin.QueryRow(ctx, `SELECT status,lease_worker,encode(lease_token_digest,'hex'),attempt,generation,captured FROM zasp_audit_export_jobs WHERE id=$1`, args[7]).Scan(&state, &worker, &tokenDigest, &attempt, &generation, &captured); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(strings.Repeat("a", 64)))
	if state != "processing" || worker != "audit-export-worker-postgres" || tokenDigest != hex.EncodeToString(digest[:]) || attempt != 1 || generation != 1 || captured {
		t.Fatal("Go/SQL claim replay or refusals changed durable lease authority")
	}
	var completions int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.complete'`).Scan(&completions); err != nil || completions != 0 {
		t.Fatal("lease test fabricated completion", err)
	}
}

func auditExportPrepareWorkerSource(t *testing.T, ctx context.Context, f auditExportPG, args []any) ([]json.RawMessage, string) {
	t.Helper()
	metadata := `{"counter":42,"verified":true,"token":"owned-secret-never-exported","quote":"<>&\"\\ café\u2028\u2029"}`
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) SELECT $1,'pid_53000001-0000-4000-8000-000000000001','pid_53000002-0000-4000-8000-000000000002','pid_53000000-0000-4000-8000-'||lpad(n::text,12,'0'),$2,'integration.webhook','owned snapshot source','rejected',$3::jsonb,'2026-09-12T13:14:15.000123Z'::timestamptz FROM generate_series(1,1005)n`, args[0], args[3], metadata); err != nil {
		t.Fatal("source fixtures", err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES('pid_54000001-0000-4000-8000-000000000001','pid_54000002-0000-4000-8000-000000000002','pid_54000003-0000-4000-8000-000000000003','pid_54000004-0000-4000-8000-000000000004',$1,'foreign.scope','excluded','succeeded','{}')`, args[3]); err != nil {
		t.Fatal(err)
	}
	// Expectations come from actual source columns and the independent Go
	// projection, never the SQL export encoder or seeded successful export rows.
	rows, err := f.admin.Query(ctx, `SELECT id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,metadata,occurred_at FROM zasp_admin_audit WHERE organization_id=$1 ORDER BY occurred_at DESC,id COLLATE "C" DESC`, args[0])
	if err != nil {
		t.Fatal(err)
	}
	expected := []json.RawMessage{}
	for rows.Next() {
		var event audit.ExportEvent
		var raw []byte
		var stamp time.Time
		if err := rows.Scan(&event.ID, &event.OrganizationID, &event.WorkspaceID, &event.EnvironmentID, &event.ActorID, &event.Action, &event.TargetID, &event.Outcome, &raw, &stamp); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var stored map[string]any
		if err := decoder.Decode(&stored); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		event.Metadata = map[string]string{}
		for key, value := range stored {
			switch v := value.(type) {
			case string:
				event.Metadata[key] = v
			case json.Number:
				event.Metadata[key] = v.String()
			case bool:
				event.Metadata[key] = strconv.FormatBool(v)
			default:
				rows.Close()
				t.Fatal("unsupported fixture source metadata")
			}
		}
		event.Ordinal = int64(len(expected) + 1)
		event.OccurredAt = stamp.UTC().Format("2006-01-02T15:04:05.000000Z")
		projected, err := audit.ProjectExportEvent(event)
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		canonical, err := audit.EncodeExportEvent(projected)
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if bytes.Contains(canonical, []byte("owned-secret-never-exported")) {
			rows.Close()
			t.Fatal("expected projection leaked secret")
		}
		expected = append(expected, canonical)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(expected) != 1006 {
		t.Fatal("full organization source count", len(expected))
	}
	fixturePath := filepath.Join(t.TempDir(), "expected-events.json")
	encoded, err := json.Marshal(expected)
	if err != nil || len(encoded) > 2<<20 {
		t.Fatal("bounded source expectations", err)
	}
	if err := os.WriteFile(fixturePath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return expected, fixturePath
}

type auditExportCapturedObject struct {
	Body    []byte `json:"body"`
	Version string `json:"version"`
}

func auditExportReadWorkerObjects(t *testing.T, path string) map[string]auditExportCapturedObject {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 2<<20 {
		t.Fatal("private provider capture unavailable", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > 2<<20 {
		t.Fatal("bounded provider capture", err, closeErr)
	}
	var objects map[string]auditExportCapturedObject
	if json.Unmarshal(raw, &objects) != nil || len(objects) != 3 {
		t.Fatal("incomplete actual provider capture")
	}
	return objects
}
