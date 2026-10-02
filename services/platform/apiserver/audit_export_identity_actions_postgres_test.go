//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

// These labels must come from the released reserve/complete protocol. Owner
// setup supplies membership only, never the successful action/audit rows.
func auditExportProduceIdentityActions(t *testing.T, ctx context.Context, f auditExportPG) []string {
	t.Helper()
	args := f.createArgs()
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_identity_memberships SET organization_reference='organization-audit-actions' WHERE organization_id=$1 AND principal_id=$2`, args[0], args[3]); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ operation, intent, result string }{
		{"createSSOConnection", `{"display_name":"Retained SSO","identity_provider":"okta","protocol":"saml"}`, `{"reference":"saml-connection-audit-actions","kind":"sso","protocol":"saml","status":"pending","display_name":"Retained SSO","identity_provider":"okta","base_url":null}`},
		{"testSSOConnection", `{"reference":"saml-connection-audit-actions"}`, `{"reference":"saml-connection-audit-actions","kind":"sso","protocol":"saml","status":"active","display_name":"Retained SSO","identity_provider":"okta","base_url":null}`},
		{"deleteSSOConnection", `{"reference":"saml-connection-audit-actions"}`, `{"reference":"saml-connection-audit-actions","kind":"sso","deleted":true}`},
		{"createSCIMConnection", `{"display_name":"Retained SCIM","identity_provider":"okta"}`, `{"reference":"scim-connection-audit-actions","kind":"scim","protocol":null,"status":"active","display_name":"Retained SCIM","identity_provider":"okta","base_url":"https://scim.invalid/v2"}`},
		{"deleteSCIMConnection", `{"reference":"scim-connection-audit-actions"}`, `{"reference":"scim-connection-audit-actions","kind":"scim","deleted":true}`},
	}
	var ids []string
	for i, c := range cases {
		id := func(n int) string { return fmt.Sprintf("pid_7910%04x-0000-4000-8000-000000000001", i*10+n) }
		intent := sha256.Sum256([]byte(c.intent))
		token := sha256.Sum256([]byte(c.operation))
		key := "retained-identity-action-" + c.operation
		var raw []byte
		if err := f.api.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,60)`, args[0], args[3], c.operation, key, id(1), intent[:], c.intent, id(2), id(3), id(4), token[:]).Scan(&raw); err != nil || !jsonContainsString(raw, "provider_organization_reference", "organization-audit-actions") {
			t.Fatal("released identity reserve", c.operation, err)
		}
		values := []any{args[0], args[3], c.operation, key, id(1), token[:], c.result, nil, nil, nil, nil, nil}
		if c.operation == "createSCIMConnection" {
			values[7], values[8], values[9], values[10], values[11] = id(5), []byte("owned-encrypted-secret"), bytes.Repeat([]byte{1}, 12), bytes.Repeat([]byte{2}, 16), time.Now().Add(5*time.Minute)
		}
		if err := f.api.QueryRow(ctx, `SELECT zasp_identity_admin_complete_mutation($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)`, values...).Scan(&raw); err != nil || !jsonContainsString(raw, "audit_id", id(2)) {
			t.Fatal("released identity complete", c.operation, err)
		}
		var action string
		if err := f.admin.QueryRow(ctx, `SELECT action FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2`, args[0], id(2)).Scan(&action); err != nil || action != "identity_provider."+c.operation {
			t.Fatal("published producer changed action", c.operation, err)
		}
		ids = append(ids, id(2))
	}
	return ids
}

func TestAuditExportIdentityActionsPostgresSQLPreservesReleasedProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, ids := auditExportRetainedIdentityFixture(t, ctx)
	expected := auditExportIdentitySource(t, ctx, f)
	if len(expected) != 5 {
		t.Fatal("five real source records required")
	}
	for ordinal, raw := range expected {
		event, err := audit.DecodeExportEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		var body []byte
		if err := f.admin.QueryRow(ctx, `SELECT zasp_audit_export_event_bytes($1,a) FROM zasp_admin_audit a WHERE id=$2`, ordinal+1, event.ID).Scan(&body); err != nil || !bytes.Equal(body, raw) {
			t.Errorf("released identity event refused or changed by SQL export encoder: %s: %v", event.ID, err)
		}
	}
	for _, action := range []string{"Identity_provider.createSSOConnection", "identity_provider.CreateSSOConnection", "identity_provider.createSsoConnection", "identity_provider.createSSOConnectionX", "identity_provider.unknownOperation", "identity_provider.createSSOConnection.", "identity_provider.createSSOConnection ", "identity_provider.createSSOConnection\n", "identity_provider.créateSSOConnection", "identity_provider..createSSOConnection", strings.Repeat("a", 128)} {
		var body []byte
		err := f.admin.QueryRow(ctx, `SELECT zasp_audit_export_event_bytes(1,jsonb_populate_record(NULL::zasp_admin_audit,to_jsonb(a)||jsonb_build_object('action',$2::text))) FROM zasp_admin_audit a WHERE id=$1`, ids[0], action).Scan(&body)
		if auditExportSQLState(err) != "22023" {
			t.Fatal("SQL accepted near-miss action", action, err)
		}
	}
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	_, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	expected = auditExportIdentitySource(t, ctx, f)
	var first, replay []byte
	capture := `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	if err := worker.QueryRow(ctx, capture, common...).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, capture, common...).Scan(&replay); err != nil || !bytes.Equal(first, replay) {
		t.Fatal("repeated capture changed progress", err)
	}
	var page struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append(common, 1)...).Scan(&replay); err != nil || json.Unmarshal(replay, &page) != nil || len(page.Events) != 6 {
		t.Fatal("replayed page", err)
	}
	for i, raw := range page.Events {
		event, err := audit.DecodeExportEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := audit.EncodeExportEvent(event)
		if err != nil || !bytes.Equal(canonical, expected[i]) {
			t.Fatal("replayed frozen action bytes changed", err)
		}
	}
}

func TestAuditExportIdentityActionsPostgresInvalidSourceIsAtomic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, _ := auditExportRetainedIdentityFixture(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, common := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	// Disposable invalid-source control, not a published producer or rewritten
	// retained row. The valid five records remain untouched alongside it.
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,'pid_79980001-0000-4000-8000-000000000001',$4,'identity_provider.createSsoConnection','invalid-source-fixture','succeeded','{}')`, request[:4]...); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, common...).Scan(&raw); err != nil || !jsonContainsString(raw, "failure_code", "invalid_source") {
		t.Fatal("near-miss did not fail capture", err)
	}
	var exact bool
	if err := f.admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_audit_export_events) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_chunks) AND NOT EXISTS(SELECT 1 FROM zasp_audit_export_intents) AND (SELECT status='failed' AND NOT captured AND reserved_bytes=0 AND completion_audit_id IS NOT NULL FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2) AND (SELECT count(*)=1 FROM zasp_admin_audit WHERE action='audit_export.complete')`, request[0], request[7]).Scan(&exact); err != nil || !exact {
		t.Fatal("invalid action left partial export", err)
	}
}

func auditExportRetainedIdentityFixture(t *testing.T, ctx context.Context) (auditExportPG, []string) {
	t.Helper()
	f := auditExportPGFixture(t, ctx)
	runner := precisionMigrationRunner(t, f.admin)
	if err := runner.DownProductionAuditExports(ctx); err != nil {
		t.Fatal("configuration-only52 Down", err)
	}
	ids := auditExportProduceIdentityActions(t, ctx, f)
	var before, after string
	snapshot := `SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM zasp_admin_audit a WHERE id=ANY($1)`
	if err := f.admin.QueryRow(ctx, snapshot, ids).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// Records were produced under51 by the unchanged published19 functions.
	installAuditExports(t, ctx, f.admin)
	auditExportConfigureSQL(t, ctx, f.admin, auditExportTestPolicy())
	f.register(t, ctx)
	if err := f.admin.QueryRow(ctx, snapshot, ids).Scan(&after); err != nil || before != after {
		t.Fatal("52 installation changed retained identity source", err)
	}
	return f, ids
}

func TestAuditExportIdentityActionsPostgresSDKPublicRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	launcher := newAuditExportProcessLauncher(t, ctx)
	f, ids := auditExportRetainedIdentityFixture(t, ctx)
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	args := f.createArgs()
	// The only owner-inserted audit row is a foreign-organization exclusion
	// control. No successful identity action, capture or receipt is seeded.
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES('pid_79990001-0000-4000-8000-000000000001','pid_79990002-0000-4000-8000-000000000001','pid_79990003-0000-4000-8000-000000000001','pid_79990004-0000-4000-8000-000000000001',$1,'workspace.update','foreign-sentinel','succeeded','{}')`, args[3]); err != nil {
		t.Fatal(err)
	}
	var created []byte
	if err := f.api.QueryRow(ctx, postgresAuditExportCreateSQL, args...).Scan(&created); err != nil {
		t.Fatal(err)
	}
	events := auditExportIdentitySource(t, ctx, f)
	if len(events) != 6 {
		t.Fatal("five retained producers and one real request required", len(events))
	}
	seen := map[string]bool{}
	for _, raw := range events {
		event, err := audit.DecodeExportEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		seen[event.ID] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatal("missing actual identity source", id)
		}
	}
	if seen["pid_79990004-0000-4000-8000-000000000001"] {
		t.Fatal("foreign source leaked")
	}
	sourceSnapshot := func() string {
		t.Helper()
		var value string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM zasp_admin_audit a WHERE id=ANY($1)`, ids).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	beforeSource := sourceSnapshot()
	provider := newAuditExportProcessProvider(t, ctx, f, worker, args, events)
	ca, token := filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(auditExportProcessToken), 0600); err != nil {
		t.Fatal(err)
	}
	launcher.run(t, ctx, f, provider, "audit-export-outbox", ca, token)
	launcher.run(t, ctx, f, provider, "audit-export", ca, token)
	auditExportAssertProcessCompletion(t, ctx, f, args, events, provider, 1)
	var frozen []byte
	rows, err := f.admin.Query(ctx, `SELECT canonical_event FROM zasp_audit_export_events WHERE organization_id=$1 AND export_id=$2 ORDER BY ordinal`, args[0], args[7])
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		if err := rows.Scan(&frozen); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if count >= len(events) || !bytes.Equal(frozen, events[count]) {
			rows.Close()
			t.Fatal("frozen bytes differ from actual source")
		}
		count++
	}
	rows.Close()
	if rows.Err() != nil || count != len(events) {
		t.Fatal("frozen source incomplete", rows.Err())
	}
	before := auditExportProcessSQLSnapshot(t, ctx, f, args)
	provider.redeliver(t)
	launcher.run(t, ctx, f, provider, "audit-export", ca, token)
	auditExportAssertProcessCompletion(t, ctx, f, args, events, provider, 2)
	if auditExportProcessSQLSnapshot(t, ctx, f, args) != before || sourceSnapshot() != beforeSource {
		t.Fatal("duplicate rewrote retained source or authority")
	}
	// Approved explicit provider-fixture handoff: only actual saved bytes and
	// versions move after real Finish. Expected bytes still come from source.
	objects := map[string]auditExportCapturedObject{}
	provider.mu.Lock()
	for reference, object := range provider.objects {
		objects[reference] = auditExportCapturedObject{Body: bytes.Clone(object.Body), Version: object.Version}
	}
	provider.mu.Unlock()
	reader := newAuditExportHTTPReaderFixture(t, ctx, f.identity.Scope)
	reader.load(objects)
	server := auditExportHTTPRealServer(t, ctx, f, reader, time.Second)
	invoke := func(cookie string, want int) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/audit-exports/"+args[7].(string), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(expectedScopeHeader, expectedScopeValue(f.identity.Scope))
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: cookie})
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, audit.ExportMaximumChunkBytes+16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("authenticated public response", response.StatusCode, want, readErr, closeErr)
		}
		return raw
	}
	raw := invoke("owned-audit-export-browser-fixture", http.StatusOK)
	var page struct {
		Export   json.RawMessage `json:"export"`
		Contents struct {
			Manifest    json.RawMessage `json:"manifest"`
			Chunk       json.RawMessage `json:"chunk"`
			ChunkSHA256 string          `json:"chunk_sha256"`
			PageInfo    struct {
				More bool    `json:"has_more"`
				Next *string `json:"next_cursor"`
			} `json:"page_info"`
		} `json:"contents"`
	}
	if json.Unmarshal(raw, &page) != nil {
		t.Fatal("public envelope")
	}
	descriptor, err := audit.DecodeExportDescriptor(page.Export)
	if err != nil || descriptor.Status != "ready" || descriptor.EventCount == nil || *descriptor.EventCount != 6 {
		t.Fatal("public descriptor", err)
	}
	var capture string
	if err := f.admin.QueryRow(ctx, `SELECT capture_id FROM zasp_audit_export_jobs WHERE organization_id=$1 AND id=$2`, args[0], args[7]).Scan(&capture); err != nil {
		t.Fatal(err)
	}
	expected, err := auditExportProcessExpected(audit.ExportBinding{OrganizationID: args[0].(string), WorkspaceID: args[1].(string), EnvironmentID: args[2].(string), ExportID: args[7].(string), CaptureID: capture}, events)
	if err != nil || !bytes.Equal(expected["chunk:1"], page.Contents.Chunk) || !bytes.Equal(expected["manifest:0"], page.Contents.Manifest) || page.Contents.PageInfo.More || page.Contents.PageInfo.Next != nil {
		t.Fatal("public canonical bytes or terminal page changed", err)
	}
	chunkSum, manifestSum := sha256.Sum256(expected["chunk:1"]), sha256.Sum256(expected["manifest:0"])
	if page.Contents.ChunkSHA256 != hex.EncodeToString(chunkSum[:]) || descriptor.ManifestSHA256 != hex.EncodeToString(manifestSum[:]) {
		t.Fatal("public action chain digest changed")
	}
	if !bytes.Equal(raw, invoke("owned-audit-export-browser-fixture", http.StatusOK)) {
		t.Fatal("public immutable replay changed")
	}
	reads := reader.calls()
	invoke("foreign-unrecognized-cookie", http.StatusUnauthorized)
	if reader.calls() != reads {
		t.Fatal("unauthorized request reached storage")
	}
	if reader.calls() != 8 || auditExportProcessSQLSnapshot(t, ctx, f, args) != before || sourceSnapshot() != beforeSource {
		t.Fatal("public reads changed source/evidence or skipped pinned SDK reads")
	}
	if err := precisionMigrationRunner(t, f.admin).DownProductionAuditExports(ctx); err == nil {
		t.Fatal("retained export Down accepted")
	}
	t.Log("five real published identity operations retained across51-to52, six exact captured events, real publisher/executor SDK and immutable receipts before ACK; authenticated public SDK read uses explicit post-Finish provider-fixture handoff, not continuous-provider or live identity-provider evidence")
}

// Project the actual legacy list source, including jsonb_each_text's existing
// numeric conversion, independently of the SQL export byte encoder.
func auditExportIdentitySource(t *testing.T, ctx context.Context, f auditExportPG) []json.RawMessage {
	t.Helper()
	rows, err := f.admin.Query(ctx, `SELECT id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,COALESCE((SELECT jsonb_object_agg(key,value) FROM jsonb_each_text(a.metadata)),'{}'),to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') FROM zasp_admin_audit a WHERE organization_id=$1 AND action<>'audit_export.complete' ORDER BY occurred_at DESC,id COLLATE "C" DESC`, f.identity.Scope.OrganizationID().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []json.RawMessage
	for rows.Next() {
		var event audit.ExportEvent
		var metadata []byte
		if err := rows.Scan(&event.ID, &event.OrganizationID, &event.WorkspaceID, &event.EnvironmentID, &event.ActorID, &event.Action, &event.TargetID, &event.Outcome, &metadata, &event.OccurredAt); err != nil {
			t.Fatal(err)
		}
		event.Ordinal = int64(len(result) + 1)
		if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
			t.Fatal(err)
		}
		projected, err := audit.ProjectExportEvent(event)
		if err != nil {
			t.Fatal("actual persisted source projection", err)
		}
		body, err := audit.EncodeExportEvent(projected)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, body)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	return result
}
