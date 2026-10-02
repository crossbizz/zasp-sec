package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"strings"
	"testing"
	"time"
)

type complianceDatabaseFixture struct {
	body  json.RawMessage
	query string
	args  []any
}

func (f *complianceDatabaseFixture) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	f.query = q
	f.args = args
	return f.body, nil
}

// A restart must load persisted bytes, never regenerate them with a new renderer.
func TestComplianceWorkerPersistedBytes(t *testing.T) {
	o, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	s, _ := domain.NewScope(o, w, e)
	id := "pid_10000004-0000-4000-8000-000000000004"
	body := []byte("previous-renderer-exact-byte-package")
	hash := sha256.Sum256(body)
	raw, _ := json.Marshal(map[string]any{"bytes_hex": hex.EncodeToString(body), "renderer_revision": "compliance-envelope-v1", "reference": id, "size": len(body), "sha256": hex.EncodeToString(hash[:]), "format_sizes": map[string]int{"json": 10, "csv": 10, "readable": 10}})
	db := &complianceDatabaseFixture{body: raw}
	a := newPostgresComplianceExportAuthority(db)
	lease := complianceExportLease{Scope: s, ExportID: id, WorkerID: "worker-1", Token: strings.Repeat("a", 64), Generation: 4, ExpiresAt: time.Now().Add(time.Minute), Lane: "execute"}
	got, err := a.LoadPrepared(context.Background(), lease)
	if err != nil || string(got.Bytes) != string(body) || got.RendererRevision != "compliance-envelope-v1" {
		t.Fatalf("persisted bytes: %+v %v", got, err)
	}
	if _, err := domain.ParseEvidenceRef(got.Reference); err != nil {
		t.Fatalf("persisted reference cannot reach export store: %v", err)
	}
	if len(db.args) != 10 || db.args[0] != o.String() || db.args[3] != id || db.args[6] != int64(4) || string(db.args[7].(json.RawMessage)) != "{}" {
		t.Fatalf("resume lost lease or rerendered: %#v", db.args)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	fields["sha256"] = strings.Repeat("0", 64)
	db.body, _ = json.Marshal(fields)
	if _, err := a.LoadPrepared(context.Background(), lease); err == nil {
		t.Fatal("changed persisted bytes accepted")
	}
	lease.Lane = "cleanup"
	db.body = json.RawMessage(`{}`)
	if err := a.ConfirmDeleted(context.Background(), lease, "", ""); err != nil {
		t.Fatal(err)
	}
	var deletion map[string]any
	_ = json.Unmarshal(db.args[7].(json.RawMessage), &deletion)
	if deletion["reference"] != nil || deletion["version"] != nil {
		t.Fatalf("unprepared cleanup lost SQL absence semantics: %v", deletion)
	}
}

func TestComplianceWorkerCleanupReceipt(t *testing.T) {
	o, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	scope, _ := domain.NewScope(o, w, e)
	id := "pid_10000004-0000-4000-8000-000000000004"
	raw, _ := json.Marshal(map[string]any{"organization_id": o.String(), "workspace_id": w.String(), "environment_id": e.String(), "export_id": id, "generation": 2, "attempt": 1, "lease_expires_at": time.Now().Add(time.Minute), "lane": "cleanup", "captured": true, "prepared": true, "reference": id, "version": "immutable-version-1", "size": 30, "sha256": strings.Repeat("a", 64)})
	db := &complianceDatabaseFixture{body: raw}
	a := newPostgresComplianceExportAuthority(db)
	lease, err := a.Claim(context.Background(), scope, id, "worker-1", strings.Repeat("a", 64), "cleanup")
	if err != nil || lease == nil || lease.Reference != id || lease.VersionID != "immutable-version-1" || lease.Size != 30 || lease.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("cleanup cannot address exact version: %+v %v", lease, err)
	}
}

func TestComplianceWorkerHeartbeat(t *testing.T) {
	old := complianceExportLease{Generation: 4, Attempt: 2, ExpiresAt: time.Now().Add(time.Second)}
	o, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	old.Scope, _ = domain.NewScope(o, w, e)
	old.ExportID = "pid_10000004-0000-4000-8000-000000000004"
	old.WorkerID = "worker-1"
	old.Token = strings.Repeat("a", 64)
	old.Lane = "execute"
	db := &complianceDatabaseFixture{}
	a := newPostgresComplianceExportAuthority(db)
	// An interface assertion makes absence a behavioral RED, not a compile failure.
	h, ok := any(a).(interface {
		Heartbeat(context.Context, complianceExportLease) (complianceExportLease, error)
	})
	if !ok {
		t.Fatal("worker has no heartbeat returning a renewed lease")
	}
	expiry := time.Now().Add(time.Minute)
	db.body, _ = json.Marshal(map[string]any{"renewed": true, "generation": 4, "attempt": 2, "lease_expires_at": expiry})
	renewed, err := h.Heartbeat(context.Background(), old)
	if err != nil || !renewed.ExpiresAt.Equal(expiry) || renewed.Generation != old.Generation || renewed.Attempt != old.Attempt || renewed.Token != old.Token {
		t.Fatalf("renewal lost lease identity: %+v %v", renewed, err)
	}
	for _, bad := range []string{`{"renewed":true}`, `{"renewed":false,"generation":4,"attempt":2,"lease_expires_at":"2099-01-01T00:00:00Z"}`} {
		db.body = json.RawMessage(bad)
		if _, err := h.Heartbeat(context.Background(), old); err == nil {
			t.Fatalf("invalid renewal accepted: %s", bad)
		}
	}
	if err := a.Retry(context.Background(), old, "heartbeat"); err == nil {
		t.Fatal("Retry silently discards renewed expiry")
	}
}
