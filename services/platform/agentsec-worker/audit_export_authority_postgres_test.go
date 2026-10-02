package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Only the parent disposable PostgreSQL fixture supplies this DSN and committed
// job. This acceptance exercises the real Go JSON adapter and registered SQL;
// no capture, provider publication, export completion or queue ACK is claimed.
func TestAuditExportAuthorityPostgres(t *testing.T) {
	dsn, scope, exportID := auditExportAuthorityPostgresInputs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database := combinedE2ERecoveryDatabase(t, ctx, dsn)
	authority, err := newPostgresAuditExportAuthority(database, auditExportWorkerPolicyFixture())
	if err != nil {
		t.Fatal("registered compiled52 authority unavailable", err)
	}
	const worker = "audit-export-worker-postgres"
	token := strings.Repeat("a", 64)
	lease, err := authority.Claim(ctx, scope, exportID, worker, token, 120)
	if err != nil || lease == nil {
		t.Fatal("actual Go claim refused", err)
	}
	if lease.Generation != 1 || lease.Attempt != 1 || lease.Captured || lease.Binding.ExportID != exportID || lease.ExpiresAt.Location() != time.UTC {
		t.Fatal("actual claim lost initial durable identity")
	}
	replay, err := authority.Claim(ctx, scope, exportID, worker, token, 120)
	if err != nil || replay == nil || *replay != *lease {
		t.Fatal("exact claim replay changed lease", err)
	}
	renewed, err := authority.Heartbeat(ctx, *lease, 180)
	if err != nil || renewed.Binding != lease.Binding || renewed.Generation != lease.Generation || renewed.Attempt != lease.Attempt || !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatal("actual Go heartbeat refused or changed identity", err)
	}
	busy, err := authority.Claim(ctx, scope, exportID, worker, strings.Repeat("b", 64), 120)
	if err != nil || busy != nil {
		t.Fatal("busy claim incorrectly acquired lease", err)
	}
	if state, err := authority.Terminal(ctx, scope, exportID); err != nil || state != "nonterminal" {
		t.Fatal("busy null became terminal ACK authority", err)
	}
	stale := renewed
	stale.token = strings.Repeat("b", 64)
	if _, err := authority.Heartbeat(ctx, stale, 180); err == nil {
		t.Fatal("different canonical token renewed actual lease")
	}
	stale = renewed
	stale.Generation++
	if _, err := authority.Heartbeat(ctx, stale, 180); err == nil {
		t.Fatal("stale generation renewed actual lease")
	}
	t.Log("registered PostgreSQL Go export authority proven: compiled52 startup, canonical64 token claim/replay, heartbeat, busy null/nonterminal, wrong-token and stale-generation refusal; no capture/provider/finish/queue proof")
}

func auditExportAuthorityPostgresInputs(t *testing.T) (string, domain.Scope, string) {
	t.Helper()
	dsn := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned local audit export PostgreSQL fixture")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid fixture configuration")
	}
	local := func(host string) bool {
		ip := net.ParseIP(host)
		return host == "localhost" || ip != nil && ip.IsLoopback() || filepath.IsAbs(host)
	}
	if config.User != "audit_export_worker_fixture" || !local(config.Host) {
		t.Fatal("fixture must use registered local export worker")
	}
	for _, fallback := range config.Fallbacks {
		if !local(fallback.Host) {
			t.Fatal("nonlocal fixture fallback refused")
		}
	}
	scope, ok := recoveryScope(os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_ORG"), os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_WORKSPACE"), os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_ENVIRONMENT"))
	exportID := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_EXPORT")
	if !ok || !validRecoveryProductID(exportID) {
		t.Fatal("invalid fixture scope/job")
	}
	return dsn, scope, exportID
}

// Separate child invocations use a persisted snapshot created by this actual Go
// authority. Only read traversal advances in memory; no receipt or ready state
// is invented. The parent expires the first lease before the resume invocation.
func TestAuditExportAuthorityCapturePostgres(t *testing.T) {
	dsn, scope, exportID := auditExportAuthorityPostgresInputs(t)
	phase := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_PHASE")
	if phase != "capture" && phase != "resume" {
		t.Fatal("invalid fixture phase")
	}
	expected := auditExportAuthorityExpectedEvents(t)
	auditExportAuthorityCapturePostgres(t, dsn, scope, exportID, phase, expected)
}

func auditExportAuthorityExpectedEvents(t *testing.T) []json.RawMessage {
	t.Helper()
	path := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_EXPECTED")
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 2<<20 {
		t.Fatal("expected bytes must be private bounded fixture")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("expected fixture unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(body) > 2<<20 {
		t.Fatal("expected fixture read failed")
	}
	var expected []json.RawMessage
	if json.Unmarshal(body, &expected) != nil || len(expected) != 1006 {
		t.Fatal("invalid complete source expectation")
	}
	for i, raw := range expected {
		event, err := audit.DecodeExportEvent(raw)
		if err != nil || event.Ordinal != int64(i+1) {
			t.Fatal("noncanonical source expectation")
		}
	}
	return expected
}

func auditExportAuthorityCapturePostgres(t *testing.T, dsn string, scope domain.Scope, exportID, phase string, expected []json.RawMessage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database := combinedE2ERecoveryDatabase(t, ctx, dsn)
	authority, err := newPostgresAuditExportAuthorityContext(ctx, database, auditExportWorkerPolicyFixture())
	if err != nil {
		t.Fatal("registered compiled52 authority unavailable", err)
	}
	token := strings.Repeat("a", 64)
	generation := int64(1)
	attempt := 1
	if phase == "resume" {
		token = strings.Repeat("b", 64)
		generation = 2
		attempt = 2
	}
	lease, err := authority.Claim(ctx, scope, exportID, "audit-export-capture-postgres", token, 180)
	if err != nil || lease == nil {
		t.Fatal("actual capture claim refused", err)
	}
	if lease.Generation != generation || lease.Attempt != attempt || lease.Captured != (phase == "resume") {
		t.Fatal("capture/resume lease identity changed")
	}
	capture, err := authority.Capture(ctx, *lease)
	if err != nil || capture.FailureCode != "" || capture.Manifest.EventCount != 1006 || capture.Manifest.ChunkCount != 2 || capture.NextChunk != 1 || capture.NextEvent != 1 || capture.RecordedChunkCount != 0 || capture.RecordedChunkBytes != 0 || capture.PreviousDigest != audit.ExportZeroDigest {
		t.Fatal("Go capture rejected durable full snapshot", err)
	}
	lease.Captured = true
	renewed, err := authority.Heartbeat(ctx, *lease, 180)
	if err != nil || !renewed.Captured || renewed.Binding != lease.Binding {
		t.Fatal("captured heartbeat changed frozen binding", err)
	}
	*lease = renewed
	traversal := capture
	var first []byte
	for traversal.NextEvent <= int64(len(expected)) {
		page, err := authority.ReadFrozenPage(ctx, *lease, traversal)
		if err != nil {
			t.Fatal("actual registered Go frozen page refused", err)
		}
		if page.Chunk.Ordinal == 1 {
			first = append([]byte(nil), page.Body...)
		}
		if page.Chunk.EventCount < 1 || page.Chunk.EventCount > 1000 || len(page.Body) > audit.ExportMaximumChunkBytes {
			t.Fatal("frozen page exceeds byte/row bound")
		}
		for index, event := range page.Chunk.Events {
			raw, err := audit.EncodeExportEvent(event)
			if err != nil || !bytes.Equal(raw, expected[traversal.NextEvent-1+int64(index)]) {
				t.Fatal("frozen page changed source bytes or order")
			}
		}
		chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: lease.Binding, Ordinal: traversal.NextChunk, FirstEvent: traversal.NextEvent, EventCount: page.Chunk.EventCount, PreviousDigest: traversal.PreviousDigest, Events: page.Chunk.Events}
		canonical, err := audit.EncodeExportChunk(chunk)
		if err != nil || !bytes.Equal(canonical, page.Body) {
			t.Fatal("planned chunk bytes differ")
		}
		digest := sha256.Sum256(canonical)
		traversal.NextChunk++
		traversal.NextEvent += page.Chunk.EventCount
		traversal.RecordedChunkCount++
		traversal.RecordedChunkBytes += int64(len(canonical))
		traversal.PreviousDigest = hex.EncodeToString(digest[:])
		if traversal.NextEvent <= 1006 {
			if page.NextEvent == nil || *page.NextEvent != traversal.NextEvent {
				t.Fatal("frozen page skipped next source")
			}
		} else if page.NextEvent != nil {
			t.Fatal("trailing source invented")
		}
	}
	if traversal.RecordedChunkCount != capture.Manifest.ChunkCount || traversal.RecordedChunkBytes != capture.Manifest.ChunkBytes || traversal.PreviousDigest != capture.Manifest.ChainRoot {
		t.Fatal("complete read chain differs from frozen manifest")
	}
	replay, err := authority.Capture(ctx, *lease)
	if err != nil || replay != capture {
		t.Fatal("read traversal changed durable receipt prefix", err)
	}
	page, err := authority.ReadFrozenPage(ctx, *lease, replay)
	if err != nil || !bytes.Equal(page.Body, first) {
		t.Fatal("same capture replay changed first page", err)
	}
	if state, err := authority.Terminal(ctx, scope, exportID); err != nil || state != "nonterminal" {
		t.Fatal("read-only capture became terminal ACK authority", err)
	}
	t.Logf("registered PostgreSQL Go capture/page proven: phase=%s events=%d chunks=%d bytes=%d root=%s; no intents/provider/receipts/finish/queue ACK", phase, capture.Manifest.EventCount, capture.Manifest.ChunkCount, capture.Manifest.ChunkBytes, capture.Manifest.ChainRoot)
}
