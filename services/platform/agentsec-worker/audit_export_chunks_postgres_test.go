package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

// Versions below are explicitly supplied SQL boundary fixtures. This test does
// not call S3 or claim that a persisted version proves an object exists.
func TestAuditExportAuthorityChunksPostgres(t *testing.T) {
	dsn, scope, exportID := auditExportAuthorityPostgresInputs(t)
	phase := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_PHASE")
	if phase != "record" && phase != "record-resume" {
		t.Fatal("invalid chunk fixture phase")
	}
	expected := auditExportAuthorityExpectedEvents(t)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	database := combinedE2ERecoveryDatabase(t, ctx, dsn)
	authority, err := newPostgresAuditExportAuthorityContext(ctx, database, auditExportWorkerPolicyFixture())
	if err != nil {
		t.Fatal("registered authority unavailable", err)
	}
	generation, attempt, token := int64(1), 1, strings.Repeat("a", 64)
	if phase == "record-resume" {
		generation, attempt, token = 2, 2, strings.Repeat("b", 64)
	}
	lease, err := authority.Claim(ctx, scope, exportID, "audit-export-chunks-postgres", token, 180)
	if err != nil || lease == nil || lease.Generation != generation || lease.Attempt != attempt || lease.Captured != (phase == "record-resume") {
		t.Fatal("chunk claim identity refused", err)
	}
	capture, err := authority.Capture(ctx, *lease)
	if err != nil || capture.FailureCode != "" || capture.Manifest.EventCount != 1006 || capture.Manifest.ChunkCount != 2 {
		t.Fatal("chunk capture refused", err)
	}
	lease.Captured = true
	if phase == "record" && (capture.NextChunk != 1 || capture.RecordedChunkCount != 0) {
		t.Fatal("new capture already has receipts")
	}
	if phase == "record-resume" && (capture.NextChunk != 2 || capture.NextEvent != 1001 || capture.RecordedChunkCount != 1) {
		t.Fatal("recreated process lost committed first chunk")
	}
	// Reconstruct all chunks from the independent raw-source expectations. On
	// resume this permits exact old receipt replay without changing the cursor.
	progress := capture
	progress.NextChunk, progress.NextEvent, progress.RecordedChunkCount, progress.RecordedChunkBytes, progress.PreviousDigest = 1, 1, 0, 0, audit.ExportZeroDigest
	for ordinal := int64(1); ordinal <= 2; ordinal++ {
		page, err := authority.ReadFrozenPage(ctx, *lease, progress)
		if err != nil {
			t.Fatal("real frozen page refused", err)
		}
		for i, event := range page.Chunk.Events {
			encoded, err := audit.EncodeExportEvent(event)
			if err != nil || !bytes.Equal(encoded, expected[progress.NextEvent-1+int64(i)]) {
				t.Fatal("chunk changed frozen source")
			}
		}
		intent, err := authority.PrepareChunk(ctx, *lease, page.Body)
		if err != nil {
			t.Fatal("actual Go PrepareChunk refused", err)
		}
		digest := sha256.Sum256(page.Body)
		if intent.Binding != lease.Binding || intent.Kind != "chunk" || intent.Ordinal != ordinal || intent.FirstEvent != progress.NextEvent || intent.EventCount != page.Chunk.EventCount || intent.PreviousDigest != progress.PreviousDigest || intent.SizeBytes != int64(len(page.Body)) || intent.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("intent lost exact canonical pins")
		}
		replay, err := authority.PrepareChunk(ctx, *lease, page.Body)
		if err != nil || replay != intent {
			t.Fatal("exact prepared intent replay changed", err)
		}
		receipt := auditExportArtifactReceipt{VersionID: fmt.Sprintf("owned-sql-only-chunk-version-%d", ordinal), SHA256: digest, SizeBytes: int64(len(page.Body))}
		for _, kind := range []string{"worker", "token", "generation", "attempt", "organization"} {
			bad := *lease
			badBody, badIntent := page.Body, intent
			switch kind {
			case "worker":
				bad.worker = "foreign-worker"
			case "token":
				bad.token = strings.Repeat("c", 64)
			case "generation":
				bad.Generation++
			case "attempt":
				bad.Attempt++
			case "organization":
				bad.Binding.OrganizationID = "pid_54000001-0000-4000-8000-000000000001"
				chunk := page.Chunk
				chunk.Binding = bad.Binding
				// A valid foreign-scope envelope reaches registered SQL; rejection
				// must not rely only on a mismatched Go body/binding pair.
				chunk.Events = append([]audit.ExportEvent(nil), chunk.Events...)
				for i := range chunk.Events {
					chunk.Events[i].OrganizationID = bad.Binding.OrganizationID
				}
				badBody, err = audit.EncodeExportChunk(chunk)
				if err != nil {
					t.Fatal("valid foreign organization envelope", err)
				}
				badIntent.Binding = bad.Binding
				badIntent.ObjectReference = strings.Replace(intent.ObjectReference, lease.Binding.OrganizationID, bad.Binding.OrganizationID, 1)
			}
			if _, err := authority.PrepareChunk(ctx, bad, badBody); err == nil {
				t.Fatal("changed lease prepared chunk", kind)
			}
			if err := authority.RecordChunk(ctx, bad, badIntent, receipt); err == nil {
				t.Fatal("changed lease recorded chunk", kind)
			}
		}
		if phase == "record-resume" {
			stale := *lease
			stale.Generation, stale.Attempt, stale.token = 1, 1, strings.Repeat("a", 64)
			if _, err := authority.PrepareChunk(ctx, stale, page.Body); err == nil {
				t.Fatal("old process prepared chunk")
			}
			if err := authority.RecordChunk(ctx, stale, intent, receipt); err == nil {
				t.Fatal("old process recorded chunk")
			}
		}
		if err := authority.RecordChunk(ctx, *lease, intent, receipt); err != nil {
			t.Fatal("actual Go RecordChunk refused", err)
		}
		if err := authority.RecordChunk(ctx, *lease, intent, receipt); err != nil {
			t.Fatal("exact recorded receipt replay refused", err)
		}
		progress.NextChunk++
		progress.NextEvent += page.Chunk.EventCount
		progress.RecordedChunkCount++
		progress.RecordedChunkBytes += intent.SizeBytes
		progress.PreviousDigest = intent.SHA256
		persisted, err := authority.Capture(ctx, *lease)
		if err != nil || persisted != progress {
			t.Fatal("receipt did not advance exact durable prefix", err)
		}
		changed := receipt
		changed.VersionID = "different-sql-version"
		if err := authority.RecordChunk(ctx, *lease, intent, changed); err == nil {
			t.Fatal("changed immutable version accepted")
		}
		if phase == "record" {
			break
		}
	}
	if phase == "record-resume" && (progress.NextChunk != 3 || progress.NextEvent != 1007 || progress.RecordedChunkBytes != progress.Manifest.ChunkBytes || progress.PreviousDigest != progress.Manifest.ChainRoot) {
		t.Fatal("resume did not complete exact frozen chunk prefix")
	}
	if state, err := authority.Terminal(ctx, scope, exportID); err != nil || state != "nonterminal" {
		t.Fatal("chunk receipts invented completion authority", err)
	}
	t.Logf("registered PostgreSQL Go chunk receipt proven: phase=%s committed=%d events=%d; supplied SQL versions only, no S3/manifest/Finish/outbox proof", phase, progress.RecordedChunkCount, progress.Manifest.EventCount)
}
