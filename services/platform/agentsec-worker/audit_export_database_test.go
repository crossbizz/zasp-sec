package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAuditExportWorkerCanonicalTokenExtremesReachExactSQL(t *testing.T) {
	for _, token := range []string{strings.Repeat("0", 63) + "1", strings.Repeat("f", 64)} {
		a, db, scope, wire := auditExportWorkerLeaseFixture(t)
		lease, err := a.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", token, 180)
		if err != nil || lease == nil {
			t.Fatal("canonical nonzero token refused", err)
		}
		if db.queries[len(db.queries)-1].Args[5] != token {
			t.Fatal("SQL token text was decoded or rewritten")
		}
		if _, err := a.Heartbeat(context.Background(), *lease, 180); err != nil {
			t.Fatal(err)
		}
		if db.queries[len(db.queries)-1].Args[8] != token {
			t.Fatal("renewal token text changed")
		}
	}
}

func TestAuditExportWorkerRejectsNonSQLLeaseTokensBeforeClaimOrHeartbeat(t *testing.T) {
	for name, token := range auditExportRejectedLeaseTokens() {
		t.Run(name, func(t *testing.T) {
			a, db, scope, wire := auditExportWorkerLeaseFixture(t)
			lease, err := a.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
			if err != nil {
				t.Fatal(err)
			}
			db.queries = nil
			if _, err := a.Claim(context.Background(), scope, lease.Binding.ExportID, "audit-export-worker", token, 180); err == nil || len(db.queries) != 0 {
				t.Fatal("non-SQL token reached claim")
			}
			lease.token = token
			if _, err := a.Heartbeat(context.Background(), *lease, 180); err == nil || len(db.queries) != 0 {
				t.Fatal("non-SQL token reached heartbeat")
			}
		})
	}
}

func auditExportFrozenFixture(t *testing.T) (*postgresAuditExportAuthority, *auditExportWorkerDatabase, auditExportLease, map[string]any, map[string]any, []byte) {
	t.Helper()
	authority, db, scope, wire := auditExportWorkerLeaseFixture(t)
	lease, err := authority.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
	if err != nil {
		t.Fatal(err)
	}
	event := audit.ExportEvent{Ordinal: 1, ID: "pid_52000009-0000-4000-8000-000000000009", OrganizationID: lease.Binding.OrganizationID, WorkspaceID: lease.Binding.WorkspaceID, EnvironmentID: lease.Binding.EnvironmentID, ActorID: "pid_52000010-0000-4000-8000-000000000010", Action: "audit.export", TargetID: lease.Binding.ExportID, Outcome: "succeeded", Metadata: map[string]string{"name": "<>& \"\\\u2028 café"}, OccurredAt: "2026-09-12T01:02:03.456789Z"}
	chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: lease.Binding, Ordinal: 1, FirstEvent: 1, EventCount: 1, PreviousDigest: audit.ExportZeroDigest, Events: []audit.ExportEvent{event}}
	body, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	progress := map[string]any{"state": "processing", "captured": true, "binding": lease.Binding, "storage_policy": lease.Policy, "event_count": int64(1), "chunk_count": int64(1), "chunk_bytes": int64(len(body)), "chain_root": hex.EncodeToString(digest[:]), "next_chunk": int64(1), "next_event": int64(1), "recorded_chunk_count": int64(0), "recorded_chunk_bytes": int64(0), "previous_digest": audit.ExportZeroDigest}
	page := map[string]any{"binding": lease.Binding, "ordinal": int64(1), "first_event": int64(1), "event_count": int64(1), "previous_digest": audit.ExportZeroDigest, "events": chunk.Events, "next_event": nil}
	db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		if sql == auditExportWorkerCaptureSQL {
			return json.Marshal(progress)
		}
		if sql == auditExportWorkerFrozenPageSQL {
			return json.Marshal(page)
		}
		t.Fatal("unexpected SQL during frozen reads", sql)
		return nil, errors.New("unexpected query")
	}
	return authority, db, *lease, progress, page, body
}

func TestAuditExportWorkerCaptureAndFrozenPagePreserveCanonicalPlan(t *testing.T) {
	authority, db, lease, wire, _, body := auditExportFrozenFixture(t)
	base := db.respond
	db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(lease.ExpiresAt.Add(-5*time.Second)) || time.Until(deadline) > 120*time.Second {
			t.Fatal("operation lacked confirmed capture bound")
		}
		return base(ctx, sql, args...)
	}
	progress, err := authority.Capture(context.Background(), lease)
	if err != nil || progress.FailureCode != "" || progress.Manifest.Binding != lease.Binding || progress.Manifest.ChainRoot != wire["chain_root"] || progress.NextEvent != 1 || progress.NextChunk != 1 {
		t.Fatal("valid frozen capture refused", err)
	}
	last := db.queries[len(db.queries)-1]
	if last.SQL != auditExportWorkerCaptureSQL || !reflect.DeepEqual(last.Args, authority.leaseArguments(lease)) {
		t.Fatal("capture lost common13 identity")
	}
	page, err := authority.ReadFrozenPage(context.Background(), lease, progress)
	if err != nil || !bytes.Equal(page.Body, body) || page.NextEvent != nil || len(page.Chunk.Events) != 1 {
		t.Fatal("canonical planned page changed/refused", err)
	}
	last = db.queries[len(db.queries)-1]
	if last.SQL != auditExportWorkerFrozenPageSQL || !reflect.DeepEqual(last.Args, append(authority.leaseArguments(lease), int64(1))) {
		t.Fatal("page lost common13+firstevent")
	}
}

func TestAuditExportWorkerCaptureAcceptsEmptyCompletedAndStableFailure(t *testing.T) {
	for _, kind := range []string{"empty", "completed", "capacity_exceeded", "invalid_source"} {
		t.Run(kind, func(t *testing.T) {
			authority, _, lease, wire, _, _ := auditExportFrozenFixture(t)
			switch kind {
			case "empty":
				wire["event_count"] = int64(0)
				wire["chunk_count"] = int64(0)
				wire["chunk_bytes"] = int64(0)
				wire["chain_root"] = audit.ExportZeroDigest
			case "completed":
				wire["next_chunk"] = int64(2)
				wire["next_event"] = int64(2)
				wire["recorded_chunk_count"] = int64(1)
				wire["recorded_chunk_bytes"] = wire["chunk_bytes"]
				wire["previous_digest"] = wire["chain_root"]
			default:
				for k := range wire {
					delete(wire, k)
				}
				wire["state"] = "failed"
				wire["failure_code"] = kind
			}
			got, err := authority.Capture(context.Background(), lease)
			if err != nil {
				t.Fatal("valid capture result refused", err)
			}
			if kind == "capacity_exceeded" || kind == "invalid_source" {
				if got.FailureCode != kind {
					t.Fatal("durable failure lost")
				}
			} else if got.FailureCode != "" {
				t.Fatal("success changed to failure")
			}
		})
	}
}

func TestAuditExportWorkerCaptureRejectsChangedFrozenAuthority(t *testing.T) {
	for _, kind := range []string{"state", "captured", "binding", "policy", "negative count", "unsafe count", "chunk count", "bytes", "root", "next chunk", "next event", "recorded count", "recorded bytes", "prefix digest", "completed root", "null count", "missing", "duplicate", "alias", "binding alias", "policy alias", "unknown", "failure extra", "failure code", "oversized", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			authority, db, lease, wire, _, _ := auditExportFrozenFixture(t)
			switch kind {
			case "state":
				wire["state"] = "ready"
			case "captured":
				wire["captured"] = false
			case "binding":
				b := lease.Binding
				b.EnvironmentID = "pid_52000099-0000-4000-8000-000000000099"
				wire["binding"] = b
			case "policy":
				p := lease.Policy
				p.Bucket = "other-valid-bucket"
				wire["storage_policy"] = p
			case "negative count":
				wire["event_count"] = int64(-1)
			case "unsafe count":
				wire["event_count"] = int64(1 << 53)
			case "chunk count":
				wire["chunk_count"] = int64(2)
			case "bytes":
				wire["chunk_bytes"] = int64(audit.ExportMaximumChunkBytes + 1)
			case "root":
				wire["chain_root"] = audit.ExportZeroDigest
			case "next chunk":
				wire["next_chunk"] = int64(2)
			case "next event":
				wire["next_event"] = int64(2)
			case "recorded count":
				wire["recorded_chunk_count"] = int64(1)
			case "recorded bytes":
				wire["recorded_chunk_bytes"] = int64(1)
			case "prefix digest":
				wire["previous_digest"] = strings.Repeat("a", 64)
			case "completed root":
				wire["next_chunk"] = int64(2)
				wire["next_event"] = int64(2)
				wire["recorded_chunk_count"] = int64(1)
				wire["recorded_chunk_bytes"] = wire["chunk_bytes"]
				wire["previous_digest"] = strings.Repeat("a", 64)
			case "null count":
				wire["recorded_chunk_count"] = nil
			case "missing":
				delete(wire, "next_event")
			case "unknown":
				wire["internal"] = true
			case "failure extra", "failure code":
				for key := range wire {
					delete(wire, key)
				}
				wire["state"] = "failed"
				wire["failure_code"] = "invalid_source"
				if kind == "failure extra" {
					wire["captured"] = true
				} else {
					wire["failure_code"] = "execution_failed"
				}
			}
			base := db.respond
			db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				body, err := base(ctx, sql, args...)
				if sql != auditExportWorkerCaptureSQL {
					return body, err
				}
				switch kind {
				case "duplicate":
					body = bytes.Replace(body, []byte(`"next_event":1`), []byte(`"next_event":2,"next_event":1`), 1)
				case "alias":
					body = bytes.Replace(body, []byte(`"next_event":`), []byte(`"Next_event":`), 1)
				case "binding alias":
					body = bytes.Replace(body, []byte(`"capture_id":`), []byte(`"Capture_id":`), 1)
				case "policy alias":
					body = bytes.Replace(body, []byte(`"bucket":`), []byte(`"Bucket":`), 1)
				case "oversized":
					body = append(body, bytes.Repeat([]byte(" "), 16384)...)
				case "trailing":
					body = append(body, []byte(`{}`)...)
				}
				return body, err
			}
			if got, err := authority.Capture(context.Background(), lease); err == nil || got.FailureCode != "" || got.Manifest.Schema != "" {
				t.Fatal("changed frozen authority accepted", kind)
			}
		})
	}
}

func auditExportCaptureFromWire(lease auditExportLease, wire map[string]any) auditExportCapture {
	return auditExportCapture{Manifest: audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: lease.Binding, EventCount: wire["event_count"].(int64), ChunkCount: wire["chunk_count"].(int64), ChunkBytes: wire["chunk_bytes"].(int64), ChainRoot: wire["chain_root"].(string)}, NextChunk: wire["next_chunk"].(int64), NextEvent: wire["next_event"].(int64), RecordedChunkCount: wire["recorded_chunk_count"].(int64), RecordedChunkBytes: wire["recorded_chunk_bytes"].(int64), PreviousDigest: wire["previous_digest"].(string)}
}

func auditExportIntentFixture(t *testing.T, kind string) (*postgresAuditExportAuthority, *auditExportWorkerDatabase, auditExportLease, map[string]any, []byte, auditExportIntent) {
	t.Helper()
	authority, db, lease, progress, _, body := auditExportFrozenFixture(t)
	lease.Captured = true
	if kind == "manifest" {
		var err error
		body, err = audit.EncodeExportManifest(auditExportCaptureFromWire(lease, progress).Manifest)
		if err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(body)
	artifact := "pid_52000020-0000-4000-8000-000000000020"
	object := "s3://zasp-audit-export-fixture/organizations/pid_52000001-0000-4000-8000-000000000001/workspaces/pid_52000002-0000-4000-8000-000000000002/environments/pid_52000003-0000-4000-8000-000000000003/exports/pid_52000020-0000-4000-8000-000000000020"
	wire := map[string]any{"binding": lease.Binding, "storage_policy": lease.Policy, "kind": kind, "artifact_id": artifact, "object_reference": object, "sha256": hex.EncodeToString(digest[:]), "size_bytes": int64(len(body))}
	intent := auditExportIntent{Binding: lease.Binding, Policy: lease.Policy, Kind: kind, ArtifactID: artifact, ObjectReference: object, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(body))}
	if kind == "chunk" {
		wire["ordinal"] = int64(1)
		wire["first_event"] = int64(1)
		wire["event_count"] = int64(1)
		wire["previous_digest"] = audit.ExportZeroDigest
		intent.Ordinal = 1
		intent.FirstEvent = 1
		intent.EventCount = 1
		intent.PreviousDigest = audit.ExportZeroDigest
	}
	db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		switch sql {
		case auditExportWorkerReadySQL:
			return json.RawMessage(`true`), nil
		case auditExportWorkerPrepareChunkSQL, auditExportWorkerPrepareManifestSQL:
			return json.Marshal(wire)
		case auditExportWorkerRecordChunkSQL:
			return json.RawMessage(`{"recorded":true}`), nil
		}
		t.Fatal("unexpected intent query", sql)
		return nil, errors.New("unexpected query")
	}
	return authority, db, lease, wire, body, intent
}

func TestAuditExportWorkerPreparesExactCanonicalIntent(t *testing.T) {
	for _, kind := range []string{"chunk", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			authority, db, lease, _, body, want := auditExportIntentFixture(t, kind)
			var got auditExportIntent
			var err error
			if kind == "chunk" {
				got, err = authority.PrepareChunk(context.Background(), lease, body)
			} else {
				got, err = authority.PrepareManifest(context.Background(), lease, body)
			}
			if err != nil || got != want {
				t.Fatal("exact prepared intent refused/changed", err)
			}
			last := db.queries[len(db.queries)-1]
			sql := auditExportWorkerPrepareChunkSQL
			if kind == "manifest" {
				sql = auditExportWorkerPrepareManifestSQL
			}
			if last.SQL != sql || !reflect.DeepEqual(last.Args, append(authority.leaseArguments(lease), body)) {
				t.Fatal("prepare did not bind common13 and full canonical bytes")
			}
		})
	}
}

func TestAuditExportWorkerRecordsExactVersionPinnedReceipt(t *testing.T) {
	authority, db, lease, _, body, intent := auditExportIntentFixture(t, "chunk")
	receipt := auditExportArtifactReceipt{VersionID: "version-1", SHA256: sha256.Sum256(body), SizeBytes: int64(len(body))}
	for retry := 0; retry < 2; retry++ {
		if err := authority.RecordChunk(context.Background(), lease, intent, receipt); err != nil {
			t.Fatal("exact receipt/retry refused", err)
		}
	}
	last := db.queries[len(db.queries)-1]
	if last.SQL != auditExportWorkerRecordChunkSQL || !reflect.DeepEqual(last.Args, append(authority.leaseArguments(lease), int64(1), "version-1", receipt.SHA256[:], int64(len(body)))) {
		t.Fatal("record lost exact17 arguments")
	}
}

func auditExportTerminalDescriptorFixture(t *testing.T, lease auditExportLease, manifest audit.ExportManifest) map[string]any {
	t.Helper()
	body, err := audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	return map[string]any{"id": lease.Binding.ExportID, "organization_id": lease.Binding.OrganizationID, "workspace_id": lease.Binding.WorkspaceID, "environment_id": lease.Binding.EnvironmentID, "created_at": "2026-09-12T01:00:00.000000Z", "audit_correlation_id": "pid_52000030-0000-4000-8000-000000000030", "status": "ready", "event_count": manifest.EventCount, "captured_at": "2026-09-12T01:02:03.456789Z", "chunk_count": manifest.ChunkCount, "chunk_bytes": manifest.ChunkBytes, "manifest_sha256": hex.EncodeToString(digest[:])}
}

func TestAuditExportWorkerFinishRequiresExactManifestDescriptor(t *testing.T) {
	authority, db, lease, _, body, intent := auditExportIntentFixture(t, "manifest")
	manifest, err := audit.DecodeExportManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := auditExportTerminalDescriptorFixture(t, lease, manifest)
	db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		if sql != auditExportWorkerFinishSQL {
			t.Fatal("unexpected finish SQL")
		}
		return json.Marshal(descriptor)
	}
	receipt := auditExportArtifactReceipt{VersionID: "version-1", SHA256: sha256.Sum256(body), SizeBytes: int64(len(body))}
	completion := "pid_52000031-0000-4000-8000-000000000031"
	for i := 0; i < 2; i++ {
		if err := authority.Finish(context.Background(), lease, intent, receipt, manifest, completion); err != nil {
			t.Fatal("exact finish/replay refused", err)
		}
	}
	last := db.queries[len(db.queries)-1]
	if last.SQL != auditExportWorkerFinishSQL || !reflect.DeepEqual(last.Args, append(authority.leaseArguments(lease), "version-1", receipt.SHA256[:], int64(len(body)), completion)) {
		t.Fatal("finish lost exact17 arguments")
	}
}

func TestAuditExportWorkerTerminalDistinguishesBusyAndDurableOutcomes(t *testing.T) {
	for _, state := range []string{"nonterminal", "ready", "failed"} {
		t.Run(state, func(t *testing.T) {
			authority, db, lease, _, body, _ := auditExportIntentFixture(t, "manifest")
			manifest, err := audit.DecodeExportManifest(body)
			if err != nil {
				t.Fatal(err)
			}
			descriptor := auditExportTerminalDescriptorFixture(t, lease, manifest)
			if state == "failed" {
				for _, key := range []string{"captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"} {
					delete(descriptor, key)
				}
				descriptor["status"] = "failed"
				descriptor["event_count"] = nil
				descriptor["failure_code"] = "execution_failed"
			}
			wire := map[string]any{"state": state}
			if state != "nonterminal" {
				wire["export"] = descriptor
			}
			db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				if sql != auditExportWorkerTerminalSQL {
					t.Fatal("unexpected terminal query")
				}
				return json.Marshal(wire)
			}
			scope, ok := authority.validLease(lease)
			if !ok {
				t.Fatal("fixture lease invalid")
			}
			got, err := authority.Terminal(context.Background(), scope, lease.Binding.ExportID)
			if err != nil || got != state {
				t.Fatal("durable state refused/changed", err)
			}
			digest, _ := hex.DecodeString(lease.Policy.PolicyDigest)
			want := []any{lease.Binding.OrganizationID, lease.Binding.WorkspaceID, lease.Binding.EnvironmentID, lease.Binding.ExportID, lease.Policy.PolicyID, digest, authority.checksum, authority.fingerprint}
			last := db.queries[len(db.queries)-1]
			if last.SQL != auditExportWorkerTerminalSQL || !reflect.DeepEqual(last.Args, want) {
				t.Fatal("terminal lost exact8 trusted-policy args")
			}
		})
	}
}

func TestAuditExportWorkerRetryReportsOnlyConfirmedTerminalFailure(t *testing.T) {
	for _, state := range []string{"retry", "failed"} {
		t.Run(state, func(t *testing.T) {
			authority, db, lease, _, _, _ := auditExportIntentFixture(t, "chunk")
			wire := map[string]any{"state": state, "failure_code": nil, "available_at": time.Now().UTC().Add(30 * time.Second).Format("2006-01-02T15:04:05.000000Z")}
			if state == "failed" {
				wire["failure_code"] = "execution_failed"
				wire["available_at"] = nil
			}
			db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				if sql != auditExportWorkerRetrySQL {
					t.Fatal("unexpected retry query")
				}
				return json.Marshal(wire)
			}
			terminal, err := authority.Retry(context.Background(), lease, 30)
			if err != nil || terminal != (state == "failed") {
				t.Fatal("retry confused schedule with durable failure", err)
			}
			last := db.queries[len(db.queries)-1]
			if last.SQL != auditExportWorkerRetrySQL || !reflect.DeepEqual(last.Args, append(authority.leaseArguments(lease), 30, "execution_failed")) {
				t.Fatal("retry lost exact15 arguments")
			}
		})
	}
}

func TestAuditExportWorkerTerminalAndFinishRejectUnboundDescriptors(t *testing.T) {
	for _, operation := range []string{"terminal", "finish"} {
		for _, change := range []string{"foreign organization", "foreign workspace", "foreign environment", "foreign export", "missing count", "null count", "alias", "duplicate", "unknown", "trailing", "oversized", "changed digest", "changed events", "changed chunks", "changed bytes", "state mismatch", "unready", "postread cancellation", "database error", "panic"} {
			if operation == "terminal" && (change == "changed digest" || change == "changed events" || change == "changed chunks" || change == "changed bytes") {
				continue
			}
			t.Run(operation+"/"+change, func(t *testing.T) {
				authority, db, lease, _, body, intent := auditExportIntentFixture(t, "manifest")
				manifest, err := audit.DecodeExportManifest(body)
				if err != nil {
					t.Fatal(err)
				}
				descriptor := auditExportTerminalDescriptorFixture(t, lease, manifest)
				switch change {
				case "foreign organization":
					descriptor["organization_id"] = "pid_52000099-0000-4000-8000-000000000099"
				case "foreign workspace":
					descriptor["workspace_id"] = "pid_52000099-0000-4000-8000-000000000099"
				case "foreign environment":
					descriptor["environment_id"] = "pid_52000099-0000-4000-8000-000000000099"
				case "foreign export":
					descriptor["id"] = "pid_52000099-0000-4000-8000-000000000099"
				case "missing count":
					delete(descriptor, "event_count")
				case "null count":
					descriptor["event_count"] = nil
				case "unknown":
					descriptor["provider"] = "private"
				case "changed digest":
					descriptor["manifest_sha256"] = strings.Repeat("a", 64)
				case "changed events":
					descriptor["event_count"] = int64(2)
				case "changed chunks":
					descriptor["event_count"] = int64(2)
					descriptor["chunk_count"] = int64(2)
				case "changed bytes":
					descriptor["chunk_bytes"] = manifest.ChunkBytes + 1
				case "state mismatch":
					descriptor["status"] = "processing"
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				before := len(db.queries)
				db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
					if sql == auditExportWorkerReadySQL {
						if change == "unready" {
							return json.RawMessage(`false`), nil
						}
						return json.RawMessage(`true`), nil
					}
					if change == "database error" {
						return nil, errors.New("private error")
					}
					if change == "panic" {
						panic("private panic")
					}
					if change == "postread cancellation" {
						cancel()
					}
					var payload []byte
					if operation == "terminal" {
						payload, _ = json.Marshal(map[string]any{"state": "ready", "export": descriptor})
					} else {
						payload, _ = json.Marshal(descriptor)
					}
					switch change {
					case "alias":
						payload = bytes.Replace(payload, []byte(`"status":`), []byte(`"Status":`), 1)
					case "duplicate":
						payload = bytes.Replace(payload, []byte(`"status":`), []byte(`"status":"failed","status":`), 1)
					case "trailing":
						payload = append(payload, []byte(`{}`)...)
					case "oversized":
						payload = append(payload, bytes.Repeat([]byte(" "), 16384)...)
					}
					return payload, nil
				}
				if operation == "terminal" {
					scope, _ := authority.validLease(lease)
					state, err := authority.Terminal(ctx, scope, lease.Binding.ExportID)
					if err == nil || state != "" {
						t.Fatal("unbound terminal accepted", change)
					}
				} else {
					err := authority.Finish(ctx, lease, intent, auditExportArtifactReceipt{VersionID: "version-1", SHA256: sha256.Sum256(body), SizeBytes: int64(len(body))}, manifest, "pid_52000031-0000-4000-8000-000000000031")
					if err == nil {
						t.Fatal("unbound finish accepted", change)
					}
				}
				want := 2
				if change == "unready" {
					want = 1
				}
				if len(db.queries)-before != want || db.queries[before].SQL != auditExportWorkerReadySQL {
					t.Fatal("terminal readiness order changed")
				}
			})
		}
	}
}

func TestAuditExportWorkerTerminalRejectsUnprovenWire(t *testing.T) {
	for _, wire := range []string{`null`, `{"state":"ready"}`, `{"state":"failed"}`, `{"state":"nonterminal","export":null}`, `{"State":"nonterminal"}`, `{"state":"ready","state":"nonterminal"}`, `{"state":"unknown"}`, `{"state":null}`} {
		t.Run(wire, func(t *testing.T) {
			authority, db, lease, _, _, _ := auditExportIntentFixture(t, "manifest")
			scope, _ := authority.validLease(lease)
			db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				return json.RawMessage(wire), nil
			}
			if state, err := authority.Terminal(context.Background(), scope, lease.Binding.ExportID); err == nil || state != "" {
				t.Fatal("unproven terminal authority accepted")
			}
		})
	}
}

func TestAuditExportWorkerRetryRefusesUnconfirmedState(t *testing.T) {
	for _, change := range []string{"state", "missing", "alias", "duplicate", "failure code", "retry timestamp null", "retry timestamp noncanonical", "failed timestamp", "zero retry", "negative retry", "too long retry", "unready", "postread cancellation"} {
		t.Run(change, func(t *testing.T) {
			authority, db, lease, _, _, _ := auditExportIntentFixture(t, "chunk")
			wire := map[string]any{"state": "retry", "failure_code": nil, "available_at": "2026-09-12T01:02:03.456789Z"}
			seconds := 30
			switch change {
			case "state":
				wire["state"] = "ready"
			case "missing":
				delete(wire, "failure_code")
			case "failure code":
				wire["failure_code"] = "execution_failed"
			case "retry timestamp null":
				wire["available_at"] = nil
			case "retry timestamp noncanonical":
				wire["available_at"] = "2026-09-12T01:02:03Z"
			case "failed timestamp":
				wire["state"] = "failed"
				wire["failure_code"] = "execution_failed"
			case "zero retry":
				seconds = 0
			case "negative retry":
				seconds = -1
			case "too long retry":
				seconds = 301
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before := len(db.queries)
			db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					if change == "unready" {
						return json.RawMessage(`null`), nil
					}
					return json.RawMessage(`true`), nil
				}
				if change == "postread cancellation" {
					cancel()
				}
				body, _ := json.Marshal(wire)
				if change == "alias" {
					body = bytes.Replace(body, []byte(`"state":`), []byte(`"State":`), 1)
				}
				if change == "duplicate" {
					body = bytes.Replace(body, []byte(`"state":`), []byte(`"state":"failed","state":`), 1)
				}
				return body, nil
			}
			if terminal, err := authority.Retry(ctx, lease, seconds); err == nil || terminal {
				t.Fatal("unconfirmed retry accepted")
			}
			if (seconds < 0 || seconds > 300) && len(db.queries) != before {
				t.Fatal("invalid retry reached SQL")
			}
		})
	}
}

func TestAuditExportWorkerIntentRejectsCoupledBindingArtifactAliases(t *testing.T) {
	for _, operation := range []string{"chunk", "manifest", "record"} {
		for _, field := range []string{"organization", "workspace", "environment", "export", "capture"} {
			t.Run(operation+"/"+field, func(t *testing.T) {
				kind := operation
				if kind == "record" {
					kind = "chunk"
				}
				authority, db, lease, wire, body, intent := auditExportIntentFixture(t, kind)
				aliases := map[string]string{"organization": lease.Binding.OrganizationID, "workspace": lease.Binding.WorkspaceID, "environment": lease.Binding.EnvironmentID, "export": lease.Binding.ExportID, "capture": lease.Binding.CaptureID}
				alias := aliases[field]
				// Change both fields: a key-only mismatch is already rejected and
				// would hide the API-incompatible artifact identity collision.
				object := strings.TrimSuffix(intent.ObjectReference, intent.ArtifactID) + alias
				wire["artifact_id"] = alias
				wire["object_reference"] = object
				intent.ArtifactID = alias
				intent.ObjectReference = object
				before := len(db.queries)
				var err error
				switch operation {
				case "chunk":
					_, err = authority.PrepareChunk(context.Background(), lease, body)
				case "manifest":
					_, err = authority.PrepareManifest(context.Background(), lease, body)
				case "record":
					err = authority.RecordChunk(context.Background(), lease, intent, auditExportArtifactReceipt{VersionID: "version-1", SHA256: sha256.Sum256(body), SizeBytes: int64(len(body))})
				}
				if err == nil {
					t.Fatal("binding identity accepted as retrievable artifact", field)
				}
				if operation == "record" && len(db.queries) != before {
					t.Fatal("aliased receipt reached SQL")
				}
			})
		}
	}
}

func TestAuditExportWorkerPreparedIntentRejectsAlteredAuthority(t *testing.T) {
	for _, kind := range []string{"chunk", "manifest"} {
		for _, change := range []string{"binding", "policy", "kind", "artifact", "object bucket", "object profile", "object scope", "object URL", "digest", "size", "null size", "duplicate", "alias", "binding alias", "policy alias", "missing", "unknown", "ordinal", "first event", "count", "previous", "trailing", "oversized"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				authority, db, lease, wire, body, _ := auditExportIntentFixture(t, kind)
				switch change {
				case "binding":
					b := lease.Binding
					b.CaptureID = "pid_52000099-0000-4000-8000-000000000099"
					wire["binding"] = b
				case "policy":
					p := lease.Policy
					p.KMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/52000099-0000-4000-8000-000000000099"
					wire["storage_policy"] = p
				case "kind":
					wire["kind"] = "other"
				case "artifact":
					wire["artifact_id"] = "pid_52000099-0000-4000-8000-000000000099"
				case "object bucket":
					wire["object_reference"] = strings.Replace(wire["object_reference"].(string), "zasp-audit-export-fixture", "other-bucket", 1)
				case "object profile":
					wire["object_reference"] = strings.Replace(wire["object_reference"].(string), "/exports/", "/artifacts/", 1)
				case "object scope":
					wire["object_reference"] = strings.Replace(wire["object_reference"].(string), lease.Binding.WorkspaceID, "pid_52000099-0000-4000-8000-000000000099", 1)
				case "object URL":
					wire["object_reference"] = "https://example.invalid/object"
				case "digest":
					wire["sha256"] = strings.Repeat("a", 64)
				case "size":
					wire["size_bytes"] = int64(len(body) + 1)
				case "null size":
					wire["size_bytes"] = nil
				case "missing":
					delete(wire, "sha256")
				case "unknown":
					wire["version_id"] = "version-1"
				case "ordinal":
					wire["ordinal"] = int64(2)
				case "first event":
					wire["first_event"] = int64(2)
				case "count":
					wire["event_count"] = int64(2)
				case "previous":
					wire["previous_digest"] = strings.Repeat("a", 64)
				}
				base := db.respond
				db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
					response, err := base(ctx, sql, args...)
					if sql == auditExportWorkerReadySQL {
						return response, err
					}
					switch change {
					case "duplicate":
						response = bytes.Replace(response, []byte(`"kind":`), []byte(`"kind":"other","kind":`), 1)
					case "alias":
						response = bytes.Replace(response, []byte(`"kind":`), []byte(`"Kind":`), 1)
					case "binding alias":
						response = bytes.Replace(response, []byte(`"capture_id":`), []byte(`"Capture_id":`), 1)
					case "policy alias":
						response = bytes.Replace(response, []byte(`"bucket":`), []byte(`"Bucket":`), 1)
					case "trailing":
						response = append(response, []byte(`{}`)...)
					case "oversized":
						response = append(response, bytes.Repeat([]byte(" "), 16384)...)
					}
					return response, err
				}
				var got auditExportIntent
				var err error
				if kind == "chunk" {
					got, err = authority.PrepareChunk(context.Background(), lease, body)
				} else {
					got, err = authority.PrepareManifest(context.Background(), lease, body)
				}
				if err == nil || got.ArtifactID != "" {
					t.Fatal("altered intent accepted", change)
				}
			})
		}
	}
}

func TestAuditExportWorkerPrepareRefusesInvalidBodyBeforeSQL(t *testing.T) {
	for _, kind := range []string{"chunk", "manifest"} {
		for _, change := range []string{"empty", "trailing", "case alias", "binding", "uncaptured", "expired", "policy budget", "nil context"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				authority, db, lease, _, body, _ := auditExportIntentFixture(t, kind)
				ctx := context.Background()
				switch change {
				case "empty":
					body = nil
				case "trailing":
					body = append(body, ' ')
				case "case alias":
					body = bytes.Replace(body, []byte(`"schema":`), []byte(`"Schema":`), 1)
				case "binding":
					body = bytes.Replace(body, []byte(lease.Binding.CaptureID), []byte("pid_52000099-0000-4000-8000-000000000099"), 1)
				case "uncaptured":
					lease.Captured = false
				case "expired":
					lease.ExpiresAt = time.Now().Add(-time.Second)
				case "policy budget":
					authority.policy.MaximumExportBytes = int64(len(body) - 1)
					lease.Policy = authority.policy
				case "nil context":
					ctx = nil
				}
				before := len(db.queries)
				var err error
				if kind == "chunk" {
					_, err = authority.PrepareChunk(ctx, lease, body)
				} else {
					_, err = authority.PrepareManifest(ctx, lease, body)
				}
				if err == nil || len(db.queries) != before {
					t.Fatal("invalid body reached SQL", change, len(db.queries)-before)
				}
			})
		}
	}
}

func TestAuditExportWorkerRecordRefusesUnverifiedReceiptBeforeSQL(t *testing.T) {
	for _, change := range []string{"version missing", "version null", "version whitespace", "version control", "version unicode", "version oversized", "digest", "size", "intent scope", "intent policy", "intent ordinal", "intent previous", "intent manifest", "intent reference", "uncaptured", "nil context"} {
		t.Run(change, func(t *testing.T) {
			authority, db, lease, _, body, intent := auditExportIntentFixture(t, "chunk")
			receipt := auditExportArtifactReceipt{VersionID: "version-1", SHA256: sha256.Sum256(body), SizeBytes: int64(len(body))}
			ctx := context.Background()
			switch change {
			case "version missing":
				receipt.VersionID = ""
			case "version null":
				receipt.VersionID = "null"
			case "version whitespace":
				receipt.VersionID = "version 1"
			case "version control":
				receipt.VersionID = "version\n1"
			case "version unicode":
				receipt.VersionID = "versión"
			case "version oversized":
				receipt.VersionID = strings.Repeat("a", 1025)
			case "digest":
				receipt.SHA256[0] ^= 1
			case "size":
				receipt.SizeBytes++
			case "intent scope":
				intent.Binding.EnvironmentID = "pid_52000099-0000-4000-8000-000000000099"
			case "intent policy":
				intent.Policy.Bucket = "other-bucket"
			case "intent ordinal":
				intent.Ordinal = 0
			case "intent previous":
				intent.PreviousDigest = strings.Repeat("a", 64)
			case "intent manifest":
				intent.Kind = "manifest"
			case "intent reference":
				intent.ObjectReference += "/extra"
			case "uncaptured":
				lease.Captured = false
			case "nil context":
				ctx = nil
			}
			before := len(db.queries)
			if err := authority.RecordChunk(ctx, lease, intent, receipt); err == nil || len(db.queries) != before {
				t.Fatal("unverified receipt reached SQL", change)
			}
		})
	}
}

func TestAuditExportWorkerIntentOperationsRequireFreshReadyAndConfirmedResponse(t *testing.T) {
	for _, operation := range []string{"chunk", "manifest", "record"} {
		for _, change := range []string{"unready", "missing readiness", "wrong readiness", "duplicate readiness", "database error", "panic", "postread cancellation", "record false", "record null", "record alias", "record duplicate", "record trailing"} {
			if operation != "record" && strings.HasPrefix(change, "record ") {
				continue
			}
			t.Run(operation+"/"+change, func(t *testing.T) {
				kind := operation
				if kind == "record" {
					kind = "chunk"
				}
				authority, db, lease, _, body, intent := auditExportIntentFixture(t, kind)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				base := db.respond
				before := len(db.queries)
				db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
					if sql == auditExportWorkerReadySQL {
						switch change {
						case "unready":
							return json.RawMessage(`false`), nil
						case "missing readiness":
							return nil, nil
						case "wrong readiness":
							return json.RawMessage(`"true"`), nil
						case "duplicate readiness":
							return json.RawMessage(`true true`), nil
						}
					}
					if sql != auditExportWorkerReadySQL {
						switch change {
						case "database error":
							return nil, errors.New("private query failure")
						case "panic":
							panic("private query failure")
						case "postread cancellation":
							cancel()
						case "record false":
							return json.RawMessage(`{"recorded":false}`), nil
						case "record null":
							return json.RawMessage(`{"recorded":null}`), nil
						case "record alias":
							return json.RawMessage(`{"Recorded":true}`), nil
						case "record duplicate":
							return json.RawMessage(`{"recorded":false,"recorded":true}`), nil
						case "record trailing":
							return json.RawMessage(`{"recorded":true}{}`), nil
						}
					}
					return base(ctx, sql, args...)
				}
				var err error
				switch operation {
				case "chunk":
					_, err = authority.PrepareChunk(ctx, lease, body)
				case "manifest":
					_, err = authority.PrepareManifest(ctx, lease, body)
				case "record":
					err = authority.RecordChunk(ctx, lease, intent, auditExportArtifactReceipt{VersionID: "version-1", SHA256: sha256.Sum256(body), SizeBytes: int64(len(body))})
				}
				if err == nil {
					t.Fatal("unconfirmed operation accepted", change)
				}
				want := 2
				if change == "unready" || strings.Contains(change, "readiness") {
					want = 1
				}
				if len(db.queries)-before != want || db.queries[before].SQL != auditExportWorkerReadySQL {
					t.Fatal("readiness/operation order changed")
				}
			})
		}
	}
}

func TestAuditExportWorkerFrozenPageStandalonePreservesBytes(t *testing.T) {
	authority, _, lease, wire, _, want := auditExportFrozenFixture(t)
	got, err := authority.ReadFrozenPage(context.Background(), lease, auditExportCaptureFromWire(lease, wire))
	if err != nil || !bytes.Equal(got.Body, want) || got.NextEvent != nil {
		t.Fatal("planned canonical chunk refused", err)
	}
}

func TestAuditExportWorkerFrozenPageRefusesInvalidProgressBeforeSQL(t *testing.T) {
	for _, kind := range []string{"empty", "completed", "failed", "binding", "gap", "policy", "nil context"} {
		t.Run(kind, func(t *testing.T) {
			authority, db, lease, wire, _, _ := auditExportFrozenFixture(t)
			progress := auditExportCaptureFromWire(lease, wire)
			ctx := context.Background()
			switch kind {
			case "empty":
				progress.Manifest.EventCount = 0
				progress.Manifest.ChunkCount = 0
				progress.Manifest.ChunkBytes = 0
				progress.Manifest.ChainRoot = audit.ExportZeroDigest
			case "completed":
				progress.RecordedChunkCount = 1
				progress.RecordedChunkBytes = progress.Manifest.ChunkBytes
				progress.NextChunk = 2
				progress.NextEvent = 2
				progress.PreviousDigest = progress.Manifest.ChainRoot
			case "failed":
				progress.FailureCode = "invalid_source"
			case "binding":
				progress.Manifest.Binding.CaptureID = "pid_52000099-0000-4000-8000-000000000099"
			case "gap":
				progress.NextChunk = 2
			case "policy":
				lease.Policy.MaximumExportBytes++
			case "nil context":
				ctx = nil
			}
			before := len(db.queries)
			if got, err := authority.ReadFrozenPage(ctx, lease, progress); err == nil || len(got.Body) != 0 || len(db.queries) != before {
				t.Fatal("invalid progress reached authority SQL")
			}
		})
	}
}

func TestAuditExportWorkerFrozenPageResumesExactContiguousPrefix(t *testing.T) {
	authority, db, lease, wire, page, firstBody := auditExportFrozenFixture(t)
	firstDigest := sha256.Sum256(firstBody)
	firstHash := hex.EncodeToString(firstDigest[:])
	event := page["events"].([]audit.ExportEvent)[0]
	event.Ordinal = 2
	event.ID = "pid_52000008-0000-4000-8000-000000000008"
	second := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: lease.Binding, Ordinal: 2, FirstEvent: 2, EventCount: 1, PreviousDigest: firstHash, Events: []audit.ExportEvent{event}}
	secondBody, err := audit.EncodeExportChunk(second)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest := sha256.Sum256(secondBody)
	wire["event_count"] = int64(2)
	wire["chunk_count"] = int64(2)
	wire["chunk_bytes"] = int64(len(firstBody) + len(secondBody))
	wire["chain_root"] = hex.EncodeToString(secondDigest[:])
	page["next_event"] = int64(2)
	progress, err := authority.Capture(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.ReadFrozenPage(context.Background(), lease, progress)
	if err != nil || !bytes.Equal(first.Body, firstBody) || first.NextEvent == nil || *first.NextEvent != 2 {
		t.Fatal("first exact planned chunk refused", err)
	}
	// Represents persisted SQL progress after a prior process recorded chunk1;
	// this fixture does not claim provider writes or a real database transition.
	wire["next_chunk"] = int64(2)
	wire["next_event"] = int64(2)
	wire["recorded_chunk_count"] = int64(1)
	wire["recorded_chunk_bytes"] = int64(len(firstBody))
	wire["previous_digest"] = firstHash
	page["ordinal"] = int64(2)
	page["first_event"] = int64(2)
	page["previous_digest"] = firstHash
	page["events"] = second.Events
	page["next_event"] = nil
	resumed, err := authority.Capture(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	got, err := authority.ReadFrozenPage(context.Background(), lease, resumed)
	if err != nil || !bytes.Equal(got.Body, secondBody) || got.NextEvent != nil {
		t.Fatal("recorded prefix was not resumed exactly", err)
	}
	last := db.queries[len(db.queries)-1]
	if len(last.Args) != 14 || last.Args[13] != int64(2) {
		t.Fatal("resume queried a different ordinal")
	}
}

func TestAuditExportWorkerFrozenPageEnforcesByteAndEventLimits(t *testing.T) {
	for _, kind := range []string{"1000 events", "near byte limit", "one byte over"} {
		t.Run(kind, func(t *testing.T) {
			authority, db, lease, wire, page, _ := auditExportFrozenFixture(t)
			count := 1000
			if kind != "1000 events" {
				count = 60
			}
			base := page["events"].([]audit.ExportEvent)[0]
			events := make([]audit.ExportEvent, count)
			for i := range events {
				events[i] = base
				events[i].Ordinal = int64(i + 1)
				events[i].ID = fmt.Sprintf("pid_52000009-0000-4000-8000-%012d", 9000-i)
				if kind != "1000 events" {
					events[i].Metadata = map[string]string{}
					for k := 0; k < 32; k++ {
						events[i].Metadata[fmt.Sprintf("field%02d", k)] = strings.Repeat("x", 512)
					}
				}
			}
			chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: lease.Binding, Ordinal: 1, FirstEvent: 1, EventCount: int64(count), PreviousDigest: audit.ExportZeroDigest, Events: events}
			canonical, err := audit.EncodeExportChunk(chunk)
			if err != nil {
				t.Fatal("bounded fixture invalid", err)
			}
			if kind != "1000 events" && len(canonical) < 1000000 {
				t.Fatal("fixture did not approach byte limit", len(canonical))
			}
			digest := sha256.Sum256(canonical)
			wire["event_count"] = int64(count)
			wire["chunk_bytes"] = int64(len(canonical))
			wire["chain_root"] = hex.EncodeToString(digest[:])
			page["event_count"] = int64(count)
			page["events"] = events
			if kind == "one byte over" {
				baseQuery := db.respond
				db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
					body, err := baseQuery(ctx, sql, args...)
					if sql == auditExportWorkerFrozenPageSQL {
						body = append(body, bytes.Repeat([]byte(" "), audit.ExportMaximumChunkBytes-len(body)+1)...)
					}
					return body, err
				}
			}
			got, err := authority.ReadFrozenPage(context.Background(), lease, auditExportCaptureFromWire(lease, wire))
			if kind == "one byte over" {
				if err == nil || len(got.Body) != 0 {
					t.Fatal("oversize page accepted")
				}
				return
			}
			if err != nil || !bytes.Equal(got.Body, canonical) || len(got.Chunk.Events) != count {
				t.Fatal("bounded page lost events/bytes", err)
			}
			t.Logf("canonical chunk bytes=%d events=%d", len(canonical), count)
		})
	}
}

func TestAuditExportWorkerFrozenPageRejectsUnboundOrNoncanonicalBytes(t *testing.T) {
	for _, kind := range []string{"binding", "ordinal", "first event", "count", "too many", "previous", "next gap", "event identity", "event scope", "event ordinal", "event bytes", "unredacted", "noncanonical event", "event alias", "duplicate event", "missing event", "null events", "null count", "missing next", "duplicate", "alias", "binding alias", "unknown", "oversized", "trailing", "root", "total bytes"} {
		t.Run(kind, func(t *testing.T) {
			authority, db, lease, wire, page, _ := auditExportFrozenFixture(t)
			capture := auditExportCaptureFromWire(lease, wire)
			events := page["events"].([]audit.ExportEvent)
			switch kind {
			case "binding":
				b := lease.Binding
				b.ExportID = "pid_52000099-0000-4000-8000-000000000099"
				page["binding"] = b
			case "ordinal":
				page["ordinal"] = int64(2)
			case "first event":
				page["first_event"] = int64(2)
			case "count":
				page["event_count"] = int64(2)
			case "too many":
				page["event_count"] = int64(1001)
			case "previous":
				page["previous_digest"] = strings.Repeat("a", 64)
			case "next gap":
				page["next_event"] = int64(3)
			case "event identity":
				events[0].ID = "pid_52000099-0000-4000-8000-000000000099"
			case "event scope":
				events[0].OrganizationID = "pid_52000099-0000-4000-8000-000000000099"
			case "event ordinal":
				events[0].Ordinal = 2
			case "event bytes":
				events[0].Metadata["name"] = "changed"
			case "unredacted":
				events[0].Metadata["password"] = "sensitive-test-value"
			case "duplicate event":
				page["events"] = append(events, events[0])
			case "missing event":
				page["events"] = []audit.ExportEvent{}
			case "null events":
				page["events"] = nil
			case "null count":
				page["event_count"] = nil
			case "missing next":
				delete(page, "next_event")
			case "unknown":
				page["schema"] = audit.ExportChunkSchema
			case "root":
				capture.Manifest.ChainRoot = strings.Repeat("a", 64)
			case "total bytes":
				capture.Manifest.ChunkBytes++
			}
			base := db.respond
			db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				body, err := base(ctx, sql, args...)
				if sql != auditExportWorkerFrozenPageSQL {
					return body, err
				}
				switch kind {
				case "noncanonical event":
					body = bytes.Replace(body, []byte(`"ordinal":1,"id"`), []byte(`"ordinal":1, "id"`), 1)
				case "event alias":
					body = bytes.Replace(body, []byte(`"actor_id":`), []byte(`"Actor_id":`), 1)
				case "duplicate":
					body = bytes.Replace(body, []byte(`"first_event":1`), []byte(`"first_event":2,"first_event":1`), 1)
				case "alias":
					body = bytes.Replace(body, []byte(`"first_event":`), []byte(`"First_event":`), 1)
				case "binding alias":
					body = bytes.Replace(body, []byte(`"capture_id":`), []byte(`"Capture_id":`), 1)
				case "oversized":
					body = append(body, bytes.Repeat([]byte(" "), audit.ExportMaximumChunkBytes)...)
				case "trailing":
					body = append(body, []byte(`{}`)...)
				}
				return body, err
			}
			if got, err := authority.ReadFrozenPage(context.Background(), lease, capture); err == nil || len(got.Body) != 0 {
				t.Fatal("unbound page accepted", kind)
			}
		})
	}
}

func TestAuditExportWorkerFrozenOperationsRequireFreshReadinessAndBudget(t *testing.T) {
	for _, operation := range []string{"capture", "page"} {
		for _, kind := range []string{"false", "null", "wrong type", "duplicate readiness", "database error", "panic", "canceled", "postread cancellation", "expired", "insufficient margin"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				authority, db, lease, wire, _, _ := auditExportFrozenFixture(t)
				capture := auditExportCaptureFromWire(lease, wire)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if kind == "expired" {
					lease.ExpiresAt = time.Now().Add(-time.Second)
				}
				if kind == "insufficient margin" {
					lease.ExpiresAt = time.Now().Add(time.Second)
				}
				if kind == "canceled" {
					cancel()
				}
				base := db.respond
				before := len(db.queries)
				db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
					if sql == auditExportWorkerReadySQL {
						switch kind {
						case "false":
							return json.RawMessage(`false`), nil
						case "null":
							return json.RawMessage(`null`), nil
						case "wrong type":
							return json.RawMessage(`"true"`), nil
						case "duplicate readiness":
							return json.RawMessage(`true true`), nil
						case "database error":
							return nil, errors.New("query failure")
						case "panic":
							panic("query failure")
						}
					}
					body, err := base(ctx, sql, args...)
					if sql != auditExportWorkerReadySQL && kind == "postread cancellation" {
						cancel()
					}
					return body, err
				}
				var err error
				if operation == "capture" {
					_, err = authority.Capture(ctx, lease)
				} else {
					_, err = authority.ReadFrozenPage(ctx, lease, capture)
				}
				if err == nil {
					t.Fatal("failed readiness/budget accepted")
				}
				want := 1
				if kind == "canceled" || kind == "expired" || kind == "insufficient margin" {
					want = 0
				}
				if kind == "postread cancellation" {
					want = 2
				}
				if len(db.queries)-before != want {
					t.Fatal("unexpected SQL after refusal", len(db.queries)-before, want)
				}
				if want == 1 && db.queries[before].SQL != auditExportWorkerReadySQL {
					t.Fatal("operation preceded readiness")
				}
			})
		}
	}
}

type auditExportWorkerQuery struct {
	SQL  string
	Args []any
}

func auditExportWorkerLeaseFixture(t *testing.T) (*postgresAuditExportAuthority, *auditExportWorkerDatabase, domain.Scope, map[string]any) {
	t.Helper()
	policyBody := `{"schema":"audit-export-policy-v1","policy_id":"pid_52000041-0000-4000-8000-000000000041","bucket":"zasp-audit-export-fixture","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}`
	var policy map[string]any
	if err := json.Unmarshal([]byte(policyBody), &policy); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(policyBody))
	policy["policy_digest"] = hex.EncodeToString(digest[:])
	scope, err := domain.NewScope(workerID(t, "pid_52000001-0000-4000-8000-000000000001"), workerID(t, "pid_52000002-0000-4000-8000-000000000002"), workerID(t, "pid_52000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	wire := map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "export_id": "pid_52000004-0000-4000-8000-000000000004", "capture_id": "pid_52000005-0000-4000-8000-000000000005", "policy_id": policy["policy_id"], "policy_digest": policy["policy_digest"], "generation": int64(1), "attempt": 1, "lease_expires_at": time.Now().Add(179 * time.Second).In(time.FixedZone("offset", -7*3600)), "captured": false, "storage_policy": policy}
	database := &auditExportWorkerDatabase{}
	authority, err := newPostgresAuditExportAuthority(database, auditExportWorkerPolicyFixture())
	if err != nil {
		t.Fatal(err)
	}
	database.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		body, err := json.Marshal(wire)
		return body, err
	}
	return authority, database, scope, wire
}

func TestAuditExportWorkerClaimAndHeartbeatBindExactTrustedPolicy(t *testing.T) {
	authority, database, scope, wire := auditExportWorkerLeaseFixture(t)
	lease, err := authority.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
	if err != nil || lease == nil {
		t.Fatal("valid lease refused", err)
	}
	if lease.Binding.CaptureID != wire["capture_id"] || lease.Generation != 1 || lease.Attempt != 1 || lease.ExpiresAt.Location() != time.UTC || !lease.ExpiresAt.Equal(wire["lease_expires_at"].(time.Time)) {
		t.Fatal("lease identity/instant changed")
	}
	digest, _ := hex.DecodeString(wire["policy_digest"].(string))
	want := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), wire["export_id"], "audit-export-worker", strings.Repeat("a", 64), 180, wire["policy_id"], digest, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}
	last := database.queries[len(database.queries)-1]
	if last.SQL != auditExportWorkerClaimSQL || !reflect.DeepEqual(last.Args, want) {
		t.Fatal("claim lost exact11 arguments")
	}
	wire["lease_expires_at"] = time.Now().Add(180 * time.Second)
	renewed, err := authority.Heartbeat(context.Background(), *lease, 180)
	if err != nil || renewed.Binding != lease.Binding || renewed.Generation != lease.Generation || renewed.Attempt != lease.Attempt || !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatal("renewal changed lease identity or failed", err)
	}
	want = []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), wire["export_id"], wire["capture_id"], int64(1), 1, "audit-export-worker", strings.Repeat("a", 64), wire["policy_id"], digest, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint(), 180}
	last = database.queries[len(database.queries)-1]
	if last.SQL != auditExportWorkerHeartbeatSQL || !reflect.DeepEqual(last.Args, want) {
		t.Fatal("heartbeat lost common13+seconds")
	}
}

func TestAuditExportWorkerLeaseRefusesUntrustedResponse(t *testing.T) {
	for _, kind := range []string{"scope", "export", "capture alias", "policy id", "policy digest", "bucket", "owner", "kms", "policy limit", "generation", "attempt", "expired", "future", "captured null", "duplicate", "alias", "policy alias", "unknown", "trailing", "oversized", "canceled", "panic", "provider error"} {
		t.Run(kind, func(t *testing.T) {
			authority, database, scope, wire := auditExportWorkerLeaseFixture(t)
			export := wire["export_id"].(string)
			policy := wire["storage_policy"].(map[string]any)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "scope":
				wire["workspace_id"] = "pid_52000099-0000-4000-8000-000000000099"
			case "export":
				wire["export_id"] = "pid_52000099-0000-4000-8000-000000000099"
			case "capture alias":
				wire["capture_id"] = wire["export_id"]
			case "policy id":
				wire["policy_id"] = "pid_52000099-0000-4000-8000-000000000099"
			case "policy digest":
				wire["policy_digest"] = strings.Repeat("f", 64)
			case "bucket":
				policy["bucket"] = "different-valid-bucket"
			case "owner":
				policy["expected_bucket_owner"] = "999999999999"
			case "kms":
				policy["kms_key_arn"] = "arn:aws:kms:us-east-1:123456789012:key/52000043-0000-4000-8000-000000000043"
			case "policy limit":
				policy["maximum_export_bytes"] = 99
			case "generation":
				wire["generation"] = 0
			case "attempt":
				wire["attempt"] = 0
			case "expired":
				wire["lease_expires_at"] = time.Now().Add(-time.Second)
			case "future":
				wire["lease_expires_at"] = time.Now().Add(time.Hour)
			case "captured null":
				wire["captured"] = nil
			}
			database.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerReadySQL {
					return json.RawMessage(`true`), nil
				}
				body, _ := json.Marshal(wire)
				switch kind {
				case "duplicate":
					body = bytes.Replace(body, []byte(`"generation":1`), []byte(`"generation":2,"generation":1`), 1)
				case "alias":
					body = bytes.Replace(body, []byte(`"generation":`), []byte(`"GENERATION":`), 1)
				case "policy alias":
					body = bytes.Replace(body, []byte(`"bucket":`), []byte(`"BUCKET":`), 1)
				case "unknown":
					body = bytes.Replace(body, []byte(`"generation":`), []byte(`"private":true,"generation":`), 1)
				case "trailing":
					body = append(body, []byte(`{}`)...)
				case "oversized":
					body = append(body, bytes.Repeat([]byte(" "), 16384)...)
				case "canceled":
					cancel()
				case "panic":
					panic("owned provider failure")
				case "provider error":
					return nil, errors.New("owned database failure")
				}
				return body, nil
			}
			if lease, err := authority.Claim(ctx, scope, export, "audit-export-worker", strings.Repeat("a", 64), 180); err == nil || lease != nil {
				t.Fatal("untrusted lease accepted")
			}
		})
	}
}

func TestAuditExportWorkerFreshReadinessBeforeClaimAndHeartbeat(t *testing.T) {
	for _, body := range []string{`false`, `null`, `"true"`, `true true`, `{"ready":true}`, strings.Repeat(" ", 17) + `true`, ``} {
		for _, operation := range []string{"claim", "heartbeat"} {
			t.Run(operation+"/"+body, func(t *testing.T) {
				authority, database, scope, wire := auditExportWorkerLeaseFixture(t)
				lease, err := authority.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
				if err != nil || lease == nil {
					t.Fatal(err)
				}
				database.queries = nil
				database.respond = func(context.Context, string, ...any) (json.RawMessage, error) { return json.RawMessage(body), nil }
				if operation == "claim" {
					_, err = authority.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
				} else {
					_, err = authority.Heartbeat(context.Background(), *lease, 180)
				}
				if err == nil || len(database.queries) != 1 || database.queries[0].SQL != auditExportWorkerReadySQL {
					t.Fatal("stale readiness authorized operation SQL")
				}
			})
		}
	}
}

type auditExportWorkerDatabase struct {
	queries []auditExportWorkerQuery
	respond func(context.Context, string, ...any) (json.RawMessage, error)
}

func (database *auditExportWorkerDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	database.queries = append(database.queries, auditExportWorkerQuery{sql, args})
	if database.respond != nil {
		return database.respond(ctx, sql, args...)
	}
	return json.RawMessage(`true`), nil
}
func auditExportWorkerPolicyFixture() migrations.AuditExportConfiguration {
	return migrations.AuditExportConfiguration{PolicyID: "pid_52000041-0000-4000-8000-000000000041", Bucket: "zasp-audit-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042", MaximumExportBytes: 1 << 30, MaximumRetainedBytes: 10 << 30, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
}
func TestAuditExportWorkerReadinessPinsCompiled52AndExecutorPrincipal(t *testing.T) {
	database := &auditExportWorkerDatabase{}
	authority, err := newPostgresAuditExportAuthority(database, auditExportWorkerPolicyFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ready(context.Background()); err != nil {
		t.Fatal("explicit export worker readiness unavailable", err)
	}
	if len(database.queries) == 0 {
		t.Fatal("readiness omitted SQL")
	}
	for _, query := range database.queries {
		if query.SQL != `SELECT to_jsonb(zasp_audit_export_worker_readiness($1,$2,$3))` || !reflect.DeepEqual(query.Args, []any{migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint(), "zasp_audit_export_worker"}) {
			t.Fatal("wrong compiled worker authority")
		}
	}
}

func TestAuditExportWorkerConstructorRefusesMissingTrust(t *testing.T) {
	for _, kind := range []string{"nil database", "typed nil database", "invalid policy", "unready", "panic"} {
		t.Run(kind, func(t *testing.T) {
			db := &auditExportWorkerDatabase{}
			var database recoveryJSONDatabase = db
			policy := auditExportWorkerPolicyFixture()
			switch kind {
			case "nil database":
				database = nil
			case "typed nil database":
				database = (*auditExportWorkerDatabase)(nil)
			case "invalid policy":
				policy.PolicyID = "unknown"
			case "unready":
				db.respond = func(context.Context, string, ...any) (json.RawMessage, error) { return json.RawMessage(`false`), nil }
			case "panic":
				db.respond = func(context.Context, string, ...any) (json.RawMessage, error) { panic("owned readiness failure") }
			}
			if authority, err := newPostgresAuditExportAuthority(database, policy); err == nil || authority != nil {
				t.Fatal("constructor accepted missing trust")
			}
			if kind == "invalid policy" && len(db.queries) != 0 {
				t.Fatal("invalid trusted policy queried SQL")
			}
		})
	}
}

func TestAuditExportWorkerHeartbeatRejectsChangedLeaseIdentity(t *testing.T) {
	for _, kind := range []string{"capture", "generation", "attempt", "captured", "deadline shorter"} {
		t.Run(kind, func(t *testing.T) {
			authority, _, scope, wire := auditExportWorkerLeaseFixture(t)
			lease, err := authority.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "capture":
				wire["capture_id"] = "pid_52000099-0000-4000-8000-000000000099"
			case "generation":
				wire["generation"] = int64(2)
			case "attempt":
				wire["attempt"] = 2
			case "captured":
				wire["captured"] = true
			case "deadline shorter":
				wire["lease_expires_at"] = time.Now().Add(60 * time.Second)
			}
			if got, err := authority.Heartbeat(context.Background(), *lease, 180); err == nil || got.Generation != 0 {
				t.Fatal("renewal substituted immutable lease identity")
			}
		})
	}
}

func TestAuditExportWorkerClaimRefusesInvalidInputBeforeSQL(t *testing.T) {
	for _, kind := range []string{"scope", "export", "worker", "token", "short duration", "long duration", "nil context", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			authority, database, scope, wire := auditExportWorkerLeaseFixture(t)
			export, worker, token, seconds := wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180
			ctx := context.Background()
			switch kind {
			case "scope":
				scope = domain.Scope{}
			case "export":
				export = "not-an-export"
			case "worker":
				worker = " "
			case "token":
				token = "short"
			case "short duration":
				seconds = 59
			case "long duration":
				seconds = 301
			case "nil context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			database.queries = nil
			if lease, err := authority.Claim(ctx, scope, export, worker, token, seconds); err == nil || lease != nil || len(database.queries) != 0 {
				t.Fatal("invalid call reached SQL")
			}
		})
	}
}

func TestAuditExportWorkerNullClaimHasNoCompletionEvidence(t *testing.T) {
	authority, database, scope, wire := auditExportWorkerLeaseFixture(t)
	database.respond = func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
		if sql == auditExportWorkerReadySQL {
			return json.RawMessage(`true`), nil
		}
		return json.RawMessage(`null`), nil
	}
	lease, err := authority.Claim(context.Background(), scope, wire["export_id"].(string), "audit-export-worker", strings.Repeat("a", 64), 180)
	if err != nil || lease != nil {
		t.Fatal("null claim invented a lease or terminal evidence", err)
	}
}
