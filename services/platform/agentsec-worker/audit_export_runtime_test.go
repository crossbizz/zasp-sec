package main

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

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func auditExportRejectedLeaseTokens() map[string]string {
	return map[string]string{"legacy16": strings.Repeat("a", 16), "legacy32": strings.Repeat("a", 32), "short63": strings.Repeat("a", 63), "long65": strings.Repeat("a", 65), "uppercase": strings.Repeat("A", 64), "nonhex": strings.Repeat("g", 64), "zero": strings.Repeat("0", 64), "whitespace": " " + strings.Repeat("a", 64), "empty": ""}
}

func TestAuditExportExecutorRejectsNonSQLLeaseTokensBeforeDatabase(t *testing.T) {
	for name, token := range auditExportRejectedLeaseTokens() {
		t.Run(name, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, true)
			f.config.NewLeaseToken = func() (string, error) { return token, nil }
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := recoveryScope(f.lease.Binding.OrganizationID, f.lease.Binding.WorkspaceID, f.lease.Binding.EnvironmentID)
			f.db.queries = nil
			if executor.Execute(context.Background(), scope, f.lease.Binding.ExportID) == nil || len(f.db.queries) != 0 {
				t.Fatal("token rejected by SQL reached executor authority")
			}
		})
	}
}

// The SQL boundary and provider driver are declared fixtures. The executor,
// repository, codecs and typed artifact store are real; this is not PG/S3 proof.
type auditExportExecutionFixture struct {
	t                                   *testing.T
	db                                  *auditExportWorkerDatabase
	config                              auditExportExecutorConfig
	lease                               auditExportLease
	progress, page                      map[string]any
	chunk, manifest                     []byte
	objects                             map[string]artifactstore.DriverObject
	trace                               []string
	ready, captured, recorded, finished bool
	change                              string
	cancel                              context.CancelFunc
	completionIDs                       []string
}

func newAuditExportExecutionFixture(t *testing.T, empty bool) *auditExportExecutionFixture {
	t.Helper()
	_, db, lease, progress, page, chunk := auditExportFrozenFixture(t)
	if empty {
		progress["event_count"] = int64(0)
		progress["chunk_count"] = int64(0)
		progress["chunk_bytes"] = int64(0)
		progress["chain_root"] = audit.ExportZeroDigest
		chunk = nil
	}
	manifest, err := audit.EncodeExportManifest(auditExportCaptureFromWire(lease, progress).Manifest)
	if err != nil {
		t.Fatal(err)
	}
	f := &auditExportExecutionFixture{t: t, db: db, lease: lease, progress: progress, page: page, chunk: chunk, manifest: manifest, objects: map[string]artifactstore.DriverObject{}, ready: true}
	store, err := artifactstore.NewExport(f, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: audit.ExportMaximumChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	f.config = auditExportExecutorConfig{Database: db, Policy: auditExportTrustedPolicy{Configuration: auditExportWorkerPolicyFixture(), Store: store}, WorkerID: "audit-export-worker", LeaseSeconds: 180, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }}
	db.respond = f.query
	return f
}

func (f *auditExportExecutionFixture) query(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	if sql == auditExportWorkerReadySQL {
		if !f.ready {
			return json.RawMessage(`false`), nil
		}
		return json.RawMessage(`true`), nil
	}
	switch sql {
	case auditExportWorkerClaimSQL, auditExportWorkerHeartbeatSQL:
		if sql == auditExportWorkerClaimSQL {
			f.trace = append(f.trace, "claim")
			if f.finished || f.change == "busy" {
				return json.RawMessage(`null`), nil
			}
		} else {
			f.trace = append(f.trace, "heartbeat")
		}
		f.lease.ExpiresAt = time.Now().UTC().Add(179 * time.Second)
		return json.Marshal(map[string]any{"organization_id": f.lease.Binding.OrganizationID, "workspace_id": f.lease.Binding.WorkspaceID, "environment_id": f.lease.Binding.EnvironmentID, "export_id": f.lease.Binding.ExportID, "capture_id": f.lease.Binding.CaptureID, "policy_id": f.lease.Policy.PolicyID, "policy_digest": f.lease.Policy.PolicyDigest, "generation": f.lease.Generation, "attempt": f.lease.Attempt, "lease_expires_at": f.lease.ExpiresAt, "captured": f.captured, "storage_policy": f.lease.Policy})
	case auditExportWorkerCaptureSQL:
		f.trace = append(f.trace, "capture")
		f.captured = true
		if f.change == "capture lost" {
			return nil, errors.New("lost capture response")
		}
		if f.recorded {
			f.progress["next_chunk"] = int64(2)
			f.progress["next_event"] = int64(2)
			f.progress["recorded_chunk_count"] = int64(1)
			f.progress["recorded_chunk_bytes"] = int64(len(f.chunk))
			digest := sha256.Sum256(f.chunk)
			f.progress["previous_digest"] = hex.EncodeToString(digest[:])
		}
		if f.change == "after capture drift" {
			f.ready = false
		}
		return json.Marshal(f.progress)
	case auditExportWorkerFrozenPageSQL:
		f.trace = append(f.trace, "page")
		if f.change == "after page drift" {
			f.ready = false
		}
		return json.Marshal(f.page)
	case auditExportWorkerPrepareChunkSQL, auditExportWorkerPrepareManifestSQL:
		kind, id, want := "chunk", "pid_52000020-0000-4000-8000-000000000020", f.chunk
		if sql == auditExportWorkerPrepareManifestSQL {
			kind = "manifest"
			id = "pid_52000021-0000-4000-8000-000000000021"
			want = f.manifest
		}
		f.trace = append(f.trace, "prepare-"+kind)
		if len(args) != 14 || !bytes.Equal(args[13].([]byte), want) {
			f.t.Fatal("executor changed frozen canonical bytes")
		}
		digest := sha256.Sum256(want)
		object := "s3://zasp-audit-export-fixture/organizations/" + f.lease.Binding.OrganizationID + "/workspaces/" + f.lease.Binding.WorkspaceID + "/environments/" + f.lease.Binding.EnvironmentID + "/exports/" + id
		wire := map[string]any{"binding": f.lease.Binding, "storage_policy": f.lease.Policy, "kind": kind, "artifact_id": id, "object_reference": object, "sha256": hex.EncodeToString(digest[:]), "size_bytes": int64(len(want))}
		if kind == "chunk" {
			wire["ordinal"] = int64(1)
			wire["first_event"] = int64(1)
			wire["event_count"] = int64(1)
			wire["previous_digest"] = audit.ExportZeroDigest
		}
		if f.change == "prepare lost" {
			return nil, errors.New("lost intent response")
		}
		return json.Marshal(wire)
	case auditExportWorkerRecordChunkSQL:
		f.trace = append(f.trace, "record")
		f.recorded = true
		if f.change == "record lost" {
			return nil, errors.New("lost receipt response")
		}
		return json.RawMessage(`{"recorded":true}`), nil
	case auditExportWorkerFinishSQL:
		f.trace = append(f.trace, "finish")
		if len(args) != 17 {
			f.t.Fatal("finish argument count")
		}
		f.completionIDs = append(f.completionIDs, args[16].(string))
		if len(f.chunk) > 0 && !f.recorded {
			f.t.Fatal("finish preceded recorded chunk")
		}
		if f.change == "finish before commit" {
			return nil, errors.New("finish did not commit")
		}
		f.finished = true
		if f.change == "finish lost" {
			return nil, errors.New("lost finish response")
		}
		manifest, err := audit.DecodeExportManifest(f.manifest)
		if err != nil {
			f.t.Fatal(err)
		}
		return json.Marshal(auditExportTerminalDescriptorFixture(f.t, f.lease, manifest))
	case auditExportWorkerTerminalSQL:
		f.trace = append(f.trace, "terminal")
		if !f.finished {
			return json.RawMessage(`{"state":"nonterminal"}`), nil
		}
		manifest, err := audit.DecodeExportManifest(f.manifest)
		if err != nil {
			f.t.Fatal(err)
		}
		return json.Marshal(map[string]any{"state": "ready", "export": auditExportTerminalDescriptorFixture(f.t, f.lease, manifest)})
	case auditExportWorkerRetrySQL:
		f.trace = append(f.trace, "retry")
		if f.finished {
			return nil, errors.New("terminal lease no longer mutable")
		}
		return json.RawMessage(`{"state":"retry","failure_code":null,"available_at":"2026-09-12T01:02:03.456789Z"}`), nil
	}
	f.t.Fatal("unexpected executor query", sql)
	return nil, errors.New("unexpected query")
}

func (f *auditExportExecutionFixture) PlannedObjectReference(locator artifactstore.DriverLocator) (string, error) {
	f.trace = append(f.trace, "plan")
	if f.change == "planned mismatch" {
		return "s3://different-bucket/" + locator.Key, nil
	}
	return "s3://zasp-audit-export-fixture/" + locator.Key, nil
}
func (f *auditExportExecutionFixture) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	if f.change == "returned reference" {
		return "s3://different-bucket/" + locator.Key, nil
	}
	return "s3://zasp-audit-export-fixture/" + locator.Key, nil
}
func (f *auditExportExecutionFixture) Put(ctx context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	f.trace = append(f.trace, "put")
	if existing, ok := f.objects[object.Key]; ok {
		if existing.SHA256 != object.SHA256 || !bytes.Equal(existing.Body, object.Body) {
			return artifactstore.DriverObject{}, errors.New("immutable conflict")
		}
		return existing, nil
	}
	object.VersionID = "version-1"
	object.Body = bytes.Clone(object.Body)
	f.objects[object.Key] = object
	if f.change == "put lost" {
		return artifactstore.DriverObject{}, errors.New("lost saved put response")
	}
	if f.change == "after put drift" {
		f.ready = false
	}
	if f.change == "provider cancellation" {
		f.cancel()
	}
	if f.change == "null version" {
		object.VersionID = "null"
	}
	return object, nil
}
func (f *auditExportExecutionFixture) Get(ctx context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	f.trace = append(f.trace, "get")
	object, ok := f.objects[locator.Key]
	if !ok || object.VersionID != locator.VersionID {
		return artifactstore.DriverObject{}, errors.New("missing pinned version")
	}
	switch f.change {
	case "get failure":
		return artifactstore.DriverObject{}, errors.New("readback failed")
	case "different readback":
		object.Body = []byte(`{"changed":true}`)
		object.SHA256 = sha256.Sum256(object.Body)
		object.Size = int64(len(object.Body))
	case "readback media":
		object.MediaType = "application/octet-stream"
	case "readback version":
		object.VersionID = "version-2"
	}
	return object, nil
}
func (f *auditExportExecutionFixture) Delete(context.Context, artifactstore.DriverLocator) error {
	f.t.Fatal("executor must not delete artifacts")
	return errors.New("delete forbidden")
}

func TestAuditExportExecutorFinishesVerifiedArtifactsBeforeSuccess(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "populated", true: "empty"}[empty], func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, empty)
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := domain.NewScope(workerID(t, f.lease.Binding.OrganizationID), workerID(t, f.lease.Binding.WorkspaceID), workerID(t, f.lease.Binding.EnvironmentID))
			if err := executor.Execute(context.Background(), scope, f.lease.Binding.ExportID); err != nil {
				t.Fatal("complete scoped export refused", err)
			}
			want := []string{"claim", "capture", "heartbeat", "page", "prepare-chunk", "plan", "put", "get", "record", "heartbeat", "prepare-manifest", "plan", "put", "get", "finish"}
			if empty {
				want = []string{"claim", "capture", "heartbeat", "prepare-manifest", "plan", "put", "get", "finish"}
			}
			if !f.finished || !reflect.DeepEqual(f.trace, want) {
				t.Fatal("success did not follow exact intent/readback/receipt/finish sequence", f.trace)
			}
			f.trace = nil
			if err := executor.Execute(context.Background(), scope, f.lease.Binding.ExportID); err != nil || !reflect.DeepEqual(f.trace, []string{"claim", "terminal"}) {
				t.Fatal("duplicate delivery lacked durable terminal read", err, f.trace)
			}
		})
	}
}

func TestAuditExportExecutorRefusesUntrustedConfiguration(t *testing.T) {
	for _, kind := range []string{"database", "store", "policy", "worker", "lease", "retry", "token function"} {
		t.Run(kind, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, false)
			switch kind {
			case "database":
				f.config.Database = nil
			case "store":
				f.config.Policy.Store = nil
			case "policy":
				f.config.Policy.Configuration.Bucket = ""
			case "worker":
				f.config.WorkerID = ""
			case "lease":
				f.config.LeaseSeconds = 301
			case "retry":
				f.config.RetrySeconds = 0
			case "token function":
				f.config.NewLeaseToken = nil
			}
			if executor, err := newAuditExportExecutor(f.config); err == nil || executor != nil {
				t.Fatal("invalid executor configuration accepted", kind)
			}
		})
	}
}

func TestAuditExportExecutorRefusesUnverifiedProviderOrLostAuthority(t *testing.T) {
	for _, kind := range []string{"busy", "planned mismatch", "mixed profile", "returned reference", "null version", "get failure", "different readback", "readback media", "readback version", "after capture drift", "after page drift", "after put drift", "provider cancellation", "unready", "invalid token", "foreign scope", "foreign export"} {
		t.Run(kind, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, false)
			f.change = kind
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			if kind == "mixed profile" {
				store, err := artifactstore.New(f, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: audit.ExportMaximumChunkBytes})
				if err != nil {
					t.Fatal(err)
				}
				f.config.Policy.Store = store
			}
			if kind == "invalid token" {
				f.config.NewLeaseToken = func() (string, error) { return "invalid", nil }
			}
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unready" {
				f.ready = false
			}
			scope, _ := domain.NewScope(workerID(t, f.lease.Binding.OrganizationID), workerID(t, f.lease.Binding.WorkspaceID), workerID(t, f.lease.Binding.EnvironmentID))
			export := f.lease.Binding.ExportID
			if kind == "foreign scope" {
				scope, _ = domain.NewScope(scope.OrganizationID(), workerID(t, "pid_52000099-0000-4000-8000-000000000099"), scope.EnvironmentID())
			}
			if kind == "foreign export" {
				export = "pid_52000099-0000-4000-8000-000000000099"
			}
			if err := executor.Execute(ctx, scope, export); err == nil || f.finished || f.recorded {
				t.Fatal("unverified execution acknowledged", kind, f.trace)
			}
			noPut := kind == "busy" || kind == "planned mismatch" || kind == "mixed profile" || kind == "after capture drift" || kind == "after page drift" || kind == "unready" || kind == "invalid token" || kind == "foreign scope" || kind == "foreign export"
			if noPut && len(f.objects) != 0 {
				t.Fatal("refusal wrote provider objects", kind)
			}
			if kind == "busy" && !reflect.DeepEqual(f.trace, []string{"claim", "terminal"}) {
				t.Fatal("null claim bypassed terminal authority", f.trace)
			}
			if kind == "provider cancellation" && f.trace[len(f.trace)-1] != "put" {
				t.Fatal("cancellation detached more work", f.trace)
			}
		})
	}
}

func TestAuditExportExecutorRecreatedAfterLostResponsesResumesExactArtifacts(t *testing.T) {
	for _, kind := range []string{"capture lost", "prepare lost", "put lost", "record lost", "finish before commit", "finish lost"} {
		t.Run(kind, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, false)
			f.change = kind
			scope, _ := domain.NewScope(workerID(t, f.lease.Binding.OrganizationID), workerID(t, f.lease.Binding.WorkspaceID), workerID(t, f.lease.Binding.EnvironmentID))
			first, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := first.Execute(context.Background(), scope, f.lease.Binding.ExportID); err == nil {
				t.Fatal("lost response was acknowledged", kind)
			}
			f.change = ""
			f.trace = nil
			// A fresh executor has no previous in-process progress. The declared SQL
			// state and immutable provider objects remain, like restart fixtures.
			restarted, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := restarted.Execute(context.Background(), scope, f.lease.Binding.ExportID); err != nil || !f.finished || len(f.objects) != 2 {
				t.Fatal("recreated executor did not finish exact retained work", kind, err, f.trace)
			}
			if kind == "finish lost" && !reflect.DeepEqual(f.trace, []string{"claim", "terminal"}) {
				t.Fatal("completed lost response republished artifacts", f.trace)
			}
			if kind == "record lost" || kind == "finish before commit" {
				for _, step := range f.trace {
					if step == "page" || step == "prepare-chunk" || step == "record" {
						t.Fatal("recorded chunk prefix was repeated", f.trace)
					}
				}
			}
			if kind == "finish before commit" && (len(f.completionIDs) != 2 || f.completionIDs[0] != f.completionIDs[1]) {
				t.Fatal("completion audit identity changed across executor recreation")
			}
			for _, object := range f.objects {
				if !bytes.Equal(object.Body, f.chunk) && !bytes.Equal(object.Body, f.manifest) {
					t.Fatal("recovery changed immutable content")
				}
			}
		})
	}
}

func TestAuditExportExecutorAcceptsOnlyDurableFailedTransition(t *testing.T) {
	for _, kind := range []string{"queued failure", "capture failure", "retry exhausted"} {
		t.Run(kind, func(t *testing.T) {
			f := newAuditExportExecutionFixture(t, false)
			base := f.db.respond
			if kind == "queued failure" {
				f.change = "busy"
			}
			if kind == "retry exhausted" {
				f.change = "planned mismatch"
			}
			f.db.respond = func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == auditExportWorkerCaptureSQL && kind == "capture failure" {
					f.trace = append(f.trace, "capture")
					return json.RawMessage(`{"state":"failed","failure_code":"invalid_source"}`), nil
				}
				if sql == auditExportWorkerRetrySQL && kind == "retry exhausted" {
					f.trace = append(f.trace, "retry")
					return json.RawMessage(`{"state":"failed","failure_code":"execution_failed","available_at":null}`), nil
				}
				if sql == auditExportWorkerTerminalSQL {
					f.trace = append(f.trace, "terminal")
					descriptor := map[string]any{"id": f.lease.Binding.ExportID, "organization_id": f.lease.Binding.OrganizationID, "workspace_id": f.lease.Binding.WorkspaceID, "environment_id": f.lease.Binding.EnvironmentID, "created_at": "2026-09-12T01:00:00.000000Z", "audit_correlation_id": "pid_52000030-0000-4000-8000-000000000030", "status": "failed", "event_count": nil, "failure_code": "capacity_exceeded"}
					if kind == "capture failure" {
						descriptor["failure_code"] = "invalid_source"
					}
					return json.Marshal(map[string]any{"state": "failed", "export": descriptor})
				}
				return base(ctx, sql, args...)
			}
			executor, err := newAuditExportExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := domain.NewScope(workerID(t, f.lease.Binding.OrganizationID), workerID(t, f.lease.Binding.WorkspaceID), workerID(t, f.lease.Binding.EnvironmentID))
			if err := executor.Execute(context.Background(), scope, f.lease.Binding.ExportID); err != nil || len(f.objects) != 0 || f.finished {
				t.Fatal("durable failure was lost or performed provider writes", kind, err)
			}
			wantLast := "terminal"
			if kind == "retry exhausted" {
				wantLast = "retry"
			}
			if f.trace[len(f.trace)-1] != wantLast {
				t.Fatal("failure success lacked terminal proof", f.trace)
			}
		})
	}
}

func TestAuditExportCompletionIdentityBindsExportAndCapture(t *testing.T) {
	binding := audit.ExportBinding{ExportID: "pid_52000004-0000-4000-8000-000000000004", CaptureID: "pid_52000005-0000-4000-8000-000000000005"}
	// Independently calculated SHA-256 namespace vector, with UUIDv4 and
	// RFC4122 variant bits applied to the first16 bytes.
	const want = "pid_cc29189d-c461-4332-95e5-d16f110afa7e"
	if got := auditExportCompletionID(binding); got != want || !validRecoveryProductID(got) {
		t.Fatal("completion audit namespace changed")
	}
	other := binding
	other.ExportID = "pid_52000006-0000-4000-8000-000000000006"
	if auditExportCompletionID(other) == want {
		t.Fatal("different export reused audit identity")
	}
	other = binding
	other.CaptureID = "pid_52000007-0000-4000-8000-000000000007"
	if auditExportCompletionID(other) == want {
		t.Fatal("different capture reused audit identity")
	}
}

func TestAuditExportCapturedQuotaIncludesCanonicalManifest(t *testing.T) {
	_, _, lease, wire, _, _ := auditExportFrozenFixture(t)
	capture := auditExportCaptureFromWire(lease, wire)
	manifest, err := audit.EncodeExportManifest(capture.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	lease.Policy.MaximumExportBytes = capture.Manifest.ChunkBytes + int64(len(manifest))
	if !validAuditExportCapture(capture, lease) {
		t.Fatal("exact complete artifact budget refused")
	}
	lease.Policy.MaximumExportBytes--
	if validAuditExportCapture(capture, lease) {
		t.Fatal("manifest bytes were not charged against export bound")
	}
}

func TestAuditExportCaptureUsesConfirmedLeaseBudget(t *testing.T) {
	for _, kind := range []string{"policy bound", "lease bound", "parent bound", "expired", "insufficient margin", "nil context", "canceled", "invalid policy bound"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now()
			lease := auditExportLease{ExpiresAt: now.Add(180 * time.Second), Policy: auditExportStoragePolicy{CaptureTimeoutSeconds: 120}}
			parent := context.Background()
			want := now.Add(120 * time.Second)
			switch kind {
			case "lease bound":
				lease.ExpiresAt = now.Add(60 * time.Second)
				want = lease.ExpiresAt.Add(-5 * time.Second)
			case "parent bound":
				var cancel context.CancelFunc
				parent, cancel = context.WithDeadline(parent, now.Add(20*time.Second))
				defer cancel()
				want = now.Add(15 * time.Second)
			case "expired":
				lease.ExpiresAt = now.Add(-time.Second)
			case "insufficient margin":
				lease.ExpiresAt = now.Add(5 * time.Second)
			case "nil context":
				parent = nil
			case "canceled":
				var cancel context.CancelFunc
				parent, cancel = context.WithCancel(parent)
				cancel()
			case "invalid policy bound":
				lease.Policy.CaptureTimeoutSeconds = 121
			}
			ctx, cancel, err := auditExportCaptureContext(parent, lease)
			if kind == "expired" || kind == "insufficient margin" || kind == "nil context" || kind == "canceled" || kind == "invalid policy bound" {
				if err == nil || ctx != nil || cancel != nil {
					t.Fatal("capture accepted invalid confirmed budget")
				}
				return
			}
			if err != nil || ctx == nil || cancel == nil {
				t.Fatal("capture budget refused", err)
			}
			defer cancel()
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(want) || deadline.After(want.Add(100*time.Millisecond)) {
				t.Fatal("capture deadline did not preserve confirmed finalization margin", deadline, want)
			}
		})
	}
}
