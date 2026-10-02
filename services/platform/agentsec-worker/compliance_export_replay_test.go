package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type complianceReplayDriver struct {
	put func(context.Context, artifactstore.DriverObject) (artifactstore.DriverObject, error)
}

func (d complianceReplayDriver) Put(ctx context.Context, o artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	return d.put(ctx, o)
}
func (d complianceReplayDriver) Get(context.Context, artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	return artifactstore.DriverObject{}, errors.New("unexpected get")
}
func (d complianceReplayDriver) Delete(context.Context, artifactstore.DriverLocator) error {
	return errors.New("unexpected delete")
}

type complianceReplayDatabase struct {
	prepared, captured json.RawMessage
	loadErr, finishErr error
	queries            []string
}

func (d *complianceReplayDatabase) QueryJSON(_ context.Context, q string, _ ...any) (json.RawMessage, error) {
	d.queries = append(d.queries, q)
	if q == complianceCaptureSQL {
		return d.captured, nil
	}
	if q == compliancePrepareSQL {
		return d.prepared, d.loadErr
	}
	if q == complianceFinishSQL {
		return json.RawMessage(`{}`), d.finishErr
	}
	return nil, errors.New("unexpected SQL during replay")
}

func TestComplianceReplayOutcomes(t *testing.T) {
	for _, name := range []string{"completed", "unprepared", "load_failed", "put_failed", "put_panic", "bad_receipt", "finish_failed", "reconcile_rejected"} {
		t.Run(name, func(t *testing.T) {
			o, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
			w, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
			e, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
			scope, _ := domain.NewScope(o, w, e)
			id := "pid_10000004-0000-4000-8000-000000000004"
			body := []byte("pinned-v1")
			hash := sha256.Sum256(body)
			raw, _ := json.Marshal(map[string]any{"bytes_hex": hex.EncodeToString(body), "renderer_revision": "compliance-envelope-v1", "reference": id, "size": len(body), "sha256": hex.EncodeToString(hash[:]), "format_sizes": map[string]int{"json": 1, "csv": 1, "readable": 1}})
			db := &complianceReplayDatabase{prepared: raw}
			snapshot, _ := json.Marshal(map[string]any{"organization_id": o.String(), "workspace_id": w.String(), "environment_id": e.String(), "mapping_revision": "product-evidence-v1", "snapshot_at": time.Now(), "controls": []any{}})
			snapshotHash := sha256.Sum256(snapshot)
			db.captured, _ = json.Marshal(map[string]any{"snapshot": json.RawMessage(snapshot), "mapping_revision": "product-evidence-v1", "sha256": hex.EncodeToString(snapshotHash[:])})
			if name == "load_failed" {
				db.loadErr = errors.New("load unavailable")
			}
			if name == "finish_failed" {
				db.finishErr = errors.New("finish unavailable")
			}
			handle := &complianceLeaseHandle{lease: complianceExportLease{Scope: scope, ExportID: id, WorkerID: "worker-1", Token: strings.Repeat("a", 64), Lane: "execute", Generation: 2, Attempt: 2, ExpiresAt: time.Now().Add(time.Minute), Prepared: true}}
			if name == "reconcile_rejected" {
				handle.lease.Lane = "reconcile"
			}
			if name == "unprepared" {
				handle.lease.Prepared = false
			}
			puts, renders := 0, 0
			store, err := artifactstore.NewExport(complianceReplayDriver{put: func(_ context.Context, obj artifactstore.DriverObject) (artifactstore.DriverObject, error) {
				puts++
				if len(db.queries) == 0 || db.queries[len(db.queries)-1] != compliancePrepareSQL {
					t.Error("provider I/O preceded persisted intent")
				}
				if !bytes.Equal(obj.Body, body) {
					t.Errorf("changed stored bytes")
				}
				if name == "put_failed" {
					return artifactstore.DriverObject{}, errors.New("unknown provider write")
				}
				if name == "put_panic" {
					panic("provider panic after possible write")
				}
				if name != "bad_receipt" {
					obj.VersionID = "immutable-v1"
				}
				return obj, nil
			}}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 8 << 20})
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := executeComplianceExportPackage(context.Background(), newPostgresComplianceExportAuthority(db), store, handle, func(_ context.Context, _ complianceExportLease, got json.RawMessage) (compliancePreparedArtifact, error) {
				renders++
				if name != "unprepared" {
					return compliancePreparedArtifact{}, errors.New("must not render")
				}
				if !bytes.Equal(got, snapshot) {
					t.Error("renderer snapshot changed")
				}
				return compliancePreparedArtifact{Bytes: body, RendererRevision: "compliance-envelope-v1", Reference: id, Size: int64(len(body)), SHA256: hex.EncodeToString(hash[:]), FormatSizes: map[string]int64{"json": 1, "csv": 1, "readable": 1}}, nil
			})
			want := complianceWriteUnknown
			wantPuts := 1
			success := name == "completed" || name == "unprepared"
			wantRenders := 0
			if name == "unprepared" {
				wantRenders = 1
			}
			if success {
				want = complianceWriteCompleted
			}
			if name == "load_failed" || name == "reconcile_rejected" {
				want = complianceBeforePut
				wantPuts = 0
			}
			if outcome != want || (err == nil) != success || puts != wantPuts || renders != wantRenders {
				t.Fatalf("outcome=%s err=%v puts=%d renders=%d", outcome, err, puts, renders)
			}
			for _, q := range db.queries {
				if q == complianceRetrySQL || q == complianceCleanupSQL {
					t.Fatal("replay released uncertain storage accounting")
				}
			}
		})
	}
}

func TestComplianceReplayRestartProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_COMPLIANCE_WORKER_DSN")
	if dsn == "" {
		t.Skip("owned parent launches worker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = "compliance_executor"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	a := newPostgresComplianceExportAuthority(db)
	o, _ := domain.ParseProductID(os.Getenv("ZASP_COMPLIANCE_ORG"))
	w, _ := domain.ParseProductID(os.Getenv("ZASP_COMPLIANCE_WORKSPACE"))
	e, _ := domain.ParseProductID(os.Getenv("ZASP_COMPLIANCE_ENV"))
	scope, _ := domain.NewScope(o, w, e)
	id := os.Getenv("ZASP_COMPLIANCE_JOB")
	pinned := []byte("stored-v1-bytes-before-process-exit")
	if os.Getenv("ZASP_COMPLIANCE_MODE") == "prepare" {
		l, err := a.Claim(ctx, scope, id, "restart-worker", strings.Repeat("a", 64), "execute")
		if err != nil || l == nil {
			t.Fatalf("claim: %+v %v", l, err)
		}
		if _, err = a.Capture(ctx, *l); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(pinned)
		_, err = a.Prepare(ctx, *l, compliancePreparedArtifact{Bytes: pinned, RendererRevision: "compliance-envelope-v1", Reference: id, Size: int64(len(pinned)), SHA256: hex.EncodeToString(h[:]), FormatSizes: map[string]int64{"json": 10, "csv": 10, "readable": 10}})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("registered worker committed exact v1 intent then exited before I/O")
		return
	}
	expires, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_COMPLIANCE_EXPIRY"))
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := strconv.ParseInt(os.Getenv("ZASP_COMPLIANCE_GENERATION"), 10, 64)
	attempt, _ := strconv.Atoi(os.Getenv("ZASP_COMPLIANCE_ATTEMPT"))
	handle := &complianceLeaseHandle{lease: complianceExportLease{Scope: scope, ExportID: id, WorkerID: "restart-worker", Token: strings.Repeat("b", 64), Lane: "execute", Generation: gen, Attempt: attempt, ExpiresAt: expires, Captured: true, Prepared: true}}
	renderCalls, puts := 0, 0
	renderV2 := func(context.Context, complianceExportLease, json.RawMessage) (compliancePreparedArtifact, error) {
		renderCalls++
		return compliancePreparedArtifact{Bytes: []byte("different-v2-rendered-bytes"), RendererRevision: "compliance-envelope-v2"}, nil
	}
	store, err := artifactstore.NewExport(complianceReplayDriver{put: func(ctx context.Context, obj artifactstore.DriverObject) (artifactstore.DriverObject, error) {
		puts++
		if !bytes.Equal(obj.Body, pinned) {
			t.Errorf("rerendered instead of replaying SQL intent: %q", obj.Body)
			return artifactstore.DriverObject{}, errWorkerExecution
		}
		if err := handle.heartbeat(ctx, a); err != nil {
			return artifactstore.DriverObject{}, err
		}
		latest := handle.current()
		if latest.Generation != gen || latest.Attempt != attempt || !latest.ExpiresAt.After(expires) {
			return artifactstore.DriverObject{}, errWorkerExecution
		}
		timer := time.NewTimer(time.Until(expires.Add(20 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return artifactstore.DriverObject{}, ctx.Err()
		case <-timer.C:
		}
		obj.VersionID = "immutable-replay-v1"
		return obj, nil
	}}, artifactstore.Config{OperationTimeout: 5 * time.Second, MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := executeComplianceExportPackage(ctx, a, store, handle, renderV2)
	if err != nil || outcome != complianceWriteCompleted || renderCalls != 0 || puts != 1 {
		t.Fatalf("replay outcome=%s error=%v renderer_v2_calls=%d puts=%d", outcome, err, renderCalls, puts)
	}
	if time.Now().Before(expires) {
		t.Fatal("Finish did not cross original lease deadline")
	}
	t.Log("fresh registered worker replayed SQL v1 bytes through NewExport.Put; renderer-v2 calls=0; Finish used renewed lease after original deadline")
}
