package main

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Dispatch must construct the actual cloud-backed mode without touching the
// database or requesting ambient credentials during composition.
func TestAttackLabReconcilerRuntimeDispatch(t *testing.T) {
	r, err := composeWorkerRuntime(context.Background(), loadAttackLabReconcilerFixture(t), readyWorkerDatabase{})
	if err != nil {
		t.Fatal("production mode not mounted", err)
	}
	if r.Processor == nil || r.Ready == nil || r.Close == nil {
		t.Fatal("incomplete worker runtime")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAttackLabReconcilerRuntimeReadOnlyArtifacts(t *testing.T) {
	api := &discoveryS3APIStub{body: []byte(`{"version":"redacted_page_v1"}`)}
	c := productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 1 << 20}
	writer, err := newProductionDiscoveryArtifactAuthority(api, c)
	if err != nil {
		t.Fatal(err)
	}
	// Seed through the real store, then give the reconciler only its reader.
	ref := fixtureAttackLabLinkArtifactReference(t)
	artifact, err := writer.Put(context.Background(), artifactstore.PutRequest{Locator: ref, MediaType: "application/json", Body: api.body})
	if err != nil {
		t.Fatal(err)
	}
	api.put = nil
	reader, err := newExistingTestArtifactReader(api, c)
	if err != nil {
		t.Fatal("reader composition rejected", err)
	}
	if _, ok := reader.(interface {
		Put(context.Context, artifactstore.PutRequest) (artifactstore.Artifact, error)
	}); ok {
		t.Fatal("reconciler exposes writes")
	}
	got, err := reader.Get(context.Background(), artifact.Locator)
	if err != nil || string(got.Body) != string(api.body) || api.put != nil {
		t.Fatal("read-only artifact retrieval failed", err)
	}
	if _, err := reader.ObjectReference(artifact.Locator); err != nil {
		t.Fatal(err)
	}
}

func fixtureAttackLabLinkArtifactReference(t *testing.T) artifactstore.Locator {
	t.Helper()
	ref, err := domain.ParseEvidenceRef(discoveryCredentialID(8).String())
	if err != nil {
		t.Fatal(err)
	}
	return artifactstore.Locator{Scope: discoveryCredentialScope(t), Reference: ref}
}

func loadAttackLabReconcilerFixture(t *testing.T) workerRuntimeConfig {
	t.Helper()
	env := attackLabReconcilerEnvironment()
	c, err := loadWorkerRuntimeConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Readiness refusal must prevent scheduling, and closed runtimes must never
// borrow their database or artifact dependency again.
func TestAttackLabReconcilerRuntimeComposition(t *testing.T) {
	c := loadAttackLabReconcilerFixture(t)
	store, _, _ := fixtureExistingTestEvidence(t)
	queries, closes := 0, 0
	available := false
	db := &reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		queries++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded runtime query")
		}
		if q != "SELECT zasp_sa_attack_lab_reconcile_scopes($1,$2,$3,$4,$5,$6)" {
			t.Fatal("unexpected authority", q)
		}
		return json.RawMessage("[]"), nil
	}}
	r, err := composeAttackLabLinkRuntime(c, db, existingTestRuntimeDependencies{Artifacts: store,
		Ready: func(context.Context) error {
			if !available {
				return errRuntimeUnavailable
			}
			return nil
		},
		Close: func() error { closes++; return nil },
	})
	if err != nil {
		t.Fatal("runtime composition rejected", err)
	}
	if r.Processor.RunOnce(context.Background()) == nil {
		t.Fatal("unready runtime scheduled")
	}
	available = true
	if err := r.Processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if queries == 0 {
		t.Fatal("runtime bypassed database readiness")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	last := queries
	if r.Ready(context.Background()) == nil || r.Processor.RunOnce(context.Background()) == nil {
		t.Fatal("closed runtime admitted work")
	}
	if err := r.Close(); err != nil || closes != 1 || queries != last {
		t.Fatal("close not idempotent or dependencies reused")
	}
}

// Shutdown must cancel a readiness borrower as well as execution and retain
// cloud/database ownership when an external call has not joined.
func TestAttackLabReconcilerRuntimeCloseRetainsReadinessBorrower(t *testing.T) {
	c := loadAttackLabReconcilerFixture(t)
	c.ShutdownTimeout = time.Second
	store, _, _ := fixtureExistingTestEvidence(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var closed atomic.Int32
	r, err := composeAttackLabLinkRuntime(c, &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) { return json.RawMessage("[]"), nil }}, existingTestRuntimeDependencies{Artifacts: store,
		Ready: func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return ctx.Err()
		},
		Close: func() error { closed.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Ready(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("readiness not entered")
	}
	var databaseClosed atomic.Int32
	closeAll := closeWorkerRuntimeDatabase(c.Mode, r.Close, func() error { databaseClosed.Add(1); return nil })
	if closeAll() == nil || closed.Load() != 0 || databaseClosed.Load() != 0 {
		t.Fatal("unjoined borrower lost its dependencies")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("readiness was not cancelled")
	}
	if r.Ready(context.Background()) == nil {
		t.Fatal("closed runtime borrowed readiness")
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel hidden")
		}
	case <-time.After(time.Second):
		t.Fatal("readiness failed to join")
	}
	if err := closeAll(); err != nil || closed.Load() != 1 || databaseClosed.Load() != 1 {
		t.Fatal("joined runtime cleanup failed")
	}
}
