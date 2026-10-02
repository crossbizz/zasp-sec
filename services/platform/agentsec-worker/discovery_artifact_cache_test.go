package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Removing the live batch guard leaks cached data after revocation. Omitting
// exact scope/version keys or clones corrupts tenant and immutable-byte bounds.
func TestDiscoveryArtifactCacheCurrentScopedBatch(t *testing.T) {
	scope := discoveryCredentialScope(t)
	config := productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20}
	s3 := &productVersionedS3{items: map[string]*discoveryS3APIStub{}}
	store, err := newProductionDiscoveryArtifactAuthority(s3, config)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := newDiscoveryArtifactCache(store, config, 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	id := strings.Repeat("a", 64)
	checks, revoked := 0, false
	ctx, cancel, err := collection.WithScopedProductEffect(context.Background(), id, scope, time.Now().Add(time.Minute), func(context.Context) error {
		checks++
		if revoked {
			return errors.New("revoked")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	put := func(n int) artifactstore.Artifact {
		ref, _ := domain.ParseEvidenceRef(discoveryCredentialID(n).String())
		a, err := cache.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: []byte(`{"verified":true}`)})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a, b := put(8), put(9)
	before := checks
	batch, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator, b.Locator})
	if err != nil || len(batch) != 2 || checks != before+1 {
		t.Fatal("bounded hit guard", checks-before, err)
	}
	batch[0].Body[0] = '!'
	before = checks
	again, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator})
	if err != nil || !bytes.Equal(again[0].Body, a.Body) || checks != before+1 {
		t.Fatal("cached authorization or borrowed bytes", err)
	}
	revoked = true
	if got, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err == nil || len(got) != 0 {
		t.Fatal("revoked cached disclosure")
	}
	revoked = false
	foreign, _ := domain.NewScope(discoveryCredentialID(20), scope.WorkspaceID(), scope.EnvironmentID())
	bad := a.Locator
	bad.Scope = foreign
	if got, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator, bad}); err == nil || len(got) != 0 {
		t.Fatal("mixed scope")
	}
	if got, err := cache.GetEffectBatch(ctx, strings.Repeat("b", 64), scope, []artifactstore.Locator{a.Locator}); err == nil || len(got) != 0 {
		t.Fatal("mixed effect")
	}
	unscoped, end, err := collection.WithProductEffect(context.Background(), id, time.Now().Add(time.Minute), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	if _, err := cache.GetEffectBatch(unscoped, id, scope, []artifactstore.Locator{a.Locator}); err == nil {
		t.Fatal("unscoped guard accepted")
	}
	bad = a.Locator
	bad.VersionID = "foreign-version"
	if _, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{bad}); err == nil {
		t.Fatal("version alias")
	}
	// FIFO eviction forces a real verified storage miss; the second locator is
	// still a hit. Then a new worker cache proves the same cold-storage path.
	c := put(10)
	before = checks
	if _, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator, c.Locator}); err != nil || checks < before+3 {
		t.Fatal("eviction/mixed miss", checks-before, err)
	}
	cold, err := newDiscoveryArtifactCache(store, config, 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if got, err := cold.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err != nil || !bytes.Equal(got[0].Body, a.Body) {
		t.Fatal("cold restart", err)
	}
	// Revocation after a miss completes but before the hit batch is copied must
	// refuse the entire result. No cross-IO authorization freshness window.
	checksInMiss := 0
	changing, stop, err := collection.WithScopedProductEffect(context.Background(), id, scope, time.Now().Add(time.Minute), func(context.Context) error {
		checksInMiss++
		if checksInMiss > 3 {
			return errors.New("revoked after miss")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if got, err := cold.GetEffectBatch(changing, id, scope, []artifactstore.Locator{b.Locator, a.Locator}); err == nil || len(got) != 0 {
		t.Fatal("miss kept stale authorization for hit batch", checksInMiss)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err == nil {
		t.Fatal("closed cache")
	}
}

func TestDiscoveryArtifactCacheTamperByteCapAndJoinedClose(t *testing.T) {
	scope := discoveryCredentialScope(t)
	config := productionDiscoveryArtifactConfig{Bucket: "zasp-production-evidence", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", OperationTimeout: time.Second, MaximumBytes: 64 << 20}
	s3 := &productVersionedS3{items: map[string]*discoveryS3APIStub{}}
	store, err := newProductionDiscoveryArtifactAuthority(s3, config)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := newDiscoveryArtifactCache(store, config, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	id := strings.Repeat("a", 64)
	ctx, cancel, err := collection.WithScopedProductEffect(context.Background(), id, scope, time.Now().Add(time.Minute), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	ref, _ := domain.ParseEvidenceRef(discoveryCredentialID(8).String())
	a, err := cache.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: []byte(`{"verified":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range s3.items {
		item.body[0] = '!'
	}
	if got, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err != nil || !bytes.Equal(got[0].Body, a.Body) {
		t.Fatal("borrowed stored body changed cache", err)
	}
	cold, err := newDiscoveryArtifactCache(store, config, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if _, err := cold.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err == nil {
		t.Fatal("cold tamper accepted")
	}
	for _, item := range s3.items {
		item.body[0] = '{'
	}
	if _, err := cold.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err != nil {
		t.Fatal("error poisoned cache", err)
	}
	other, _ := domain.NewScope(discoveryCredentialID(20), scope.WorkspaceID(), scope.EnvironmentID())
	foreign, stop, err := collection.WithScopedProductEffect(context.Background(), id, other, time.Now().Add(time.Minute), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	b, err := cache.Put(foreign, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: other, Reference: ref}, MediaType: "application/json", Body: []byte(`{"foreign":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	reads := s3.reads
	if got, err := cache.GetEffectBatch(ctx, id, scope, []artifactstore.Locator{a.Locator}); err != nil || !bytes.Equal(got[0].Body, a.Body) || s3.reads <= reads {
		t.Fatal("byte cap or tenant alias", err)
	}
	if got, err := cache.GetEffectBatch(foreign, id, other, []artifactstore.Locator{b.Locator}); err != nil || !bytes.Equal(got[0].Body, b.Body) {
		t.Fatal("foreign scoped bytes", err)
	}
	entered, release, finished, closed := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan error, 1)
	blocked, done, err := collection.WithScopedProductEffect(context.Background(), id, other, time.Now().Add(time.Minute), func(context.Context) error { close(entered); <-release; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	go func() {
		_, err := cache.GetEffectBatch(blocked, id, other, []artifactstore.Locator{b.Locator})
		finished <- err
	}()
	<-entered
	go func() { closed <- cache.Close() }()
	select {
	case <-closed:
		t.Fatal("close did not join active batch")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
