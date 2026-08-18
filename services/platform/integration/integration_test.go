package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func fixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureID(t, 1), fixtureID(t, 2), fixtureID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestConnectorManifestPublicBoundaryAndCatalog(t *testing.T) {
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	items, err := catalog.Search(CatalogFilter{Query: "webhook", Category: "notification", Action: "approval_response"})
	if err != nil || len(items) != 1 {
		t.Fatalf("catalog=%+v err=%v", items, err)
	}
	encoded, err := json.Marshal(items[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"adapter", "oss", "nango", "provider_key"} {
		if json.Valid(encoded) && containsFold(string(encoded), forbidden) {
			t.Fatalf("public manifest leaked %q: %s", forbidden, encoded)
		}
	}
	if err := catalog.ValidateSetup("generic-webhook", map[string]string{
		"destination_url":          "https://hooks.customer.invalid/zasp",
		"signing_secret_reference": "secret_ref_1234",
	}); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]map[string]string{
		"http":       {"destination_url": "http://customer.invalid/hook", "signing_secret_reference": "secret_ref_1234"},
		"query":      {"destination_url": "https://customer.invalid/hook?next=https://evil.invalid", "signing_secret_reference": "secret_ref_1234"},
		"per-action": {"destination_url": "https://customer.invalid/hook", "approval_url": "https://evil.invalid", "signing_secret_reference": "secret_ref_1234"},
		"loopback":   {"destination_url": "https://127.0.0.1/hook", "signing_secret_reference": "secret_ref_1234"},
	} {
		t.Run(name, func(t *testing.T) {
			if catalog.ValidateSetup("generic-webhook", config) == nil {
				t.Fatal("unsafe webhook config accepted")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := catalog.SearchContext(canceled, CatalogFilter{}); err == nil {
		t.Fatal("canceled catalog search accepted")
	}
}

func TestIntegrationLifecycleAndIdempotentSyncJob(t *testing.T) {
	sequence := 10
	generate := func() (domain.ProductID, error) { sequence++; return fixtureID(t, sequence), nil }
	now := func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	service, err := NewService(NewMemoryStore(generate, now), mustCatalog(t), now)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureScope(t)
	created, err := service.Create(context.Background(), scope, IntegrationInput{
		ConnectorKey: "generic-webhook", Name: "Response notifications",
		Configuration: map[string]string{"destination_url": "https://hooks.customer.invalid/zasp", "signing_secret_reference": "secret_ref_1234"},
	})
	if err != nil || created.Status() != IntegrationPendingAuthorization {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	if _, err := service.Authorize(context.Background(), scope, created.ID()); err != nil {
		t.Fatal(err)
	}
	sync, job, err := service.Sync(context.Background(), scope, created.ID(), "job_1234")
	if err != nil || sync.Status() != SyncQueued || job.JobID != "job_1234" || job.IntegrationID != created.ID() {
		t.Fatalf("sync=%+v job=%+v err=%v", sync, job, err)
	}
	duplicate, duplicateJob, err := service.Sync(context.Background(), scope, created.ID(), "job_1234")
	if err != nil || duplicate.ID() != sync.ID() || duplicateJob != job {
		t.Fatalf("duplicate sync was not idempotent: %+v %+v %v", duplicate, duplicateJob, err)
	}
	for _, transition := range []SyncStatus{SyncRunning, SyncSucceeded} {
		current, err := service.Transition(context.Background(), job, transition)
		if err != nil || current.Status() != transition {
			t.Fatalf("transition=%s current=%+v err=%v", transition, current, err)
		}
	}
	if _, err := service.Transition(context.Background(), job, SyncRunning); err == nil {
		t.Fatal("terminal sync moved backwards")
	}
	second, err := service.Create(context.Background(), scope, IntegrationInput{
		ConnectorKey: "generic-webhook", Name: "Second notifications",
		Configuration: map[string]string{"destination_url": "https://hooks.customer.invalid/second", "signing_secret_reference": "secret_ref_1234"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(context.Background(), scope, second.ID(), IntegrationUpdate{Name: created.Name(), Configuration: second.Configuration()}); err != ErrConflict {
		t.Fatalf("duplicate update error=%v", err)
	}
	listed, err := service.ListSyncs(context.Background(), scope, created.ID())
	if err != nil || len(listed) != 1 || listed[0].ID() != sync.ID() {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	foreign, _ := domain.NewScope(fixtureID(t, 20), fixtureID(t, 21), fixtureID(t, 22))
	if _, err := service.Get(context.Background(), foreign, created.ID()); err != ErrForbidden {
		t.Fatalf("foreign error=%v", err)
	}
}

func mustCatalog(t *testing.T) *Catalog {
	t.Helper()
	catalog, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestServiceNilReceiverFailsClosed(t *testing.T) {
	var service *Service
	scope := fixtureScope(t)
	id := fixtureID(t, 30)
	checks := []func() error{
		func() error { _, err := service.Catalog(context.Background(), CatalogFilter{}); return err },
		func() error { _, err := service.List(context.Background(), scope); return err },
		func() error { _, err := service.Get(context.Background(), scope, id); return err },
		func() error {
			_, err := service.Update(context.Background(), scope, id, IntegrationUpdate{})
			return err
		},
		func() error { return service.Delete(context.Background(), scope, id) },
		func() error { _, err := service.Authorize(context.Background(), scope, id); return err },
		func() error { _, err := service.ListSyncs(context.Background(), scope, id); return err },
		func() error { _, err := service.GetSync(context.Background(), scope, id, id); return err },
	}
	for index, check := range checks {
		if err := check(); err == nil {
			t.Fatalf("nil service check %d succeeded", index)
		}
	}
}
