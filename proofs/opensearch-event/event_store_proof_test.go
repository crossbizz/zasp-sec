package main

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/eventstore"
)

type proofProductStore struct {
	indexed  []eventstore.Event
	searches []struct {
		scope  string
		filter eventstore.Filter
	}
	failIndex     error
	applyThenFail bool
	cancel        context.CancelFunc
	cancelOnFail  bool
	failSearchAt  map[int]error
	panicSearchAt int
	leakB         bool
	duplicateA    bool
}

type nilMapProductStore map[string]eventstore.Event

func (nilMapProductStore) Index(context.Context, domain.Scope, eventstore.Event) error {
	panic("typed nil store reached")
}

func (nilMapProductStore) Search(context.Context, domain.Scope, eventstore.Filter) ([]eventstore.Event, error) {
	panic("typed nil store reached")
}

func (store *proofProductStore) Index(_ context.Context, scope domain.Scope, event eventstore.Event) error {
	if store.applyThenFail {
		store.indexed = append(store.indexed, event)
		if store.cancel != nil {
			store.cancel()
		}
		return store.failIndex
	}
	if store.failIndex != nil {
		if store.cancelOnFail && store.cancel != nil {
			store.cancel()
		}
		return store.failIndex
	}
	if scope != event.Scope {
		return eventstore.ErrEvent
	}
	store.indexed = append(store.indexed, event)
	return nil
}

func (store *proofProductStore) Search(_ context.Context, scope domain.Scope, filter eventstore.Filter) ([]eventstore.Event, error) {
	if scope.Validate() != nil || filter.SessionID.String() == "" || filter.Limit <= 0 {
		return nil, eventstore.ErrFilter
	}
	store.searches = append(store.searches, struct {
		scope  string
		filter eventstore.Filter
	}{scope: scope.OrganizationID().String(), filter: filter})
	call := len(store.searches)
	if call == store.panicSearchAt {
		panic("provider detail")
	}
	if err := store.failSearchAt[call]; err != nil {
		return nil, err
	}
	if len(store.indexed) == 1 && scope == store.indexed[0].Scope && filter.SessionID == store.indexed[0].SessionID {
		result := []eventstore.Event{store.indexed[0]}
		if store.duplicateA && call == 1 {
			result = append(result, store.indexed[0])
		}
		return result, nil
	}
	if store.leakB && len(store.indexed) == 1 && scope != store.indexed[0].Scope {
		return []eventstore.Event{store.indexed[0]}, nil
	}
	return []eventstore.Event{}, nil
}

type delayedProductIndexAdmin struct {
	*fakeBackend
	spec     IndexSpec
	appeared bool
}

func (admin *delayedProductIndexAdmin) CreateIndex(_ context.Context, spec IndexSpec) (IndexState, error) {
	admin.operations = append(admin.operations, "create-index")
	admin.counts["create-index"]++
	admin.spec = cloneIndexSpec(spec)
	return IndexState{}, ambiguousMutationError()
}

func (admin *delayedProductIndexAdmin) InspectIndex(_ context.Context, name string) (IndexState, error) {
	admin.operations = append(admin.operations, "inspect-index")
	admin.counts["inspect-index"]++
	if admin.counts["inspect-index"] < 3 {
		return IndexState{}, errProvider
	}
	if _, exists := admin.indexes[name]; !exists {
		admin.indexes[name] = &fakeIndex{state: cloneIndexState(admin.spec)}
	}
	return cloneIndexState(admin.indexes[name].state), nil
}

func (admin *delayedProductIndexAdmin) ListIndexes(ctx context.Context, prefix string) ([]IndexState, error) {
	if admin.counts["list-indexes"] >= 2 && !admin.appeared {
		admin.indexes[admin.spec.Name] = &fakeIndex{state: cloneIndexState(admin.spec)}
		admin.appeared = true
	}
	return admin.fakeBackend.ListIndexes(ctx, prefix)
}

type extraProductIndexAdmin struct{ *fakeBackend }

type panicAfterProductIndexCreateAdmin struct{ *fakeBackend }

func (admin *panicAfterProductIndexCreateAdmin) CreateIndex(ctx context.Context, spec IndexSpec) (IndexState, error) {
	_, _ = admin.fakeBackend.CreateIndex(ctx, spec)
	panic("provider detail")
}

func (admin *extraProductIndexAdmin) DeleteIndex(ctx context.Context, name string) error {
	err := admin.fakeBackend.DeleteIndex(ctx, name)
	extra := cloneIndexState(expectedIndexSpec(testMarker))
	extra.Name += "-extra"
	admin.indexes[extra.Name] = &fakeIndex{state: extra}
	return err
}

func TestRunEventStoreProofIndexesSearchesScopesAndCleans(t *testing.T) {
	t.Parallel()
	admin := newFakeBackend()
	events := &proofProductStore{}
	result, err := RunEventStoreProof(context.Background(), EventStoreProofOptions{
		Marker: testMarker, Events: events, Admin: admin,
		CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RunEventStoreProof: %v", err)
	}
	want := EventStoreProofResult{Indexed: true, Searched: true, Scoped: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}
	if result != want {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
	if len(events.indexed) != 1 || len(events.searches) != 3 {
		t.Fatalf("event calls = indexed %#v searches %#v", events.indexed, events.searches)
	}
	if !reflect.DeepEqual(admin.operations, []string{"list-indexes", "create-index", "inspect-index", "inspect-index", "delete-index", "list-indexes", "list-indexes"}) {
		t.Fatalf("admin events = %#v", admin.operations)
	}
}

func TestRunEventStoreProofRejectsNonPointerTypedNilStoreBeforeAdminIO(t *testing.T) {
	t.Parallel()
	var events nilMapProductStore
	admin := newFakeBackend()
	_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, events))
	if !errors.Is(err, errConfiguration) || len(admin.operations) != 0 {
		t.Fatalf("typed nil store = %v, operations=%v", err, admin.operations)
	}
}

func TestRunEventStoreProofReconcilesOnlyAmbiguousIndexCreation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"ambiguous", "malformed success"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			admin := newFakeBackend()
			if mode == "ambiguous" {
				admin.ambiguous["create-index"] = true
			} else {
				admin.invalidSuccessfulResponse["create-index"] = true
			}
			result, err := RunEventStoreProof(context.Background(), productProofOptions(admin, &proofProductStore{}))
			if err != nil || result != (EventStoreProofResult{Indexed: true, Searched: true, Scoped: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}) {
				t.Fatalf("RunEventStoreProof = %#v, %v", result, err)
			}
			if len(admin.indexes) != 0 {
				t.Fatal("reconciled index remained after cleanup")
			}
		})
	}

	t.Run("definitive collision is never adopted", func(t *testing.T) {
		admin := newFakeBackend()
		admin.rejectCreateCollision = true
		_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, &proofProductStore{}))
		if !errors.Is(err, errProvider) || len(admin.indexes) != 1 || slices.Contains(admin.operations, "inspect-index") || slices.Contains(admin.operations, "delete-index") {
			t.Fatalf("definitive collision was reconciled: error=%v operations=%v", err, admin.operations)
		}
	})
}

func TestRunEventStoreProofPollsDelayedAmbiguousIndexWithIndependentCleanup(t *testing.T) {
	t.Parallel()
	admin := &delayedProductIndexAdmin{fakeBackend: newFakeBackend()}
	_, err := RunEventStoreProof(context.Background(), EventStoreProofOptions{
		Marker: testMarker, Events: &proofProductStore{}, Admin: admin,
		CleanupTimeout: 100 * time.Millisecond, PollInterval: time.Millisecond,
	})
	if !errors.Is(err, errOwnership) {
		t.Fatalf("RunEventStoreProof error = %v, want original ownership failure; operations=%v indexes=%d", err, admin.operations, len(admin.indexes))
	}
	indexes, listErr := admin.ListIndexes(context.Background(), proofPrefix+testMarker)
	if listErr != nil || len(indexes) != 0 {
		t.Fatalf("delayed ambiguous index escaped cleanup: indexes=%#v error=%v", indexes, listErr)
	}
}

func TestRunEventStoreProofRearmsIndexAppliedBeforeCreatePanic(t *testing.T) {
	t.Parallel()
	admin := &panicAfterProductIndexCreateAdmin{fakeBackend: newFakeBackend()}
	_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, &proofProductStore{}))
	if !errors.Is(err, errProvider) || len(admin.indexes) != 0 {
		t.Fatalf("panic-after-create cleanup = %v, indexes=%d", err, len(admin.indexes))
	}
}

func TestRunEventStoreProofRejectsForeignAndDuplicateProductResults(t *testing.T) {
	t.Parallel()
	for name, store := range map[string]*proofProductStore{
		"cross organization": {leakB: true},
		"duplicate A":        {duplicateA: true},
	} {
		name, store := name, store
		t.Run(name, func(t *testing.T) {
			admin := newFakeBackend()
			_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, store))
			if name == "cross organization" && !errors.Is(err, errScope) {
				t.Fatalf("error = %v, want scope", err)
			}
			if name == "duplicate A" && !errors.Is(err, errContent) {
				t.Fatalf("error = %v, want content", err)
			}
			if len(admin.indexes) != 0 {
				t.Fatal("product result failure bypassed cleanup")
			}
		})
	}
}

func TestRunEventStoreProofContainsPanicsAndGivesCleanupPrecedence(t *testing.T) {
	t.Parallel()
	t.Run("main panic uses independent cleanup", func(t *testing.T) {
		admin := newFakeBackend()
		store := &proofProductStore{panicSearchAt: 1}
		_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, store))
		if !errors.Is(err, errProvider) || len(admin.indexes) != 0 {
			t.Fatalf("main panic = %v, indexes=%d", err, len(admin.indexes))
		}
	})
	t.Run("cleanup panic is contained", func(t *testing.T) {
		admin := newFakeBackend()
		store := &proofProductStore{panicSearchAt: 3}
		_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, store))
		if !errors.Is(err, errCleanup) {
			t.Fatalf("cleanup panic = %v", err)
		}
	})
	t.Run("cleanup failure overrides product failure", func(t *testing.T) {
		admin := newFakeBackend()
		admin.fail["delete-index"] = errProvider
		store := &proofProductStore{failSearchAt: map[int]error{1: eventstore.ErrSearch}}
		_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, store))
		if !errors.Is(err, errCleanup) {
			t.Fatalf("cleanup precedence = %v", err)
		}
	})
}

func TestRunEventStoreProofCleansCanceledAmbiguousProductWriteWithIndependentContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	admin := newFakeBackend()
	store := &proofProductStore{applyThenFail: true, failIndex: eventstore.ErrIndex, cancel: cancel}
	_, err := RunEventStoreProof(ctx, productProofOptions(admin, store))
	if !errors.Is(err, errProvider) {
		t.Fatalf("canceled ambiguous product write error = %v, want original provider failure", err)
	}
	if len(admin.indexes) != 0 {
		t.Fatal("canceled ambiguous product write bypassed independent cleanup")
	}
}

func TestRunEventStoreProofCleansBothAppliedAndUnappliedUncertainProductWrites(t *testing.T) {
	t.Parallel()
	t.Run("applied without caller cancellation", func(t *testing.T) {
		admin := newFakeBackend()
		store := &proofProductStore{applyThenFail: true, failIndex: eventstore.ErrIndex}
		_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, store))
		if !errors.Is(err, errProvider) || len(admin.indexes) != 0 {
			t.Fatalf("applied uncertain write = %v, indexes=%d", err, len(admin.indexes))
		}
	})
	t.Run("unapplied with caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		admin := newFakeBackend()
		store := &proofProductStore{failIndex: eventstore.ErrIndex, cancel: cancel, cancelOnFail: true}
		_, err := RunEventStoreProof(ctx, productProofOptions(admin, store))
		if !errors.Is(err, errProvider) || len(admin.indexes) != 0 {
			t.Fatalf("unapplied uncertain write = %v, indexes=%d", err, len(admin.indexes))
		}
	})
}

func TestRunEventStoreProofRejectsPrefixWideExtraIndexDuringFinalAudit(t *testing.T) {
	t.Parallel()
	admin := &extraProductIndexAdmin{fakeBackend: newFakeBackend()}
	_, err := RunEventStoreProof(context.Background(), productProofOptions(admin, &proofProductStore{}))
	if !errors.Is(err, errCleanup) {
		t.Fatalf("prefix-wide extra index error = %v", err)
	}
	if len(admin.indexes) != 1 {
		t.Fatal("test did not retain the unowned extra index")
	}
}

func productProofOptions(admin ProjectionAdmin, store eventstore.EventStore) EventStoreProofOptions {
	return EventStoreProofOptions{
		Marker: testMarker, Events: store, Admin: admin,
		CleanupTimeout: 50 * time.Millisecond, PollInterval: time.Millisecond,
	}
}
