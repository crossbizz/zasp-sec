package inventorysearch

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recordingDriver struct {
	stage       func(context.Context, DriverStage) (DriverStaged, error)
	activate    func(context.Context, DriverActivation) (DriverActivated, error)
	discard     func(context.Context, DriverDiscard) (DriverDiscarded, error)
	removeStale func(context.Context, DriverCleanup) (DriverCleaned, error)
	search      func(context.Context, DriverQuery) (DriverSearchResult, error)
}

func (driver *recordingDriver) Stage(ctx context.Context, input DriverStage) (DriverStaged, error) {
	return driver.stage(ctx, input)
}

func (driver *recordingDriver) Activate(ctx context.Context, input DriverActivation) (DriverActivated, error) {
	return driver.activate(ctx, input)
}

func (driver *recordingDriver) DiscardStage(ctx context.Context, input DriverDiscard) (DriverDiscarded, error) {
	return driver.discard(ctx, input)
}

func (driver *recordingDriver) RemoveStale(ctx context.Context, input DriverCleanup) (DriverCleaned, error) {
	return driver.removeStale(ctx, input)
}

func (driver *recordingDriver) Search(ctx context.Context, input DriverQuery) (DriverSearchResult, error) {
	return driver.search(ctx, input)
}

func TestStoreStagesActivatesThenCleansCompleteSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	wantIDs := []string{
		"inv_4bea8b2f1c3c4ab4bc8b82ca513b04fdaca49dca4d1912070bea54c3fcfcb30b",
		"inv_8235a7b22be7a82bba80b9d9e18d3ef8f0da9c9b714e6415df40c1f5cb68cffb",
	}
	// Independent literal locks the canonical digest wire contract.
	wantContentDigest := [sha256.Size]byte{0x23, 0x9c, 0x50, 0x84, 0x36, 0x58, 0xd7, 0x61, 0xfe, 0x2e, 0x6f, 0x5a, 0x46, 0x59, 0x8b, 0xf6, 0xc7, 0x45, 0x71, 0xac, 0xe6, 0x2b, 0xf2, 0x5d, 0x55, 0x5b, 0x96, 0x99, 0x69, 0xe3, 0x66, 0x62}
	calls := make([]string, 0, 3)
	driver := &recordingDriver{}
	driver.stage = func(ctx context.Context, input DriverStage) (DriverStaged, error) {
		calls = append(calls, "stage")
		if ctx == nil || !sameBinding(input.Snapshot, driverBinding(snapshot, wantContentDigest)) || len(input.Documents) != 2 {
			t.Fatalf("Stage input = %#v", input)
		}
		if input.Documents[0].EntityID != snapshot.Documents[1].EntityID.String() || input.Documents[1].EntityID != snapshot.Documents[0].EntityID.String() {
			t.Fatalf("documents not sorted by entity ID: %#v", input.Documents)
		}
		if !reflect.DeepEqual(input.Documents[0].Attributes, []Attribute{{Name: "instance_type", Value: "m7g.large"}, {Name: "region", Value: "us-west-2"}}) {
			t.Fatalf("attributes not canonical: %#v", input.Documents[0].Attributes)
		}
		for index, document := range input.Documents {
			if document.DocumentID != wantIDs[index] || !sameBinding(document.Snapshot, input.Snapshot) {
				t.Fatalf("document %d = %#v", index, document)
			}
		}
		return DriverStaged{Snapshot: input.Snapshot, DocumentIDs: append([]string(nil), wantIDs...)}, nil
	}
	driver.activate = func(ctx context.Context, input DriverActivation) (DriverActivated, error) {
		calls = append(calls, "activate")
		if ctx == nil || !sameBinding(input.Snapshot, driverBinding(snapshot, wantContentDigest)) || !reflect.DeepEqual(input.DocumentIDs, wantIDs) {
			t.Fatalf("Activate input = %#v", input)
		}
		return DriverActivated{ActiveSnapshot: input.Snapshot, ActiveDocumentIDs: append([]string(nil), input.DocumentIDs...)}, nil
	}
	driver.removeStale = func(ctx context.Context, input DriverCleanup) (DriverCleaned, error) {
		calls = append(calls, "cleanup")
		if ctx == nil || !sameBinding(input.ActiveSnapshot, driverBinding(snapshot, wantContentDigest)) {
			t.Fatalf("RemoveStale input = %#v", input)
		}
		return DriverCleaned{ActiveSnapshot: input.ActiveSnapshot, Removed: 3}, nil
	}
	driver.search = unexpectedSearch

	result, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("ApplySnapshot() error = %v", err)
	}
	if result.SnapshotID != snapshot.SnapshotID || result.Generation != snapshot.Generation || result.InputDigest != snapshot.InputDigest || result.ContentDigest != wantContentDigest || result.Replayed || result.Removed != 3 || !reflect.DeepEqual(result.DocumentIDs, wantIDs) {
		t.Fatalf("ApplySnapshot() = %#v", result)
	}
	if !reflect.DeepEqual(calls, []string{"stage", "activate", "cleanup"}) {
		t.Fatalf("phase calls = %#v", calls)
	}
}

func TestStoreCompleteSnapshotReplaceAcceptsSubsetAndEmpty(t *testing.T) {
	t.Parallel()

	for _, count := range []int{1, 0} {
		count := count
		t.Run(string(rune('0'+count))+" documents", func(t *testing.T) {
			snapshot := fixtureSnapshot(t)
			snapshot.Generation++
			snapshot.SnapshotID = mustProductID(t, "pid_80000000-0000-4000-8000-000000000008")
			snapshot.Documents = snapshot.Documents[:count]
			calls := make([]string, 0, 3)
			driver := successfulDriver(&calls)
			result, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("ApplySnapshot() error = %v", err)
			}
			if len(result.DocumentIDs) != count || !reflect.DeepEqual(calls, []string{"stage", "activate", "cleanup"}) {
				t.Fatalf("result/calls = %#v / %#v", result, calls)
			}
		})
	}
}

func TestStorePhaseFailuresPreserveActivationFenceAndRecoverByExactReplay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		failPhase string
		failure   error
		wantCalls []string
	}{
		{name: "stage lost acknowledgement", failPhase: "stage", failure: ErrUnknownOutcome, wantCalls: []string{"stage"}},
		{name: "activation lost acknowledgement", failPhase: "activate", failure: ErrUnknownOutcome, wantCalls: []string{"stage", "activate"}},
		{name: "stale older generation", failPhase: "activate", failure: ErrStale, wantCalls: []string{"stage", "activate", "discard"}},
		{name: "cleanup lost acknowledgement", failPhase: "cleanup", failure: ErrUnknownOutcome, wantCalls: []string{"stage", "activate", "cleanup"}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			calls := make([]string, 0, 3)
			driver := successfulDriver(&calls)
			switch testCase.failPhase {
			case "stage":
				driver.stage = func(context.Context, DriverStage) (DriverStaged, error) {
					calls = append(calls, "stage")
					return DriverStaged{}, testCase.failure
				}
			case "activate":
				driver.activate = func(context.Context, DriverActivation) (DriverActivated, error) {
					calls = append(calls, "activate")
					if errors.Is(testCase.failure, ErrStale) {
						active := driverBinding(fixtureSnapshot(t), sha256.Sum256([]byte("newer-content")))
						active.SnapshotID = "pid_80000000-0000-4000-8000-000000000008"
						active.Generation++
						active.InputDigest = sha256.Sum256([]byte("newer-input"))
						return DriverActivated{ActiveSnapshot: active}, testCase.failure
					}
					return DriverActivated{}, testCase.failure
				}
			case "cleanup":
				driver.removeStale = func(context.Context, DriverCleanup) (DriverCleaned, error) {
					calls = append(calls, "cleanup")
					return DriverCleaned{}, testCase.failure
				}
			}
			if _, err := mustStore(t, driver).ApplySnapshot(context.Background(), fixtureSnapshot(t)); !errors.Is(err, testCase.failure) {
				t.Fatalf("ApplySnapshot() error = %v", err)
			}
			if !reflect.DeepEqual(calls, testCase.wantCalls) {
				t.Fatalf("phase calls = %#v, want %#v", calls, testCase.wantCalls)
			}
		})
	}

	calls := make([]string, 0, 3)
	driver := successfulDriver(&calls)
	driver.stage = func(_ context.Context, input DriverStage) (DriverStaged, error) {
		calls = append(calls, "stage")
		return DriverStaged{Snapshot: input.Snapshot, DocumentIDs: documentIDs(input.Documents), Replayed: true}, nil
	}
	driver.activate = func(_ context.Context, input DriverActivation) (DriverActivated, error) {
		calls = append(calls, "activate")
		return DriverActivated{ActiveSnapshot: input.Snapshot, ActiveDocumentIDs: append([]string(nil), input.DocumentIDs...), Replayed: true}, nil
	}
	driver.removeStale = func(_ context.Context, input DriverCleanup) (DriverCleaned, error) {
		calls = append(calls, "cleanup")
		return DriverCleaned{ActiveSnapshot: input.ActiveSnapshot, Replayed: true}, nil
	}
	result, err := mustStore(t, driver).ApplySnapshot(context.Background(), fixtureSnapshot(t))
	if err != nil || !result.Replayed || !reflect.DeepEqual(calls, []string{"stage", "activate", "cleanup"}) {
		t.Fatalf("exact recovery replay = %#v, %v, calls %#v", result, err, calls)
	}
}

func TestStoreRejectedCandidatesLeaveNoResidueAndPreserveNewerActiveSnapshot(t *testing.T) {
	t.Parallel()

	driver := newStatefulDriver()
	store := mustStore(t, driver)
	newer := fixtureSnapshot(t)
	newer.Generation = 8
	newer.SnapshotID = mustProductID(t, "pid_80000000-0000-4000-8000-000000000008")
	newer.InputDigest = sha256.Sum256([]byte("snapshot-8-input"))
	newerResult, err := store.ApplySnapshot(context.Background(), newer)
	if err != nil {
		t.Fatalf("ApplySnapshot(newer) error = %v", err)
	}
	if len(driver.documents) != len(newer.Documents) {
		t.Fatalf("documents after newer = %d", len(driver.documents))
	}

	delayedOlder := fixtureSnapshot(t)
	delayedOlder.SnapshotID = mustProductID(t, "pid_71000000-0000-4000-8000-000000000007")
	if _, err := store.ApplySnapshot(context.Background(), delayedOlder); !errors.Is(err, ErrStale) {
		t.Fatalf("ApplySnapshot(delayed older) error = %v", err)
	}
	assertOnlyDocumentIDs(t, driver.documents, newerResult.DocumentIDs)
	if driver.active.Generation != newer.Generation || driver.active.SnapshotID != newer.SnapshotID.String() {
		t.Fatalf("active after delayed older = %#v", driver.active)
	}

	sameGenerationDrift := newer
	sameGenerationDrift.SnapshotID = mustProductID(t, "pid_81000000-0000-4000-8000-000000000008")
	sameGenerationDrift.InputDigest = sha256.Sum256([]byte("snapshot-8-conflict"))
	sameGenerationDrift.Documents = append([]Document(nil), newer.Documents[:1]...)
	if _, err := store.ApplySnapshot(context.Background(), sameGenerationDrift); !errors.Is(err, ErrDrift) {
		t.Fatalf("ApplySnapshot(same generation drift) error = %v", err)
	}
	assertOnlyDocumentIDs(t, driver.documents, newerResult.DocumentIDs)

	olderActive := driverBinding(delayedOlder, contentDigestFromApply(t, delayedOlder))
	if _, err := driver.RemoveStale(context.Background(), DriverCleanup{ActiveSnapshot: olderActive}); !errors.Is(err, ErrStale) {
		t.Fatalf("delayed old RemoveStale() error = %v", err)
	}
	assertOnlyDocumentIDs(t, driver.documents, newerResult.DocumentIDs)
}

func TestStoreDiscardUnknownOutcomeRequiresExactRetryBeforeRejectedResult(t *testing.T) {
	t.Parallel()

	active := fixtureSnapshot(t)
	active.Generation = 8
	active.SnapshotID = mustProductID(t, "pid_80000000-0000-4000-8000-000000000008")
	active.InputDigest = sha256.Sum256([]byte("snapshot-8-input"))
	driver := newStatefulDriver()
	store := mustStore(t, driver)
	if _, err := store.ApplySnapshot(context.Background(), active); err != nil {
		t.Fatalf("ApplySnapshot(active) error = %v", err)
	}

	candidate := fixtureSnapshot(t)
	candidate.SnapshotID = mustProductID(t, "pid_71000000-0000-4000-8000-000000000007")
	driver.failDiscardOnce = true
	if _, err := store.ApplySnapshot(context.Background(), candidate); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("ApplySnapshot(discard crash) error = %v", err)
	}
	if len(driver.documents) <= len(active.Documents) {
		t.Fatalf("discard crash did not leave an observable retry candidate")
	}
	if _, err := store.ApplySnapshot(context.Background(), candidate); !errors.Is(err, ErrStale) {
		t.Fatalf("ApplySnapshot(discard retry) error = %v", err)
	}
	if len(driver.documents) != len(active.Documents) {
		t.Fatalf("documents after exact discard retry = %d", len(driver.documents))
	}
}

func TestStoreActiveAdvanceDuringDiscardForcesRetryUntilRejectedResidueIsGone(t *testing.T) {
	t.Parallel()

	driver := newStatefulDriver()
	store := mustStore(t, driver)
	active := fixtureSnapshot(t)
	active.Generation = 8
	active.SnapshotID = mustProductID(t, "pid_80000000-0000-4000-8000-000000000008")
	active.InputDigest = sha256.Sum256([]byte("snapshot-8-input"))
	if _, err := store.ApplySnapshot(context.Background(), active); err != nil {
		t.Fatalf("ApplySnapshot(active) error = %v", err)
	}

	newest := fixtureSnapshot(t)
	newest.Generation = 9
	newest.SnapshotID = mustProductID(t, "pid_90000000-0000-4000-8000-000000000009")
	newest.InputDigest = sha256.Sum256([]byte("snapshot-9-input"))
	newest.Documents = append([]Document(nil), newest.Documents[:1]...)
	newestStage := captureDriverStage(t, newest)
	driver.advanceOnDiscard = &newestStage

	rejected := fixtureSnapshot(t)
	rejected.SnapshotID = mustProductID(t, "pid_71000000-0000-4000-8000-000000000007")
	if _, err := store.ApplySnapshot(context.Background(), rejected); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("ApplySnapshot(active advanced) error = %v", err)
	}
	if driver.active != newestStage.Snapshot {
		t.Fatalf("active after advance = %#v", driver.active)
	}
	if len(driver.documents) <= len(newestStage.Documents) {
		t.Fatalf("first attempt incorrectly acknowledged rejected cleanup")
	}
	if _, err := store.ApplySnapshot(context.Background(), rejected); !errors.Is(err, ErrStale) {
		t.Fatalf("ApplySnapshot(exact retry) error = %v", err)
	}
	assertOnlyDocumentIDs(t, driver.documents, documentIDs(newestStage.Documents))
}

func TestStoreBindsCanonicalContentDigestAndRejectsPhaseDrift(t *testing.T) {
	t.Parallel()

	original := fixtureSnapshot(t)
	reordered := fixtureSnapshot(t)
	reordered.Documents[0], reordered.Documents[1] = reordered.Documents[1], reordered.Documents[0]
	reordered.Documents[0].Attributes[0], reordered.Documents[0].Attributes[1] = reordered.Documents[0].Attributes[1], reordered.Documents[0].Attributes[0]
	changed := fixtureSnapshot(t)
	changed.Documents[0].Attributes[0].Value = "mysql"
	digests := make([][sha256.Size]byte, 0, 3)
	for _, snapshot := range []Snapshot{original, reordered, changed} {
		driver := successfulDriver(nil)
		driver.stage = func(_ context.Context, input DriverStage) (DriverStaged, error) {
			digests = append(digests, input.Snapshot.ContentDigest)
			return DriverStaged{Snapshot: input.Snapshot, DocumentIDs: documentIDs(input.Documents)}, nil
		}
		if _, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot); err != nil {
			t.Fatalf("ApplySnapshot() error = %v", err)
		}
	}
	if digests[0] != digests[1] || digests[0] == digests[2] {
		t.Fatalf("canonical digests = %x / %x / %x", digests[0], digests[1], digests[2])
	}

	tests := []struct {
		name string
		edit func(*DriverSnapshot)
	}{
		{name: "foreign snapshot", edit: func(value *DriverSnapshot) { value.SnapshotID = "pid_90000000-0000-4000-8000-000000000009" }},
		{name: "newer generation", edit: func(value *DriverSnapshot) { value.Generation++ }},
		{name: "foreign input digest", edit: func(value *DriverSnapshot) { value.InputDigest[0] ^= 0xff }},
		{name: "foreign content digest", edit: func(value *DriverSnapshot) { value.ContentDigest[0] ^= 0xff }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			driver := successfulDriver(nil)
			driver.activate = func(_ context.Context, input DriverActivation) (DriverActivated, error) {
				binding := input.Snapshot
				testCase.edit(&binding)
				return DriverActivated{ActiveSnapshot: binding, ActiveDocumentIDs: append([]string(nil), input.DocumentIDs...), Replayed: true}, nil
			}
			if _, err := mustStore(t, driver).ApplySnapshot(context.Background(), original); !errors.Is(err, ErrDrift) {
				t.Fatalf("ApplySnapshot() error = %v", err)
			}
		})
	}
}

func TestStoreRejectsSecretBearingUnknownAndNestedAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		kind       string
		attributes []Attribute
	}{
		{name: "secret name", kind: "database", attributes: []Attribute{{Name: "access_token", Value: "plaintext"}}},
		{name: "unknown field", kind: "database", attributes: []Attribute{{Name: "endpoint", Value: "db.example"}}},
		{name: "nested object", kind: "database", attributes: []Attribute{{Name: "engine", Value: `{"token":"plaintext"}`}}},
		{name: "nested array", kind: "database", attributes: []Attribute{{Name: "engine", Value: `["plaintext"]`}}},
		{name: "duplicate", kind: "database", attributes: []Attribute{{Name: "engine", Value: "postgres"}, {Name: "engine", Value: "postgres"}}},
		{name: "unknown kind", kind: "future_provider_secret", attributes: nil},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			driver := successfulDriver(nil)
			driver.stage = func(context.Context, DriverStage) (DriverStaged, error) { calls++; return DriverStaged{}, nil }
			snapshot := fixtureSnapshot(t)
			snapshot.Documents = []Document{{EntityID: snapshot.Documents[0].EntityID, Kind: testCase.kind, DisplayName: "hostile", Attributes: testCase.attributes}}
			if _, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrInput) {
				t.Fatalf("ApplySnapshot() error = %v", err)
			}
			if calls != 0 {
				t.Fatalf("driver calls = %d", calls)
			}
		})
	}
}

func TestStoreSearchesOnlyExactActiveSnapshotAndRequestedKinds(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	contentDigest := contentDigestFromApply(t, snapshot)
	driver := successfulDriver(nil)
	driver.search = func(ctx context.Context, input DriverQuery) (DriverSearchResult, error) {
		if ctx == nil || input.OrganizationID != snapshot.Scope.OrganizationID().String() || input.WorkspaceID != snapshot.Scope.WorkspaceID().String() || input.EnvironmentID != snapshot.Scope.EnvironmentID().String() || input.IntegrationID != snapshot.IntegrationID.String() || input.SnapshotID != snapshot.SnapshotID.String() || input.Generation != snapshot.Generation || input.InputDigest != snapshot.InputDigest || input.ContentDigest != contentDigest || input.Text != "database" || !reflect.DeepEqual(input.Kinds, []string{"aws_instance", "database"}) || input.AfterEntityID != "" || input.Limit != 2 || !reflect.DeepEqual(input.Sort, []string{"entity_id"}) {
			t.Fatalf("Search input = %#v", input)
		}
		return DriverSearchResult{Hits: []DriverDocument{productDriverDocument(snapshot, contentDigest, snapshot.Documents[1]), productDriverDocument(snapshot, contentDigest, snapshot.Documents[0])}, NextEntityID: snapshot.Documents[0].EntityID.String()}, nil
	}
	store := mustStore(t, driver)
	query := Query{IntegrationID: snapshot.IntegrationID, SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, ContentDigest: contentDigest, Text: "database", Kinds: []string{"database", "aws_instance"}, Limit: 2}
	page, err := store.Search(context.Background(), snapshot.Scope, query)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(page.Hits) != 2 || page.Hits[0].EntityID != snapshot.Documents[1].EntityID || page.Hits[1].EntityID != snapshot.Documents[0].EntityID || page.NextEntityID != snapshot.Documents[0].EntityID {
		t.Fatalf("Search() = %#v", page)
	}

	driver.search = func(context.Context, DriverQuery) (DriverSearchResult, error) {
		foreignKind := productDriverDocument(snapshot, contentDigest, snapshot.Documents[1])
		foreignKind.Kind = "aws_instance"
		foreignKind.Attributes = []Attribute{{Name: "instance_type", Value: "m7g.large"}, {Name: "region", Value: "us-west-2"}}
		return DriverSearchResult{Hits: []DriverDocument{foreignKind}}, nil
	}
	query.Kinds = []string{"database"}
	query.Limit = 1
	if _, err := store.Search(context.Background(), snapshot.Scope, query); !errors.Is(err, ErrDrift) {
		t.Fatalf("Search(foreign kind) error = %v", err)
	}
}

func TestStoreRejectsInvalidInputsAndSanitizesDriverErrors(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	calls := 0
	driver := successfulDriver(nil)
	driver.stage = func(context.Context, DriverStage) (DriverStaged, error) {
		calls++
		return DriverStaged{}, errors.New("Authorization=credential-must-not-escape")
	}
	driver.search = func(context.Context, DriverQuery) (DriverSearchResult, error) {
		calls++
		return DriverSearchResult{}, errors.New("Authorization=credential-must-not-escape")
	}
	store := mustStore(t, driver)

	invalid := snapshot
	invalid.Generation = 0
	if _, err := store.ApplySnapshot(context.Background(), invalid); !errors.Is(err, ErrInput) || calls != 0 {
		t.Fatalf("ApplySnapshot(invalid) = %v, calls %d", err, calls)
	}
	if _, err := store.ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("ApplySnapshot(driver error) = %q", err)
	}
	contentDigest := contentDigestFromApply(t, snapshot)
	if _, err := store.Search(context.Background(), snapshot.Scope, Query{IntegrationID: snapshot.IntegrationID, SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, ContentDigest: contentDigest, Text: strings.Repeat("x", 257), Limit: 1}); !errors.Is(err, ErrInput) {
		t.Fatalf("Search(invalid) error = %v", err)
	}
	if _, err := store.Search(context.Background(), snapshot.Scope, Query{IntegrationID: snapshot.IntegrationID, SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, ContentDigest: contentDigest, Limit: 1}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("Search(driver error) = %q", err)
	}
}

func successfulDriver(calls *[]string) *recordingDriver {
	driver := &recordingDriver{}
	driver.stage = func(_ context.Context, input DriverStage) (DriverStaged, error) {
		if calls != nil {
			*calls = append(*calls, "stage")
		}
		return DriverStaged{Snapshot: input.Snapshot, DocumentIDs: documentIDs(input.Documents)}, nil
	}
	driver.activate = func(_ context.Context, input DriverActivation) (DriverActivated, error) {
		if calls != nil {
			*calls = append(*calls, "activate")
		}
		return DriverActivated{ActiveSnapshot: input.Snapshot, ActiveDocumentIDs: append([]string(nil), input.DocumentIDs...)}, nil
	}
	driver.discard = func(_ context.Context, input DriverDiscard) (DriverDiscarded, error) {
		if calls != nil {
			*calls = append(*calls, "discard")
		}
		return DriverDiscarded{CandidateSnapshot: input.CandidateSnapshot, ActiveSnapshot: input.ExpectedActiveSnapshot, ActiveDocumentIDs: append([]string(nil), input.ExpectedActiveDocumentIDs...)}, nil
	}
	driver.removeStale = func(_ context.Context, input DriverCleanup) (DriverCleaned, error) {
		if calls != nil {
			*calls = append(*calls, "cleanup")
		}
		return DriverCleaned{ActiveSnapshot: input.ActiveSnapshot}, nil
	}
	driver.search = unexpectedSearch
	return driver
}

func unexpectedSearch(context.Context, DriverQuery) (DriverSearchResult, error) {
	return DriverSearchResult{}, errors.New("unexpected search")
}

func documentIDs(documents []DriverDocument) []string {
	ids := make([]string, len(documents))
	for index, document := range documents {
		ids[index] = document.DocumentID
	}
	return ids
}

func mustStore(t *testing.T, driver Driver) *Store {
	t.Helper()
	store, err := New(driver, Config{MaximumDocuments: 1_000, MaximumDocumentBytes: 65_536, MaximumBatchBytes: 8 << 20, MaximumResults: 100})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store
}

func fixtureSnapshot(t *testing.T) Snapshot {
	t.Helper()
	return Snapshot{
		Scope:         fixtureScope(t),
		IntegrationID: mustProductID(t, "pid_60000000-0000-4000-8000-000000000006"),
		SnapshotID:    mustProductID(t, "pid_70000000-0000-4000-8000-000000000007"),
		Generation:    7,
		InputDigest:   sha256.Sum256([]byte("snapshot-7-input")),
		Documents: []Document{
			{EntityID: mustProductID(t, "pid_50000000-0000-4000-8000-000000000005"), Kind: "database", DisplayName: "payments-db", Attributes: []Attribute{{Name: "region", Value: "us-west-2"}, {Name: "engine", Value: "postgres"}}},
			{EntityID: mustProductID(t, "pid_40000000-0000-4000-8000-000000000004"), Kind: "aws_instance", DisplayName: "worker-a", Attributes: []Attribute{{Name: "region", Value: "us-west-2"}, {Name: "instance_type", Value: "m7g.large"}}},
		},
	}
}

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	organizationID := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	workspaceID := mustProductID(t, "pid_20000000-0000-4000-8000-000000000002")
	environmentID := mustProductID(t, "pid_30000000-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	return scope
}

func mustProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatalf("ParseProductID(%q) error = %v", value, err)
	}
	return id
}

func driverBinding(snapshot Snapshot, contentDigest [sha256.Size]byte) DriverSnapshot {
	return DriverSnapshot{OrganizationID: snapshot.Scope.OrganizationID().String(), WorkspaceID: snapshot.Scope.WorkspaceID().String(), EnvironmentID: snapshot.Scope.EnvironmentID().String(), IntegrationID: snapshot.IntegrationID.String(), SnapshotID: snapshot.SnapshotID.String(), Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, ContentDigest: contentDigest}
}

func sameBinding(left, right DriverSnapshot) bool { return left == right }

func productDriverDocument(snapshot Snapshot, contentDigest [sha256.Size]byte, document Document) DriverDocument {
	attributes := append([]Attribute(nil), document.Attributes...)
	if len(attributes) > 1 && attributes[0].Name > attributes[1].Name {
		attributes[0], attributes[1] = attributes[1], attributes[0]
	}
	return DriverDocument{Snapshot: driverBinding(snapshot, contentDigest), DocumentID: documentID(snapshot.Scope, snapshot.IntegrationID, snapshot.SnapshotID, snapshot.Generation, snapshot.InputDigest, contentDigest, document.EntityID), EntityID: document.EntityID.String(), Kind: document.Kind, DisplayName: document.DisplayName, Attributes: attributes}
}

func contentDigestFromApply(t *testing.T, snapshot Snapshot) [sha256.Size]byte {
	t.Helper()
	var digest [sha256.Size]byte
	driver := successfulDriver(nil)
	driver.stage = func(_ context.Context, input DriverStage) (DriverStaged, error) {
		digest = input.Snapshot.ContentDigest
		return DriverStaged{Snapshot: input.Snapshot, DocumentIDs: documentIDs(input.Documents)}, nil
	}
	if _, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("ApplySnapshot() error = %v", err)
	}
	return digest
}

type statefulDriver struct {
	documents        map[string]DriverDocument
	active           DriverSnapshot
	activeIDs        []string
	failDiscardOnce  bool
	advanceOnDiscard *DriverStage
}

func newStatefulDriver() *statefulDriver {
	return &statefulDriver{documents: make(map[string]DriverDocument)}
}

func (driver *statefulDriver) Stage(_ context.Context, input DriverStage) (DriverStaged, error) {
	replayed := true
	for _, document := range input.Documents {
		if current, ok := driver.documents[document.DocumentID]; ok {
			if !reflect.DeepEqual(current, document) {
				return DriverStaged{}, ErrDrift
			}
			continue
		}
		driver.documents[document.DocumentID] = document
		replayed = false
	}
	return DriverStaged{Snapshot: input.Snapshot, DocumentIDs: documentIDs(input.Documents), Replayed: replayed}, nil
}

func (driver *statefulDriver) Activate(_ context.Context, input DriverActivation) (DriverActivated, error) {
	if driver.active.Generation > input.Snapshot.Generation {
		return DriverActivated{ActiveSnapshot: driver.active, ActiveDocumentIDs: append([]string(nil), driver.activeIDs...)}, ErrStale
	}
	if driver.active.Generation == input.Snapshot.Generation {
		if driver.active != input.Snapshot || !equalDocumentIDs(driver.activeIDs, input.DocumentIDs) {
			return DriverActivated{ActiveSnapshot: driver.active, ActiveDocumentIDs: append([]string(nil), driver.activeIDs...)}, ErrDrift
		}
		return DriverActivated{ActiveSnapshot: driver.active, ActiveDocumentIDs: append([]string(nil), driver.activeIDs...), Replayed: true}, nil
	}
	driver.active = input.Snapshot
	driver.activeIDs = append([]string(nil), input.DocumentIDs...)
	return DriverActivated{ActiveSnapshot: driver.active, ActiveDocumentIDs: append([]string(nil), driver.activeIDs...)}, nil
}

func (driver *statefulDriver) DiscardStage(_ context.Context, input DriverDiscard) (DriverDiscarded, error) {
	if driver.advanceOnDiscard != nil {
		newest := *driver.advanceOnDiscard
		driver.advanceOnDiscard = nil
		candidateIDs := make(map[string]struct{}, len(input.CandidateDocumentIDs))
		for _, id := range input.CandidateDocumentIDs {
			candidateIDs[id] = struct{}{}
		}
		for id := range driver.documents {
			if _, candidate := candidateIDs[id]; !candidate {
				delete(driver.documents, id)
			}
		}
		for _, document := range newest.Documents {
			driver.documents[document.DocumentID] = document
		}
		driver.active = newest.Snapshot
		driver.activeIDs = documentIDs(newest.Documents)
	}
	if driver.failDiscardOnce {
		driver.failDiscardOnce = false
		return DriverDiscarded{}, ErrUnknownOutcome
	}
	if driver.active != input.ExpectedActiveSnapshot || !equalDocumentIDs(driver.activeIDs, input.ExpectedActiveDocumentIDs) {
		return DriverDiscarded{}, ErrStale
	}
	activeIDs := make(map[string]struct{}, len(driver.activeIDs))
	for _, id := range driver.activeIDs {
		activeIDs[id] = struct{}{}
	}
	removed := 0
	for _, id := range input.CandidateDocumentIDs {
		if _, active := activeIDs[id]; active {
			continue
		}
		if _, found := driver.documents[id]; found {
			delete(driver.documents, id)
			removed++
		}
	}
	return DriverDiscarded{CandidateSnapshot: input.CandidateSnapshot, ActiveSnapshot: driver.active, ActiveDocumentIDs: append([]string(nil), driver.activeIDs...), Removed: removed}, nil
}

func (driver *statefulDriver) RemoveStale(_ context.Context, input DriverCleanup) (DriverCleaned, error) {
	if driver.active.Generation > input.ActiveSnapshot.Generation {
		return DriverCleaned{}, ErrStale
	}
	if driver.active != input.ActiveSnapshot {
		return DriverCleaned{}, ErrDrift
	}
	removed := 0
	for id, document := range driver.documents {
		if document.Snapshot.OrganizationID == driver.active.OrganizationID && document.Snapshot.WorkspaceID == driver.active.WorkspaceID && document.Snapshot.EnvironmentID == driver.active.EnvironmentID && document.Snapshot.IntegrationID == driver.active.IntegrationID && document.Snapshot.Generation < driver.active.Generation {
			delete(driver.documents, id)
			removed++
		}
	}
	return DriverCleaned{ActiveSnapshot: driver.active, Removed: removed}, nil
}

func (driver *statefulDriver) Search(context.Context, DriverQuery) (DriverSearchResult, error) {
	return DriverSearchResult{}, errors.New("unexpected search")
}

func assertOnlyDocumentIDs(t *testing.T, documents map[string]DriverDocument, want []string) {
	t.Helper()
	if len(documents) != len(want) {
		t.Fatalf("document count = %d, want %d", len(documents), len(want))
	}
	for _, id := range want {
		if _, found := documents[id]; !found {
			t.Fatalf("missing active document %q", id)
		}
	}
}

func captureDriverStage(t *testing.T, snapshot Snapshot) DriverStage {
	t.Helper()
	var captured DriverStage
	driver := successfulDriver(nil)
	driver.stage = func(_ context.Context, input DriverStage) (DriverStaged, error) {
		captured = input
		return DriverStaged{}, ErrUnknownOutcome
	}
	if _, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("capture ApplySnapshot() error = %v", err)
	}
	return captured
}
