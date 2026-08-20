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
	apply  func(context.Context, DriverApply) (DriverApplied, error)
	search func(context.Context, DriverQuery) (DriverSearchResult, error)
}

func (driver *recordingDriver) Apply(ctx context.Context, input DriverApply) (DriverApplied, error) {
	return driver.apply(ctx, input)
}

func (driver *recordingDriver) Search(ctx context.Context, input DriverQuery) (DriverSearchResult, error) {
	return driver.search(ctx, input)
}

func TestStoreAppliesDeterministicImmutableSnapshotDocuments(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	wantIDs := []string{
		"inv_4b4b10357e769fa0466914778849bbe66cc57e27d2bd706485cc2beea8fa8520",
		"inv_f79d5d34514bb43980eed61fd638d9d914b16d185126412d4ba71e2e9a344449",
	}
	driver := &recordingDriver{}
	driver.apply = func(ctx context.Context, input DriverApply) (DriverApplied, error) {
		if ctx == nil || input.OrganizationID != snapshot.Scope.OrganizationID().String() || input.WorkspaceID != snapshot.Scope.WorkspaceID().String() || input.EnvironmentID != snapshot.Scope.EnvironmentID().String() || input.IntegrationID != snapshot.IntegrationID.String() || input.SnapshotID != snapshot.SnapshotID.String() || input.Generation != 7 || input.InputDigest != snapshot.InputDigest || len(input.Documents) != 2 {
			t.Fatalf("Apply input = %#v", input)
		}
		if input.Documents[0].EntityID != snapshot.Documents[1].EntityID.String() || input.Documents[1].EntityID != snapshot.Documents[0].EntityID.String() {
			t.Fatalf("documents not sorted by entity ID: %#v", input.Documents)
		}
		for index, document := range input.Documents {
			if document.DocumentID != wantIDs[index] || document.OrganizationID != input.OrganizationID || document.WorkspaceID != input.WorkspaceID || document.EnvironmentID != input.EnvironmentID || document.IntegrationID != input.IntegrationID || document.SnapshotID != input.SnapshotID || document.Generation != input.Generation || document.InputDigest != input.InputDigest {
				t.Fatalf("document %d = %#v", index, document)
			}
		}
		return DriverApplied{SnapshotID: input.SnapshotID, Generation: input.Generation, InputDigest: input.InputDigest, DocumentIDs: append([]string(nil), wantIDs...)}, nil
	}
	driver.search = func(context.Context, DriverQuery) (DriverSearchResult, error) {
		return DriverSearchResult{}, errors.New("unexpected search")
	}
	store := mustStore(t, driver)

	result, err := store.ApplySnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("ApplySnapshot() error = %v", err)
	}
	if result.SnapshotID != snapshot.SnapshotID || result.Generation != snapshot.Generation || result.InputDigest != snapshot.InputDigest || result.Replayed || !reflect.DeepEqual(result.DocumentIDs, wantIDs) {
		t.Fatalf("ApplySnapshot() = %#v", result)
	}
}

func TestStoreAcceptsExactReplayAndRejectsHostileDriverDrift(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	cases := []struct {
		name string
		edit func(*DriverApplied)
	}{
		{name: "foreign snapshot", edit: func(value *DriverApplied) { value.SnapshotID = "pid_90000000-0000-4000-8000-000000000009" }},
		{name: "newer generation", edit: func(value *DriverApplied) { value.Generation++ }},
		{name: "foreign digest", edit: func(value *DriverApplied) { value.InputDigest[0] ^= 0xff }},
		{name: "foreign document", edit: func(value *DriverApplied) {
			value.DocumentIDs[0] = "inv_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			driver := &recordingDriver{}
			driver.apply = func(_ context.Context, input DriverApply) (DriverApplied, error) {
				ids := make([]string, len(input.Documents))
				for index, document := range input.Documents {
					ids[index] = document.DocumentID
				}
				value := DriverApplied{SnapshotID: input.SnapshotID, Generation: input.Generation, InputDigest: input.InputDigest, DocumentIDs: ids, Replayed: true}
				testCase.edit(&value)
				return value, nil
			}
			driver.search = func(context.Context, DriverQuery) (DriverSearchResult, error) { return DriverSearchResult{}, nil }
			store := mustStore(t, driver)
			if _, err := store.ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "foreign") {
				t.Fatalf("ApplySnapshot() error = %q", err)
			}
		})
	}

	driver := &recordingDriver{}
	driver.apply = func(_ context.Context, input DriverApply) (DriverApplied, error) {
		ids := make([]string, len(input.Documents))
		for index, document := range input.Documents {
			ids[index] = document.DocumentID
		}
		return DriverApplied{SnapshotID: input.SnapshotID, Generation: input.Generation, InputDigest: input.InputDigest, DocumentIDs: ids, Replayed: true}, nil
	}
	driver.search = func(context.Context, DriverQuery) (DriverSearchResult, error) { return DriverSearchResult{}, nil }
	result, err := mustStore(t, driver).ApplySnapshot(context.Background(), snapshot)
	if err != nil || !result.Replayed {
		t.Fatalf("exact replay = %#v, %v", result, err)
	}
}

func TestStoreSearchesOnlyExactScopeIntegrationAndSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	driver := &recordingDriver{}
	driver.apply = func(context.Context, DriverApply) (DriverApplied, error) {
		return DriverApplied{}, errors.New("unexpected apply")
	}
	driver.search = func(ctx context.Context, input DriverQuery) (DriverSearchResult, error) {
		if ctx == nil || input.OrganizationID != snapshot.Scope.OrganizationID().String() || input.WorkspaceID != snapshot.Scope.WorkspaceID().String() || input.EnvironmentID != snapshot.Scope.EnvironmentID().String() || input.IntegrationID != snapshot.IntegrationID.String() || input.SnapshotID != snapshot.SnapshotID.String() || input.Generation != snapshot.Generation || input.InputDigest != snapshot.InputDigest || input.Text != "database" || !reflect.DeepEqual(input.Kinds, []string{"aws_instance", "database"}) || input.AfterEntityID != "" || input.Limit != 2 || !reflect.DeepEqual(input.Sort, []string{"entity_id"}) {
			t.Fatalf("Search input = %#v", input)
		}
		return DriverSearchResult{
			Hits: []DriverDocument{
				productDriverDocument(snapshot, snapshot.Documents[1]),
				productDriverDocument(snapshot, snapshot.Documents[0]),
			},
			NextEntityID: snapshot.Documents[0].EntityID.String(),
		}, nil
	}
	store := mustStore(t, driver)

	page, err := store.Search(context.Background(), snapshot.Scope, Query{
		IntegrationID: snapshot.IntegrationID,
		SnapshotID:    snapshot.SnapshotID,
		Generation:    snapshot.Generation,
		InputDigest:   snapshot.InputDigest,
		Text:          "database",
		Kinds:         []string{"database", "aws_instance"},
		Limit:         2,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(page.Hits) != 2 || page.Hits[0].EntityID != snapshot.Documents[1].EntityID || page.Hits[1].EntityID != snapshot.Documents[0].EntityID || page.NextEntityID != snapshot.Documents[0].EntityID {
		t.Fatalf("Search() = %#v", page)
	}
}

func TestStoreRejectsInvalidInputsAndSanitizesDriverErrors(t *testing.T) {
	t.Parallel()

	snapshot := fixtureSnapshot(t)
	calls := 0
	driver := &recordingDriver{}
	driver.apply = func(context.Context, DriverApply) (DriverApplied, error) {
		calls++
		return DriverApplied{}, errors.New("Authorization=credential-must-not-escape")
	}
	driver.search = func(context.Context, DriverQuery) (DriverSearchResult, error) {
		calls++
		return DriverSearchResult{}, errors.New("Authorization=credential-must-not-escape")
	}
	store := mustStore(t, driver)

	invalid := snapshot
	invalid.Generation = 0
	if _, err := store.ApplySnapshot(context.Background(), invalid); !errors.Is(err, ErrInput) {
		t.Fatalf("ApplySnapshot(invalid) error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("driver calls after invalid input = %d", calls)
	}
	if _, err := store.ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("ApplySnapshot(driver error) = %q", err)
	}
	if _, err := store.Search(context.Background(), snapshot.Scope, Query{IntegrationID: snapshot.IntegrationID, SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, Text: strings.Repeat("x", 257), Limit: 1}); !errors.Is(err, ErrInput) {
		t.Fatalf("Search(invalid) error = %v", err)
	}
	if _, err := store.Search(context.Background(), snapshot.Scope, Query{IntegrationID: snapshot.IntegrationID, SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, Limit: 1}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("Search(driver error) = %q", err)
	}
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
	scope := fixtureScope(t)
	documents := []Document{
		{EntityID: mustProductID(t, "pid_50000000-0000-4000-8000-000000000005"), Kind: "database", DisplayName: "payments-db", StableFields: []byte(`{"engine":"postgres","region":"us-west-2"}`)},
		{EntityID: mustProductID(t, "pid_40000000-0000-4000-8000-000000000004"), Kind: "aws_instance", DisplayName: "worker-a", StableFields: []byte(`{"instance_type":"m7g.large"}`)},
	}
	return Snapshot{
		Scope:         scope,
		IntegrationID: mustProductID(t, "pid_60000000-0000-4000-8000-000000000006"),
		SnapshotID:    mustProductID(t, "pid_70000000-0000-4000-8000-000000000007"),
		Generation:    7,
		InputDigest:   sha256.Sum256([]byte("snapshot-7-input")),
		Documents:     documents,
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

func productDriverDocument(snapshot Snapshot, document Document) DriverDocument {
	return DriverDocument{
		OrganizationID: snapshot.Scope.OrganizationID().String(),
		WorkspaceID:    snapshot.Scope.WorkspaceID().String(),
		EnvironmentID:  snapshot.Scope.EnvironmentID().String(),
		IntegrationID:  snapshot.IntegrationID.String(),
		SnapshotID:     snapshot.SnapshotID.String(),
		Generation:     snapshot.Generation,
		InputDigest:    snapshot.InputDigest,
		DocumentID:     documentID(snapshot.Scope, snapshot.IntegrationID, snapshot.SnapshotID, document.EntityID),
		EntityID:       document.EntityID.String(),
		Kind:           document.Kind,
		DisplayName:    document.DisplayName,
		StableFields:   append([]byte(nil), document.StableFields...),
	}
}
