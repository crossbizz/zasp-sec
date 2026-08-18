package eventstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recordingDriver struct {
	indexCalls  []DriverDocument
	searchCalls []DriverQuery
	indexed     DriverIndexed
	documents   []DriverDocument
}

type functionDriver struct {
	index  func(context.Context, DriverDocument) (DriverIndexed, error)
	search func(context.Context, DriverQuery) ([]DriverDocument, error)
}

func (driver functionDriver) Index(ctx context.Context, document DriverDocument) (DriverIndexed, error) {
	return driver.index(ctx, document)
}

func (driver functionDriver) Search(ctx context.Context, query DriverQuery) ([]DriverDocument, error) {
	return driver.search(ctx, query)
}

func (driver *recordingDriver) Index(_ context.Context, document DriverDocument) (DriverIndexed, error) {
	driver.indexCalls = append(driver.indexCalls, document)
	return driver.indexed, nil
}

func (driver *recordingDriver) Search(_ context.Context, query DriverQuery) ([]DriverDocument, error) {
	driver.searchCalls = append(driver.searchCalls, query)
	return driver.documents, nil
}

func TestStoreIndexesAndSearchesExactScopedEvent(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "1", "2", "3")
	event := testEvent(t, scope, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	document := DriverDocument{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		EventID:        event.EventID.String(),
		SessionID:      event.SessionID.String(),
		AgentID:        event.AgentID.String(),
		Source:         "runtime_gateway",
		SourceEventID:  "source-event-1",
		Class:          "tool",
		Action:         "invoke",
		Decision:       "allowed",
		EventTime:      "2026-08-15T20:21:22.123Z",
	}
	driver := &recordingDriver{
		indexed:   DriverIndexed{EventID: event.EventID.String()},
		documents: []DriverDocument{document},
	}
	store, err := New(driver, Config{OperationTimeout: time.Second, MaximumResults: 10})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	var contract EventStore = store

	if err := contract.Index(context.Background(), scope, event); err != nil {
		t.Fatalf("Index returned error: %v", err)
	}
	if !reflect.DeepEqual(driver.indexCalls, []DriverDocument{document}) {
		t.Fatalf("Index driver calls = %#v", driver.indexCalls)
	}

	result, err := contract.Search(context.Background(), scope, Filter{SessionID: event.SessionID, Limit: 10})
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	wantQuery := DriverQuery{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		SessionID:      event.SessionID.String(),
		Limit:          10,
		Sort:           []string{"event_time", "event_id"},
	}
	if !reflect.DeepEqual(driver.searchCalls, []DriverQuery{wantQuery}) {
		t.Fatalf("Search driver calls = %#v", driver.searchCalls)
	}
	if !reflect.DeepEqual(result, []Event{event}) {
		t.Fatalf("Search result = %#v", result)
	}
	result[0] = Event{}
	if driver.documents[0] != document {
		t.Fatal("caller mutation changed driver-owned state")
	}
}

func TestStoreRejectsInvalidConfigurationAndInputBeforeDriverIO(t *testing.T) {
	t.Parallel()
	var typedNil *recordingDriver
	for name, candidate := range map[string]struct {
		driver Driver
		config Config
	}{
		"nil driver":       {driver: nil, config: Config{OperationTimeout: time.Second, MaximumResults: 10}},
		"typed nil driver": {driver: typedNil, config: Config{OperationTimeout: time.Second, MaximumResults: 10}},
		"zero timeout":     {driver: &recordingDriver{}, config: Config{MaximumResults: 10}},
		"long timeout":     {driver: &recordingDriver{}, config: Config{OperationTimeout: 30*time.Second + time.Nanosecond, MaximumResults: 10}},
		"zero results":     {driver: &recordingDriver{}, config: Config{OperationTimeout: time.Second}},
		"too many results": {driver: &recordingDriver{}, config: Config{OperationTimeout: time.Second, MaximumResults: 101}},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := New(candidate.driver, candidate.config)
			if !errors.Is(err, ErrConfiguration) || store != nil {
				t.Fatalf("New = %#v, %v", store, err)
			}
		})
	}

	scope := testScope(t, "1", "2", "3")
	event := testEvent(t, scope, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	var calls atomic.Int64
	driver := functionDriver{
		index: func(context.Context, DriverDocument) (DriverIndexed, error) {
			calls.Add(1)
			return DriverIndexed{}, nil
		},
		search: func(context.Context, DriverQuery) ([]DriverDocument, error) {
			calls.Add(1)
			return nil, nil
		},
	}
	store, err := New(driver, Config{OperationTimeout: time.Second, MaximumResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	foreignScope := testScope(t, "7", "8", "9")
	invalidEvents := map[string]Event{
		"zero":              {},
		"foreign scope":     func() Event { copy := event; copy.Scope = foreignScope; return copy }(),
		"zero event":        func() Event { copy := event; copy.EventID = domain.ProductID{}; return copy }(),
		"zero session":      func() Event { copy := event; copy.SessionID = domain.ProductID{}; return copy }(),
		"zero agent":        func() Event { copy := event; copy.AgentID = domain.ProductID{}; return copy }(),
		"wrong source":      func() Event { copy := event; copy.Source = "opensearch"; return copy }(),
		"wrong class":       func() Event { copy := event; copy.Class = "prompt"; return copy }(),
		"wrong action":      func() Event { copy := event; copy.Action = "execute"; return copy }(),
		"wrong decision":    func() Event { copy := event; copy.Decision = "permit"; return copy }(),
		"empty source ID":   func() Event { copy := event; copy.SourceEventID = ""; return copy }(),
		"trimmed source ID": func() Event { copy := event; copy.SourceEventID = " source"; return copy }(),
		"control source ID": func() Event { copy := event; copy.SourceEventID = "source\n"; return copy }(),
		"invalid UTF-8":     func() Event { copy := event; copy.SourceEventID = string([]byte{0xff}); return copy }(),
		"long source ID":    func() Event { copy := event; copy.SourceEventID = strings.Repeat("x", 257); return copy }(),
		"non UTC time": func() Event {
			copy := event
			copy.EventTime = event.EventTime.In(time.FixedZone("offset", 3600))
			return copy
		}(),
		"sub millisecond": func() Event { copy := event; copy.EventTime = event.EventTime.Add(time.Nanosecond); return copy }(),
	}
	for name, invalid := range invalidEvents {
		t.Run("index "+name, func(t *testing.T) {
			if err := store.Index(context.Background(), scope, invalid); !errors.Is(err, ErrEvent) {
				t.Fatalf("Index error = %v", err)
			}
		})
	}
	for name, filter := range map[string]Filter{
		"zero":         {},
		"zero session": {Limit: 1},
		"zero limit":   {SessionID: event.SessionID},
		"over limit":   {SessionID: event.SessionID, Limit: 11},
	} {
		t.Run("search "+name, func(t *testing.T) {
			if _, err := store.Search(context.Background(), scope, filter); !errors.Is(err, ErrFilter) {
				t.Fatalf("Search error = %v", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid input reached driver %d times", calls.Load())
	}
}

func TestStoreContainsDriverErrorsCancellationDeadlinesAndPanics(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "1", "2", "3")
	event := testEvent(t, scope, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	providerError := errors.New("provider detail")
	for name, behavior := range map[string]func(context.Context){
		"panic":    func(context.Context) { panic("provider panic detail") },
		"deadline": func(ctx context.Context) { <-ctx.Done() },
	} {
		t.Run(name+" index", func(t *testing.T) {
			driver := functionDriver{
				index: func(ctx context.Context, _ DriverDocument) (DriverIndexed, error) {
					behavior(ctx)
					return DriverIndexed{EventID: event.EventID.String()}, nil
				},
				search: func(context.Context, DriverQuery) ([]DriverDocument, error) { return nil, nil },
			}
			store, err := New(driver, Config{OperationTimeout: 5 * time.Millisecond, MaximumResults: 10})
			if err != nil {
				t.Fatal(err)
			}
			returned, panicked := captureError(func() error { return store.Index(context.Background(), scope, event) })
			if panicked || !errors.Is(returned, ErrIndex) {
				t.Fatalf("Index = %v, panicked=%v", returned, panicked)
			}
		})
		t.Run(name+" search", func(t *testing.T) {
			driver := functionDriver{
				index: func(context.Context, DriverDocument) (DriverIndexed, error) { return DriverIndexed{}, nil },
				search: func(ctx context.Context, _ DriverQuery) ([]DriverDocument, error) {
					behavior(ctx)
					return nil, nil
				},
			}
			store, err := New(driver, Config{OperationTimeout: 5 * time.Millisecond, MaximumResults: 10})
			if err != nil {
				t.Fatal(err)
			}
			returned, panicked := captureError(func() error {
				_, searchErr := store.Search(context.Background(), scope, Filter{SessionID: event.SessionID, Limit: 1})
				return searchErr
			})
			if panicked || !errors.Is(returned, ErrSearch) {
				t.Fatalf("Search = %v, panicked=%v", returned, panicked)
			}
		})
	}

	errorDriver := functionDriver{
		index:  func(context.Context, DriverDocument) (DriverIndexed, error) { return DriverIndexed{}, providerError },
		search: func(context.Context, DriverQuery) ([]DriverDocument, error) { return nil, providerError },
	}
	store, err := New(errorDriver, Config{OperationTimeout: time.Second, MaximumResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Index(context.Background(), scope, event); !errors.Is(err, ErrIndex) || errors.Is(err, providerError) {
		t.Fatalf("Index provider error = %v", err)
	}
	if _, err := store.Search(context.Background(), scope, Filter{SessionID: event.SessionID, Limit: 1}); !errors.Is(err, ErrSearch) || errors.Is(err, providerError) {
		t.Fatalf("Search provider error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Index(canceled, scope, event); !errors.Is(err, ErrIndex) {
		t.Fatalf("canceled Index error = %v", err)
	}
	if _, err := store.Search(canceled, scope, Filter{SessionID: event.SessionID, Limit: 1}); !errors.Is(err, ErrSearch) {
		t.Fatalf("canceled Search error = %v", err)
	}
}

func TestStoreRejectsMalformedForeignDuplicateAndUnorderedSearchResults(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "1", "2", "3")
	first := testEvent(t, scope, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	second := testEvent(t, scope, "7", "5", "8", "2026-08-15T20:21:22.124Z")
	firstDocument, secondDocument := mustDriverDocument(t, scope, first), mustDriverDocument(t, scope, second)
	secondSameTime := secondDocument
	secondSameTime.EventTime = firstDocument.EventTime
	foreign := firstDocument
	foreign.OrganizationID = testProductID(t, "9").String()
	malformed := firstDocument
	malformed.Source = "provider"
	for name, documents := range map[string][]DriverDocument{
		"foreign scope":     {foreign},
		"malformed":         {malformed},
		"duplicate":         {firstDocument, firstDocument},
		"time unordered":    {secondDocument, firstDocument},
		"ID unordered":      {secondSameTime, firstDocument},
		"over result limit": {firstDocument, secondDocument},
	} {
		t.Run(name, func(t *testing.T) {
			driver := functionDriver{
				index:  func(context.Context, DriverDocument) (DriverIndexed, error) { return DriverIndexed{}, nil },
				search: func(context.Context, DriverQuery) ([]DriverDocument, error) { return documents, nil },
			}
			store, err := New(driver, Config{OperationTimeout: time.Second, MaximumResults: 10})
			if err != nil {
				t.Fatal(err)
			}
			limit := 10
			if name == "over result limit" {
				limit = 1
			}
			if result, err := store.Search(context.Background(), scope, Filter{SessionID: first.SessionID, Limit: limit}); !errors.Is(err, ErrSearch) || result != nil {
				t.Fatalf("Search = %#v, %v", result, err)
			}
		})
	}
}

func TestStoreRejectsMismatchedIndexAcknowledgement(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "1", "2", "3")
	event := testEvent(t, scope, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	driver := functionDriver{
		index: func(context.Context, DriverDocument) (DriverIndexed, error) {
			return DriverIndexed{EventID: testProductID(t, "7").String()}, nil
		},
		search: func(context.Context, DriverQuery) ([]DriverDocument, error) { return nil, nil },
	}
	store, err := New(driver, Config{OperationTimeout: time.Second, MaximumResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Index(context.Background(), scope, event); !errors.Is(err, ErrIndex) {
		t.Fatalf("Index error = %v", err)
	}
}

func TestStoreSupportsConcurrentIndependentOperations(t *testing.T) {
	t.Parallel()
	scopes := []domain.Scope{testScope(t, "1", "2", "3"), testScope(t, "7", "2", "3")}
	events := []Event{
		testEvent(t, scopes[0], "4", "5", "6", "2026-08-15T20:21:22.123Z"),
		testEvent(t, scopes[1], "8", "5", "9", "2026-08-15T20:21:22.123Z"),
	}
	documents := map[string]DriverDocument{
		scopes[0].OrganizationID().String(): mustDriverDocument(t, scopes[0], events[0]),
		scopes[1].OrganizationID().String(): mustDriverDocument(t, scopes[1], events[1]),
	}
	driver := functionDriver{
		index: func(_ context.Context, document DriverDocument) (DriverIndexed, error) {
			return DriverIndexed{EventID: document.EventID}, nil
		},
		search: func(_ context.Context, query DriverQuery) ([]DriverDocument, error) {
			return []DriverDocument{documents[query.OrganizationID]}, nil
		},
	}
	store, err := New(driver, Config{OperationTimeout: time.Second, MaximumResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsFound := make(chan error, 64)
	for index := 0; index < 32; index++ {
		scope := scopes[index%len(scopes)]
		event := events[index%len(events)]
		wait.Add(2)
		go func() {
			defer wait.Done()
			errorsFound <- store.Index(context.Background(), scope, event)
		}()
		go func() {
			defer wait.Done()
			_, searchErr := store.Search(context.Background(), scope, Filter{SessionID: event.SessionID, Limit: 1})
			errorsFound <- searchErr
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent operation error = %v", err)
		}
	}
}

func TestScopedBuildersRequireExactOrganizationAndOwnQueryState(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "1", "2", "3")
	event := testEvent(t, scope, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	wantDocument := DriverDocument{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		EventID:        event.EventID.String(),
		SessionID:      event.SessionID.String(),
		AgentID:        event.AgentID.String(),
		Source:         "runtime_gateway",
		SourceEventID:  "source-event-1",
		Class:          "tool",
		Action:         "invoke",
		Decision:       "allowed",
		EventTime:      "2026-08-15T20:21:22.123Z",
	}
	document, err := buildDriverDocument(scope, event)
	if err != nil || document != wantDocument {
		t.Fatalf("buildDriverDocument = %#v, %v", document, err)
	}

	filter := Filter{SessionID: event.SessionID, Limit: 7}
	query, err := buildDriverQuery(scope, filter, 10)
	wantQuery := DriverQuery{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		SessionID:      event.SessionID.String(),
		Limit:          7,
		Sort:           []string{"event_time", "event_id"},
	}
	if err != nil || !reflect.DeepEqual(query, wantQuery) {
		t.Fatalf("buildDriverQuery = %#v, %v", query, err)
	}
	query.Sort[0] = "attacker"
	second, err := buildDriverQuery(scope, filter, 10)
	if err != nil || !reflect.DeepEqual(second, wantQuery) {
		t.Fatalf("second buildDriverQuery = %#v, %v", second, err)
	}

	foreign := event
	foreign.Scope = testScope(t, "7", "2", "3")
	for name, candidate := range map[string]struct {
		scope domain.Scope
		event Event
	}{
		"zero scope":       {scope: domain.Scope{}, event: event},
		"mismatched scope": {scope: scope, event: foreign},
		"zero event":       {scope: scope, event: Event{}},
	} {
		t.Run("document "+name, func(t *testing.T) {
			if result, buildErr := buildDriverDocument(candidate.scope, candidate.event); !errors.Is(buildErr, ErrEvent) || result != (DriverDocument{}) {
				t.Fatalf("buildDriverDocument = %#v, %v", result, buildErr)
			}
		})
	}
	for name, candidate := range map[string]struct {
		scope   domain.Scope
		filter  Filter
		maximum int
	}{
		"zero scope":     {scope: domain.Scope{}, filter: filter, maximum: 10},
		"zero filter":    {scope: scope, filter: Filter{}, maximum: 10},
		"over maximum":   {scope: scope, filter: Filter{SessionID: event.SessionID, Limit: 11}, maximum: 10},
		"zero maximum":   {scope: scope, filter: filter, maximum: 0},
		"global maximum": {scope: scope, filter: Filter{SessionID: event.SessionID, Limit: 1}, maximum: 101},
	} {
		t.Run("query "+name, func(t *testing.T) {
			if result, buildErr := buildDriverQuery(candidate.scope, candidate.filter, candidate.maximum); !errors.Is(buildErr, ErrFilter) || !reflect.DeepEqual(result, DriverQuery{}) {
				t.Fatalf("buildDriverQuery = %#v, %v", result, buildErr)
			}
		})
	}
}

func TestOrganizationAQueryRejectsOrganizationBFixtureWithSameSession(t *testing.T) {
	t.Parallel()
	organizationA := testScope(t, "1", "2", "3")
	organizationB := testScope(t, "7", "2", "3")
	eventA := testEvent(t, organizationA, "4", "5", "6", "2026-08-15T20:21:22.123Z")
	eventB := testEvent(t, organizationB, "8", "5", "9", "2026-08-15T20:21:22.123Z")
	documentB, err := buildDriverDocument(organizationB, eventB)
	if err != nil {
		t.Fatal(err)
	}
	driver := &recordingDriver{documents: []DriverDocument{documentB}}
	store, err := New(driver, Config{OperationTimeout: time.Second, MaximumResults: 10})
	if err != nil {
		t.Fatal(err)
	}

	result, searchErr := store.Search(context.Background(), organizationA, Filter{SessionID: eventA.SessionID, Limit: 1})
	if !errors.Is(searchErr, ErrSearch) || result != nil {
		t.Fatalf("Search = %#v, %v", result, searchErr)
	}
	wantQuery, err := buildDriverQuery(organizationA, Filter{SessionID: eventA.SessionID, Limit: 1}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(driver.searchCalls, []DriverQuery{wantQuery}) {
		t.Fatalf("Search driver calls = %#v", driver.searchCalls)
	}
}

func captureError(call func() error) (result error, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return call(), false
}

func testScope(t *testing.T, organization, workspace, environment string) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		testProductID(t, organization),
		testProductID(t, workspace),
		testProductID(t, environment),
	)
	if err != nil {
		t.Fatalf("NewScope returned error: %v", err)
	}
	return scope
}

func testProductID(t *testing.T, suffix string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID("pid_00000000-0000-4000-8000-00000000000" + suffix)
	if err != nil {
		t.Fatalf("ParseProductID(%q): %v", suffix, err)
	}
	return id
}

func testEvent(t *testing.T, scope domain.Scope, event, session, agent, timestamp string) Event {
	t.Helper()
	eventTime, err := time.Parse("2006-01-02T15:04:05.000Z", timestamp)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", timestamp, err)
	}
	return Event{
		Scope: scope, EventID: testProductID(t, event), SessionID: testProductID(t, session), AgentID: testProductID(t, agent),
		Source: "runtime_gateway", SourceEventID: "source-event-1", Class: "tool", Action: "invoke", Decision: "allowed", EventTime: eventTime,
	}
}

func mustDriverDocument(t *testing.T, scope domain.Scope, event Event) DriverDocument {
	t.Helper()
	document, err := buildDriverDocument(scope, event)
	if err != nil {
		t.Fatalf("buildDriverDocument returned error: %v", err)
	}
	return document
}
