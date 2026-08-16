package neo4jstore

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const seededProviderDetail = "seeded-provider-detail-must-not-escape"

func TestAdapterRejectsInvalidConfiguration(t *testing.T) {
	var _ graphstore.Driver = (*Adapter)(nil)

	var typedNil *fakeOfficialDriver
	tests := []struct {
		name      string
		new       func() (*Adapter, error)
		wantError error
	}{
		{name: "nil driver", new: func() (*Adapter, error) { return New(nil, databaseName) }, wantError: ErrConfiguration},
		{name: "typed nil driver", new: func() (*Adapter, error) { return New(typedNil, databaseName) }, wantError: ErrConfiguration},
		{name: "wrong database", new: func() (*Adapter, error) { return New(&fakeOfficialDriver{}, "system") }, wantError: ErrConfiguration},
		{name: "empty database", new: func() (*Adapter, error) { return New(&fakeOfficialDriver{}, "") }, wantError: ErrConfiguration},
		{name: "nil provider", new: func() (*Adapter, error) { return newAdapterForProvider(nil, databaseName) }, wantError: ErrConfiguration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, err := test.new()
			if adapter != nil || !errors.Is(err, test.wantError) || strings.Contains(err.Error(), seededProviderDetail) {
				t.Fatalf("new adapter = (%v, %v), want (nil, %v) without provider detail", adapter, err, test.wantError)
			}
		})
	}

	provider := &fakeProvider{session: validSchemaSession()}
	adapter, err := newAdapterForProvider(provider, databaseName)
	if err != nil || adapter == nil {
		t.Fatalf("valid new adapter = (%v, %v)", adapter, err)
	}
	if provider.calls != 0 {
		t.Fatalf("New opened %d sessions, want side-effect free", provider.calls)
	}
	if adapter, err = New(&fakeOfficialDriver{}, databaseName); err != nil || adapter == nil {
		t.Fatalf("valid public New = (%v, %v)", adapter, err)
	}
}

func TestEnsureSchemaUsesExactConstraintsAndVerifiesState(t *testing.T) {
	session := validSchemaSession()
	provider := &fakeProvider{session: session}
	if err := ensureSchemaWithProvider(context.Background(), provider, databaseName); err != nil {
		t.Fatalf("EnsureSchema = %v", err)
	}

	wantQueries := []string{createNodeConstraintQuery, createEdgeConstraintQuery, showOwnedConstraintsQuery}
	if !reflect.DeepEqual(session.tx.queries, wantQueries) {
		t.Fatalf("queries = %#v, want %#v", session.tx.queries, wantQueries)
	}
	if !reflect.DeepEqual(session.tx.parameters, []map[string]any{{}, {}, {"prefix": constraintPrefix}}) {
		t.Fatalf("parameters = %#v", session.tx.parameters)
	}
	if provider.calls != 1 || !reflect.DeepEqual(provider.configs, []sessionConfig{{Database: databaseName, Access: accessWrite}}) {
		t.Fatalf("provider calls/configs = %d/%#v", provider.calls, provider.configs)
	}
	if session.tx.commitCalls != 1 || session.tx.rollbackCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
	}
	if session.tx.results[0].consumeCalls != 1 || session.tx.results[1].consumeCalls != 1 || session.tx.results[2].consumeCalls != 1 {
		t.Fatalf("all schema results must be consumed exactly once")
	}
}

func TestEnsureSchemaRejectsMalformedOwnedState(t *testing.T) {
	validRows := validConstraintRows()
	tests := []struct {
		name    string
		keys    []string
		records []graphRecord
	}{
		{name: "missing edge", keys: constraintResultKeys, records: validRows[:1]},
		{name: "duplicate node", keys: constraintResultKeys, records: []graphRecord{validRows[0], validRows[0], validRows[1]}},
		{name: "extra owned", keys: constraintResultKeys, records: append(append([]graphRecord{}, validRows...), constraintRow("zasp_graph_extra_v1", "UNIQUENESS", "NODE", []any{nodeLabel}, []any{"node_id"}, "zasp_graph_extra_v1"))},
		{name: "wrong keys", keys: []string{"name", "type"}, records: validRows},
		{name: "wrong name", keys: constraintResultKeys, records: []graphRecord{constraintRow("ZASP_GRAPH_NODE_IDENTITY_V1", "UNIQUENESS", "NODE", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint), validRows[1]}},
		{name: "wrong type", keys: constraintResultKeys, records: []graphRecord{constraintRow(nodeConstraint, "NODE_KEY", "NODE", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint), validRows[1]}},
		{name: "wrong entity", keys: constraintResultKeys, records: []graphRecord{constraintRow(nodeConstraint, "UNIQUENESS", "RELATIONSHIP", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint), validRows[1]}},
		{name: "extra label", keys: constraintResultKeys, records: []graphRecord{constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel, "Foreign"}, nodeConstraintProperties, nodeConstraint), validRows[1]}},
		{name: "wrong properties", keys: constraintResultKeys, records: []graphRecord{constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel}, []any{"node_id"}, nodeConstraint), validRows[1]}},
		{name: "string list alias", keys: constraintResultKeys, records: []graphRecord{constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []string{nodeLabel}, nodeConstraintProperties, nodeConstraint), validRows[1]}},
		{name: "wrong owned index", keys: constraintResultKeys, records: []graphRecord{constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel}, nodeConstraintProperties, "foreign-index"), validRows[1]}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := validSchemaSession()
			session.tx.results[2] = &fakeResult{keys: test.keys, records: test.records}
			err := ensureSchemaWithProvider(context.Background(), &fakeProvider{session: session}, databaseName)
			if !errors.Is(err, ErrSchema) || strings.Contains(err.Error(), seededProviderDetail) {
				t.Fatalf("EnsureSchema = %v, want fixed ErrSchema", err)
			}
			if session.tx.commitCalls != 0 || session.tx.rollbackCalls != 1 || session.closeCalls != 1 {
				t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
			}
		})
	}
}

func TestEnsureSchemaContainsPanicsAndSettlesEveryBoundary(t *testing.T) {
	providerError := errors.New(seededProviderDetail)
	tests := []struct {
		name   string
		mutate func(*fakeProvider, *fakeSession)
	}{
		{name: "provider panic", mutate: func(provider *fakeProvider, _ *fakeSession) { provider.panic = true }},
		{name: "nil session", mutate: func(provider *fakeProvider, _ *fakeSession) { provider.session = nil }},
		{name: "begin error with candidate", mutate: func(_ *fakeProvider, session *fakeSession) { session.beginErr = providerError }},
		{name: "begin panic", mutate: func(_ *fakeProvider, session *fakeSession) { session.beginPanic = true }},
		{name: "run error", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.runErrorAt = 1 }},
		{name: "keys error", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.results[2].keysErr = providerError }},
		{name: "next panic", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.results[2].nextPanic = true }},
		{name: "cursor error", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.results[2].cursorErr = providerError }},
		{name: "consume error", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.results[2].consumeErr = providerError }},
		{name: "commit error", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.commitErr = providerError }},
		{name: "rollback error", mutate: func(_ *fakeProvider, session *fakeSession) {
			session.tx.results[2].consumeErr = providerError
			session.tx.rollbackErr = providerError
		}},
		{name: "close error", mutate: func(_ *fakeProvider, session *fakeSession) { session.closeErr = providerError }},
		{name: "close panic", mutate: func(_ *fakeProvider, session *fakeSession) { session.closePanic = true }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := validSchemaSession()
			provider := &fakeProvider{session: session}
			test.mutate(provider, session)
			err := ensureSchemaWithProvider(context.Background(), provider, databaseName)
			if !errors.Is(err, ErrSchema) || strings.Contains(err.Error(), seededProviderDetail) {
				t.Fatalf("EnsureSchema = %v, want fixed ErrSchema", err)
			}
			if !provider.panic && provider.session != nil && session.closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", session.closeCalls)
			}
			if session.tx != nil && session.tx.commitCalls == 0 && !session.beginPanic && !provider.panic && provider.session != nil && session.tx.rollbackCalls != 1 {
				t.Fatalf("rollback calls = %d, want 1", session.tx.rollbackCalls)
			}
		})
	}
}

func TestEnsureSchemaRejectsNilAndCanceledContextsBeforeProviderIO(t *testing.T) {
	provider := &fakeProvider{session: validSchemaSession()}
	if err := ensureSchemaWithProvider(nil, provider, databaseName); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil context = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ensureSchemaWithProvider(canceled, provider, databaseName); !errors.Is(err, ErrSchema) {
		t.Fatalf("canceled context = %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want 0", provider.calls)
	}
}

func validSchemaSession() *fakeSession {
	return &fakeSession{tx: &fakeTransaction{results: []*fakeResult{
		{keys: []string{}, records: []graphRecord{}},
		{keys: []string{}, records: []graphRecord{}},
		{keys: constraintResultKeys, records: validConstraintRows()},
	}}}
}

func validConstraintRows() []graphRecord {
	return []graphRecord{
		constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint),
		constraintRow(edgeConstraint, "UNIQUENESS", "RELATIONSHIP", []any{edgeType}, edgeConstraintProperties, edgeConstraint),
	}
}

func constraintRow(name, constraintType, entityType string, labelsOrTypes, properties any, ownedIndex string) graphRecord {
	return graphRecord{
		Keys:   constraintResultKeys,
		Values: []any{name, constraintType, entityType, labelsOrTypes, properties, ownedIndex},
	}
}

type fakeProvider struct {
	session  graphSession
	sessions []graphSession
	panic    bool
	calls    int
	configs  []sessionConfig
}

func (provider *fakeProvider) NewSession(_ context.Context, config sessionConfig) graphSession {
	provider.calls++
	provider.configs = append(provider.configs, config)
	if provider.panic {
		panic(seededProviderDetail)
	}
	if len(provider.sessions) >= provider.calls {
		return provider.sessions[provider.calls-1]
	}
	return provider.session
}

type fakeSession struct {
	tx              *fakeTransaction
	beginErr        error
	beginPanic      bool
	closeErr        error
	closePanic      bool
	closeCalls      int
	closeContextErr error
}

func (session *fakeSession) Begin(context.Context) (graphTransaction, error) {
	if session.beginPanic {
		panic(seededProviderDetail)
	}
	return session.tx, session.beginErr
}

func (session *fakeSession) Close(ctx context.Context) error {
	session.closeCalls++
	session.closeContextErr = ctx.Err()
	if session.closePanic {
		panic(seededProviderDetail)
	}
	return session.closeErr
}

type fakeTransaction struct {
	results            []*fakeResult
	queries            []string
	parameters         []map[string]any
	runErrorAt         int
	runCalls           int
	commitErr          error
	rollbackErr        error
	commitCalls        int
	rollbackCalls      int
	rollbackContextErr error
}

func (transaction *fakeTransaction) Run(_ context.Context, query string, parameters map[string]any) (graphResult, error) {
	transaction.runCalls++
	transaction.queries = append(transaction.queries, query)
	transaction.parameters = append(transaction.parameters, parameters)
	if transaction.runErrorAt == transaction.runCalls {
		return nil, errors.New(seededProviderDetail)
	}
	if transaction.runCalls > len(transaction.results) {
		return nil, errors.New(seededProviderDetail)
	}
	return transaction.results[transaction.runCalls-1], nil
}

func (transaction *fakeTransaction) Commit(context.Context) error {
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakeTransaction) Rollback(ctx context.Context) error {
	transaction.rollbackCalls++
	transaction.rollbackContextErr = ctx.Err()
	return transaction.rollbackErr
}

type fakeResult struct {
	keys         []string
	keysErr      error
	records      []graphRecord
	index        int
	nextPanic    bool
	cursorErr    error
	consumeErr   error
	consumeCalls int
	onNext       func()
}

func (result *fakeResult) Keys() ([]string, error) {
	return append([]string(nil), result.keys...), result.keysErr
}

func (result *fakeResult) Next(context.Context) bool {
	if result.onNext != nil {
		result.onNext()
	}
	if result.nextPanic {
		panic(seededProviderDetail)
	}
	if result.index >= len(result.records) {
		return false
	}
	result.index++
	return true
}

func (result *fakeResult) Record() graphRecord {
	if result.index == 0 || result.index > len(result.records) {
		return graphRecord{}
	}
	return result.records[result.index-1]
}

func (result *fakeResult) Err() error { return result.cursorErr }

func (result *fakeResult) Consume(context.Context) error {
	result.consumeCalls++
	return result.consumeErr
}

type fakeOfficialDriver struct{}

func (*fakeOfficialDriver) ExecuteQueryBookmarkManager() neo4j.BookmarkManager { return nil }
func (*fakeOfficialDriver) Target() url.URL                                    { return url.URL{} }
func (*fakeOfficialDriver) NewSession(context.Context, neo4j.SessionConfig) neo4j.Session {
	return nil
}
func (*fakeOfficialDriver) VerifyConnectivity(context.Context) error { return nil }
func (*fakeOfficialDriver) VerifyAuthentication(context.Context, *neo4j.AuthToken) error {
	return nil
}
func (*fakeOfficialDriver) Close(context.Context) error                             { return nil }
func (*fakeOfficialDriver) IsEncrypted() bool                                       { return false }
func (*fakeOfficialDriver) GetServerInfo(context.Context) (neo4j.ServerInfo, error) { return nil, nil }
