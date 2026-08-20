package neo4jstore

import (
	"context"
	"crypto/tls"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/auth"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/config"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const seededProviderDetail = "seeded-provider-detail-must-not-escape"

func TestProductionAdapterOwnsVerifiedTLSAuthenticationAndReadiness(t *testing.T) {
	validReference := "ref:neo4j/auth/production-0001"
	tests := []struct {
		name      string
		endpoint  string
		reference string
		resolver  *productionAuthResolverStub
		driver    *fakeOfficialDriver
	}{
		{name: "insecure neo4j", endpoint: "neo4j://graph.example.test:7687", reference: validReference},
		{name: "insecure bolt", endpoint: "bolt://graph.example.test:7687", reference: validReference},
		{name: "self signed neo4j", endpoint: "neo4j+ssc://graph.example.test:7687", reference: validReference},
		{name: "self signed bolt", endpoint: "bolt+ssc://graph.example.test:7687", reference: validReference},
		{name: "userinfo", endpoint: "neo4j+s://admin:secret@graph.example.test:7687", reference: validReference},
		{name: "query", endpoint: "neo4j+s://graph.example.test:7687?policy=hostile", reference: validReference},
		{name: "path", endpoint: "neo4j+s://graph.example.test:7687/database", reference: validReference},
		{name: "fragment", endpoint: "neo4j+s://graph.example.test:7687#secret", reference: validReference},
		{name: "missing host", endpoint: "neo4j+s://", reference: validReference},
		{name: "missing reference", endpoint: "neo4j+s://graph.example.test:7687"},
		{name: "malformed reference", endpoint: "neo4j+s://graph.example.test:7687", reference: "secret-inline"},
		{name: "resolver failure", endpoint: "neo4j+s://graph.example.test:7687", reference: validReference, resolver: &productionAuthResolverStub{err: errors.New(seededProviderDetail)}},
		{name: "no auth", endpoint: "neo4j+s://graph.example.test:7687", reference: validReference, resolver: &productionAuthResolverStub{manager: neo4j.NoAuth()}},
		{name: "connectivity failure", endpoint: "neo4j+s://graph.example.test:7687", reference: validReference, driver: &fakeOfficialDriver{encrypted: true, connectivityErr: errors.New(seededProviderDetail)}},
		{name: "authentication failure", endpoint: "neo4j+s://graph.example.test:7687", reference: validReference, driver: &fakeOfficialDriver{encrypted: true, authenticationErr: errors.New(seededProviderDetail)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := test.resolver
			if resolver == nil {
				resolver = &productionAuthResolverStub{manager: neo4j.BasicAuth("graph-user", "graph-password", "")}
			}
			driver := test.driver
			if driver == nil {
				driver = &fakeOfficialDriver{encrypted: true}
			}
			factory := &productionDriverFactoryStub{driver: driver}
			adapter, err := newProductionAdapter(context.Background(), ProductionConfig{Endpoint: test.endpoint, AuthenticationReference: test.reference, ReadinessTimeout: time.Second}, resolver, factory)
			if adapter != nil || !errors.Is(err, ErrConfiguration) || strings.Contains(err.Error(), seededProviderDetail) {
				t.Fatalf("new production adapter = (%v, %v), want redacted ErrConfiguration", adapter, err)
			}
			if test.driver != nil && (test.driver.connectivityErr != nil || test.driver.authenticationErr != nil) && test.driver.closeCalls != 1 {
				t.Fatalf("failed readiness closed driver %d times, want 1", test.driver.closeCalls)
			}
		})
	}

	for _, endpoint := range []string{"neo4j+s://graph.example.test:7687", "bolt+s://graph.example.test:7687"} {
		t.Run(endpoint, func(t *testing.T) {
			driver := &fakeOfficialDriver{encrypted: true}
			resolver := &productionAuthResolverStub{manager: neo4j.BasicAuth("graph-user", "graph-password", "")}
			factory := &productionDriverFactoryStub{driver: driver}
			adapter, err := newProductionAdapter(context.Background(), ProductionConfig{Endpoint: endpoint, AuthenticationReference: validReference, ReadinessTimeout: time.Second}, resolver, factory)
			if err != nil || adapter == nil {
				t.Fatalf("new production adapter = (%v, %v)", adapter, err)
			}
			if resolver.calls != 1 || resolver.reference != validReference || factory.calls != 1 || factory.endpoint != endpoint ||
				driver.connectivityCalls != 1 || driver.authenticationCalls != 1 || driver.closeCalls != 0 {
				t.Fatalf("authority calls resolver=%d/%q factory=%d/%q connectivity=%d authentication=%d close=%d", resolver.calls, resolver.reference, factory.calls, factory.endpoint, driver.connectivityCalls, driver.authenticationCalls, driver.closeCalls)
			}
			if factory.tlsConfig == nil || factory.tlsConfig.InsecureSkipVerify || factory.tlsConfig.MinVersion < tls.VersionTLS12 || factory.tlsConfig.RootCAs != nil {
				t.Fatalf("TLS config = %#v, want system trust with verified TLS 1.2+", factory.tlsConfig)
			}
		})
	}
}

func TestProductionAdapterClosesOwnedDriverOnceWithBoundedCleanupContext(t *testing.T) {
	driver := &fakeOfficialDriver{encrypted: true}
	resolver := &productionAuthResolverStub{manager: neo4j.BasicAuth("graph-user", "graph-password", "")}
	adapter, err := newProductionAdapter(context.Background(), ProductionConfig{
		Endpoint:                "neo4j+s://graph.example.test:7687",
		AuthenticationReference: "ref:neo4j/auth/production-0001",
		ReadinessTimeout:        time.Second,
	}, resolver, &productionDriverFactoryStub{driver: driver})
	if err != nil {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	const callers = 8
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- adapter.Close(canceled)
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for closeErr := range errorsSeen {
		if closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}
	if driver.closeCalls != 1 {
		t.Fatalf("driver close calls = %d, want 1", driver.closeCalls)
	}
	if driver.closeContextErr != nil {
		t.Fatalf("driver close context entered canceled: %v", driver.closeContextErr)
	}
	closeWindow := driver.closeDeadline.Sub(driver.closeStartedAt)
	if driver.closeDeadline.IsZero() || driver.closeStartedAt.IsZero() || closeWindow <= 0 || closeWindow > cleanupTimeout {
		t.Fatalf("driver close deadline = %v, want fresh deadline within %v", driver.closeDeadline, cleanupTimeout)
	}

	externalDriver := &fakeOfficialDriver{encrypted: true}
	external, err := newAdapterForDriver(externalDriver, databaseName)
	if err != nil {
		t.Fatal(err)
	}
	if err := external.Close(context.Background()); err != nil {
		t.Fatalf("non-owning Close() error = %v", err)
	}
	if externalDriver.closeCalls != 0 {
		t.Fatalf("non-owning adapter closed external driver %d times", externalDriver.closeCalls)
	}
}

func TestProductionAdapterCloseReturnsStableRedactedFailure(t *testing.T) {
	driver := &fakeOfficialDriver{encrypted: true, closeErr: errors.New(seededProviderDetail)}
	adapter, err := newProductionAdapter(context.Background(), ProductionConfig{
		Endpoint:                "neo4j+s://graph.example.test:7687",
		AuthenticationReference: "ref:neo4j/auth/production-0001",
		ReadinessTimeout:        time.Second,
	}, &productionAuthResolverStub{manager: neo4j.BasicAuth("graph-user", "graph-password", "")}, &productionDriverFactoryStub{driver: driver})
	if err != nil {
		t.Fatal(err)
	}

	first := adapter.Close(context.Background())
	second := adapter.Close(context.Background())
	if !errors.Is(first, ErrClose) || !errors.Is(second, ErrClose) || first.Error() != second.Error() || strings.Contains(first.Error(), seededProviderDetail) {
		t.Fatalf("Close() errors = (%v, %v), want stable redacted ErrClose", first, second)
	}
	if driver.closeCalls != 1 {
		t.Fatalf("driver close calls = %d, want 1", driver.closeCalls)
	}
}

func TestAdapterRejectsInvalidConfiguration(t *testing.T) {
	var _ graphstore.Driver = (*Adapter)(nil)
	var _ graphstore.SnapshotDriver = (*Adapter)(nil)

	var typedNil *fakeOfficialDriver
	tests := []struct {
		name      string
		new       func() (*Adapter, error)
		wantError error
	}{
		{name: "nil driver", new: func() (*Adapter, error) { return newAdapterForDriver(nil, databaseName) }, wantError: ErrConfiguration},
		{name: "typed nil driver", new: func() (*Adapter, error) { return newAdapterForDriver(typedNil, databaseName) }, wantError: ErrConfiguration},
		{name: "unencrypted driver", new: func() (*Adapter, error) { return newAdapterForDriver(&fakeOfficialDriver{}, databaseName) }, wantError: ErrConfiguration},
		{name: "wrong database", new: func() (*Adapter, error) { return newAdapterForDriver(&fakeOfficialDriver{encrypted: true}, "system") }, wantError: ErrConfiguration},
		{name: "empty database", new: func() (*Adapter, error) { return newAdapterForDriver(&fakeOfficialDriver{encrypted: true}, "") }, wantError: ErrConfiguration},
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
	if adapter, err = newAdapterForDriver(&fakeOfficialDriver{encrypted: true}, databaseName); err != nil || adapter == nil {
		t.Fatalf("valid driver adapter = (%v, %v)", adapter, err)
	}
}

func TestEnsureSchemaUsesExactConstraintsAndVerifiesState(t *testing.T) {
	session := validSchemaSession()
	provider := &fakeProvider{session: session}
	if err := ensureSchemaWithProvider(context.Background(), provider, databaseName); err != nil {
		t.Fatalf("EnsureSchema = %v", err)
	}

	wantQueries := []string{createNodeConstraintQuery, createEdgeConstraintQuery, createSnapshotMarkerConstraintQuery, createSnapshotNodeConstraintQuery, createSnapshotEdgeConstraintQuery, showOwnedConstraintsQuery}
	if !reflect.DeepEqual(session.tx.queries, wantQueries) {
		t.Fatalf("queries = %#v, want %#v", session.tx.queries, wantQueries)
	}
	if !reflect.DeepEqual(session.tx.parameters, []map[string]any{{}, {}, {}, {}, {}, {"prefix": constraintPrefix}}) {
		t.Fatalf("parameters = %#v", session.tx.parameters)
	}
	if provider.calls != 1 || !reflect.DeepEqual(provider.configs, []sessionConfig{{Database: databaseName, Access: accessWrite}}) {
		t.Fatalf("provider calls/configs = %d/%#v", provider.calls, provider.configs)
	}
	if session.tx.commitCalls != 1 || session.tx.rollbackCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
	}
	for index, result := range session.tx.results {
		if result.consumeCalls != 1 {
			t.Fatalf("schema result %d consumed %d times", index, result.consumeCalls)
		}
	}
}

func TestEnsureSchemaRejectsMalformedOwnedState(t *testing.T) {
	validRows := validConstraintRows()
	tests := []struct {
		name    string
		keys    []string
		records []graphRecord
	}{
		{name: "missing snapshot edge", keys: constraintResultKeys, records: validRows[:len(validRows)-1]},
		{name: "duplicate node", keys: constraintResultKeys, records: append([]graphRecord{validRows[0]}, validRows...)},
		{name: "extra owned", keys: constraintResultKeys, records: append(append([]graphRecord{}, validRows...), constraintRow("zasp_graph_extra_v1", "UNIQUENESS", "NODE", []any{nodeLabel}, []any{"node_id"}, "zasp_graph_extra_v1"))},
		{name: "wrong keys", keys: []string{"name", "type"}, records: validRows},
		{name: "wrong name", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow("ZASP_GRAPH_NODE_IDENTITY_V1", "UNIQUENESS", "NODE", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint))},
		{name: "wrong type", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow(nodeConstraint, "NODE_KEY", "NODE", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint))},
		{name: "node type used for relationship", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 1, constraintRow(edgeConstraint, "UNIQUENESS", "RELATIONSHIP", []any{edgeType}, edgeConstraintProperties, edgeConstraint))},
		{name: "wrong entity", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow(nodeConstraint, "UNIQUENESS", "RELATIONSHIP", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint))},
		{name: "extra label", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel, "Foreign"}, nodeConstraintProperties, nodeConstraint))},
		{name: "wrong properties", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel}, []any{"node_id"}, nodeConstraint))},
		{name: "string list alias", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []string{nodeLabel}, nodeConstraintProperties, nodeConstraint))},
		{name: "wrong owned index", keys: constraintResultKeys, records: replaceConstraintRow(validRows, 0, constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel}, nodeConstraintProperties, "foreign-index"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := validSchemaSession()
			session.tx.results[len(session.tx.results)-1] = &fakeResult{keys: test.keys, records: test.records}
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
		{name: "keys error", mutate: func(_ *fakeProvider, session *fakeSession) {
			session.tx.results[len(session.tx.results)-1].keysErr = providerError
		}},
		{name: "next panic", mutate: func(_ *fakeProvider, session *fakeSession) {
			session.tx.results[len(session.tx.results)-1].nextPanic = true
		}},
		{name: "cursor error", mutate: func(_ *fakeProvider, session *fakeSession) {
			session.tx.results[len(session.tx.results)-1].cursorErr = providerError
		}},
		{name: "consume error", mutate: func(_ *fakeProvider, session *fakeSession) {
			session.tx.results[len(session.tx.results)-1].consumeErr = providerError
		}},
		{name: "commit error", mutate: func(_ *fakeProvider, session *fakeSession) { session.tx.commitErr = providerError }},
		{name: "rollback error", mutate: func(_ *fakeProvider, session *fakeSession) {
			session.tx.results[len(session.tx.results)-1].consumeErr = providerError
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
		{keys: []string{}, records: []graphRecord{}},
		{keys: []string{}, records: []graphRecord{}},
		{keys: []string{}, records: []graphRecord{}},
		{keys: constraintResultKeys, records: validConstraintRows()},
	}}}
}

func validConstraintRows() []graphRecord {
	return []graphRecord{
		constraintRow(nodeConstraint, "UNIQUENESS", "NODE", []any{nodeLabel}, nodeConstraintProperties, nodeConstraint),
		constraintRow(edgeConstraint, "RELATIONSHIP_UNIQUENESS", "RELATIONSHIP", []any{edgeType}, edgeConstraintProperties, edgeConstraint),
		constraintRow(snapshotMarkerConstraint, "UNIQUENESS", "NODE", []any{snapshotMarkerLabel}, snapshotMarkerConstraintProperties, snapshotMarkerConstraint),
		constraintRow(snapshotNodeConstraint, "UNIQUENESS", "NODE", []any{snapshotNodeLabel}, snapshotNodeConstraintProperties, snapshotNodeConstraint),
		constraintRow(snapshotEdgeConstraint, "RELATIONSHIP_UNIQUENESS", "RELATIONSHIP", []any{snapshotEdgeType}, snapshotEdgeConstraintProperties, snapshotEdgeConstraint),
	}
}

func replaceConstraintRow(rows []graphRecord, index int, replacement graphRecord) []graphRecord {
	result := append([]graphRecord(nil), rows...)
	result[index] = replacement
	return result
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
	lockVersion        int64
	lockVersionBefore  int64
	lockTouched        bool
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
	if query == lockSnapshotQuery {
		transaction.lockVersionBefore = transaction.lockVersion
		transaction.lockVersion++
		transaction.lockTouched = true
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
	if transaction.rollbackErr == nil && transaction.lockTouched {
		transaction.lockVersion = transaction.lockVersionBefore
	}
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

type productionAuthResolverStub struct {
	manager   auth.TokenManager
	err       error
	calls     int
	reference string
}

func (resolver *productionAuthResolverStub) ResolveNeo4jAuthentication(_ context.Context, reference string) (auth.TokenManager, error) {
	resolver.calls++
	resolver.reference = reference
	return resolver.manager, resolver.err
}

type productionDriverFactoryStub struct {
	driver    neo4j.Driver
	err       error
	calls     int
	endpoint  string
	tlsConfig *tls.Config
}

func (factory *productionDriverFactoryStub) New(endpoint string, manager auth.TokenManager, configurers ...func(*config.Config)) (neo4j.Driver, error) {
	factory.calls++
	factory.endpoint = endpoint
	if manager == nil {
		return nil, errors.New("missing auth manager")
	}
	driverConfig := &config.Config{}
	for _, configure := range configurers {
		configure(driverConfig)
	}
	if driverConfig.TlsConfig != nil {
		factory.tlsConfig = driverConfig.TlsConfig.Clone()
	}
	return factory.driver, factory.err
}

type fakeOfficialDriver struct {
	encrypted           bool
	connectivityErr     error
	authenticationErr   error
	closeErr            error
	connectivityCalls   int
	authenticationCalls int
	closeCalls          int
	closeContextErr     error
	closeStartedAt      time.Time
	closeDeadline       time.Time
}

func (*fakeOfficialDriver) ExecuteQueryBookmarkManager() neo4j.BookmarkManager { return nil }
func (*fakeOfficialDriver) Target() url.URL                                    { return url.URL{} }
func (*fakeOfficialDriver) NewSession(context.Context, neo4j.SessionConfig) neo4j.Session {
	return nil
}
func (driver *fakeOfficialDriver) VerifyConnectivity(context.Context) error {
	driver.connectivityCalls++
	return driver.connectivityErr
}
func (driver *fakeOfficialDriver) VerifyAuthentication(context.Context, *neo4j.AuthToken) error {
	driver.authenticationCalls++
	return driver.authenticationErr
}
func (driver *fakeOfficialDriver) Close(ctx context.Context) error {
	driver.closeCalls++
	driver.closeContextErr = ctx.Err()
	driver.closeStartedAt = time.Now()
	driver.closeDeadline, _ = ctx.Deadline()
	return driver.closeErr
}
func (driver *fakeOfficialDriver) IsEncrypted() bool                                { return driver.encrypted }
func (*fakeOfficialDriver) GetServerInfo(context.Context) (neo4j.ServerInfo, error) { return nil, nil }
