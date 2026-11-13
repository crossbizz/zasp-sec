package neo4jstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
)

// These tests pin the two settings that exist only for a development graph
// database, and show that a ProductionConfig without them behaves as before.

func developmentTestAdapter(t *testing.T, production ProductionConfig) (*Adapter, *productionDriverFactoryStub) {
	t.Helper()
	production.Endpoint = "neo4j+s://graph.example.test:7687"
	production.AuthenticationReference = "ref:neo4j/auth/production-0001"
	production.ReadinessTimeout = time.Second
	factory := &productionDriverFactoryStub{driver: &fakeOfficialDriver{encrypted: true}}
	adapter, err := newProductionAdapter(context.Background(), production, &productionAuthResolverStub{manager: neo4j.BasicAuth("graph-user", "graph-password", "")}, factory)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, factory
}

func TestProductionDriverTrustsSystemRootsUnlessDevelopmentRootsAreGiven(t *testing.T) {
	adapter, factory := developmentTestAdapter(t, ProductionConfig{})
	if factory.tlsConfig == nil || factory.tlsConfig.RootCAs != nil || factory.tlsConfig.InsecureSkipVerify || factory.tlsConfig.MinVersion != tls.VersionTLS12 || adapter.developmentCommunityEdition {
		t.Fatalf("production TLS configuration = %#v, community = %v", factory.tlsConfig, adapter.developmentCommunityEdition)
	}

	roots := x509.NewCertPool()
	adapter, factory = developmentTestAdapter(t, ProductionConfig{DevelopmentRootCAs: roots, DevelopmentCommunityEdition: true})
	if factory.tlsConfig == nil || !factory.tlsConfig.RootCAs.Equal(roots) || factory.tlsConfig.InsecureSkipVerify || factory.tlsConfig.MinVersion != tls.VersionTLS12 || !adapter.developmentCommunityEdition {
		t.Fatalf("development TLS configuration = %#v, community = %v", factory.tlsConfig, adapter.developmentCommunityEdition)
	}
}

func TestReadinessAcceptsCommunityEditionOnlyWhenDevelopmentAllowsIt(t *testing.T) {
	principal, role := "zasp_graph_worker", "zasp_graph_writer"
	edition := func(name string) *fakeResult {
		return &fakeResult{keys: serverEditionResultKeys, records: []graphRecord{{Keys: serverEditionResultKeys, Values: []any{name}}}}
	}
	user := func(values ...any) *fakeResult {
		return &fakeResult{keys: currentUserResultKeys, records: []graphRecord{{Keys: currentUserResultKeys, Values: values}}}
	}
	privileges := func() *fakeResult {
		commands := expectedWorkerPrivilegeCommands(role)
		rows := make([]graphRecord, len(commands))
		for index, command := range commands {
			rows[index] = graphRecord{Keys: privilegeCommandResultKeys, Values: []any{command}}
		}
		return &fakeResult{keys: privilegeCommandResultKeys, records: rows}
	}
	constraints := func() *fakeResult { return &fakeResult{keys: constraintResultKeys, records: validConstraintRows()} }
	ready := func(development bool, results ...*fakeResult) (error, *fakeProvider, *fakeTransaction) {
		transaction := &fakeTransaction{results: results}
		provider := &fakeProvider{session: &fakeSession{tx: transaction}}
		adapter, err := newAdapterForProvider(provider, databaseName)
		if err != nil {
			t.Fatal(err)
		}
		adapter.expectedPrincipal, adapter.expectedRole, adapter.developmentCommunityEdition = principal, role, development
		return adapter.Ready(context.Background()), provider, transaction
	}
	communityUser := []any{principal, nil, false, nil}
	enterpriseUser := []any{principal, []any{"PUBLIC", role}, false, false}

	// Production never asks for the edition and refuses what Community answers.
	err, _, transaction := ready(false, user(communityUser...), privileges(), constraints())
	if !errors.Is(err, ErrSchema) || !reflect.DeepEqual(transaction.queries, []string{showCurrentUserQuery}) {
		t.Fatalf("production readiness on Community = %v, queries %#v", err, transaction.queries)
	}
	// Production: the identity and the constraints are read in two read-only
	// transactions, because Neo4j refuses to mix their commands in one.
	err, provider, transaction := ready(false, user(enterpriseUser...), privileges(), constraints())
	if err != nil || provider.calls != 2 || transaction.commitCalls != 2 || provider.configs[0].Access != accessRead || provider.configs[1].Access != accessRead ||
		!reflect.DeepEqual(transaction.queries, []string{showCurrentUserQuery, showUserPrivilegesQuery, showOwnedConstraintsQuery}) {
		t.Fatalf("production readiness = %v, sessions %d, queries %#v", err, provider.calls, transaction.queries)
	}

	// Development on Community: principal, password state and constraints.
	err, provider, transaction = ready(true, edition("community"), user(communityUser...), constraints())
	if err != nil || provider.calls != 3 || !reflect.DeepEqual(transaction.queries, []string{showServerEditionQuery, showCurrentUserQuery, showOwnedConstraintsQuery}) {
		t.Fatalf("development readiness on Community = %v, queries %#v", err, transaction.queries)
	}
	for name, values := range map[string][]any{
		"another principal":        {"neo4j", nil, false, nil},
		"password change required": {principal, nil, true, nil},
		"unexpected roles":         {principal, []any{"PUBLIC", "admin"}, false, nil},
		"suspension state":         {principal, nil, false, false},
		"missing column":           {principal, nil, false},
	} {
		if err, _, _ := ready(true, edition("community"), user(values...), constraints()); !errors.Is(err, ErrSchema) {
			t.Fatalf("%s: development readiness on Community = %v", name, err)
		}
	}
	// The constraints are still exact on Community.
	if err, _, _ := ready(true, edition("community"), user(communityUser...), &fakeResult{keys: constraintResultKeys}); !errors.Is(err, ErrSchema) {
		t.Fatalf("development readiness without constraints = %v", err)
	}

	// Development on any other edition: the full production check.
	err, _, transaction = ready(true, edition("enterprise"), user(enterpriseUser...), privileges(), constraints())
	if err != nil || !reflect.DeepEqual(transaction.queries, []string{showServerEditionQuery, showCurrentUserQuery, showUserPrivilegesQuery, showOwnedConstraintsQuery}) {
		t.Fatalf("development readiness on Enterprise = %v, queries %#v", err, transaction.queries)
	}
	if err, _, _ := ready(true, edition("enterprise"), user(communityUser...), constraints()); !errors.Is(err, ErrSchema) {
		t.Fatalf("development readiness on Enterprise without a role = %v", err)
	}
	// An edition answer that cannot be read is refused, not treated as Community.
	for name, result := range map[string]*fakeResult{
		"no row":     {keys: serverEditionResultKeys},
		"two rows":   {keys: serverEditionResultKeys, records: []graphRecord{{Keys: serverEditionResultKeys, Values: []any{"community"}}, {Keys: serverEditionResultKeys, Values: []any{"community"}}}},
		"wrong keys": {keys: []string{"name"}, records: []graphRecord{{Keys: []string{"name"}, Values: []any{"community"}}}},
		"not text":   {keys: serverEditionResultKeys, records: []graphRecord{{Keys: serverEditionResultKeys, Values: []any{int64(5)}}}},
	} {
		if err, _, _ := ready(true, result, user(communityUser...), constraints()); !errors.Is(err, ErrSchema) {
			t.Fatalf("%s: development readiness = %v", name, err)
		}
	}
}
