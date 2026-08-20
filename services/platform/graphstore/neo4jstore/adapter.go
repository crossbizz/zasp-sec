package neo4jstore

import (
	"context"
	"crypto/tls"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/auth"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/config"
)

const (
	databaseName             = "neo4j"
	nodeLabel                = "ZaspGraphNode"
	edgeType                 = "ZASP_GRAPH_EDGE"
	nodeConstraint           = "zasp_graph_node_identity_v1"
	edgeConstraint           = "zasp_graph_edge_identity_v1"
	snapshotMarkerConstraint = "zasp_graph_projection_identity_v1"
	snapshotNodeConstraint   = "zasp_graph_snapshot_node_identity_v1"
	snapshotEdgeConstraint   = "zasp_graph_snapshot_edge_identity_v1"
	constraintPrefix         = "zasp_graph_"
	schemaVersion            = int64(1)
	cleanupTimeout           = 2 * time.Second
	minimumReadinessTimeout  = 100 * time.Millisecond
	maximumReadinessTimeout  = 30 * time.Second

	createNodeConstraintQuery           = "CREATE CONSTRAINT zasp_graph_node_identity_v1 IF NOT EXISTS FOR (node:ZaspGraphNode) REQUIRE (node.organization_id, node.workspace_id, node.environment_id, node.node_id) IS UNIQUE"
	createEdgeConstraintQuery           = "CREATE CONSTRAINT zasp_graph_edge_identity_v1 IF NOT EXISTS FOR ()-[edge:ZASP_GRAPH_EDGE]-() REQUIRE (edge.organization_id, edge.workspace_id, edge.environment_id, edge.edge_id) IS UNIQUE"
	createSnapshotMarkerConstraintQuery = "CREATE CONSTRAINT zasp_graph_projection_identity_v1 IF NOT EXISTS FOR (marker:ZaspGraphProjection) REQUIRE (marker.organization_id, marker.workspace_id, marker.environment_id, marker.integration_id, marker.source) IS UNIQUE"
	createSnapshotNodeConstraintQuery   = "CREATE CONSTRAINT zasp_graph_snapshot_node_identity_v1 IF NOT EXISTS FOR (node:ZaspInventoryGraphNode) REQUIRE (node.organization_id, node.workspace_id, node.environment_id, node.integration_id, node.source, node.node_id) IS UNIQUE"
	createSnapshotEdgeConstraintQuery   = "CREATE CONSTRAINT zasp_graph_snapshot_edge_identity_v1 IF NOT EXISTS FOR ()-[edge:ZASP_INVENTORY_GRAPH_EDGE]-() REQUIRE (edge.organization_id, edge.workspace_id, edge.environment_id, edge.integration_id, edge.source, edge.edge_id) IS UNIQUE"
	showOwnedConstraintsQuery           = "SHOW CONSTRAINTS YIELD name, type, entityType, labelsOrTypes, properties, ownedIndex WHERE name STARTS WITH $prefix RETURN name, type, entityType, labelsOrTypes, properties, ownedIndex ORDER BY name"
	showCurrentUserQuery                = "SHOW CURRENT USER YIELD user, roles, passwordChangeRequired, suspended RETURN user, roles, passwordChangeRequired, suspended"
	showUserPrivilegesQuery             = "SHOW USER $principal PRIVILEGES AS COMMANDS YIELD command RETURN command ORDER BY command"
)

var (
	ErrConfiguration = errors.New("neo4j graph store configuration rejected")
	ErrClose         = errors.New("neo4j graph store close failed")
	ErrSchema        = errors.New("neo4j graph store schema rejected")
	ErrUpsert        = errors.New("neo4j graph store upsert failed")
	ErrRead          = errors.New("neo4j graph store read failed")

	constraintResultKeys               = []string{"name", "type", "entityType", "labelsOrTypes", "properties", "ownedIndex"}
	nodeConstraintProperties           = []any{"organization_id", "workspace_id", "environment_id", "node_id"}
	edgeConstraintProperties           = []any{"organization_id", "workspace_id", "environment_id", "edge_id"}
	snapshotMarkerConstraintProperties = []any{"organization_id", "workspace_id", "environment_id", "integration_id", "source"}
	snapshotNodeConstraintProperties   = []any{"organization_id", "workspace_id", "environment_id", "integration_id", "source", "node_id"}
	snapshotEdgeConstraintProperties   = []any{"organization_id", "workspace_id", "environment_id", "integration_id", "source", "edge_id"}
	productionAuthReferencePattern     = regexp.MustCompile(`^ref:neo4j/auth/[a-z0-9][a-z0-9_./:-]{7,487}$`)
	productionPrincipalPattern         = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	currentUserResultKeys              = []string{"user", "roles", "passwordChangeRequired", "suspended"}
	privilegeCommandResultKeys         = []string{"command"}
)

type accessMode uint8

const (
	accessRead accessMode = iota + 1
	accessWrite
)

type sessionConfig struct {
	Database string
	Access   accessMode
}

type sessionProvider interface {
	NewSession(context.Context, sessionConfig) graphSession
}

type graphSession interface {
	Begin(context.Context) (graphTransaction, error)
	Close(context.Context) error
}

type graphTransaction interface {
	Run(context.Context, string, map[string]any) (graphResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type graphResult interface {
	Keys() ([]string, error)
	Next(context.Context) bool
	Record() graphRecord
	Err() error
	Consume(context.Context) error
}

type graphRecord struct {
	Keys   []string
	Values []any
}

type Adapter struct {
	provider          sessionProvider
	database          string
	ownedDriver       neo4j.Driver
	expectedPrincipal string
	expectedRole      string
	closeOnce         sync.Once
	closeErr          error
}

// ProductionConfig identifies one verified-TLS Neo4j endpoint and an opaque
// authentication reference. It never accepts inline credentials.
type ProductionConfig struct {
	Endpoint                string
	AuthenticationReference string
	ReadinessTimeout        time.Duration
	ExpectedPrincipal       string
	ExpectedRole            string
}

// AuthenticationResolver is the only production authority that may turn the
// configured opaque reference into a Neo4j authentication manager.
type AuthenticationResolver interface {
	ResolveNeo4jAuthentication(context.Context, string) (auth.TokenManager, error)
}

type productionDriverFactory interface {
	New(string, auth.TokenManager, ...func(*config.Config)) (neo4j.Driver, error)
}

type officialDriverFactory struct{}

func (officialDriverFactory) New(endpoint string, manager auth.TokenManager, configurers ...func(*config.Config)) (neo4j.Driver, error) {
	return neo4j.NewDriver(endpoint, manager, configurers...)
}

// NewProduction owns endpoint validation, authentication resolution, driver
// creation, and bounded connectivity/authentication readiness verification.
func NewProduction(ctx context.Context, production ProductionConfig, resolver AuthenticationResolver) (*Adapter, error) {
	return newProductionAdapter(ctx, production, resolver, officialDriverFactory{})
}

func newProductionAdapter(ctx context.Context, production ProductionConfig, resolver AuthenticationResolver, factory productionDriverFactory) (*Adapter, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(resolver) || nilInterface(factory) || !validProductionEndpoint(production.Endpoint) ||
		!productionAuthReferencePattern.MatchString(production.AuthenticationReference) || production.ReadinessTimeout < minimumReadinessTimeout ||
		production.ReadinessTimeout > maximumReadinessTimeout || (production.ExpectedPrincipal == "") != (production.ExpectedRole == "") ||
		production.ExpectedPrincipal != "" && (!productionPrincipalPattern.MatchString(production.ExpectedPrincipal) || !productionPrincipalPattern.MatchString(production.ExpectedRole)) {
		return nil, ErrConfiguration
	}
	readyCtx, cancel := context.WithTimeout(ctx, production.ReadinessTimeout)
	defer cancel()
	manager, err := resolveProductionAuthentication(readyCtx, resolver, production.AuthenticationReference)
	if err != nil || !authenticatedTokenManager(readyCtx, manager) {
		return nil, ErrConfiguration
	}
	driver, err := newProductionDriver(factory, production.Endpoint, manager)
	if err != nil || nilInterface(driver) || !encryptedDriver(driver) {
		closeProductionDriver(readyCtx, driver)
		return nil, ErrConfiguration
	}
	if !verifyProductionDriver(readyCtx, driver) {
		closeProductionDriver(readyCtx, driver)
		return nil, ErrConfiguration
	}
	adapter, err := newAdapterForProvider(officialProvider{driver: driver}, databaseName)
	if err != nil {
		closeProductionDriver(readyCtx, driver)
		return nil, ErrConfiguration
	}
	adapter.ownedDriver = driver
	adapter.expectedPrincipal, adapter.expectedRole = production.ExpectedPrincipal, production.ExpectedRole
	return adapter, nil
}

func newAdapterForDriver(driver neo4j.Driver, database string) (*Adapter, error) {
	if nilInterface(driver) || !encryptedDriver(driver) {
		return nil, ErrConfiguration
	}
	return newAdapterForProvider(officialProvider{driver: driver}, database)
}

func validProductionEndpoint(endpoint string) bool {
	if len(endpoint) < 1 || len(endpoint) > 2048 || strings.TrimSpace(endpoint) != endpoint {
		return false
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.Hostname() == "" {
		return false
	}
	return parsed.Scheme == "neo4j+s" || parsed.Scheme == "bolt+s"
}

func resolveProductionAuthentication(ctx context.Context, resolver AuthenticationResolver, reference string) (manager auth.TokenManager, err error) {
	defer func() {
		if recover() != nil {
			manager = nil
			err = ErrConfiguration
		}
	}()
	manager, err = resolver.ResolveNeo4jAuthentication(ctx, reference)
	if err != nil || nilInterface(manager) {
		return nil, ErrConfiguration
	}
	return manager, nil
}

func authenticatedTokenManager(ctx context.Context, manager auth.TokenManager) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	token, err := manager.GetAuthToken(ctx)
	if err != nil || ctx.Err() != nil || token.Tokens == nil {
		return false
	}
	scheme, schemeOK := token.Tokens["scheme"].(string)
	credentials, credentialsOK := token.Tokens["credentials"].(string)
	if !schemeOK || !credentialsOK || len(credentials) < 1 || len(credentials) > 8192 {
		return false
	}
	switch scheme {
	case "basic":
		principal, ok := token.Tokens["principal"].(string)
		return ok && len(principal) >= 1 && len(principal) <= 512
	case "bearer", "kerberos":
		return true
	default:
		return false
	}
}

func newProductionDriver(factory productionDriverFactory, endpoint string, manager auth.TokenManager) (driver neo4j.Driver, err error) {
	defer func() {
		if recover() != nil {
			driver = nil
			err = ErrConfiguration
		}
	}()
	return factory.New(endpoint, manager, func(driverConfig *config.Config) {
		driverConfig.TlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	})
}

func verifyProductionDriver(ctx context.Context, driver neo4j.Driver) (ready bool) {
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return driver.VerifyConnectivity(ctx) == nil && ctx.Err() == nil && driver.VerifyAuthentication(ctx, nil) == nil && ctx.Err() == nil
}

func closeProductionDriver(ctx context.Context, driver neo4j.Driver) {
	if nilInterface(driver) {
		return
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	_ = closeOwnedDriver(closeCtx, driver)
}

// Close releases the production-owned Neo4j driver exactly once. Adapters
// created around injected drivers or providers remain non-owning.
func (adapter *Adapter) Close(ctx context.Context) error {
	if adapter == nil {
		return ErrClose
	}
	adapter.closeOnce.Do(func() {
		driver := adapter.ownedDriver
		adapter.ownedDriver = nil
		if nilInterface(driver) {
			return
		}
		if ctx == nil {
			ctx = context.Background()
		}
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		if !closeOwnedDriver(closeCtx, driver) {
			adapter.closeErr = ErrClose
		}
	})
	return adapter.closeErr
}

func closeOwnedDriver(ctx context.Context, driver neo4j.Driver) (closed bool) {
	defer func() {
		if recover() != nil {
			closed = false
		}
	}()
	return driver.Close(ctx) == nil && ctx.Err() == nil
}

func newAdapterForProvider(provider sessionProvider, database string) (*Adapter, error) {
	if nilInterface(provider) || database != databaseName {
		return nil, ErrConfiguration
	}
	return &Adapter{provider: provider, database: database}, nil
}

func EnsureSchema(ctx context.Context, driver neo4j.Driver, database string) error {
	if ctx == nil || nilInterface(driver) || !encryptedDriver(driver) || database != databaseName {
		return ErrConfiguration
	}
	return ensureSchemaWithProvider(ctx, officialProvider{driver: driver}, database)
}

// Ready verifies the exact owned schema using read authority only. Schema DDL
// remains the responsibility of the separately privileged EnsureSchema path.
func (adapter *Adapter) Ready(ctx context.Context) error {
	if adapter == nil || nilInterface(adapter.provider) || adapter.database != databaseName || ctx == nil || ctx.Err() != nil {
		return ErrSchema
	}
	return verifyReadinessWithProvider(ctx, adapter.provider, adapter.database, adapter.expectedPrincipal, adapter.expectedRole)
}

// EnsureSchema executes the exact five-constraint DDL contract. Production
// callers must expose this only from a separately privileged one-shot job.
func (adapter *Adapter) EnsureSchema(ctx context.Context) error {
	if adapter == nil || nilInterface(adapter.provider) || adapter.database != databaseName || ctx == nil || ctx.Err() != nil {
		return ErrSchema
	}
	return ensureSchemaWithProvider(ctx, adapter.provider, adapter.database)
}

func encryptedDriver(driver neo4j.Driver) (encrypted bool) {
	defer func() {
		if recover() != nil {
			encrypted = false
		}
	}()
	return driver.IsEncrypted()
}

func ensureSchemaWithProvider(ctx context.Context, provider sessionProvider, database string) error {
	if ctx == nil || nilInterface(provider) || database != databaseName {
		return ErrConfiguration
	}
	if ctx.Err() != nil {
		return ErrSchema
	}
	return executeTransaction(ctx, provider, sessionConfig{Database: database, Access: accessWrite}, ErrSchema, func(tx graphTransaction) error {
		if err := runEmpty(ctx, tx, createNodeConstraintQuery, map[string]any{}); err != nil {
			return ErrSchema
		}
		if err := runEmpty(ctx, tx, createEdgeConstraintQuery, map[string]any{}); err != nil {
			return ErrSchema
		}
		if err := runEmpty(ctx, tx, createSnapshotMarkerConstraintQuery, map[string]any{}); err != nil {
			return ErrSchema
		}
		if err := runEmpty(ctx, tx, createSnapshotNodeConstraintQuery, map[string]any{}); err != nil {
			return ErrSchema
		}
		if err := runEmpty(ctx, tx, createSnapshotEdgeConstraintQuery, map[string]any{}); err != nil {
			return ErrSchema
		}
		result, err := tx.Run(ctx, showOwnedConstraintsQuery, map[string]any{"prefix": constraintPrefix})
		if err != nil || nilInterface(result) || !validConstraintResult(ctx, result) {
			return ErrSchema
		}
		return nil
	})
}

func verifySchemaWithProvider(ctx context.Context, provider sessionProvider, database string) error {
	if ctx == nil || ctx.Err() != nil || nilInterface(provider) || database != databaseName {
		return ErrSchema
	}
	return executeTransaction(ctx, provider, sessionConfig{Database: database, Access: accessRead}, ErrSchema, func(tx graphTransaction) error {
		result, err := tx.Run(ctx, showOwnedConstraintsQuery, map[string]any{"prefix": constraintPrefix})
		if err != nil || nilInterface(result) || !validConstraintResult(ctx, result) {
			return ErrSchema
		}
		return nil
	})
}

func verifyReadinessWithProvider(ctx context.Context, provider sessionProvider, database, principal, role string) error {
	if principal == "" && role == "" {
		return verifySchemaWithProvider(ctx, provider, database)
	}
	if ctx == nil || ctx.Err() != nil || nilInterface(provider) || database != databaseName || !productionPrincipalPattern.MatchString(principal) || !productionPrincipalPattern.MatchString(role) {
		return ErrSchema
	}
	return executeTransaction(ctx, provider, sessionConfig{Database: database, Access: accessRead}, ErrSchema, func(tx graphTransaction) error {
		current, err := tx.Run(ctx, showCurrentUserQuery, map[string]any{})
		if err != nil || !validCurrentUser(ctx, current, principal, role) {
			return ErrSchema
		}
		privileges, err := tx.Run(ctx, showUserPrivilegesQuery, map[string]any{"principal": principal})
		if err != nil || !validWorkerPrivileges(ctx, privileges, role) {
			return ErrSchema
		}
		constraints, err := tx.Run(ctx, showOwnedConstraintsQuery, map[string]any{"prefix": constraintPrefix})
		if err != nil || !validConstraintResult(ctx, constraints) {
			return ErrSchema
		}
		return nil
	})
}

func validCurrentUser(ctx context.Context, result graphResult, principal, role string) bool {
	if nilInterface(result) {
		return false
	}
	keys, err := result.Keys()
	if err != nil || !slices.Equal(keys, currentUserResultKeys) || !result.Next(ctx) {
		return false
	}
	record := result.Record()
	roles, rolesOK := exactStringList(record.Values[1])
	slices.Sort(roles)
	valid := slices.Equal(record.Keys, currentUserResultKeys) && len(record.Values) == 4 && record.Values[0] == principal && rolesOK && slices.Equal(roles, []string{"PUBLIC", role}) && record.Values[2] == false && record.Values[3] == false
	return valid && !result.Next(ctx) && result.Err() == nil && result.Consume(ctx) == nil
}

func validWorkerPrivileges(ctx context.Context, result graphResult, role string) bool {
	if nilInterface(result) {
		return false
	}
	keys, err := result.Keys()
	if err != nil || !slices.Equal(keys, privilegeCommandResultKeys) {
		return false
	}
	commands := []string{}
	for result.Next(ctx) {
		record := result.Record()
		if !slices.Equal(record.Keys, privilegeCommandResultKeys) || len(record.Values) != 1 {
			return false
		}
		command, ok := record.Values[0].(string)
		if !ok {
			return false
		}
		commands = append(commands, command)
	}
	return result.Err() == nil && result.Consume(ctx) == nil && slices.Equal(commands, expectedWorkerPrivilegeCommands(role))
}

func expectedWorkerPrivilegeCommands(role string) []string {
	quoted := "`" + role + "`"
	return []string{
		"GRANT ACCESS ON DATABASE neo4j TO " + quoted,
		"GRANT MATCH {*} ON GRAPH neo4j ELEMENTS * TO " + quoted,
		"GRANT SHOW CONSTRAINT ON DATABASE neo4j TO " + quoted,
		"GRANT WRITE ON GRAPH neo4j TO " + quoted,
	}
}

func runEmpty(ctx context.Context, transaction graphTransaction, query string, parameters map[string]any) error {
	result, err := transaction.Run(ctx, query, parameters)
	if err != nil || nilInterface(result) {
		return ErrSchema
	}
	keys, err := result.Keys()
	if err != nil || len(keys) != 0 || result.Next(ctx) || result.Err() != nil || result.Consume(ctx) != nil {
		return ErrSchema
	}
	return nil
}

func validConstraintResult(ctx context.Context, result graphResult) bool {
	keys, err := result.Keys()
	if err != nil || !slices.Equal(keys, constraintResultKeys) {
		return false
	}
	seen := make(map[string]struct{}, 5)
	for result.Next(ctx) {
		record := result.Record()
		if !slices.Equal(record.Keys, constraintResultKeys) || len(record.Values) != len(constraintResultKeys) {
			return false
		}
		name, ok := record.Values[0].(string)
		if !ok {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		if !validConstraintRow(name, record.Values) {
			return false
		}
		seen[name] = struct{}{}
	}
	if result.Err() != nil || result.Consume(ctx) != nil {
		return false
	}
	_, nodeSeen := seen[nodeConstraint]
	_, edgeSeen := seen[edgeConstraint]
	_, markerSeen := seen[snapshotMarkerConstraint]
	_, snapshotNodeSeen := seen[snapshotNodeConstraint]
	_, snapshotEdgeSeen := seen[snapshotEdgeConstraint]
	return len(seen) == 5 && nodeSeen && edgeSeen && markerSeen && snapshotNodeSeen && snapshotEdgeSeen
}

func validConstraintRow(name string, values []any) bool {
	constraintType, typeOK := values[1].(string)
	entityType, entityOK := values[2].(string)
	labelsOrTypes, labelsOK := exactStringList(values[3])
	properties, propertiesOK := exactStringList(values[4])
	ownedIndex, indexOK := values[5].(string)
	if !typeOK || !entityOK || !labelsOK || !propertiesOK || !indexOK || ownedIndex != name {
		return false
	}
	switch name {
	case nodeConstraint:
		return constraintType == "UNIQUENESS" && entityType == "NODE" && slices.Equal(labelsOrTypes, []string{nodeLabel}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "node_id"})
	case edgeConstraint:
		return constraintType == "RELATIONSHIP_UNIQUENESS" && entityType == "RELATIONSHIP" && slices.Equal(labelsOrTypes, []string{edgeType}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "edge_id"})
	case snapshotMarkerConstraint:
		return constraintType == "UNIQUENESS" && entityType == "NODE" && slices.Equal(labelsOrTypes, []string{snapshotMarkerLabel}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "integration_id", "source"})
	case snapshotNodeConstraint:
		return constraintType == "UNIQUENESS" && entityType == "NODE" && slices.Equal(labelsOrTypes, []string{snapshotNodeLabel}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "integration_id", "source", "node_id"})
	case snapshotEdgeConstraint:
		return constraintType == "RELATIONSHIP_UNIQUENESS" && entityType == "RELATIONSHIP" && slices.Equal(labelsOrTypes, []string{snapshotEdgeType}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "integration_id", "source", "edge_id"})
	default:
		return false
	}
}

func exactStringList(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	strings := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		strings[index] = text
	}
	return strings, true
}

func executeTransaction(
	ctx context.Context,
	provider sessionProvider,
	config sessionConfig,
	fixedError error,
	work func(graphTransaction) error,
) (err error) {
	var session graphSession
	var transaction graphTransaction
	committed := false
	cleanupFailed := false
	defer func() {
		if recover() != nil {
			err = fixedError
		}
		if !nilInterface(transaction) && !committed {
			rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			if !safeRollback(rollbackCtx, transaction) {
				cleanupFailed = true
			}
			cancelRollback()
		}
		if !nilInterface(session) {
			closeCtx, cancelClose := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			if !safeClose(closeCtx, session) {
				cleanupFailed = true
			}
			cancelClose()
		}
		if err != nil || cleanupFailed {
			err = fixedError
		}
	}()

	session = provider.NewSession(ctx, config)
	if nilInterface(session) {
		return fixedError
	}
	transaction, err = session.Begin(ctx)
	if err != nil || nilInterface(transaction) {
		return fixedError
	}
	if err = work(transaction); err != nil || ctx.Err() != nil {
		return fixedError
	}
	if err = transaction.Commit(ctx); err != nil {
		return fixedError
	}
	committed = true
	return nil
}

func safeRollback(ctx context.Context, transaction graphTransaction) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return transaction.Rollback(ctx) == nil
}

func safeClose(ctx context.Context, session graphSession) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return session.Close(ctx) == nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type officialProvider struct {
	driver neo4j.Driver
}

func (provider officialProvider) NewSession(ctx context.Context, config sessionConfig) graphSession {
	mode := neo4j.AccessModeRead
	if config.Access == accessWrite {
		mode = neo4j.AccessModeWrite
	}
	session := provider.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: config.Database, AccessMode: mode})
	if nilInterface(session) {
		return nil
	}
	return officialSession{session: session}
}

type officialSession struct {
	session neo4j.Session
}

func (session officialSession) Begin(ctx context.Context) (graphTransaction, error) {
	transaction, err := session.session.BeginTransaction(ctx)
	if nilInterface(transaction) {
		return nil, err
	}
	return officialTransaction{transaction: transaction}, err
}

func (session officialSession) Close(ctx context.Context) error {
	return session.session.Close(ctx)
}

type officialTransaction struct {
	transaction neo4j.ExplicitTransaction
}

func (transaction officialTransaction) Run(ctx context.Context, query string, parameters map[string]any) (graphResult, error) {
	result, err := transaction.transaction.Run(ctx, query, parameters)
	if nilInterface(result) {
		return nil, err
	}
	return officialResult{result: result}, err
}

func (transaction officialTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction officialTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

type officialResult struct {
	result neo4j.Result
}

func (result officialResult) Keys() ([]string, error)       { return result.result.Keys() }
func (result officialResult) Next(ctx context.Context) bool { return result.result.Next(ctx) }
func (result officialResult) Err() error                    { return result.result.Err() }

func (result officialResult) Record() graphRecord {
	record := result.result.Record()
	if record == nil {
		return graphRecord{}
	}
	return graphRecord{Keys: append([]string(nil), record.Keys...), Values: append([]any(nil), record.Values...)}
}

func (result officialResult) Consume(ctx context.Context) error {
	_, err := result.result.Consume(ctx)
	return err
}
