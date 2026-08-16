package neo4jstore

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
)

const (
	databaseName     = "neo4j"
	nodeLabel        = "ZaspGraphNode"
	edgeType         = "ZASP_GRAPH_EDGE"
	nodeConstraint   = "zasp_graph_node_identity_v1"
	edgeConstraint   = "zasp_graph_edge_identity_v1"
	constraintPrefix = "zasp_graph_"
	schemaVersion    = int64(1)
	cleanupTimeout   = 2 * time.Second

	createNodeConstraintQuery = "CREATE CONSTRAINT zasp_graph_node_identity_v1 IF NOT EXISTS FOR (node:ZaspGraphNode) REQUIRE (node.organization_id, node.workspace_id, node.environment_id, node.node_id) IS UNIQUE"
	createEdgeConstraintQuery = "CREATE CONSTRAINT zasp_graph_edge_identity_v1 IF NOT EXISTS FOR ()-[edge:ZASP_GRAPH_EDGE]-() REQUIRE (edge.organization_id, edge.workspace_id, edge.environment_id, edge.edge_id) IS UNIQUE"
	showOwnedConstraintsQuery = "SHOW CONSTRAINTS YIELD name, type, entityType, labelsOrTypes, properties, ownedIndex WHERE name STARTS WITH $prefix RETURN name, type, entityType, labelsOrTypes, properties, ownedIndex ORDER BY name"
)

var (
	ErrConfiguration = errors.New("neo4j graph store configuration rejected")
	ErrSchema        = errors.New("neo4j graph store schema rejected")
	ErrUpsert        = errors.New("neo4j graph store upsert failed")
	ErrRead          = errors.New("neo4j graph store read failed")

	constraintResultKeys     = []string{"name", "type", "entityType", "labelsOrTypes", "properties", "ownedIndex"}
	nodeConstraintProperties = []any{"organization_id", "workspace_id", "environment_id", "node_id"}
	edgeConstraintProperties = []any{"organization_id", "workspace_id", "environment_id", "edge_id"}
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
	provider sessionProvider
	database string
}

func New(driver neo4j.Driver, database string) (*Adapter, error) {
	if nilInterface(driver) {
		return nil, ErrConfiguration
	}
	return newAdapterForProvider(officialProvider{driver: driver}, database)
}

func newAdapterForProvider(provider sessionProvider, database string) (*Adapter, error) {
	if nilInterface(provider) || database != databaseName {
		return nil, ErrConfiguration
	}
	return &Adapter{provider: provider, database: database}, nil
}

func EnsureSchema(ctx context.Context, driver neo4j.Driver, database string) error {
	if ctx == nil || nilInterface(driver) || database != databaseName {
		return ErrConfiguration
	}
	return ensureSchemaWithProvider(ctx, officialProvider{driver: driver}, database)
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
		result, err := tx.Run(ctx, showOwnedConstraintsQuery, map[string]any{"prefix": constraintPrefix})
		if err != nil || nilInterface(result) || !validConstraintResult(ctx, result) {
			return ErrSchema
		}
		return nil
	})
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
	seen := make(map[string]struct{}, 2)
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
	return len(seen) == 2 && nodeSeen && edgeSeen
}

func validConstraintRow(name string, values []any) bool {
	constraintType, typeOK := values[1].(string)
	entityType, entityOK := values[2].(string)
	labelsOrTypes, labelsOK := exactStringList(values[3])
	properties, propertiesOK := exactStringList(values[4])
	ownedIndex, indexOK := values[5].(string)
	if !typeOK || !entityOK || !labelsOK || !propertiesOK || !indexOK || constraintType != "UNIQUENESS" || ownedIndex != name {
		return false
	}
	switch name {
	case nodeConstraint:
		return entityType == "NODE" && slices.Equal(labelsOrTypes, []string{nodeLabel}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "node_id"})
	case edgeConstraint:
		return entityType == "RELATIONSHIP" && slices.Equal(labelsOrTypes, []string{edgeType}) &&
			slices.Equal(properties, []string{"organization_id", "workspace_id", "environment_id", "edge_id"})
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
