package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/auth"
	neo4jconfig "github.com/neo4j/neo4j-go-driver/v6/neo4j/config"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore/neo4jstore"
)

const (
	successLine    = "Neo4j GraphStore proof passed: nodes=3 edges=2 replay=true scoped=true cross_organization_zero=true cleanup=true audit=true tls=true untrusted_zero=true bad_auth_zero=true."
	mainTimeout    = 90 * time.Second
	cleanupTimeout = 20 * time.Second
)

var (
	errConfiguration = errors.New("configuration")
	errProvider      = errors.New("provider")
	errOwnership     = errors.New("ownership")
	errOperation     = errors.New("operation")
	errCleanup       = errors.New("cleanup")
)

type proofResult struct {
	Nodes                 int
	Edges                 int
	Replay                bool
	Scoped                bool
	CrossOrganizationZero bool
	Cleanup               bool
	Audit                 bool
}

type fixtureState struct {
	scopeA     domain.Scope
	scopeB     domain.Scope
	projection graphstore.Projection
}

type fixtureAuditor interface {
	Verify(context.Context, fixtureState) error
	Delete(context.Context, fixtureState) error
	Absent(context.Context, fixtureState) error
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--tls-fixture" {
		if err := writeTLSFixture(os.Args[2]); err != nil {
			os.Exit(1)
		}
		return
	}
	os.Exit(runMain(os.Getenv, os.Stdout, executeProof))
}

func runMain(getenv func(string) string, output io.Writer, execute func(context.Context, string) error) (code int) {
	line := "Neo4j GraphStore proof failed: operation rejected."
	defer func() {
		if recover() != nil {
			code = 1
			line = "Neo4j GraphStore proof failed: operation rejected."
		}
		_, _ = io.WriteString(output, line+"\n")
	}()
	uri := getenv("NEO4J_GRAPHSTORE_URI")
	if !validURI(uri) {
		line = "Neo4j GraphStore proof failed: configuration rejected."
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), mainTimeout)
	defer cancel()
	err := execute(ctx, uri)
	if err == nil {
		line = successLine
		return 0
	}
	switch {
	case errors.Is(err, errConfiguration):
		line = "Neo4j GraphStore proof failed: configuration rejected."
	case errors.Is(err, errProvider):
		line = "Neo4j GraphStore proof failed: provider rejected."
	case errors.Is(err, errOwnership):
		line = "Neo4j GraphStore proof failed: ownership rejected."
	case errors.Is(err, errCleanup):
		line = "Neo4j GraphStore proof failed: cleanup rejected."
	default:
		line = "Neo4j GraphStore proof failed: operation rejected."
	}
	return 1
}

func validURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "bolt+s" || parsed.User != nil || parsed.Hostname() != "127.0.0.1" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	return err == nil && port >= 1 && port <= 65535 && parsed.Host == net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func executeProof(ctx context.Context, uri string) (err error) {
	password := os.Getenv("NEO4J_GRAPHSTORE_PASSWORD")
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(password) || os.Getenv("GODEBUG") != "x509usefallbackroots=1" {
		return errConfiguration
	}
	block, rest := pem.Decode([]byte(os.Getenv("NEO4J_GRAPHSTORE_CA_PEM")))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return errConfiguration
	}
	certificate, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil || !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil || certificate.VerifyHostname("127.0.0.1") != nil {
		return errConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	// This standalone disposable proof trusts only its generated certificate.
	// No operating-system trust or production TLS configuration is changed.
	x509.SetFallbackRoots(roots)
	manager := neo4j.BasicAuth("neo4j", password, "")
	driver, driverErr := neo4j.NewDriver(uri, manager, func(config *neo4jconfig.Config) {
		config.MaxTransactionRetryTime = 0
		config.MaxConnectionPoolSize = 4
		config.ConnectionAcquisitionTimeout = 5 * time.Second
		config.SocketConnectTimeout = 5 * time.Second
		config.TelemetryDisabled = true
		config.DisableAutoCommitRetries = true
	})
	if driverErr != nil || driver == nil {
		return errProvider
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if driver.Close(closeCtx) != nil {
			err = errCleanup
		}
	}()
	if driver.VerifyConnectivity(ctx) != nil || driver.VerifyAuthentication(ctx, nil) != nil {
		return errProvider
	}
	if err := verifyTLSAuthenticationNegatives(ctx, uri, password); err != nil {
		return err
	}
	if neo4jstore.EnsureSchema(ctx, driver, "neo4j") != nil {
		return errProvider
	}
	// Community has no publisher-role attestation. This proves authenticated
	// TLS persistence, not the production expected-principal/role deployment gate.
	adapter, adapterErr := neo4jstore.NewProduction(ctx, neo4jstore.ProductionConfig{Endpoint: uri, AuthenticationReference: "ref:neo4j/auth/local-disposable-proof", ReadinessTimeout: 10 * time.Second}, fixtureAuthenticationResolver{manager})
	if adapterErr != nil {
		return errConfiguration
	}
	defer func() {
		if adapter.Close(context.Background()) != nil {
			err = errCleanup
		}
	}()
	if adapter.Ready(ctx) != nil {
		return errProvider
	}
	store, storeErr := graphstore.New(adapter, graphstore.Config{
		OperationTimeout: 20 * time.Second, MaximumNodes: 10, MaximumEdges: 10, MaximumDepth: 8,
	})
	if storeErr != nil {
		return errConfiguration
	}
	result, proofErr := runFixture(ctx, store, &neo4jAuditor{driver: driver})
	if proofErr != nil {
		return proofErr
	}
	want := proofResult{Nodes: 3, Edges: 2, Replay: true, Scoped: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}
	if result != want {
		return errOwnership
	}
	return nil
}

type fixtureAuthenticationResolver struct{ manager auth.TokenManager }

func (resolver fixtureAuthenticationResolver) ResolveNeo4jAuthentication(context.Context, string) (auth.TokenManager, error) {
	return resolver.manager, nil
}

func verifyTLSAuthenticationNegatives(ctx context.Context, uri, password string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	untrusted, err := neo4j.NewDriver(uri, neo4j.BasicAuth("neo4j", password, ""), func(config *neo4jconfig.Config) {
		config.TlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}
		config.MaxTransactionRetryTime = 0
		config.ConnectionAcquisitionTimeout = 2 * time.Second
		config.SocketConnectTimeout = 2 * time.Second
		config.TelemetryDisabled = true
	})
	if err != nil || untrusted == nil {
		return errProvider
	}
	connectErr := untrusted.VerifyConnectivity(probeCtx)
	closeCtx, closeCancel := context.WithTimeout(context.Background(), cleanupTimeout)
	closeErr := untrusted.Close(closeCtx)
	closeCancel()
	if closeErr != nil {
		return errCleanup
	}
	if connectErr == nil || probeCtx.Err() != nil {
		return errProvider
	}
	wrong := "0" + password[1:]
	if wrong == password {
		wrong = "1" + password[1:]
	}
	adapter, err := neo4jstore.NewProduction(ctx, neo4jstore.ProductionConfig{Endpoint: uri, AuthenticationReference: "ref:neo4j/auth/local-disposable-proof", ReadinessTimeout: 5 * time.Second}, fixtureAuthenticationResolver{neo4j.BasicAuth("neo4j", wrong, "")})
	if adapter != nil {
		_ = adapter.Close(context.Background())
		return errProvider
	}
	if !errors.Is(err, neo4jstore.ErrConfiguration) || ctx.Err() != nil {
		return errProvider
	}
	return nil
}

func runFixture(ctx context.Context, store graphstore.GraphStore, auditor fixtureAuditor) (result proofResult, err error) {
	if ctx == nil || store == nil || auditor == nil {
		return proofResult{}, errConfiguration
	}
	fixture := mustFixture()
	cleanupArmed := false
	defer func() {
		if recover() != nil {
			err = errOperation
		}
		if !cleanupArmed {
			return
		}
		deleteCtx, cancelDelete := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		deleteErr := safeAuditCall(deleteCtx, func(callCtx context.Context) error { return auditor.Delete(callCtx, fixture) })
		cancelDelete()
		absentCtx, cancelAbsent := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		absentErr := safeAuditCall(absentCtx, func(callCtx context.Context) error { return auditor.Absent(callCtx, fixture) })
		cancelAbsent()
		if deleteErr != nil || absentErr != nil {
			err = errCleanup
			result = proofResult{}
			return
		}
		result.Cleanup = true
	}()

	cleanupArmed = true
	if store.Upsert(ctx, fixture.scopeA, fixture.projection) != nil || store.Upsert(ctx, fixture.scopeA, fixture.projection) != nil {
		return proofResult{}, errOperation
	}
	result.Replay = true
	if safeAuditCall(ctx, func(callCtx context.Context) error { return auditor.Verify(callCtx, fixture) }) != nil {
		return proofResult{}, errOwnership
	}
	result.Audit = true

	requests := []struct {
		scope   domain.Scope
		request graphstore.ReadRequest
		want    graphstore.Projection
	}{
		{fixture.scopeA, graphstore.ReadRequest{RootID: fixture.projection.Nodes[0].NodeID, Direction: graphstore.DirectionOutgoing, MaximumDepth: 2, MaximumNodes: 3, MaximumEdges: 2}, fixture.projection},
		{fixture.scopeA, graphstore.ReadRequest{RootID: fixture.projection.Nodes[2].NodeID, Direction: graphstore.DirectionIncoming, MaximumDepth: 2, MaximumNodes: 3, MaximumEdges: 2}, fixture.projection},
		{fixture.scopeA, graphstore.ReadRequest{RootID: fixture.projection.Nodes[1].NodeID, Direction: graphstore.DirectionBoth, MaximumDepth: 1, MaximumNodes: 3, MaximumEdges: 2}, fixture.projection},
		{fixture.scopeA, graphstore.ReadRequest{RootID: fixture.projection.Nodes[0].NodeID, Direction: graphstore.DirectionOutgoing, MaximumDepth: 0, MaximumNodes: 1, MaximumEdges: 1}, graphstore.Projection{Nodes: []graphstore.Node{fixture.projection.Nodes[0]}, Edges: []graphstore.Edge{}}},
		{fixture.scopeB, graphstore.ReadRequest{RootID: fixture.projection.Nodes[0].NodeID, Direction: graphstore.DirectionOutgoing, MaximumDepth: 2, MaximumNodes: 3, MaximumEdges: 2}, graphstore.Projection{Nodes: []graphstore.Node{}, Edges: []graphstore.Edge{}}},
	}
	for _, request := range requests {
		got, readErr := store.Read(ctx, request.scope, request.request)
		if readErr != nil || !reflect.DeepEqual(got, request.want) {
			return proofResult{}, errOperation
		}
	}
	result.Nodes = 3
	result.Edges = 2
	result.Scoped = true
	result.CrossOrganizationZero = true
	return result, nil
}

func safeAuditCall(ctx context.Context, call func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errOperation
		}
	}()
	return call(ctx)
}

func mustFixture() fixtureState {
	ids := make([]domain.ProductID, 11)
	for index := range ids {
		parsed, err := domain.ParseProductID(fmt.Sprintf("pid_00000000-0000-4000-8000-%012x", index+1))
		if err != nil {
			panic("invalid fixed fixture")
		}
		ids[index] = parsed
	}
	scopeA, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		panic("invalid fixed scope")
	}
	scopeB, err := domain.NewScope(ids[8], ids[9], ids[10])
	if err != nil {
		panic("invalid fixed scope")
	}
	nodes := []graphstore.Node{
		{Scope: scopeA, NodeID: ids[3], Kind: "cloud_account"},
		{Scope: scopeA, NodeID: ids[4], Kind: "identity_role"},
		{Scope: scopeA, NodeID: ids[6], Kind: "agent_runtime"},
	}
	edges := []graphstore.Edge{
		{Scope: scopeA, EdgeID: ids[5], Kind: "contains_identity", SourceID: ids[3], TargetID: ids[4]},
		{Scope: scopeA, EdgeID: ids[7], Kind: "permits_runtime", SourceID: ids[4], TargetID: ids[6]},
	}
	return fixtureState{scopeA: scopeA, scopeB: scopeB, projection: graphstore.Projection{Nodes: nodes, Edges: edges}}
}

type neo4jAuditor struct{ driver neo4j.Driver }

func (auditor *neo4jAuditor) Verify(ctx context.Context, fixture fixtureState) error {
	nodes, edges, err := auditor.snapshot(ctx, fixture)
	if err != nil || !slices.Equal(nodes, expectedNodeAudit()) || !slices.Equal(edges, expectedEdgeAudit()) {
		return errOwnership
	}
	return nil
}

func (auditor *neo4jAuditor) Delete(ctx context.Context, fixture fixtureState) error {
	nodes, edges, err := auditor.snapshot(ctx, fixture)
	if err != nil || !orderedSubset(nodes, expectedNodeAudit()) || !orderedSubset(edges, expectedEdgeAudit()) {
		return errCleanup
	}
	parameters := fixtureParameters(fixture)
	if err := auditor.mutate(ctx, "MATCH ()-[edge:ZASP_GRAPH_EDGE]->() WHERE edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.edge_id IN $edge_ids DELETE edge RETURN count(edge) AS deleted", parameters); err != nil {
		return errCleanup
	}
	if err := auditor.mutate(ctx, "MATCH (node:ZaspGraphNode) WHERE node.organization_id = $organization_id AND node.workspace_id = $workspace_id AND node.environment_id = $environment_id AND node.node_id IN $node_ids DETACH DELETE node RETURN count(node) AS deleted", parameters); err != nil {
		return errCleanup
	}
	return nil
}

func (auditor *neo4jAuditor) Absent(ctx context.Context, fixture fixtureState) error {
	nodes, edges, err := auditor.snapshot(ctx, fixture)
	if err != nil || len(nodes) != 0 || len(edges) != 0 {
		return errCleanup
	}
	return nil
}

func (auditor *neo4jAuditor) snapshot(ctx context.Context, fixture fixtureState) ([]string, []string, error) {
	query := "CALL { MATCH (node:ZaspGraphNode) WHERE node.organization_id = $organization_id AND node.workspace_id = $workspace_id AND node.environment_id = $environment_id WITH node ORDER BY node.node_id RETURN collect(node.node_id + '|' + node.kind + '|' + toString(node.schema_version)) AS nodes } CALL { MATCH (source:ZaspGraphNode)-[edge:ZASP_GRAPH_EDGE]->(target:ZaspGraphNode) WHERE edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id WITH source, edge, target ORDER BY edge.edge_id RETURN collect(edge.edge_id + '|' + edge.kind + '|' + source.node_id + '|' + target.node_id + '|' + toString(edge.schema_version)) AS edges } RETURN nodes, edges"
	record, err := auditor.single(ctx, neo4j.AccessModeRead, query, fixtureParameters(fixture))
	if err != nil || record == nil || !slices.Equal(record.Keys, []string{"nodes", "edges"}) || len(record.Values) != 2 {
		return nil, nil, errProvider
	}
	nodes, ok := strictStrings(record.Values[0])
	if !ok {
		return nil, nil, errProvider
	}
	edges, ok := strictStrings(record.Values[1])
	if !ok {
		return nil, nil, errProvider
	}
	return nodes, edges, nil
}

func (auditor *neo4jAuditor) mutate(ctx context.Context, query string, parameters map[string]any) error {
	record, err := auditor.single(ctx, neo4j.AccessModeWrite, query, parameters)
	if err != nil || record == nil || !slices.Equal(record.Keys, []string{"deleted"}) || len(record.Values) != 1 {
		return errProvider
	}
	_, ok := record.Values[0].(int64)
	if !ok {
		return errProvider
	}
	return nil
}

func (auditor *neo4jAuditor) single(ctx context.Context, mode neo4j.AccessMode, query string, parameters map[string]any) (record *neo4j.Record, err error) {
	session := auditor.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j", AccessMode: mode})
	if session == nil {
		return nil, errProvider
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		if session.Close(closeCtx) != nil {
			err = errProvider
			record = nil
		}
	}()
	tx, beginErr := session.BeginTransaction(ctx)
	return auditSingleWithTransaction(ctx, tx, beginErr, func(transaction neo4j.ExplicitTransaction) (*neo4j.Record, error) {
		result, runErr := transaction.Run(ctx, query, parameters)
		if runErr != nil || result == nil {
			return nil, errProvider
		}
		record, singleErr := result.Single(ctx)
		if singleErr != nil || record == nil {
			return nil, errProvider
		}
		if _, consumeErr := result.Consume(ctx); consumeErr != nil {
			return nil, errProvider
		}
		return record, nil
	})
}

func auditSingleWithTransaction(
	ctx context.Context,
	transaction neo4j.ExplicitTransaction,
	beginErr error,
	work func(neo4j.ExplicitTransaction) (*neo4j.Record, error),
) (record *neo4j.Record, err error) {
	committed := false
	defer func() {
		if transaction != nil && !committed {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			defer cancel()
			if transaction.Rollback(rollbackCtx) != nil {
				err = errProvider
				record = nil
			}
		}
	}()
	if beginErr != nil || transaction == nil || work == nil {
		return nil, errProvider
	}
	record, err = work(transaction)
	if err != nil || record == nil {
		return nil, errProvider
	}
	if transaction.Commit(ctx) != nil {
		return nil, errProvider
	}
	committed = true
	return record, nil
}

func fixtureParameters(fixture fixtureState) map[string]any {
	nodeIDs := make([]any, len(fixture.projection.Nodes))
	for index, node := range fixture.projection.Nodes {
		nodeIDs[index] = node.NodeID.String()
	}
	edgeIDs := make([]any, len(fixture.projection.Edges))
	for index, edge := range fixture.projection.Edges {
		edgeIDs[index] = edge.EdgeID.String()
	}
	return map[string]any{
		"organization_id": fixture.scopeA.OrganizationID().String(), "workspace_id": fixture.scopeA.WorkspaceID().String(),
		"environment_id": fixture.scopeA.EnvironmentID().String(), "node_ids": nodeIDs, "edge_ids": edgeIDs,
	}
}

func expectedNodeAudit() []string {
	return []string{
		"pid_00000000-0000-4000-8000-000000000004|cloud_account|1",
		"pid_00000000-0000-4000-8000-000000000005|identity_role|1",
		"pid_00000000-0000-4000-8000-000000000007|agent_runtime|1",
	}
}

func expectedEdgeAudit() []string {
	return []string{
		"pid_00000000-0000-4000-8000-000000000006|contains_identity|pid_00000000-0000-4000-8000-000000000004|pid_00000000-0000-4000-8000-000000000005|1",
		"pid_00000000-0000-4000-8000-000000000008|permits_runtime|pid_00000000-0000-4000-8000-000000000005|pid_00000000-0000-4000-8000-000000000007|1",
	}
}

func strictStrings(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result[index] = text
	}
	return result, true
}

func orderedSubset(candidate, expected []string) bool {
	if len(candidate) > len(expected) {
		return false
	}
	previous := ""
	for _, value := range candidate {
		if !slices.Contains(expected, value) {
			return false
		}
		if previous != "" && previous >= value {
			return false
		}
		previous = value
	}
	return true
}
