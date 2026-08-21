package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestProductionCombinedE2EDiscoveryWorker(t *testing.T) {
	workerDSN := os.Getenv("ZASP_COMBINED_E2E_WORKER_DSN")
	if workerDSN == "" {
		t.Skip("combined E2E helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := combinedE2EScope(t)
	jobID := combinedE2EProductID(t, os.Getenv("ZASP_COMBINED_E2E_JOB_ID"))
	parserVersion, toolVersion := os.Getenv("ZASP_COMBINED_E2E_PARSER_VERSION"), os.Getenv("ZASP_COMBINED_E2E_TOOL_VERSION")
	scenario := os.Getenv("ZASP_COMBINED_E2E_SCENARIO")
	if parserVersion == "" || toolVersion == "" || scenario == "" {
		t.Fatal("combined E2E authority is incomplete")
	}

	poolConfig, err := pgxpool.ParseConfig(workerDSN)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns, poolConfig.MinConns = 3, 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	postgresTrace := &combinedE2EPostgresTrace{}
	database, err := apiserver.NewPostgresJSONDatabase(&combinedE2EPostgresDriver{delegate: &workerPostgresDriver{pool: pool}, trace: postgresTrace})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	tracedDatabase := &combinedE2ETracingDatabase{delegate: database}

	factory, err := newCombinedE2ECollectorFactory(scenario, parserVersion, toolVersion)
	if err != nil {
		t.Fatal(err)
	}
	queue := &combinedE2EDiscoveryQueue{delivery: jobqueue.Delivery{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: []byte(`{}`)}}}
	config := workerRuntimeConfig{
		Mode: workerModeDiscovery, PostgresDSN: workerDSN, DatabaseAuthority: "zasp_discovery_worker", WorkerID: "production-e2e-local-discovery",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 10 * time.Second, BatchSize: 1, ShutdownTimeout: 5 * time.Second,
		DiscoveryQueueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-discovery-jobs", AWSRegion: "us-east-1",
		EvidenceBucket: "zasp-production-e2e-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		ParserVersion: parserVersion, ToolVersion: toolVersion, DiscoveryRoleARN: "arn:aws:iam::123456789012:role/zasp-production-e2e-discovery", DiscoveryTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", DiscoverySecretPrefix: "zasp-production-e2e/connectors",
		AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "collector_v1", GitHubCollectorVersion: "collector_v1", OktaCollectorVersion: "collector_v1", KubernetesEgressCIDRs: []string{"203.0.113.0/24"},
		GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret", ProviderTimeout: time.Second, DiscoveryReadinessTimeout: time.Second,
	}
	dependencies, err := composeDiscoveryWorkerRuntime(config, tracedDatabase, &productionDiscoveryDependencies{Factory: factory, Queue: queue, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("%v; database trace=%s; postgres trace=%s", err, tracedDatabase.Trace(), postgresTrace.String())
	}
	wantAcknowledged := scenario != "partial"
	if queue.acknowledged != wantAcknowledged {
		t.Fatalf("scenario %q acknowledged=%v want %v; database trace=%s; postgres trace=%s", scenario, queue.acknowledged, wantAcknowledged, tracedDatabase.Trace(), postgresTrace.String())
	}
	t.Log("deterministic local provider and artifact authority completed public sync")
}

func TestProductionCombinedE2EProviderFixturesAreCanonical(t *testing.T) {
	for _, fixture := range []struct {
		provider  collection.Provider
		subject   collection.SubjectBinding
		class     collection.CredentialClass
		reference string
	}{
		{collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, collection.CredentialAWSAssumeRole, "ref:aws/assume-role/e2e-account"},
		{collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}, collection.CredentialKubernetesCluster, "ref:kubernetes/cluster/e2e-a"},
		{collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "424242"}, collection.CredentialGitHubInstallation, "ref:github/installation/e2e-424242"},
		{collection.ProviderOkta, collection.SubjectBinding{Kind: "okta_tenant", ID: "e2e.okta.com"}, collection.CredentialOktaRefresh, "ref:okta/refresh/e2e-tenant"},
	} {
		t.Run(string(fixture.provider), func(t *testing.T) {
			entities, relationships, complete, err := combinedE2EPageValues(fixture.provider, "complete")
			if err != nil {
				t.Fatal(err)
			}
			cursor := collection.Cursor{Provider: fixture.provider, Version: "local_e2e_v1", Value: "complete-1"}
			var pageErr error
			switch fixture.provider {
			case collection.ProviderAWS:
				_, pageErr = awsdiscovery.NewCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			case collection.ProviderKubernetes:
				_, pageErr = kubernetesdiscovery.NewCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			case collection.ProviderGitHub:
				_, pageErr = githubdiscovery.NewCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			case collection.ProviderOkta:
				_, pageErr = idpdiscovery.NewOktaCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			}
			if pageErr != nil {
				t.Fatalf("canonical page: %v", pageErr)
			}
			driver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
			artifacts, artifactErr := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
			if artifactErr != nil {
				t.Fatal(artifactErr)
			}
			api := &combinedE2ECollectionAPI{scenario: "complete"}
			var client collection.ProviderClient
			switch fixture.provider {
			case collection.ProviderAWS:
				client, pageErr = awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			case collection.ProviderKubernetes:
				client, pageErr = kubernetesdiscovery.NewCollectionClient(api, artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			case collection.ProviderGitHub:
				client, pageErr = githubdiscovery.NewCollectionClient(api, artifacts, githubdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			case collection.ProviderOkta:
				client, pageErr = idpdiscovery.NewOktaCollectionClient(api, artifacts, idpdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			}
			if pageErr != nil {
				t.Fatalf("client: %v", pageErr)
			}
			request := collection.Request{
				Scope: combinedE2EScope(t), IntegrationID: combinedE2EProductID(t, "pid_77000001-0000-4000-8000-000000000001"), ConnectionID: combinedE2EProductID(t, "pid_77000002-0000-4000-8000-000000000002"), JobID: combinedE2EProductID(t, "pid_77000003-0000-4000-8000-000000000003"),
				Attempt: 1, Provider: fixture.provider, CollectorVersion: "collector_v1", CredentialClass: fixture.class, CredentialReference: fixture.reference, ExpectedSubject: fixture.subject,
				ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: combinedE2EClock(), Bounds: collection.Bounds{MaxPages: 1, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second},
			}
			outcome, collectErr := client.(interface {
				CollectWithCredential(context.Context, collection.Request, []byte) (collection.Outcome, error)
			}).CollectWithCredential(context.Background(), request, []byte("local-e2e-credential-material"))
			if collectErr != nil || outcome == nil {
				t.Fatalf("collect: outcome=%T err=%v", outcome, collectErr)
			}
		})
	}
}

func TestProductionCombinedE2EPartialFixtureProducesDurablePartialOutcome(t *testing.T) {
	scope := workerScope(t)
	input := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	input.Provider = collection.ProviderKubernetes
	input.CredentialClass = collection.CredentialKubernetesCluster
	input.CredentialReference = "ref:kubernetes/cluster/e2e-partial"
	input.SubjectKind = "kubernetes_cluster"
	input.SubjectID = "prod.example/cluster-partial"
	input.ExpectedSubject = collection.SubjectBinding{Kind: input.SubjectKind, ID: input.SubjectID}
	input.CursorProvider, input.CursorVersion, input.CursorValue = nil, nil, nil
	input.ParserVersion, input.ToolVersion = "inventory-parser-2026.08.20", "collector-tool-2026.08.20"
	input.Configuration = json.RawMessage(`{"cluster":"prod.example/cluster-partial"}`)
	factory, err := newCombinedE2ECollectorFactory("partial", input.ParserVersion, input.ToolVersion)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "production-e2e-local-discovery", LeaseToken: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Destroy()
	request, ok := collectionRequest(scope, input)
	if !ok {
		t.Fatal("partial fixture request was invalid")
	}
	outcome, err := collector.Collect(context.Background(), request)
	if err != nil {
		t.Fatalf("partial fixture returned %T: %v", err, err)
	}
	if _, ok := outcome.(collection.PartialResult); !ok {
		t.Fatalf("partial fixture outcome = %T, want collection.PartialResult", outcome)
	}
}

type combinedE2EPostgresTrace struct {
	mu    sync.Mutex
	value string
}

func (trace *combinedE2EPostgresTrace) set(value string) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.value = value
}

func (trace *combinedE2EPostgresTrace) String() string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.value
}

type combinedE2EPostgresDriver struct {
	delegate apiserver.PostgresDriver
	trace    *combinedE2EPostgresTrace
}

func (driver *combinedE2EPostgresDriver) QueryRow(ctx context.Context, query string, arguments ...any) apiserver.PostgresRow {
	return &combinedE2ETracingRow{delegate: driver.delegate.QueryRow(ctx, query, arguments...), stage: combinedE2EDatabaseStage(query), trace: driver.trace}
}

func (driver *combinedE2EPostgresDriver) Exec(ctx context.Context, query string, arguments ...any) error {
	err := driver.delegate.Exec(ctx, query, arguments...)
	if err != nil {
		driver.trace.set(combinedE2EPostgresError(combinedE2EDatabaseStage(query), err))
	}
	return err
}

func (driver *combinedE2EPostgresDriver) Close() error { return driver.delegate.Close() }

type combinedE2ETracingRow struct {
	delegate apiserver.PostgresRow
	stage    string
	trace    *combinedE2EPostgresTrace
}

func (row *combinedE2ETracingRow) Scan(destinations ...any) error {
	err := row.delegate.Scan(destinations...)
	if err != nil {
		row.trace.set(combinedE2EPostgresError(row.stage, err))
	}
	return err
}

func combinedE2EPostgresError(stage string, err error) string {
	var provider *pgconn.PgError
	if !errors.As(err, &provider) {
		return stage + ":non_provider"
	}
	message := provider.Message
	if len(message) < 1 || len(message) > 128 || strings.IndexFunc(message, func(character rune) bool {
		return character != ' ' && character != '_' && character != '-' && (character < 'a' || character > 'z')
	}) >= 0 {
		message = "redacted"
	}
	return stage + ":" + provider.Code + ":" + message
}

type combinedE2ETracingDatabase struct {
	mu       sync.Mutex
	delegate apiserver.JSONDatabase
	stages   []string
}

func (database *combinedE2ETracingDatabase) SchemaVersion(ctx context.Context) (string, error) {
	value, err := database.delegate.SchemaVersion(ctx)
	database.record("schema_version", err)
	return value, err
}

func (database *combinedE2ETracingDatabase) QueryJSON(ctx context.Context, query string, arguments ...any) (json.RawMessage, error) {
	value, err := database.delegate.QueryJSON(ctx, query, arguments...)
	stage := combinedE2EDatabaseStage(query)
	if err == nil && (stage == "zasp_execution_claim_delivery" || stage == "zasp_execution_finish_job") {
		if stage == "zasp_execution_finish_job" && len(arguments) == 11 {
			stage = fmt.Sprintf("%s:%v:%v", stage, arguments[6], arguments[8])
		}
		var result struct {
			Attempt     int    `json:"attempt"`
			Disposition string `json:"disposition"`
			State       string `json:"state"`
		}
		if json.Unmarshal(value, &result) == nil {
			stage = fmt.Sprintf("%s:%s:%s:%d", stage, result.Disposition, result.State, result.Attempt)
		}
	}
	database.record(stage, err)
	return value, err
}

func (database *combinedE2ETracingDatabase) Exec(ctx context.Context, query string, arguments ...any) error {
	err := database.delegate.Exec(ctx, query, arguments...)
	database.record(combinedE2EDatabaseStage(query), err)
	return err
}

func (database *combinedE2ETracingDatabase) record(stage string, err error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	if err != nil {
		classification := "unavailable"
		for candidate, name := range map[error]string{
			apiserver.ErrRepositoryOperation: "operation", apiserver.ErrRepositoryConflict: "conflict", apiserver.ErrRepositoryNotFound: "not_found",
		} {
			if errors.Is(err, candidate) {
				classification = name
				break
			}
		}
		stage += ":error:" + classification + ":" + fmt.Sprintf("%T", err)
	}
	database.stages = append(database.stages, stage)
}

func (database *combinedE2ETracingDatabase) Trace() string {
	database.mu.Lock()
	defer database.mu.Unlock()
	return strings.Join(database.stages, ",")
}

func combinedE2EDatabaseStage(query string) string {
	for _, stage := range []string{
		"zasp_inventory_readiness", "zasp_execution_principal_ready", "zasp_execution_claim_delivery", "zasp_execution_job_input",
		"zasp_execution_heartbeat_job", "zasp_execution_checkpoint_partial", "zasp_execution_apply_complete_snapshot", "zasp_execution_finish_job",
	} {
		if strings.Contains(query, stage) {
			return stage
		}
	}
	return "other"
}

type combinedE2EDiscoveryQueue struct {
	mu           sync.Mutex
	delivery     jobqueue.Delivery
	consumed     bool
	acknowledged bool
}

func (queue *combinedE2EDiscoveryQueue) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.consumed {
		return []jobqueue.Delivery{}, nil
	}
	queue.consumed = true
	return []jobqueue.Delivery{queue.delivery}, nil
}

func (queue *combinedE2EDiscoveryQueue) AcknowledgeBatch(context.Context, []jobqueue.Receipt) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.acknowledged = true
	return nil
}

func (*combinedE2EDiscoveryQueue) ExtendVisibility(context.Context, []jobqueue.Receipt, time.Duration) error {
	return nil
}

type combinedE2ECredentialResolver struct{}

func (*combinedE2ECredentialResolver) ResolveDiscoveryCredential(_ context.Context, request discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error) {
	return collection.NewCredentialMaterial(request.Credential, []byte("local-e2e-credential-material"), time.Now().Add(5*time.Minute))
}

func newCombinedE2ECollectorFactory(scenario, parserVersion, toolVersion string) (discoveryCollectorFactory, error) {
	driver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		return nil, err
	}
	api := &combinedE2ECollectionAPI{scenario: scenario}
	clients := make(map[collection.Provider]collection.ProviderClient, 4)
	clients[collection.ProviderAWS], err = awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	if err == nil {
		clients[collection.ProviderKubernetes], err = kubernetesdiscovery.NewCollectionClient(api, artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	}
	if err == nil {
		clients[collection.ProviderGitHub], err = githubdiscovery.NewCollectionClient(api, artifacts, githubdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	}
	if err == nil {
		clients[collection.ProviderOkta], err = idpdiscovery.NewOktaCollectionClient(api, artifacts, idpdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	}
	if err != nil {
		return nil, err
	}
	classes := map[collection.Provider]collection.CredentialClass{
		collection.ProviderAWS: collection.CredentialAWSAssumeRole, collection.ProviderKubernetes: collection.CredentialKubernetesCluster,
		collection.ProviderGitHub: collection.CredentialGitHubInstallation, collection.ProviderOkta: collection.CredentialOktaRefresh,
	}
	registrations := make([]firstPartyProviderClientRegistration, 0, 4)
	for _, provider := range []collection.Provider{collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub, collection.ProviderOkta} {
		probe, ok := clients[provider].(collection.ReadinessProbe)
		if !ok {
			return nil, errors.New("local provider readiness unavailable")
		}
		registrations = append(registrations, firstPartyProviderClientRegistration{Provider: provider, CollectorVersion: "collector_v1", CredentialClass: classes[provider], Client: clients[provider], Readiness: probe, ReadinessTimeout: time.Second})
	}
	providers, err := newFirstPartyCollectionFactory(registrations)
	if err != nil {
		return nil, err
	}
	return newProductionDiscoveryCollectorFactory(providers, &combinedE2ECredentialResolver{})
}

func combinedE2EClock() time.Time { return time.Now().UTC().Truncate(time.Second) }

type combinedE2ECollectionAPI struct{ scenario string }

func (*combinedE2ECollectionAPI) CheckCollectionReadiness(context.Context) error { return nil }

func (api *combinedE2ECollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request awsdiscovery.CollectionPageRequest) (awsdiscovery.CollectionPage, error) {
	if ctx == nil || ctx.Err() != nil || len(credential) < 16 {
		return awsdiscovery.CollectionPage{}, collection.ErrContract
	}
	if api.scenario == "failed" {
		failure, _ := collection.NewFailure(collection.FailureMalformed, time.Time{})
		return awsdiscovery.CollectionPage{}, failure
	}
	entities, relationships, complete, err := combinedE2EPageValues(request.Provider, api.scenario)
	if err != nil {
		return awsdiscovery.CollectionPage{}, err
	}
	cursor := collection.Cursor{Provider: request.Provider, Version: "local_e2e_v1", Value: fmt.Sprintf("%s-%d", api.scenario, request.Page)}
	switch request.Provider {
	case collection.ProviderAWS:
		return awsdiscovery.NewCollectionPage(request.Subject, cursor, complete, entities, relationships)
	case collection.ProviderKubernetes:
		return kubernetesdiscovery.NewCollectionPage(request.Subject, cursor, complete, entities, relationships)
	case collection.ProviderGitHub:
		return githubdiscovery.NewCollectionPage(request.Subject, cursor, complete, entities, relationships)
	case collection.ProviderOkta:
		return idpdiscovery.NewOktaCollectionPage(request.Subject, cursor, complete, entities, relationships)
	default:
		return awsdiscovery.CollectionPage{}, collection.ErrContract
	}
}

type combinedE2EEntity struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	DisplayName    string          `json:"display_name"`
	StableFields   json.RawMessage `json:"stable_fields"`
	Attributes     json.RawMessage `json:"attributes"`
}

type combinedE2ERelationship struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
	Attributes     json.RawMessage `json:"attributes"`
}

func combinedE2EPageValues(provider collection.Provider, scenario string) ([]json.RawMessage, []json.RawMessage, bool, error) {
	if scenario == "empty" {
		return []json.RawMessage{}, []json.RawMessage{}, true, nil
	}
	if scenario == "partial" {
		if provider != collection.ProviderKubernetes {
			return nil, nil, false, collection.ErrContract
		}
		entities := make([]json.RawMessage, 1000)
		for index := range entities {
			entities[index] = combinedE2EMarshal(combinedE2EEntity{ID: fmt.Sprintf("pid_%08x-0000-4000-8000-%012x", 0x25000000+index, index+1), Kind: "kubernetes_resource", SourceNativeID: fmt.Sprintf("partial-%04d", index), DisplayName: fmt.Sprintf("Partial resource %04d", index), StableFields: json.RawMessage(fmt.Sprintf(`{"api_group":"core","api_version":"v1","cluster":"prod.example/cluster-a","name":"partial-%04d","namespace":"partial","resource_kind":"ConfigMap"}`, index)), Attributes: json.RawMessage(`{"namespaced":true,"state":"active"}`)})
		}
		return entities, []json.RawMessage{}, false, nil
	}
	var entities []combinedE2EEntity
	var relationships []combinedE2ERelationship
	switch provider {
	case collection.ProviderAWS:
		entities = []combinedE2EEntity{{ID: "pid_24000001-0000-4000-8000-000000000001", Kind: "aws_account", SourceNativeID: "123456789012", DisplayName: "Production AWS account", StableFields: json.RawMessage(`{"account_id":"123456789012"}`), Attributes: json.RawMessage(`{"state":"active"}`)}}
	case collection.ProviderKubernetes:
		entities = []combinedE2EEntity{{ID: "pid_21000001-0000-4000-8000-000000000001", Kind: "kubernetes_agent", SourceNativeID: "support-agent", DisplayName: "Support agent", StableFields: json.RawMessage(`{"api_group":"apps","api_version":"v1","cluster":"prod.example/cluster-a","name":"support-agent","namespace":"zasp","resource_kind":"DaemonSet","service_account":"support-agent"}`), Attributes: json.RawMessage(`{"namespaced":true,"posture":{"cicd_write":false,"credential_active":true,"credential_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","destructive_tool":false,"host_filesystem":false,"human_credential":false,"privileged":false,"production_agent":true,"production_credential":true,"production_secret_reach":false,"production_write":false,"runtime_control":true,"runtime_policy_supported":true,"sensitive_data_reach":false,"shell_execution":false,"unapproved_remote_tool":false,"unrestricted_egress":false,"untrusted_input":false},"state":"active"}`)}}
		if scenario != "shared" {
			entities = append(entities,
				combinedE2EEntity{ID: "pid_21000002-0000-4000-8000-000000000002", Kind: "kubernetes_workload", SourceNativeID: "support-runtime", DisplayName: "Production runtime", StableFields: json.RawMessage(`{"api_group":"apps","api_version":"v1","cluster":"prod.example/cluster-a","name":"support-runtime","namespace":"zasp","resource_kind":"Deployment","service_account":"support-runtime"}`), Attributes: json.RawMessage(`{"namespaced":true,"state":"active"}`)},
				combinedE2EEntity{ID: "pid_21000004-0000-4000-8000-000000000004", Kind: "kubernetes_service_account", SourceNativeID: "zasp/support-agent", DisplayName: "Support agent identity", StableFields: json.RawMessage(`{"api_group":"core","api_version":"v1","cluster":"prod.example/cluster-a","name":"support-agent","namespace":"zasp","resource_kind":"ServiceAccount"}`), Attributes: json.RawMessage(`{"namespaced":true,"state":"active"}`)},
			)
			relationships = []combinedE2ERelationship{{ID: "pid_21000003-0000-4000-8000-000000000003", Kind: "uses_identity", SourceNativeID: "support-agent-identity", FromEntityID: "pid_21000001-0000-4000-8000-000000000001", ToEntityID: "pid_21000004-0000-4000-8000-000000000004", Attributes: json.RawMessage(`{"state":"active","type":"service_account"}`)}}
		}
	case collection.ProviderGitHub:
		entities = []combinedE2EEntity{{ID: "pid_22000001-0000-4000-8000-000000000001", Kind: "github_repository", SourceNativeID: "zasp/security-automation", DisplayName: "Automation repository", StableFields: json.RawMessage(`{"installation_id":424242,"name":"security-automation","owner":"zasp","repository":"security-automation","visibility":"private"}`), Attributes: json.RawMessage(`{"archived":false,"default_branch":"main","state":"active"}`)}}
	case collection.ProviderOkta:
		entities = []combinedE2EEntity{{ID: "pid_23000001-0000-4000-8000-000000000001", Kind: "okta_group", SourceNativeID: "security-operators", DisplayName: "Security operators", StableFields: json.RawMessage(`{"name":"security-operators","object_type":"group","tenant":"e2e.okta.com"}`), Attributes: json.RawMessage(`{"state":"active","status":"ACTIVE"}`)}}
	default:
		return nil, nil, false, collection.ErrContract
	}
	encodedEntities := make([]json.RawMessage, len(entities))
	for index := range entities {
		encodedEntities[index] = combinedE2EMarshal(entities[index])
	}
	encodedRelationships := make([]json.RawMessage, len(relationships))
	for index := range relationships {
		encodedRelationships[index] = combinedE2EMarshal(relationships[index])
	}
	return encodedEntities, encodedRelationships, true, nil
}

func combinedE2EMarshal(value any) json.RawMessage {
	body, _ := json.Marshal(value)
	return body
}

type combinedE2EArtifactDriver struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (driver *combinedE2EArtifactDriver) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	version := "version-" + hex.EncodeToString(object.SHA256[:8])
	object.VersionID = version
	key := object.Key + "\x1f" + version
	if current, exists := driver.objects[key]; exists {
		if current.MediaType != object.MediaType || current.SHA256 != object.SHA256 || !bytes.Equal(current.Body, object.Body) {
			return artifactstore.DriverObject{}, errors.New("artifact drift")
		}
		return combinedE2ECloneDriverObject(current), nil
	}
	driver.objects[key] = combinedE2ECloneDriverObject(object)
	return combinedE2ECloneDriverObject(object), nil
}

func (driver *combinedE2EArtifactDriver) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	object, ok := driver.objects[locator.Key+"\x1f"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("artifact missing")
	}
	return combinedE2ECloneDriverObject(object), nil
}

func (driver *combinedE2EArtifactDriver) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	delete(driver.objects, locator.Key+"\x1f"+locator.VersionID)
	return nil
}

func (*combinedE2EArtifactDriver) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	if locator.Key == "" || locator.VersionID == "" {
		return "", errors.New("artifact reference unavailable")
	}
	return "s3://zasp-production-e2e-evidence/" + locator.Key, nil
}

func combinedE2ECloneDriverObject(object artifactstore.DriverObject) artifactstore.DriverObject {
	object.Body = bytes.Clone(object.Body)
	object.SHA256 = sha256.Sum256(object.Body)
	object.Size = int64(len(object.Body))
	return object
}

func combinedE2EScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		combinedE2EProductID(t, "pid_10000001-0000-4000-8000-000000000001"),
		combinedE2EProductID(t, "pid_10000002-0000-4000-8000-000000000002"),
		combinedE2EProductID(t, "pid_10000003-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func combinedE2EProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
