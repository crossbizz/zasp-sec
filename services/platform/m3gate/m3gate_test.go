package m3gate

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestGatePassesOnlyCompleteIndependentEvidence(t *testing.T) {
	evidence := Evidence{
		ConnectorAssets: 16, SensorSupported: true, OTLPEvents: 1, TetragonEvents: 3,
		BatchIDStable: true, ArchiveIndexLinked: true, ReplayIdempotent: true, DLQMessages: 0,
		LastKnownInventoryRetained: true, Freshness: "stale",
	}
	report, err := Evaluate(evidence)
	if err != nil || report.Status != "PASS" || report.Checks != 5 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	mutations := []func(*Evidence){
		func(value *Evidence) { value.ConnectorAssets = 0 },
		func(value *Evidence) { value.SensorSupported = false },
		func(value *Evidence) { value.OTLPEvents = 0 },
		func(value *Evidence) { value.TetragonEvents = 0 },
		func(value *Evidence) { value.BatchIDStable = false },
		func(value *Evidence) { value.ArchiveIndexLinked = false },
		func(value *Evidence) { value.ReplayIdempotent = false },
		func(value *Evidence) { value.DLQMessages = 1 },
		func(value *Evidence) { value.LastKnownInventoryRetained = false },
		func(value *Evidence) { value.Freshness = "healthy" },
	}
	for index, mutate := range mutations {
		forged := evidence
		mutate(&forged)
		if _, err := Evaluate(forged); err == nil {
			t.Fatalf("mutation %d passed", index)
		}
	}
}

func TestComposedConnectorSensorIngestQueueAndFreshnessFixture(t *testing.T) {
	ctx := context.Background()
	scope := fixtureScope(t)
	normalized := []connectors.Batch{}
	appendBatch := func(batch connectors.Batch, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		normalized = append(normalized, batch)
	}
	appendBatch(connectors.NormalizeAWS(scope, connectors.AWSFixture{AccountID: "000000000000", RoleARN: "arn:aws:iam::000000000000:role/shared-fixture-role", PolicyARN: "arn:aws:iam::000000000000:policy/shared-fixture-policy"}))
	appendBatch(connectors.NormalizeKubernetes(scope, connectors.KubernetesFixture{Cluster: "production", Namespace: "agents", ServiceAccount: "agent-runtime", Workload: "support-agent"}))
	appendBatch(connectors.NormalizeGitHub(scope, connectors.GitHubFixture{Organization: "zasp", Repository: "agent-runtime", App: "zasp-security", Workflow: "deploy", Permission: "contents:read"}))
	appendBatch(connectors.NormalizeIdP(scope, connectors.IdPFixture{Provider: "directory", User: "owner", Group: "agent-platform", Application: "support-agent", ServicePrincipal: "agent-runtime"}))
	assets := 0
	for _, batch := range normalized {
		assets += len(batch.Entities)
	}
	if assets != 16 {
		t.Fatalf("connector assets=%d", assets)
	}

	ids := []domain.ProductID{fixtureID(t, 20)}
	tokens := []string{"sensor_token_abcdefghijklmnopqrstuvwxyz012345"}
	sensorStore := sensor.NewMemoryStore(func() (domain.ProductID, error) { return ids[0], nil }, func() (string, error) { return tokens[0], nil }, fixtureTime)
	enrollment, err := sensorStore.Create(ctx, scope, sensor.Input{Name: "production-us-west", Mode: "metadata_only"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sensorStore.Heartbeat(ctx, scope, enrollment.Sensor.ID, enrollment.Token, sensor.Heartbeat{Capabilities: []string{"network", "process"}, Kernel: "6.8.0", BTF: true, EventRate: 100, Drops: 0}); err != nil {
		t.Fatal(err)
	}
	coverage, err := sensorStore.Coverage(ctx, scope, enrollment.Sensor.ID)
	if err != nil || !coverage.Supported {
		t.Fatalf("coverage=%+v err=%v", coverage, err)
	}

	records := []runtimeevent.Record{}
	for index, kind := range []string{"process", "file", "network"} {
		record, adaptErr := runtimeevent.AdaptTetragon(runtimeevent.TetragonInput{Scope: scope, SourceEventID: fmt.Sprintf("runtime-%d", index), Kind: kind, Action: map[string]string{"process": "exec", "file": "read", "network": "connect"}[kind], WorkloadID: "support-agent", EventTime: fixtureTime(), EvidenceID: fixtureID(t, 30+index)})
		if adaptErr != nil {
			t.Fatal(adaptErr)
		}
		records = append(records, record)
	}
	otlp, err := runtimeevent.AdaptOTLP(runtimeevent.OTLPInput{Scope: scope, EventTime: fixtureTime(), EvidenceID: fixtureID(t, 40), Attributes: map[string]string{
		"event.id": "tool-1", "event.class": "tool", "event.action": "invoke", "agent.id": fixtureID(t, 41).String(), "session.id": fixtureID(t, 42).String(), "task.id": "task-1", "tool.id": "tool-1", "sandbox.id": "sandbox-1", "trace.id": "0123456789abcdef0123456789abcdef", "span.id": "0123456789abcdef",
	}})
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, otlp)
	batches, err := runtimeevent.BuildBatches(records, 100, 512*1024)
	if err != nil || len(batches) != 1 {
		t.Fatalf("batches=%d err=%v", len(batches), err)
	}
	durable := runtimeevent.NewMemoryDurable()
	worker, err := runtimeevent.NewWorker(durable, durable, durable)
	if err != nil {
		t.Fatal(err)
	}
	acknowledged := 0
	for range 2 {
		if err := worker.Process(ctx, runtimeevent.Delivery{Batch: batches[0], Acknowledge: func(context.Context) error { acknowledged++; return nil }}); err != nil {
			t.Fatal(err)
		}
	}
	archiveKey := durable.ArchiveKey(batches[0].ID)
	documents, err := runtimeevent.SortedIndexDocuments(records, archiveKey)
	if err != nil || len(documents) != 4 || documents[0]["archive_key"] != archiveKey {
		t.Fatalf("documents=%d err=%v", len(documents), err)
	}

	freshness := connectors.NewFreshnessStore()
	connectorID := fixtureID(t, 50)
	if err := freshness.RecordSuccess(scope, connectorID, fixtureTime(), normalized[0].Entities); err != nil {
		t.Fatal(err)
	}
	if err := freshness.RecordFailure(scope, connectorID, fixtureTime().Add(time.Minute), "provider unavailable", time.Time{}); err != nil {
		t.Fatal(err)
	}
	state, err := freshness.Get(scope, connectorID, fixtureTime().Add(25*time.Hour))
	if err != nil || !state.Stale || len(state.Inventory) == 0 {
		t.Fatalf("freshness=%+v err=%v", state, err)
	}

	report, err := Evaluate(Evidence{ConnectorAssets: assets, SensorSupported: coverage.Supported, OTLPEvents: 1, TetragonEvents: 3,
		BatchIDStable: acknowledged == 2 && durable.ArchiveCount() == 1, ArchiveIndexLinked: documents[0]["archive_key"] == archiveKey,
		ReplayIdempotent: durable.IndexCount() == 4 && durable.CorrelationCount() == 4, DLQMessages: 0,
		LastKnownInventoryRetained: len(state.Inventory) > 0, Freshness: "stale"})
	if err != nil || report.Status != "PASS" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func fixtureTime() time.Time { return time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC) }

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureID(t, 1), fixtureID(t, 2), fixtureID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func fixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
