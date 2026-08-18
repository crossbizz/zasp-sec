package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestRunRollbackRehearsalBindsRecordedReleaseAndExactState(t *testing.T) {
	runtime := &fakeRollbackRuntime{snapshot: RollbackSnapshot{Version: "1.4.2", SchemaCompatible: true, ResourceCounts: map[string]uint64{"assets": 3}, EvidenceSampleValid: true}}
	result, err := RunRollbackRehearsal(context.Background(), RollbackRequest{FixtureID: "fixture-1", ReleaseID: "release-1", PriorVersion: "1.4.2", ExpectedCounts: map[string]uint64{"assets": 3}, UpgradeEvidence: "s3://release/evidence.json"}, runtime)
	if err != nil || result.RollbackID != "rollback-1" || !result.StateValidated || runtime.releaseID != "release-1" {
		t.Fatalf("RunRollbackRehearsal() = %#v, %v, release=%q", result, err, runtime.releaseID)
	}
	runtime.snapshot.ResourceCounts["assets"] = 2
	if _, err := RunRollbackRehearsal(context.Background(), RollbackRequest{FixtureID: "fixture-1", ReleaseID: "release-1", PriorVersion: "1.4.2", ExpectedCounts: map[string]uint64{"assets": 3}, UpgradeEvidence: "s3://release/evidence.json"}, runtime); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestBuildDiagnosticsBundleClonesBoundedAllowlistedDataAndRejectsSecrets(t *testing.T) {
	input := DiagnosticsInput{OrganizationID: "org-a", Health: map[string]string{"api": "ready"}, Versions: map[string]string{"product": "1.5.0"}, Configuration: map[string]string{"mode": "single_tenant"}, Logs: []string{"request completed"}}
	bundle, err := BuildDiagnosticsBundle(input)
	if err != nil || bundle.Health["api"] != "ready" {
		t.Fatalf("BuildDiagnosticsBundle() = %#v, %v", bundle, err)
	}
	input.Health["api"] = "changed"
	if bundle.Health["api"] != "ready" {
		t.Fatal("bundle retained mutable input")
	}
	input.Logs = []string{"Authorization: Bearer seeded-value"}
	if _, err := BuildDiagnosticsBundle(input); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("seeded secret error = %v", err)
	}
}

func TestDiagnosticsCommandEmitsOnlyValidatedBundle(t *testing.T) {
	input := DiagnosticsInput{OrganizationID: "org-a", Health: map[string]string{"api": "ready"}, Versions: map[string]string{"product": "1.5.0"}, Configuration: map[string]string{"mode": "single_tenant"}, Logs: []string{"request completed"}}
	encoded, err := jsonBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runCommand(&output, bytes.NewReader(encoded), []string{"diagnostics"}, "dev"); err != nil || !strings.Contains(output.String(), `"organization_id":"org-a"`) {
		t.Fatalf("diagnostics output=%q error=%v", output.String(), err)
	}
}

func TestEvaluateParityRequiresAllRealProviderSemanticsAndCleanup(t *testing.T) {
	valid := ParityObservation{IAMAllowed: true, IAMExplicitDeny: true, SourceIdentityBound: true, IRSABound: true, S3KMSSucceeded: true, SecretsSucceeded: true, SQSSucceeded: true, OpenSearchSucceeded: true, FargateScheduled: true, DirectEgressDenied: true, ProxyDestinationPassed: true, Cleaned: true}
	if report, err := EvaluateParity(valid); err != nil || !report.Ready {
		t.Fatalf("EvaluateParity() = %#v, %v", report, err)
	}
	valid.Cleaned = false
	if _, err := EvaluateParity(valid); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("cleanup error = %v", err)
	}
}

func TestEvaluateOutagesRequiresEveryExactDegradedBehavior(t *testing.T) {
	values := []OutageObservation{
		{Name: "stytch", DependencyDegraded: true, RuntimePolicyActive: true, TokenValidityUnchanged: true},
		{Name: "neon", DependencyDegraded: true, RuntimePolicyActive: true, MutationFailedFast: true},
		{Name: "nango", DependencyDegraded: true, RuntimePolicyActive: true, CoreFeaturesActive: true},
		{Name: "optional_vendors", DependencyDegraded: true, RuntimePolicyActive: true, CoreFeaturesActive: true},
		{Name: "opensearch", DependencyDegraded: true, RuntimePolicyActive: true, BacklogVisible: true},
		{Name: "neo4j", DependencyDegraded: true, RuntimePolicyActive: true, BasicInventoryActive: true},
		{Name: "sqs_saturation", DependencyDegraded: true, RuntimePolicyActive: true, MemoryBounded: true, QueueAgeVisible: true},
	}
	if report, err := EvaluateOutages(values); err != nil || !report.Ready || len(report.Checks) != 7 {
		t.Fatalf("EvaluateOutages() = %#v, %v", report, err)
	}
	values[0].TokenValidityUnchanged = false
	if _, err := EvaluateOutages(values); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("outage mismatch error = %v", err)
	}
	values[0].TokenValidityUnchanged = true
	values = append(values, OutageObservation{Name: "unexpected"})
	if _, err := EvaluateOutages(values); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("extra outage error = %v", err)
	}
}

func TestLatencyAndBoundedAPILoadGates(t *testing.T) {
	samples := repeatedDurations(100, 20*time.Millisecond)
	if report, err := EvaluateRuntimeLatency(samples); err != nil || report.P95 != 20*time.Millisecond {
		t.Fatalf("EvaluateRuntimeLatency() = %#v, %v", report, err)
	}
	api := APILoadArtifact{ReferenceProfile: "reference-m7i", Duration: 5 * time.Minute, Endpoints: []string{"/api/v1/assets", "/api/v1/findings"}, Latencies: repeatedDurations(100, 700*time.Millisecond), Requests: 100, Errors: 1}
	if report, err := EvaluateAPILoad(api); err != nil || !report.Passed || report.ErrorRate != 0.01 {
		t.Fatalf("EvaluateAPILoad() = %#v, %v", report, err)
	}
	api.Endpoints[0] = "/api/v1/assets?unbounded=*"
	if _, err := EvaluateAPILoad(api); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("unbounded endpoint error = %v", err)
	}
	api.Endpoints[0] = "/api/v1/assets"
	api.Requests++
	if _, err := EvaluateAPILoad(api); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("request/sample mismatch error = %v", err)
	}
}

func TestGraphEventAndSensorMeasurementsAreBounded(t *testing.T) {
	graph := GraphLoadArtifact{ReferenceProfile: "reference-m7i", Depth: 3, ResultLimit: 1000, Durations: repeatedDurations(20, 3*time.Second)}
	if report, err := EvaluateGraphLoad(graph); err != nil || !report.Passed {
		t.Fatalf("EvaluateGraphLoad() = %#v, %v", report, err)
	}
	plan, err := GenerateEventLoad("org-a", 5000, 5*time.Minute, 500)
	if err != nil || plan.EventCount != 1_500_000 || plan.BatchCount != 3000 {
		t.Fatalf("GenerateEventLoad() = %#v, %v", plan, err)
	}
	event := EventLoadArtifact{ReferenceProfile: "reference-m7i", ObservedRate: 5000, BacklogRecovered: true, GeneratedEvents: 1_500_000, IndexedEvents: 1_500_000, RetryCount: 10}
	if report, err := EvaluateEventLoad(event); err != nil || !report.Passed {
		t.Fatalf("EvaluateEventLoad() = %#v, %v", report, err)
	}
	overhead := SensorOverhead{ReferenceProfile: "reference-m7i", Workload: "event-floor", CPUCoreSeconds: 12.5, PeakMemoryBytes: 128 << 20, Duration: 5 * time.Minute}
	if _, err := RecordSensorOverhead(overhead); err != nil {
		t.Fatalf("RecordSensorOverhead() error = %v", err)
	}
	graph.Durations[0] = 4 * time.Second
	if _, err := EvaluateGraphLoad(graph); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("graph maximum error = %v", err)
	}
	overhead.CPUCoreSeconds = math.NaN()
	if _, err := RecordSensorOverhead(overhead); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("non-finite overhead error = %v", err)
	}
}

func TestLatencyGatesRejectSlowOrInvalidSamples(t *testing.T) {
	if _, err := EvaluateRuntimeLatency(repeatedDurations(100, 26*time.Millisecond)); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("slow runtime error = %v", err)
	}
	if _, err := EvaluateRuntimeLatency(repeatedDurations(19, 1*time.Millisecond)); !errors.Is(err, errResilienceRejected) {
		t.Fatalf("short artifact error = %v", err)
	}
}

func repeatedDurations(count int, duration time.Duration) []time.Duration {
	values := make([]time.Duration, count)
	for index := range values {
		values[index] = duration
	}
	return values
}

type fakeRollbackRuntime struct {
	snapshot  RollbackSnapshot
	releaseID string
}

func (runtime *fakeRollbackRuntime) Rollback(_ context.Context, _ string, releaseID string, _ string) (string, error) {
	runtime.releaseID = releaseID
	return "rollback-1", nil
}
func (runtime *fakeRollbackRuntime) ValidateRollback(context.Context, string) (RollbackSnapshot, error) {
	return runtime.snapshot, nil
}
