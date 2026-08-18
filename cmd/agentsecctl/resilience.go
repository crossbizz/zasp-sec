package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

var errResilienceRejected = errors.New("resilience evidence rejected")

type RollbackRuntime interface {
	Rollback(context.Context, string, string, string) (string, error)
	ValidateRollback(context.Context, string) (RollbackSnapshot, error)
}

type RollbackSnapshot struct {
	Version             string
	SchemaCompatible    bool
	ResourceCounts      map[string]uint64
	EvidenceSampleValid bool
}

type RollbackRequest struct {
	FixtureID       string
	ReleaseID       string
	PriorVersion    string
	ExpectedCounts  map[string]uint64
	UpgradeEvidence string
}

type RollbackResult struct {
	RollbackID      string `json:"rollback_id"`
	UpgradeEvidence string `json:"upgrade_evidence"`
	StateValidated  bool   `json:"state_validated"`
}

func RunRollbackRehearsal(ctx context.Context, request RollbackRequest, runtime RollbackRuntime) (RollbackResult, error) {
	if ctx == nil || runtime == nil || !validIdentifier(request.FixtureID) || !validIdentifier(request.ReleaseID) || !canonicalSemanticVersion(request.PriorVersion) || len(request.ExpectedCounts) == 0 || !validReference(request.UpgradeEvidence) {
		return RollbackResult{}, errResilienceRejected
	}
	rollbackID, err := runtime.Rollback(ctx, request.FixtureID, request.ReleaseID, request.PriorVersion)
	if err != nil || !validIdentifier(rollbackID) {
		return RollbackResult{}, errResilienceRejected
	}
	snapshot, err := runtime.ValidateRollback(ctx, request.FixtureID)
	if err != nil || snapshot.Version != request.PriorVersion || !snapshot.SchemaCompatible || !snapshot.EvidenceSampleValid || !equalCounts(snapshot.ResourceCounts, request.ExpectedCounts) {
		return RollbackResult{}, errResilienceRejected
	}
	return RollbackResult{RollbackID: rollbackID, UpgradeEvidence: request.UpgradeEvidence, StateValidated: true}, nil
}

type DiagnosticsInput struct {
	OrganizationID string            `json:"organization_id"`
	Health         map[string]string `json:"health"`
	Versions       map[string]string `json:"versions"`
	Configuration  map[string]string `json:"configuration"`
	Logs           []string          `json:"logs"`
}

type DiagnosticsBundle struct {
	OrganizationID string            `json:"organization_id"`
	Health         map[string]string `json:"health"`
	Versions       map[string]string `json:"versions"`
	Configuration  map[string]string `json:"configuration"`
	Logs           []string          `json:"logs"`
}

func BuildDiagnosticsBundle(input DiagnosticsInput) (DiagnosticsBundle, error) {
	if !validIdentifier(input.OrganizationID) || len(input.Health) == 0 || len(input.Versions) == 0 || len(input.Configuration) > 32 || len(input.Logs) > 20 {
		return DiagnosticsBundle{}, errResilienceRejected
	}
	for _, values := range []map[string]string{input.Health, input.Versions, input.Configuration} {
		for key, value := range values {
			if !validIdentifier(key) || unsafeDiagnostic(value) || len(value) > 256 {
				return DiagnosticsBundle{}, errResilienceRejected
			}
		}
	}
	for _, line := range input.Logs {
		if len(line) > 4096 || unsafeDiagnostic(line) {
			return DiagnosticsBundle{}, errResilienceRejected
		}
	}
	return DiagnosticsBundle{
		OrganizationID: input.OrganizationID,
		Health:         cloneStrings(input.Health), Versions: cloneStrings(input.Versions), Configuration: cloneStrings(input.Configuration), Logs: append([]string(nil), input.Logs...),
	}, nil
}

func unsafeDiagnostic(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization", "bearer ", "token", "secret", "password", "private_key", "private key", "api_key", "session="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.ContainsAny(value, "\x00\r")
}

type ParityObservation struct {
	IAMAllowed             bool
	IAMExplicitDeny        bool
	SourceIdentityBound    bool
	IRSABound              bool
	S3KMSSucceeded         bool
	SecretsSucceeded       bool
	SQSSucceeded           bool
	OpenSearchSucceeded    bool
	FargateScheduled       bool
	DirectEgressDenied     bool
	ProxyDestinationPassed bool
	Cleaned                bool
}

type ParityReport struct {
	Ready  bool             `json:"ready"`
	Checks []PreflightCheck `json:"checks"`
}

func EvaluateParity(value ParityObservation) (ParityReport, error) {
	checks := []PreflightCheck{
		check("real_aws_iam", value.IAMAllowed && value.IAMExplicitDeny && value.SourceIdentityBound && value.IRSABound, true, "prove IAM, STS SourceIdentity, explicit deny, and IRSA in the isolated AWS account"),
		check("real_aws_storage", value.S3KMSSucceeded && value.SecretsSucceeded && value.SQSSucceeded && value.OpenSearchSucceeded, true, "prove scoped storage, queue, secret, and search operations in the isolated AWS account"),
		check("real_aws_fargate", value.FargateScheduled && value.DirectEgressDenied && value.ProxyDestinationPassed && value.Cleaned, true, "prove exact Fargate scheduling, proxy-only egress, and cleanup"),
	}
	report := ParityReport{Ready: true, Checks: checks}
	for _, item := range checks {
		if item.Status == checkFail {
			report.Ready = false
		}
	}
	if !report.Ready {
		return report, errResilienceRejected
	}
	return report, nil
}

type OutageObservation struct {
	Name                   string
	DependencyDegraded     bool
	MutationFailedFast     bool
	RuntimePolicyActive    bool
	TokenValidityUnchanged bool
	CoreFeaturesActive     bool
	BacklogVisible         bool
	BasicInventoryActive   bool
	MemoryBounded          bool
	QueueAgeVisible        bool
}

type OutageReport struct {
	Ready  bool             `json:"ready"`
	Checks []PreflightCheck `json:"checks"`
}

func EvaluateOutages(values []OutageObservation) (OutageReport, error) {
	expected := []string{"stytch", "neon", "nango", "optional_vendors", "opensearch", "neo4j", "sqs_saturation"}
	if len(values) != len(expected) {
		return OutageReport{}, errResilienceRejected
	}
	byName := make(map[string]OutageObservation, len(values))
	for _, value := range values {
		if !contains(expected, value.Name) {
			return OutageReport{}, errResilienceRejected
		}
		if _, duplicate := byName[value.Name]; duplicate {
			return OutageReport{}, errResilienceRejected
		}
		byName[value.Name] = value
	}
	checks := make([]PreflightCheck, 0, len(expected))
	for _, name := range expected {
		value, present := byName[name]
		passed := present && value.DependencyDegraded && value.RuntimePolicyActive
		switch name {
		case "stytch":
			passed = passed && value.TokenValidityUnchanged
		case "neon":
			passed = passed && value.MutationFailedFast
		case "nango", "optional_vendors":
			passed = passed && value.CoreFeaturesActive
		case "opensearch":
			passed = passed && value.BacklogVisible
		case "neo4j":
			passed = passed && value.BasicInventoryActive
		case "sqs_saturation":
			passed = passed && value.MemoryBounded && value.QueueAgeVisible
		}
		checks = append(checks, check(name, passed, true, "retain deterministic runtime enforcement and expose the exact degraded dependency state"))
	}
	report := OutageReport{Ready: true, Checks: checks}
	for _, item := range checks {
		if item.Status == checkFail {
			report.Ready = false
		}
	}
	if !report.Ready {
		return report, errResilienceRejected
	}
	return report, nil
}

type LatencyReport struct {
	Samples int           `json:"samples"`
	P50     time.Duration `json:"p50"`
	P95     time.Duration `json:"p95"`
	P99     time.Duration `json:"p99"`
	Passed  bool          `json:"passed"`
}

func EvaluateRuntimeLatency(samples []time.Duration) (LatencyReport, error) {
	report, err := evaluateLatency(samples, 25*time.Millisecond)
	if err != nil {
		return LatencyReport{}, err
	}
	return report, nil
}

type APILoadArtifact struct {
	ReferenceProfile string
	Duration         time.Duration
	Endpoints        []string
	Latencies        []time.Duration
	Requests         uint64
	Errors           uint64
}

type APILoadReport struct {
	Latency   LatencyReport `json:"latency"`
	ErrorRate float64       `json:"error_rate"`
	Profile   string        `json:"profile"`
	Passed    bool          `json:"passed"`
}

func EvaluateAPILoad(value APILoadArtifact) (APILoadReport, error) {
	if !validIdentifier(value.ReferenceProfile) || value.Duration <= 0 || value.Duration > 5*time.Minute || value.Requests == 0 || value.Requests != uint64(len(value.Latencies)) || value.Errors > value.Requests || len(value.Endpoints) == 0 || len(value.Endpoints) > 16 {
		return APILoadReport{}, errResilienceRejected
	}
	for _, endpoint := range value.Endpoints {
		if len(endpoint) > 128 || !strings.HasPrefix(endpoint, "/api/v1/") || strings.ContainsAny(endpoint, "?*\r\n") {
			return APILoadReport{}, errResilienceRejected
		}
	}
	latency, err := evaluateLatency(value.Latencies, 750*time.Millisecond)
	if err != nil {
		return APILoadReport{}, err
	}
	errorRate := float64(value.Errors) / float64(value.Requests)
	report := APILoadReport{Latency: latency, ErrorRate: errorRate, Profile: value.ReferenceProfile, Passed: latency.Passed && errorRate <= 0.01}
	if !report.Passed {
		return report, errResilienceRejected
	}
	return report, nil
}

type GraphLoadArtifact struct {
	ReferenceProfile string
	Depth            int
	ResultLimit      int
	Durations        []time.Duration
}

func EvaluateGraphLoad(value GraphLoadArtifact) (LatencyReport, error) {
	if !validIdentifier(value.ReferenceProfile) || value.Depth < 1 || value.Depth > 3 || value.ResultLimit < 1 || value.ResultLimit > 1000 {
		return LatencyReport{}, errResilienceRejected
	}
	for _, duration := range value.Durations {
		if duration > 3*time.Second {
			return LatencyReport{}, errResilienceRejected
		}
	}
	report, err := evaluateLatency(value.Durations, 3*time.Second)
	if err != nil {
		return report, errResilienceRejected
	}
	return report, nil
}

type EventLoadPlan struct {
	OrganizationID string        `json:"organization_id"`
	RatePerSecond  int           `json:"rate_per_second"`
	Duration       time.Duration `json:"duration"`
	BatchSize      int           `json:"batch_size"`
	BatchCount     int           `json:"batch_count"`
	EventCount     int           `json:"event_count"`
}

func GenerateEventLoad(organizationID string, rate int, duration time.Duration, batchSize int) (EventLoadPlan, error) {
	if !validIdentifier(organizationID) || rate < 1 || rate > 10_000 || duration < time.Second || duration > 5*time.Minute || batchSize < 1 || batchSize > 1000 {
		return EventLoadPlan{}, errResilienceRejected
	}
	events := rate * int(duration/time.Second)
	return EventLoadPlan{OrganizationID: organizationID, RatePerSecond: rate, Duration: duration, BatchSize: batchSize, BatchCount: (events + batchSize - 1) / batchSize, EventCount: events}, nil
}

type EventLoadArtifact struct {
	ReferenceProfile string
	ObservedRate     int
	BacklogRecovered bool
	IndexedEvents    uint64
	GeneratedEvents  uint64
	DroppedEvents    uint64
	RetryCount       uint64
}

type EventLoadReport struct {
	ObservedRate     int    `json:"observed_rate"`
	BacklogRecovered bool   `json:"backlog_recovered"`
	IndexedEvents    uint64 `json:"indexed_events"`
	DroppedEvents    uint64 `json:"dropped_events"`
	RetryCount       uint64 `json:"retry_count"`
	Passed           bool   `json:"passed"`
}

func EvaluateEventLoad(value EventLoadArtifact) (EventLoadReport, error) {
	passed := validIdentifier(value.ReferenceProfile) && value.ObservedRate >= 5000 && value.BacklogRecovered && value.GeneratedEvents > 0 && value.IndexedEvents == value.GeneratedEvents && value.DroppedEvents == 0 && value.RetryCount <= value.GeneratedEvents/10
	report := EventLoadReport{ObservedRate: value.ObservedRate, BacklogRecovered: value.BacklogRecovered, IndexedEvents: value.IndexedEvents, DroppedEvents: value.DroppedEvents, RetryCount: value.RetryCount, Passed: passed}
	if !passed {
		return report, errResilienceRejected
	}
	return report, nil
}

type SensorOverhead struct {
	ReferenceProfile string        `json:"reference_profile"`
	Workload         string        `json:"workload"`
	CPUCoreSeconds   float64       `json:"cpu_core_seconds"`
	PeakMemoryBytes  uint64        `json:"peak_memory_bytes"`
	Duration         time.Duration `json:"duration"`
}

func RecordSensorOverhead(value SensorOverhead) (SensorOverhead, error) {
	if !validIdentifier(value.ReferenceProfile) || !validIdentifier(value.Workload) || math.IsNaN(value.CPUCoreSeconds) || math.IsInf(value.CPUCoreSeconds, 0) || value.CPUCoreSeconds < 0 || value.PeakMemoryBytes == 0 || value.Duration <= 0 || value.Duration > 15*time.Minute {
		return SensorOverhead{}, errResilienceRejected
	}
	return value, nil
}

func evaluateLatency(samples []time.Duration, limit time.Duration) (LatencyReport, error) {
	if len(samples) < 20 || len(samples) > 100_000 {
		return LatencyReport{}, errResilienceRejected
	}
	copyOfSamples := append([]time.Duration(nil), samples...)
	for _, sample := range copyOfSamples {
		if sample <= 0 || sample > time.Minute {
			return LatencyReport{}, errResilienceRejected
		}
	}
	sort.Slice(copyOfSamples, func(left, right int) bool { return copyOfSamples[left] < copyOfSamples[right] })
	report := LatencyReport{Samples: len(copyOfSamples), P50: percentile(copyOfSamples, 50), P95: percentile(copyOfSamples, 95), P99: percentile(copyOfSamples, 99)}
	report.Passed = report.P95 <= limit
	if !report.Passed {
		return report, errResilienceRejected
	}
	return report, nil
}

func percentile(samples []time.Duration, percentage int) time.Duration {
	index := (len(samples)*percentage + 99) / 100
	if index < 1 {
		index = 1
	}
	return samples[index-1]
}

func cloneStrings(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func canonicalSemanticVersion(value string) bool {
	var major, minor, patch int
	if _, err := fmt.Sscanf(value, "%d.%d.%d", &major, &minor, &patch); err != nil || major < 0 || minor < 0 || patch < 0 {
		return false
	}
	return value == fmt.Sprintf("%d.%d.%d", major, minor, patch)
}
