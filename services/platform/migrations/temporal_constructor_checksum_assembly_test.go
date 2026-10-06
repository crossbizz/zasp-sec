package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
)

// Test-only predecessor oracles retain the source assembly that rendered unused
// ancestor SQL for checksum operands. They are not runtime branches or caches.
// Original function-body identities are retained in the private batch receipt.
func preChecksumOptimizationProductionTemporalLegacyTests() Metadata {
	sum := sha256.Sum256([]byte(temporalLegacyTestsSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- legacy71 checksum", checksum, "-- legacy71 fingerprint", TemporalLegacyTestsFingerprint(), "-- compatibility70 checksum", preChecksumOptimizationProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalLegacyTestsSQL)
	return Metadata{version: 71, name: "production_temporal_legacy_tests_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalDomain() Metadata {
	digest := sha256.Sum256([]byte(temporalDomainBaseSQL + "\x00" + temporalDomainUpSQL))
	checksum := hex.EncodeToString(digest[:])
	return Metadata{version: 67, name: "production_temporal_domain_extension", checksum: checksum, up: temporalDomainBind(checksum).Replace(temporalDomainUpSQL)}
}

func preChecksumOptimizationProductionTemporalExecutor() Metadata {
	source := temporalExecutorSource()
	digest := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(digest[:])
	bind := strings.NewReplacer("-- executor68 checksum", checksum,
		"-- executor68 fingerprint", TemporalExecutorFingerprint(),
		"-- executor68 base fingerprint", TemporalExecutorBaseFingerprint(),
		"-- executor68 domain fingerprint", TemporalExecutorDomainFingerprint(),
		"-- domain67 checksum", preChecksumOptimizationProductionTemporalDomain().Checksum(),
		"-- domain67 fingerprint", TemporalDomainFingerprint(),
		"-- release61 checksum", ProductionSecurityAgentMultistep().Checksum(),
		"-- release61 fingerprint", SecurityAgentMultistepRegisteredFingerprint())
	return Metadata{version: 68, name: "production_temporal_executor_extension", checksum: checksum, up: bind.Replace(source)}
}

func preChecksumOptimizationProductionTemporalHumanAdmission() Metadata {
	sum := sha256.Sum256([]byte(temporalHumanAdmissionSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- human76 checksum", checksum, "-- human76 fingerprint", TemporalHumanAdmissionFingerprint(), "-- selector75 checksum", preChecksumOptimizationProductionTemporalTestSelector().Checksum(), "-- selector75 fingerprint", TemporalTestSelectorFingerprint(), "-- compatibility70 checksum", preChecksumOptimizationProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalHumanAdmissionSQL)
	return Metadata{version: 76, name: "production_temporal_human_admission_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalDiscovery() Metadata {
	sum := sha256.Sum256([]byte(temporalDiscoverySQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- discovery72 checksum", checksum, "-- discovery72 fingerprint", TemporalDiscoveryFingerprint(), "-- legacy71 checksum", preChecksumOptimizationProductionTemporalLegacyTests().Checksum(), "-- legacy71 fingerprint", TemporalLegacyTestsFingerprint()).Replace(temporalDiscoverySQL)
	return Metadata{version: 72, name: "production_temporal_discovery_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalAdmission() Metadata {
	sum := sha256.Sum256([]byte(temporalAdmissionSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- admission73 checksum", checksum, "-- admission73 fingerprint", TemporalAdmissionFingerprint(), "-- discovery72 checksum", preChecksumOptimizationProductionTemporalDiscovery().Checksum(), "-- discovery72 fingerprint", TemporalDiscoveryFingerprint(), "-- compatibility70 checksum", preChecksumOptimizationProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalAdmissionSQL)
	return Metadata{version: 73, name: "production_temporal_admission_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalTestSelector() Metadata {
	sum := sha256.Sum256([]byte(temporalTestSelectorSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- selector75 checksum", checksum, "-- selector75 fingerprint", TemporalTestSelectorFingerprint(), "-- test74 checksum", preChecksumOptimizationProductionTemporalTestExecutor().Checksum(), "-- test74 fingerprint", TemporalTestExecutorFingerprint(), "-- compatibility70 checksum", preChecksumOptimizationProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(temporalTestSelectorSQL)
	return Metadata{version: 75, name: "production_temporal_test_selector_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalCompatibility() Metadata {
	sum := sha256.Sum256([]byte(temporalCompatibilitySQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- compatibility70 checksum", checksum, "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint(), "-- workflow69 checksum", preChecksumOptimizationProductionTemporalWorkflow().Checksum(), "-- workflow69 fingerprint", TemporalWorkflowFingerprint()).Replace(temporalCompatibilitySQL)
	return Metadata{version: 70, name: "production_temporal_compatibility_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalTestExecutor() Metadata {
	source := temporalTestExecutorSource()
	sum := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- test74 checksum", checksum, "-- test74 fingerprint", TemporalTestExecutorFingerprint(), "-- admission73 checksum", preChecksumOptimizationProductionTemporalAdmission().Checksum(), "-- admission73 fingerprint", TemporalAdmissionFingerprint(), "-- compatibility70 checksum", preChecksumOptimizationProductionTemporalCompatibility().Checksum(), "-- compatibility70 fingerprint", TemporalCompatibilityFingerprint()).Replace(source)
	return Metadata{version: 74, name: "production_temporal_test_executor_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationProductionTemporalWorkflow() Metadata {
	sum := sha256.Sum256([]byte(temporalWorkflowSQL))
	checksum := hex.EncodeToString(sum[:])
	bound := strings.NewReplacer("-- workflow69 checksum", checksum, "-- workflow69 fingerprint", TemporalWorkflowFingerprint(), "-- executor68 checksum", preChecksumOptimizationProductionTemporalExecutor().Checksum(), "-- executor68 fingerprint", TemporalExecutorFingerprint()).Replace(temporalWorkflowSQL)
	return Metadata{version: 69, name: "production_temporal_workflow_extension", checksum: checksum, up: bound}
}

func preChecksumOptimizationWorkerProfileSource() (string, string) {
	source := strings.NewReplacer(
		"-- worker finding checksum", TemporalFindingResponseChecksum(),
		"-- worker finding fingerprint", TemporalFindingResponseFingerprint(),
		"-- worker test checksum", preChecksumOptimizationProductionTemporalTestExecutor().Checksum(),
		"-- worker test fingerprint", TemporalTestExecutorFingerprint(),
	).Replace(strings.NewReplacer("-- worker source definitions", authorizationWorkerSourcesSQL, "-- worker planning definitions", authorizationWorkerPlanningSQL, "-- worker test definitions", authorizationWorkerTestsSQL, "-- worker test effect definitions", authorizationWorkerTestEffectsSQL, "-- worker test adapter definitions", authorizationWorkerTestAdapterSQL, "-- worker test completion definitions", authorizationWorkerTestCompletionSQL, "-- worker test receipt definitions", authorizationWorkerTestReceiptSQL, "-- worker test settlement definitions", authorizationWorkerTestSettlementSQL, "-- worker test catalog definitions", authorizationWorkerTestCatalogSQL).Replace(authorizationWorkerProfileSQL))
	source = strings.ReplaceAll(source, "-- worker planner portability definitions", authorizationWorkerPlannerPortabilitySQL)
	lifecycle := strings.NewReplacer("-- worker test checksum", preChecksumOptimizationProductionTemporalTestExecutor().Checksum(), "-- worker test fingerprint", TemporalTestExecutorFingerprint()).Replace(authorizationWorkerTestLifecycleSQL)
	lifecycle = authorizationWorkerStopSuccessor(preChecksumOptimizationProductionTemporalTestExecutor().UpSQL()) + "\n" + lifecycle
	source = strings.ReplaceAll(source, "-- worker test lifecycle definitions", lifecycle)
	source = strings.ReplaceAll(source, "-- worker test activation definitions", authorizationWorkerTestActivationSQL)
	source = strings.NewReplacer("-- worker discovery source definitions", authorizationWorkerDiscoverySourcesSQL, "-- worker discovery fence definitions", authorizationWorkerDiscoveryFencesSQL, "-- worker discovery catalog definitions", authorizationWorkerDiscoveryCatalogSQL).Replace(source)
	source = authorizationWorkerOrderedSource(source)
	source = strings.ReplaceAll(source, "-- worker gateway writer definitions", authorizationWorkerGatewayWritersSQL)
	source = authorizationWorkerRuntimeSource(source)
	source = authorizationWorkerRuntimeAncestrySource(source)
	// Inline the catalog query, not the callable fingerprint helper. Pin the
	// checksum-free gate body before calculating the profile checksum, avoiding
	// both recursive readiness calls and a checksum fixed point.
	parts := strings.Split(source, "$fingerprint$")
	if len(parts) < 3 {
		panic("worker fingerprint source missing")
	}
	source = strings.ReplaceAll(source, "-- worker inline fingerprint", parts[1])
	gate := strings.Split(source, "$catalog$")
	if len(gate) != 3 {
		panic("worker catalog source missing")
	}
	gateHash := sha256.Sum256([]byte(gate[1]))
	source = strings.ReplaceAll(source, "-- worker catalog body digest", hex.EncodeToString(gateHash[:]))
	h := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- worker profile checksum", checksum), checksum
}

func TestTemporalChecksumOperandAssemblyPreservesPredecessorBytes(t *testing.T) {
	pairs := []struct {
		name          string
		before, after func() Metadata
	}{
		{"Domain", preChecksumOptimizationProductionTemporalDomain, ProductionTemporalDomain},
		{"Executor", preChecksumOptimizationProductionTemporalExecutor, ProductionTemporalExecutor},
		{"Workflow", preChecksumOptimizationProductionTemporalWorkflow, ProductionTemporalWorkflow},
		{"Compatibility", preChecksumOptimizationProductionTemporalCompatibility, ProductionTemporalCompatibility},
		{"LegacyTests", preChecksumOptimizationProductionTemporalLegacyTests, ProductionTemporalLegacyTests},
		{"Discovery", preChecksumOptimizationProductionTemporalDiscovery, ProductionTemporalDiscovery},
		{"Admission", preChecksumOptimizationProductionTemporalAdmission, ProductionTemporalAdmission},
		{"TestExecutor", preChecksumOptimizationProductionTemporalTestExecutor, ProductionTemporalTestExecutor},
		{"TestSelector", preChecksumOptimizationProductionTemporalTestSelector, ProductionTemporalTestSelector},
		{"HumanAdmission", preChecksumOptimizationProductionTemporalHumanAdmission, ProductionTemporalHumanAdmission},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			if p.before() != p.after() {
				t.Fatal("bound metadata bytes or checksum changed")
			}
		})
	}
}

func TestWorkerSourceChecksumOperandsAvoidUnusedAncestorRendering(t *testing.T) {
	measure := func(build func() (string, string)) (string, string, uint64) {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		source, checksum := build()
		runtime.ReadMemStats(&after)
		return source, checksum, after.TotalAlloc - before.TotalAlloc
	}
	original, checksum, before := measure(preChecksumOptimizationWorkerProfileSource)
	current, next, after := measure(authorizationWorkerProfileSource)
	if original != current || checksum != next {
		t.Fatal("worker compiled predecessor bytes changed")
	}
	if after > before/2 {
		t.Fatalf("checksum operands still rendered unused ancestor SQL: before=%d after=%d", before, after)
	}
	t.Logf("fresh worker source allocation: predecessor=%d successor=%d", before, after)
}

func TestTemporalChecksumOperandAssemblyRecomputesSourceMutations(t *testing.T) {
	original := temporalAdmissionSQL
	defer func() { temporalAdmissionSQL = original }()
	temporalAdmissionSQL = original + "\n-- owned in-memory checksum mutation\n"
	changedBefore := preChecksumOptimizationProductionTemporalTestExecutor()
	changedAfter := ProductionTemporalTestExecutor()
	if changedBefore != changedAfter {
		t.Fatal("mutated ancestor source identity was hidden")
	}
	temporalAdmissionSQL = original
	if restoredBefore, restoredAfter := preChecksumOptimizationProductionTemporalTestExecutor(), ProductionTemporalTestExecutor(); restoredBefore != restoredAfter || restoredAfter == changedAfter {
		t.Fatal("source restoration was cached or changed")
	}
}
