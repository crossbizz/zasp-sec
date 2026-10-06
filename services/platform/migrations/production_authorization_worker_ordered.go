package migrations

import (
	_ "embed"
	"strings"
)

//go:embed sql/0080_authorization_worker_ordered_sources.sql
var authorizationWorkerOrderedSourcesSQL string

//go:embed sql/0080_authorization_worker_ordered_planning.sql
var authorizationWorkerOrderedPlanningSQL string

//go:embed sql/0080_authorization_worker_ordered_catalog.sql
var authorizationWorkerOrderedCatalogSQL string

//go:embed sql/0080_authorization_worker_ordered_human.sql
var authorizationWorkerOrderedHumanSQL string

//go:embed sql/0080_authorization_worker_ordered_approval_inner.sql
var authorizationWorkerOrderedApprovalInnerSQL string

//go:embed sql/0080_authorization_worker_ordered_writers.sql
var authorizationWorkerOrderedWritersSQL string

//go:embed sql/0080_authorization_worker_ordered_writer_catalog.sql
var authorizationWorkerOrderedWriterCatalogSQL string

//go:embed sql/0080_authorization_worker_ordered_writer_late_catalog.sql
var authorizationWorkerOrderedWriterLateCatalogSQL string

//go:embed sql/0080_authorization_worker_ordered_targets.sql
var authorizationWorkerOrderedTargetsSQL string

//go:embed sql/0080_authorization_worker_ordered_effects.sql
var authorizationWorkerOrderedEffectsSQL string

//go:embed sql/0080_authorization_worker_ordered_policy.sql
var authorizationWorkerOrderedPolicySQL string

//go:embed sql/0080_authorization_worker_ordered_operations.sql
var authorizationWorkerOrderedOperationsSQL string

//go:embed sql/0080_authorization_worker_ordered_signing_inner.sql
var authorizationWorkerOrderedSigningInnerSQL string

//go:embed sql/0080_authorization_worker_ordered_lifecycle.sql
var authorizationWorkerOrderedLifecycleSQL string

//go:embed sql/0080_authorization_worker_ordered_retirement.sql
var authorizationWorkerOrderedRetirementSQL string

//go:embed sql/0080_authorization_worker_ordered_effect_catalog.sql
var authorizationWorkerOrderedEffectCatalogSQL string

//go:embed sql/0080_authorization_worker_readiness_graph.sql
var authorizationWorkerReadinessGraphSQL string

func authorizationWorkerOrderedSource(source string) string {
	return authorizationWorkerOrderedSourceWithGraph(source, authorizationWorkerReadinessGraphSQL)
}

func authorizationWorkerOrderedSourceWithGraph(source, graph string) string {
	const gateway = "-- worker gateway writer definitions"
	if strings.Count(source, gateway) != 1 {
		panic("ordered writer gateway predecessor marker changed")
	}
	// The catalog extends the effective gateway projections, so execute it
	// after that module while leaving its later expansion/ownership untouched.
	// Types precede their readers; private effect reads precede signing,
	// ordinary operations and lifecycle copies. Every new trigger is separately
	// pinned by the worker catalog before its retained projection excludes it.
	connected := strings.Join([]string{
		authorizationWorkerOrderedWritersSQL,
		authorizationWorkerOrderedWriterCatalogSQL,
		authorizationWorkerOrderedTargetsSQL,
		authorizationWorkerOrderedEffectsSQL,
		authorizationWorkerOrderedPolicySQL,
		authorizationWorkerOrderedSigningInnerSQL,
		authorizationWorkerOrderedOperationsSQL,
		authorizationWorkerOrderedLifecycleSQL,
		strings.ReplaceAll(authorizationWorkerOrderedRetirementSQL, "-- retirement69 original fingerprint", TemporalWorkflowFingerprint()),
		authorizationWorkerOrderedTestSQL,
		authorizationWorkerOrderedEffectCatalogSQL,
	}, "\n")
	source = strings.Replace(source, gateway, gateway+"\n"+connected, 1)
	const finalGate = "CREATE OR REPLACE FUNCTION zasp_temporal78.fingerprint()"
	if strings.Count(source, finalGate) != 1 {
		panic("ordered writer final catalog boundary changed")
	}
	source = strings.Replace(source, finalGate, authorizationWorkerOrderedWriterLateCatalogSQL+"\n"+finalGate, 1)
	return strings.NewReplacer(
		"-- worker ordered source definitions", authorizationWorkerOrderedSourcesSQL,
		"-- worker ordered planning definitions", authorizationWorkerOrderedPlanningSQL,
		"-- worker ordered catalog definitions", authorizationWorkerOrderedHumanSQL+"\n"+authorizationWorkerOrderedApprovalInnerSQL+"\n"+authorizationWorkerOrderedCatalogSQL,
	).Replace(source) + "\n" + graph
}
