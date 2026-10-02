package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// The worker profile is private and additive. Number81 remains reserved for the
// separate policy-response product family; canonical61 and source80 stay intact.
const AuthorizationWorkerProfileName = "canonical61-temporal78-authorization79-80-worker-v1"

//go:embed sql/0080_authorization_worker_profile.sql
var authorizationWorkerProfileSQL string

//go:embed sql/0080_authorization_worker_sources.sql
var authorizationWorkerSourcesSQL string

//go:embed sql/0080_authorization_worker_planning.sql
var authorizationWorkerPlanningSQL string

//go:embed sql/0080_authorization_worker_planner_portability.sql
var authorizationWorkerPlannerPortabilitySQL string

//go:embed sql/0080_authorization_worker_tests.sql
var authorizationWorkerTestsSQL string

//go:embed sql/0080_authorization_worker_test_effects.sql
var authorizationWorkerTestEffectsSQL string

//go:embed sql/0080_authorization_worker_test_adapter.sql
var authorizationWorkerTestAdapterSQL string

//go:embed sql/0080_authorization_worker_test_completion.sql
var authorizationWorkerTestCompletionSQL string

//go:embed sql/0080_authorization_worker_test_receipt.sql
var authorizationWorkerTestReceiptSQL string

//go:embed sql/0080_authorization_worker_test_settlement.sql
var authorizationWorkerTestSettlementSQL string

//go:embed sql/0080_authorization_worker_test_lifecycle.sql
var authorizationWorkerTestLifecycleSQL string

//go:embed sql/0080_authorization_worker_test_activation.sql
var authorizationWorkerTestActivationSQL string

//go:embed sql/0080_authorization_worker_test_catalog.sql
var authorizationWorkerTestCatalogSQL string

//go:embed sql/0080_authorization_worker_gateway_writers.sql
var authorizationWorkerGatewayWritersSQL string

const workerStopParentAnchor = " IF t.run_id IS NULL OR (t.definition_version,t.input_digest) IS DISTINCT FROM(x.definition_version,x.input_digest)"
const workerSettledStopArm = ` -- A verified late receipt may change only the parent's receipt reason.
 -- The immutable stop, audit, effect identity and all predecessor checks remain.
 IF NOT COALESCE(parent_valid,false) AND t.proof->>'kind'='admitted'
 AND t.proof->>'effect_state' IN('started','unknown')
 AND rr.state=t.proof->>'parent_state'
 AND EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE(organization_id,workspace_id,environment_id,run_id,step_id,effect_key)=(o,w,e,r,x.step_id,f.effect_key)) THEN
  PERFORM zasp_temporal74.parent_evidence(o,w,e,r,x.step_id);
  parent_valid:=true;
 END IF;
`

// Compile the successor from the fixed original source, never a candidate DB.
// The copy is private to source80. Original74 bytes and semantics stay intact.
func authorizationWorkerStopSuccessor(source string) string {
	const header = "CREATE FUNCTION zasp_temporal74.stop_evidence(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$"
	if strings.Count(source, header) != 1 {
		panic("worker stop declaration changed")
	}
	start := strings.Index(source, header)
	end := strings.Index(source[start:], "END $evidence$;")
	if end < 0 {
		panic("worker stop body changed")
	}
	copy := source[start : start+end+len("END $evidence$;")]
	if strings.Count(copy, workerStopParentAnchor) != 1 {
		panic("worker stop parent guard changed")
	}
	copy = strings.Replace(copy, workerStopParentAnchor, workerSettledStopArm+workerStopParentAnchor, 1)
	return strings.Replace(copy, "FUNCTION zasp_temporal74.stop_evidence(", "FUNCTION zasp_authorization80_worker.test74_stop_evidence(", 1)
}

func authorizationWorkerProfileSource() (string, string) {
	source := strings.NewReplacer(
		"-- worker finding checksum", TemporalFindingResponseChecksum(),
		"-- worker finding fingerprint", TemporalFindingResponseFingerprint(),
		"-- worker test checksum", ProductionTemporalTestExecutor().Checksum(),
		"-- worker test fingerprint", TemporalTestExecutorFingerprint(),
	).Replace(strings.NewReplacer("-- worker source definitions", authorizationWorkerSourcesSQL, "-- worker planning definitions", authorizationWorkerPlanningSQL, "-- worker test definitions", authorizationWorkerTestsSQL, "-- worker test effect definitions", authorizationWorkerTestEffectsSQL, "-- worker test adapter definitions", authorizationWorkerTestAdapterSQL, "-- worker test completion definitions", authorizationWorkerTestCompletionSQL, "-- worker test receipt definitions", authorizationWorkerTestReceiptSQL, "-- worker test settlement definitions", authorizationWorkerTestSettlementSQL, "-- worker test catalog definitions", authorizationWorkerTestCatalogSQL).Replace(authorizationWorkerProfileSQL))
	source = strings.ReplaceAll(source, "-- worker planner portability definitions", authorizationWorkerPlannerPortabilitySQL)
	lifecycle := strings.NewReplacer("-- worker test checksum", ProductionTemporalTestExecutor().Checksum(), "-- worker test fingerprint", TemporalTestExecutorFingerprint()).Replace(authorizationWorkerTestLifecycleSQL)
	lifecycle = authorizationWorkerStopSuccessor(ProductionTemporalTestExecutor().UpSQL()) + "\n" + lifecycle
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

func (r *Runner) UpProductionAuthorizationWorkerProfile(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(q string, args ...any) error {
			var ok bool
			if err := scanRow(ctx, tx, q, args, &ok); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if err := check(`SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1)`, ProductionSecurityAgentMultistep().Checksum()); err != nil {
			return err
		}
		if err := check(`SELECT to_regnamespace('zasp_authorization80_temporal') IS NOT NULL AND to_regnamespace('zasp_temporal78') IS NOT NULL`); err != nil {
			return err
		}
		if err := check(`SELECT zasp_authorization80_temporal.ready()`); err != nil {
			return err
		}
		source, checksum := authorizationWorkerProfileSource()
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_authorization80_worker') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, source); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_authorization80_worker.registration(checksum,fingerprint) VALUES($1,zasp_authorization80_worker.fingerprint())`, checksum); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return check(`SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready()`, checksum)
	})
}
