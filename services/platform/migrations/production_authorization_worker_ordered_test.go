package migrations

import (
	"strings"
	"testing"
)

func TestOrdered68ConnectedProfileAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	last := -1
	for _, boundary := range []string{
		"DO $ordered_writer_catalog$",
		"CREATE TABLE zasp_authorization80_worker.ordered_effect_scope(",
		"DO $ordered_effect_boundary$",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_policy_metadata(",
		"DO $ordinary_boundaries$",
		"CREATE FUNCTION zasp_authorization80_worker.ordered69_source(",
		"DO $ordered_effect_catalog$",
		"DO $ordered_writer_late_catalog$",
		"FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace LOOP",
	} {
		position := strings.Index(source, boundary)
		if strings.Count(source, boundary) != 1 || position <= last {
			t.Fatalf("connected Ordered boundary absent, duplicated or out of order: %s", boundary)
		}
		last = position
	}
	for _, required := range []string{
		"'ordered-execution-trigger'",
		"pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text",
		"PERFORM zasp_authorization80_worker.expire_ordered_effects(o);",
		"PERFORM zasp_authorization80_worker.expire_ordered_policies(o);",
		"SELECT zasp_temporal78.current_ready() AND false",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing connected Ordered contract: %s", required)
		}
	}
}

func TestOrdered62PrivateApprovalAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, marker := range []string{"DO $ordered_approval_inner$", "'FUNCTION zasp_authorization80_worker.ordered62_inner_ready('", "'FUNCTION zasp_authorization80_worker.ordered62_mutate_inner('", "'FUNCTION zasp_authorization80_worker.ordered62_decide_inner('"} {
		if strings.Count(source, marker) != 1 {
			t.Errorf("missing or repeated private approval boundary: %s", marker)
		}
	}
	if strings.Index(source, "DO $ordered_approval_inner$") <= strings.Index(source, "END $ordered_human$;") {
		t.Fatal("private approval must copy already-fenced native bodies")
	}
	for _, private := range []string{"ordered62_inner_ready", "ordered62_mutate_inner", "ordered62_decide_inner"} {
		if strings.Contains(source, "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker."+private) {
			t.Errorf("exposed private approval helper: %s", private)
		}
	}
}

func TestOrdered68WriterProfileAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	last := -1
	for _, boundary := range []string{
		"CREATE FUNCTION zasp_authorization80_worker.ordered62_replace(",
		"CREATE FUNCTION zasp_authorization80_worker.gateway_organization_lock(",
		"CREATE FUNCTION zasp_authorization80_worker.ordered_legacy_writer_organization(",
		"DO $save_ordered_writers$",
		"DO $ordered_writers$",
		"CREATE FUNCTION zasp_authorization80_worker.ordered_writer_definition(",
		"DO $ordered_writer_catalog$",
		"DO $ordered_writer_late_catalog$",
		"CREATE OR REPLACE FUNCTION zasp_temporal78.fingerprint()",
	} {
		position := strings.Index(source, boundary)
		if strings.Count(source, boundary) != 1 || position <= last {
			t.Fatalf("ordered writer assembly boundary absent, duplicated or out of order: %s", boundary)
		}
		last = position
	}
	if strings.Contains(authorizationWorkerOrderedWriterCatalogSQL, "CREATE OR REPLACE FUNCTION zasp_temporal67.") ||
		!strings.Contains(authorizationWorkerOrderedWriterCatalogSQL, "ELSE public.zasp_sa_multistep_function_identity(p.oid) END") ||
		!strings.Contains(authorizationWorkerOrderedWriterCatalogSQL, "signature='zasp_temporal77.base67_fingerprint()'") {
		t.Fatal("ordered writer catalog must preserve native77 compiler projection and public67 gates")
	}
	if runtime := strings.LastIndex(source, "DO $runtime_source_catalog$"); runtime >= strings.Index(source, "DO $ordered_writer_late_catalog$") {
		t.Fatal("ordered writer catalog must extend effective runtime source projections")
	}
	for _, forbidden := range []string{"-- worker gateway writer definitions", "-- compiled multistep checksum", "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered_legacy", "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered_writer"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("unexpanded or exposed ordered writer contract: %s", forbidden)
		}
	}
}

func TestOrdered68PlanningProfileAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, required := range []string{
		"CREATE TABLE zasp_authorization80_worker.ordered_associations(",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_facts(",
		"CREATE FUNCTION zasp_authorization80_worker.prepare_ordered68(",
		"PERFORM zasp_authorization80_worker.require_planning68(",
		"GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.prepare_ordered68(jsonb) TO zasp_temporal_executor;",
		"GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning68_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;",
		"GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning68_recovery(jsonb) TO zasp_temporal_compensation;",
		"'ordered-capture-trigger'",
		"PERFORM zasp_authorization80_worker.expire_ordered_targets(o);",
		"SELECT zasp_temporal78.current_ready() AND false",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing ordered profile contract %q", required)
		}
	}
	for _, forbidden := range []string{"-- worker ordered source definitions", "-- worker ordered planning definitions", "-- worker ordered catalog definitions", "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_facts", "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.require_planning68"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("unexpanded or exposed ordered contract %q", forbidden)
		}
	}
}

func TestOrdered68TargetLineageAssembly(t *testing.T) {
	source := authorizationWorkerOrderedSourcesSQL
	for _, required := range []string{
		"resolution:=zasp_temporal68.test_target(",
		"snapshot_id text NOT NULL,evidence_id text NOT NULL,integration_id text NOT NULL,source text NOT NULL",
		"WHEN 'zasp_inventory_evidence' THEN a.evidence_id=v->>'id'",
		"WHEN 'zasp_discovery_snapshots' THEN a.snapshot_id=v->>'id'",
		"WHEN 'zasp_inventory_source_observations' THEN(a.target_id,a.integration_id,a.source,a.snapshot_id,a.evidence_id)",
		"target_hash:=encode(digest(convert_to(resolution::text,'UTF8'),'sha256'),'hex');",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing ordered native target contract %q", required)
		}
	}
	assembled, _ := authorizationWorkerProfileSource()
	var fingerprint string
	for _, line := range strings.Split(assembled, "\n") {
		if strings.Contains(line, "'ordered-capture-trigger'") {
			fingerprint = line
		}
	}
	for _, table := range []string{"zasp_inventory_evidence", "zasp_discovery_snapshots", "zasp_inventory_source_observations"} {
		if !strings.Contains(fingerprint, "'public."+table+"'::regclass") {
			t.Errorf("ordered target trigger missing fingerprint: %s", table)
		}
	}
}
