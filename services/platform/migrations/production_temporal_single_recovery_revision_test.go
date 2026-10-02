package migrations

import (
	"os"
	"strings"
	"testing"
)

func revisionTestSQL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("sql/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func revisionTestBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, "CREATE FUNCTION "+signature)
	if start < 0 {
		t.Fatalf("function %s missing", signature)
	}
	bodyStart := strings.Index(source[start:], " AS $body$")
	if bodyStart < 0 {
		t.Fatalf("function %s body missing", signature)
	}
	bodyStart += start + len(" AS $body$")
	bodyEnd := strings.Index(source[bodyStart:], "$body$;")
	if bodyEnd < 0 {
		t.Fatalf("function %s body terminator missing", signature)
	}
	return source[bodyStart : bodyStart+bodyEnd]
}

func TestSingleTestRecoveryPostMutationRevisionFence(t *testing.T) {
	projection := revisionTestSQL(t, "0079_production_authorization_projection.up.sql")
	worker := revisionTestSQL(t, "0080_authorization_worker_sources.sql")
	tests := revisionTestSQL(t, "0080_authorization_worker_tests.sql")
	ordered := revisionTestSQL(t, "0080_authorization_worker_ordered_sources.sql")
	admission := revisionTestSQL(t, "0080_temporal_single_recovery.admission.sql")
	up := revisionTestSQL(t, "0080_temporal_single_recovery.up.sql")

	t.Run("installed cancellation captures", func(t *testing.T) {
		if !strings.Contains(projection, "['zasp_security_agent_runs','organization_id','organization_id,workspace_id,environment_id,run_id,definition_id,state']") {
			t.Fatal("base run authorization capture changed")
		}
		captures := []struct {
			name, source, update, trigger string
		}{
			{
				name:    "run_state",
				source:  worker,
				update:  "UPDATE zasp_authorization80_worker.run_state SET definition_id=NEW.definition_id,definition_version=NEW.definition_version,state=NEW.state,run_version=NEW.version",
				trigger: "CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.run_state",
			},
			{
				name:    "test_state",
				source:  worker + "\n" + tests,
				update:  "UPDATE zasp_authorization80_worker.test_state SET definition_id=NEW.definition_id,definition_version=NEW.definition_version,state=NEW.state,run_version=NEW.version",
				trigger: "CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.test_state",
			},
			{
				name:    "ordered_state",
				source:  ordered,
				update:  "UPDATE zasp_authorization80_worker.ordered_state SET definition_id=NEW.definition_id,definition_version=NEW.definition_version,state=NEW.state,run_version=NEW.version",
				trigger: "CREATE TRIGGER worker_revision AFTER INSERT OR UPDATE OR DELETE ON zasp_authorization80_worker.ordered_state",
			},
		}
		for _, capture := range captures {
			if strings.Count(capture.source, capture.update) != 1 || strings.Count(capture.source, capture.trigger) != 1 {
				t.Fatalf("%s cancellation capture is not exact", capture.name)
			}
		}
	})

	t.Run("private delta helper", func(t *testing.T) {
		for _, required := range []string{
			"WHERE n.nspname='zasp_temporal_single_recovery'",
			"REVOKE ALL ON FUNCTION %s FROM PUBLIC",
		} {
			if !strings.Contains(up, required) {
				t.Fatalf("final helper privilege sweep omitted %q", required)
			}
		}
		if strings.Contains(up, "GRANT EXECUTE ON FUNCTION zasp_temporal_single_recovery.human") {
			t.Fatal("internal recovery fence was granted to an API role")
		}
	})

	t.Run("exact local delta", func(t *testing.T) {
		human := revisionTestBody(t, admission, "zasp_temporal_single_recovery.human(q jsonb,mutate boolean,current_version boolean,revision_delta bigint) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public")
		for _, required := range []string{
			"revision_delta NOT BETWEEN 0 AND 4",
			"(p#>>'{revision,desired}')::bigint+revision_delta",
			"(p#>>'{revision,applied}')::bigint",
			"(p#>>'{revision,generation}')::bigint",
			"p#>>'{revision,store_id}'",
			"p#>>'{revision,model_id}'",
			"PERFORM zasp_authorization80.identity_fence(p)",
			"p IS DISTINCT FROM zasp_authorization80.context()",
		} {
			if !strings.Contains(human, required) {
				t.Fatalf("revision fence omitted %q", required)
			}
		}
		legacy := revisionTestBody(t, admission, "zasp_temporal_single_recovery.human(q jsonb,mutate boolean,current_version boolean) RETURNS void LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public")
		if strings.TrimSpace(legacy) != "SELECT zasp_temporal_single_recovery.human(q,mutate,current_version,0)" {
			t.Fatal("three-argument recovery fence no longer fixes a zero delta")
		}

		admit := revisionTestBody(t, admission, "zasp_temporal_single_recovery.admit(a jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public")
		for _, table := range []string{"run_state", "test_state", "ordered_state"} {
			lockAndCount := "FOR capture_row IN SELECT definition_id,definition_version,state,run_version FROM zasp_authorization80_worker." + table + " WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE LOOP"
			if strings.Count(admit, lockAndCount) != 1 {
				t.Fatalf("%s is not locked and counted exactly once", table)
			}
		}
		if strings.Count(admit, "IS DISTINCT FROM(rr.definition_id,rr.definition_version,rr.state,rr.version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='recovery captured state changed';END IF;revision_delta:=revision_delta+1;") != 3 {
			t.Fatal("captured rows are not matched to the pre-cancellation run")
		}
		base := "revision_delta:=1;"
		finalFence := "PERFORM zasp_temporal_single_recovery.human(q,true,false,revision_delta);RETURN result_value;"
		if strings.Count(admit, base) != 1 || strings.Count(admit, finalFence) != 1 {
			t.Fatal("post-cancellation fence does not use the exact local delta")
		}
		if strings.Index(admit, base) > strings.Index(admit, "zasp_temporal74.cancel_core(") || strings.Index(admit, finalFence) < strings.Index(admit, "zasp_temporal74.cancel_core(") {
			t.Fatal("local delta is not measured before mutation and checked after it")
		}
	})
}
