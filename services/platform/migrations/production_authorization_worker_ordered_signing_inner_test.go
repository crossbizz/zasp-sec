package migrations

import (
	"strings"
	"testing"
)

func TestOrdered68SigningInnerAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, marker := range []string{
		"DO $ordered_signing_inner$",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_signing_boundary(",
		"'ordered68_signing_facts_inner'",
		"'ordered68_signing_effect_metadata_inner'",
		"'ordered68_signing_effect_source_inner'",
		"'ordered68_signing_metadata_inner'",
		"'ordered68_signing_source_inner'",
		"'ordered68_signing_proof_inner'",
		"'ordered68_signing_read_inner'",
	} {
		if !strings.Contains(source, marker) {
			t.Errorf("missing signing call-local boundary %s", marker)
		}
	}
	if strings.Index(source, "DO $ordered_signing_inner$") <= strings.Index(source, "END $store$;") {
		t.Error("signing copies must follow complete original signing protocol")
	}
	for _, required := range []string{
		"PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));",
		"NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()",
		"EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature_value);",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing full outer readiness/private ownership contract %s", required)
		}
	}
}
