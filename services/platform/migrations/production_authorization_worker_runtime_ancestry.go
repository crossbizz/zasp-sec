package migrations

import (
	_ "embed"
	"strings"
)

//go:embed sql/0080_authorization_worker_runtime_admission.sql
var authorizationWorkerRuntimeAdmissionSQL string

//go:embed sql/0080_authorization_worker_runtime_sources.sql
var authorizationWorkerRuntimeSourcesSQL string

//go:embed sql/0080_authorization_worker_runtime_source_catalog.sql
var authorizationWorkerRuntimeSourceCatalogSQL string

//go:embed sql/0080_authorization_worker_test_pricing_inner.sql
var authorizationWorkerTestPricingInnerSQL string

//go:embed sql/0080_authorization_worker_test_context_inner.sql
var authorizationWorkerTestContextInnerSQL string

func authorizationWorkerRuntimeAncestrySource(source string) string {
	const marker = "-- worker runtime ancestry definitions"
	if strings.Count(source, marker) != 1 {
		panic("runtime ancestry assembly marker changed")
	}
	pricing := strings.NewReplacer("-- worker pricing checksum", ProductionSecurityAgentMultistep().Checksum(), "-- worker pricing fingerprint", SecurityAgentMultistepRegisteredFingerprint()).Replace(authorizationWorkerTestPricingInnerSQL)
	return strings.Replace(source, marker, authorizationWorkerRuntimeAdmissionSQL+"\n"+authorizationWorkerRuntimeSourcesSQL+"\n"+authorizationWorkerRuntimeSourceCatalogSQL+"\n"+pricing+"\n"+authorizationWorkerTestContextInnerSQL, 1)
}
