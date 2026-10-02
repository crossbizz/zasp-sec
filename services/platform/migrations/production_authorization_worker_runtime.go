package migrations

import (
	_ "embed"
	"strings"
)

//go:embed sql/0080_authorization_worker_runtime_catalog.sql
var authorizationWorkerRuntimeCatalogSQL string

func authorizationWorkerRuntimeSource(source string) string {
	runtime, _ := authorizationRuntimeProfileSource()
	const boundary = "CREATE FUNCTION zasp_authorization80_runtime.fingerprint()"
	if strings.Count(runtime, boundary) != 1 {
		panic("runtime bootstrap boundary changed")
	}
	start := strings.Index(runtime, boundary)
	parts := strings.Split(runtime, "$runtime_fingerprint$")
	if len(parts) != 3 {
		panic("runtime independent catalog query changed")
	}
	for _, marker := range []string{"-- worker runtime bootstrap definitions", "-- worker runtime module definitions", "-- worker runtime catalog definitions", "-- worker inline runtime fingerprint"} {
		if strings.Count(source, marker) != 1 {
			panic("runtime assembly marker changed")
		}
	}
	return strings.NewReplacer(
		"-- worker runtime bootstrap definitions", runtime[:start],
		"-- worker runtime module definitions", runtime[start:],
		"-- worker runtime catalog definitions", authorizationWorkerRuntimeCatalogSQL,
		"-- worker inline runtime fingerprint", parts[1],
	).Replace(source)
}
