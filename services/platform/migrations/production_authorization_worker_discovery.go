package migrations

import _ "embed"

// These are an additive part of the named worker profile, not a new numbered
// migration. The profile assembler pins all bytes and live replacement identity.
//
//go:embed sql/0080_authorization_worker_discovery_sources.sql
var authorizationWorkerDiscoverySourcesSQL string

//go:embed sql/0080_authorization_worker_discovery_fences.sql
var authorizationWorkerDiscoveryFencesSQL string

//go:embed sql/0080_authorization_worker_discovery_catalog.sql
var authorizationWorkerDiscoveryCatalogSQL string
