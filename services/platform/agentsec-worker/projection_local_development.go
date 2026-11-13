package main

import (
	"crypto/x509"
	"path/filepath"

	"github.com/zasp-ai/zasp-sec/services/platform/localcloud"
)

// localNeo4jCAVariable names a PEM file holding the certificate authority of a
// local graph database. Like ZASP_LOCAL_HEALTH_PORT it is read only when the
// local cloud emulator is enabled, which production refuses.
const localNeo4jCAVariable = "ZASP_LOCAL_NEO4J_CA_FILE"

const localNeo4jCAMaximumBytes = 64 << 10

// projectionGraphDevelopment is the graph-store configuration that exists
// only for a local stack.
type projectionGraphDevelopment struct {
	// RootCAs is the trust store for the Bolt connection, or nil for the
	// system one. TLS verification is never turned off.
	RootCAs *x509.CertPool
	// CommunityEdition lets readiness accept a Neo4j Community server, which
	// has no roles (see neo4jstore.ProductionConfig).
	CommunityEdition bool
}

// loadProjectionGraphDevelopment returns the zero value, whatever the
// environment holds, unless the local cloud emulator is enabled (a development
// or test deployment with ZASP_LOCAL_CLOUD_ENDPOINT set). With the emulator, a
// named authority file that cannot be used refuses the start instead of
// falling back to the system trust store.
func loadProjectionGraphDevelopment(settings localcloud.Settings, getenv func(string) string, readFile func(string) ([]byte, error)) (projectionGraphDevelopment, error) {
	if !settings.Enabled() {
		return projectionGraphDevelopment{}, nil
	}
	development := projectionGraphDevelopment{CommunityEdition: true}
	if getenv == nil {
		return development, nil
	}
	path := getenv(localNeo4jCAVariable)
	if path == "" {
		return development, nil
	}
	if readFile == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return projectionGraphDevelopment{}, errWorkerConfiguration
	}
	encoded, err := readFile(path)
	if err != nil || len(encoded) < 1 || len(encoded) > localNeo4jCAMaximumBytes {
		return projectionGraphDevelopment{}, errWorkerConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		return projectionGraphDevelopment{}, errWorkerConfiguration
	}
	development.RootCAs = roots
	return development, nil
}
