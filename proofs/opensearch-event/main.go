package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	platformeventstore "github.com/zasp-ai/zasp-sec/services/platform/eventstore"
)

const proofSuccess = "OpenSearch event projection proof passed: indexed=true scoped_query=true cross_organization_zero=true cleanup=true audit=true."
const eventStoreProofSuccess = "OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true."

func main() {
	code, line := executeMain(os.Args, os.LookupEnv)
	if code == 0 {
		fmt.Fprintln(os.Stdout, line)
	} else {
		fmt.Fprintln(os.Stderr, line)
	}
	os.Exit(code)
}

func executeMain(arguments []string, lookupEnv func(string) (string, bool)) (int, string) {
	if len(arguments) == 2 && arguments[1] == "event-store" {
		return executeEventStoreMain(lookupEnv)
	}
	if len(arguments) != 1 || lookupEnv == nil {
		return failureLine("configuration")
	}
	endpoint, exists := lookupEnv("OPENSEARCH_ENDPOINT")
	if !exists {
		return failureLine("configuration")
	}
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		return failureLine("configuration")
	}
	marker := hex.EncodeToString(markerBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	spec := expectedIndexSpec(marker)
	backend, err := newHTTPBackend(ctx, endpoint, spec)
	if err != nil {
		return failureLine("configuration")
	}
	defer backend.Close()
	result, err := RunProof(ctx, ProofOptions{
		Endpoint: endpoint, Marker: marker, Events: backend, Admin: backend,
		CleanupTimeout: 20 * time.Second, PollInterval: 100 * time.Millisecond,
	})
	if err != nil {
		return failureLine(fixedCategory(err))
	}
	if result != (ProofResult{Indexed: true, ScopedQuery: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}) {
		return failureLine("operation")
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer auditCancel()
	indexes, err := backend.ListIndexes(auditCtx, proofPrefix+marker)
	if err != nil || len(indexes) != 0 {
		return failureLine("operation")
	}
	return 0, proofSuccess
}

func executeEventStoreMain(lookupEnv func(string) (string, bool)) (int, string) {
	if lookupEnv == nil {
		return eventStoreFailureLine("configuration")
	}
	endpoint, exists := lookupEnv("OPENSEARCH_ENDPOINT")
	if !exists {
		return eventStoreFailureLine("configuration")
	}
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		return eventStoreFailureLine("configuration")
	}
	marker := hex.EncodeToString(markerBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	spec := expectedIndexSpec(marker)
	backend, err := newHTTPBackend(ctx, endpoint, spec)
	if err != nil {
		return eventStoreFailureLine("configuration")
	}
	defer backend.Close()
	driver, err := newOpenSearchEventDriver(backend)
	if err != nil {
		return eventStoreFailureLine("configuration")
	}
	store, err := platformeventstore.New(driver, platformeventstore.Config{OperationTimeout: 15 * time.Second, MaximumResults: 2})
	if err != nil {
		return eventStoreFailureLine("configuration")
	}
	result, err := RunEventStoreProof(ctx, EventStoreProofOptions{
		Marker: marker, Events: store, Admin: backend,
		CleanupTimeout: 20 * time.Second, PollInterval: 100 * time.Millisecond,
	})
	if err != nil {
		return eventStoreFailureLine(fixedCategory(err))
	}
	if result != (EventStoreProofResult{Indexed: true, Searched: true, Scoped: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}) {
		return eventStoreFailureLine("operation")
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer auditCancel()
	indexes, err := backend.ListIndexes(auditCtx, proofPrefix+marker)
	if err != nil || len(indexes) != 0 {
		return eventStoreFailureLine("operation")
	}
	return 0, eventStoreProofSuccess
}

func failureLine(category string) (int, string) {
	return 1, fmt.Sprintf("OpenSearch event projection proof failed: %s rejected.", category)
}

func eventStoreFailureLine(category string) (int, string) {
	return 1, fmt.Sprintf("OpenSearch event store failed: %s rejected.", category)
}
