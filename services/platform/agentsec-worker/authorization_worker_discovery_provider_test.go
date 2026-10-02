package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

func TestP7Discovery72OwnedProviderProductContract(t *testing.T) {
	scope := workerScope(t)
	legacy := workerExecutionInput(scope, "pid_72008005-0000-4000-8000-000000000005")
	observed := time.Now().UTC().Truncate(time.Second)
	input := apiserver.DiscoveryCollectionInput{OrganizationID: legacy.OrganizationID, WorkspaceID: legacy.WorkspaceID, EnvironmentID: legacy.EnvironmentID, JobID: legacy.JobID, SyncID: legacy.SyncID, IntegrationID: legacy.IntegrationID, ConnectionID: legacy.ConnectionID, SnapshotID: legacy.SnapshotID, Generation: 1, ObservationTime: observed, Provider: legacy.Provider, CollectorVersion: legacy.CollectorVersion, CredentialClass: legacy.CredentialClass, CredentialReference: legacy.CredentialReference, SubjectKind: legacy.SubjectKind, SubjectID: legacy.SubjectID, ParserVersion: legacy.ParserVersion, ToolVersion: legacy.ToolVersion, Configuration: legacy.Configuration, EffectID: strings.Repeat("ab", 32), Deadline: observed.Add(24 * time.Hour)}
	request, err := input.CollectionRequest(scope)
	if err != nil {
		t.Fatal("real native product input contract", err)
	}
	var sends atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { sends.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer endpoint.Close()
	provider := &discoveryNativeProvider{t: t, client: endpoint.Client(), url: endpoint.URL}
	outcome, err := provider.CollectWithCredential(context.Background(), request, []byte("owned-provider-contract"))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok || !complete.Snapshot().TypedObservations() || sends.Load() != 1 {
		t.Fatalf("owned provider rejected product observation contract: complete=%t typed=%t sends=%d error=%v", ok, complete.Snapshot().TypedObservations(), sends.Load(), err)
	}
	provider.partial = true
	outcome, err = provider.CollectWithCredential(context.Background(), request, []byte("owned-provider-contract"))
	if _, ok := outcome.(collection.PartialResult); err != nil || !ok || sends.Load() != 2 {
		t.Fatal("owned partial provider contract", err)
	}
}
