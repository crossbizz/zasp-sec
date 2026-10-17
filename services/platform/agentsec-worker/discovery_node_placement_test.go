package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"testing"
	"time"
)

// Late mounting coverage, separate from the actual initial collector/parser RED.
func TestNodePlacementWorkerCredentialMount(t *testing.T) {
	now := time.Now().UTC()
	envelope := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderKubernetes, SubjectKind: "kubernetes_cluster", SubjectID: "cluster.example.test/customer", ExpiresAt: now.Add(time.Minute), Endpoint: "https://cluster.example.test", Context: "customer", CABundlePEM: []byte(testDiscoveryCACertificatePEM), BearerToken: []byte("kubernetes-token-customer-0001")}
	credential, err := encodeDiscoveryCredentialEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credential)
	for _, selected := range []bool{false, true} {
		stub := &discoveryCollectionAPIStub{}
		var got kubernetesdiscovery.PinnedCollectionAPIConfig
		api := &discoveryBearerCollectionAPI{provider: collection.ProviderKubernetes, nodePlacement: selected, allowedCIDRs: []string{"203.0.113.0/24"}, timeout: time.Second, kubernetes: func(config kubernetesdiscovery.PinnedCollectionAPIConfig) (kubernetesdiscovery.CollectionAPI, error) {
			got = config
			return stub, nil
		}}
		request := githubdiscovery.CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: envelope.SubjectKind, ID: envelope.SubjectID}, Page: 1, RemainingItems: 1, RemainingBytes: 4096}
		if _, err := api.FetchCollectionPage(context.Background(), credential, request); err != nil {
			t.Fatal(err)
		}
		if got.NodePlacement != selected || api.NodePlacementEnabled() != selected || got.Endpoint != envelope.Endpoint || len(got.CABundlePEM) == 0 || len(got.AllowedCIDRs) != 1 || string(stub.credential) != string(envelope.BearerToken) {
			t.Fatal("selected recipe lost exact credential/endpoint mount")
		}
	}
}
