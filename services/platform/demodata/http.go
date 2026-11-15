package demodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/microsoftdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/salesforcediscovery"
)

// The collectors require a credential of a plausible length and send it to
// the provider they are given, which here is the in-process replay. This
// value opens nothing and is not shaped like any provider's token.
const placeholderCredential = "demo-collection-no-credential"

const providerTimeout = 20 * time.Second

func init() {
	collectors["kubernetes"] = collectKubernetes
	collectors["github"] = collectGitHub
	collectors["okta"] = collectOkta
	collectors["microsoft"] = collectMicrosoft
	collectors["salesforce"] = collectSalesforce
	collectors["gcp"] = collectGCP
	collectors["saas"] = collectSaaS
}

func failed(integration Integration, err error) (Snapshot, error) {
	return Snapshot{}, fmt.Errorf("%w: %s: %v", ErrCollection, integration.Key, err)
}

func collectKubernetes(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	transport := newReplay(integration.HTTP, target)
	api, err := kubernetesdiscovery.NewKubernetesCollectionAPIWithTransport(integration.HTTP.Endpoint, transport, providerTimeout)
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := kubernetesdiscovery.NewCollectionClient(api, artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	built, err := request(integration, target, collection.ProviderKubernetes, collection.CredentialKubernetesCluster, "ref:kubernetes/demo/"+integration.Key, "kubernetes_cluster")
	if err != nil {
		return Snapshot{}, err
	}
	outcome, err := client.CollectWithCredential(ctx, built, []byte(placeholderCredential))
	return finish(integration, outcome, err, transport)
}

func collectGitHub(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	transport := newReplay(integration.HTTP, target)
	api, err := githubdiscovery.NewInstallationCollectionAPIWithTransport(transport, providerTimeout)
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := githubdiscovery.NewCollectionClient(api, artifacts, githubdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	built, err := request(integration, target, collection.ProviderGitHub, collection.CredentialGitHubInstallation, "ref:github/demo/"+integration.Key, "github_installation")
	if err != nil {
		return Snapshot{}, err
	}
	outcome, err := client.CollectWithCredential(ctx, built, []byte(placeholderCredential))
	return finish(integration, outcome, err, transport)
}

func collectOkta(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	transport := newReplay(integration.HTTP, target)
	api, err := idpdiscovery.NewOktaCollectionAPIWithTransport(integration.HTTP.Endpoint, transport, providerTimeout)
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := idpdiscovery.NewOktaCollectionClient(api, artifacts, idpdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	built, err := request(integration, target, collection.ProviderOkta, collection.CredentialOktaRefresh, "ref:okta/demo/"+integration.Key, "okta_tenant")
	if err != nil {
		return Snapshot{}, err
	}
	outcome, err := client.CollectWithCredential(ctx, built, []byte(placeholderCredential))
	return finish(integration, outcome, err, transport)
}

func collectMicrosoft(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	transport := newReplay(integration.HTTP, target)
	api, err := microsoftdiscovery.NewMicrosoftCollectionAPI(microsoftdiscovery.CollectionAPIConfig{Transport: transport, Timeout: providerTimeout, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := microsoftdiscovery.NewMicrosoftCollectionClient(api, artifacts, microsoftdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	built, err := request(integration, target, collection.ProviderMicrosoft, collection.CredentialMicrosoftClient, "ref:microsoft/demo/"+integration.Key, "microsoft_tenant")
	if err != nil {
		return Snapshot{}, err
	}
	// The credential envelope the worker's token client hands the collector:
	// one placeholder per audience, and the Dataverse environment.
	credential := `{"dataverse_token":"` + placeholderCredential + `","dataverse_url":"` + integration.HTTP.Endpoint + `","graph_token":"` + placeholderCredential + `"}`
	if integration.HTTP.Azure {
		credential = `{"ai_token":"` + placeholderCredential + `","arm_token":"` + placeholderCredential + `",` + credential[1:]
	}
	outcome, err := client.CollectWithCredential(ctx, built, []byte(credential))
	return finish(integration, outcome, err, transport)
}

func collectSalesforce(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	transport := newReplay(integration.HTTP, target)
	api, err := salesforcediscovery.NewSalesforceCollectionAPI(salesforcediscovery.CollectionAPIConfig{Transport: transport, Timeout: providerTimeout, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := salesforcediscovery.NewSalesforceCollectionClient(api, artifacts, salesforcediscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	built, err := request(integration, target, collection.ProviderSalesforce, collection.CredentialSalesforceClient, "ref:salesforce/demo/"+integration.Key, "salesforce_org")
	if err != nil {
		return Snapshot{}, err
	}
	credential := `{"access_token":"` + placeholderCredential + `","instance_url":"` + integration.HTTP.Endpoint + `"}`
	outcome, err := client.CollectWithCredential(ctx, built, []byte(credential))
	return finish(integration, outcome, err, transport)
}

func collectGCP(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	transport := newReplay(integration.HTTP, target)
	api, err := gcpdiscovery.NewGCPCollectionAPI(gcpdiscovery.CollectionAPIConfig{Transport: transport, Timeout: providerTimeout,
		// The collector stamps its findings with this clock, and the pipeline
		// requires a finding to carry the collection time.
		Clock: func() time.Time { return target.ObservedAt }})
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := gcpdiscovery.NewGCPCollectionClient(api, artifacts, gcpdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	built, err := request(integration, target, collection.ProviderGCP, collection.CredentialGCPAccessToken, "ref:gcp/demo/"+integration.Key, "gcp_scope")
	if err != nil {
		return Snapshot{}, err
	}
	credential, valid := gcpdiscovery.EncodeCredential([]byte(placeholderCredential))
	if !valid {
		return failed(integration, ErrCollection)
	}
	outcome, err := client.CollectWithCredential(ctx, built, credential)
	return finish(integration, outcome, err, transport)
}

// replayProxy stands where the Nango proxy stands for a SaaS platform: it
// answers the collector's provider requests from the route table.
type replayProxy struct{ transport *replay }

func (proxy replayProxy) Do(_ context.Context, request nango.Request) (nango.ProxyResponse, error) {
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}
	status, headers, body := proxy.transport.answer(method, request.Host, request.Path, request.Query, request.Body)
	if status < 200 || status > 299 {
		return nango.ProxyResponse{}, &nango.StatusError{StatusCode: status}
	}
	return nango.ProxyResponse{StatusCode: status, Body: body, Link: headers.Get("Link")}, nil
}

func collectSaaS(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	registry, err := saasdiscovery.NewRegistry(platforms.All()...)
	if err != nil {
		return failed(integration, err)
	}
	transport := newReplay(integration.HTTP, target)
	api, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: replayProxy{transport: transport}, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return failed(integration, err)
	}
	client, err := saasdiscovery.NewCollectionClient(api, artifacts, saasdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return failed(integration, err)
	}
	// A Nango connection reference is a UUID. This one is derived from the
	// integration's key and names no connection.
	digest := sha256.Sum256([]byte("zasp-demo-connection\x1f" + integration.Key))
	text := hex.EncodeToString(digest[:])
	reference := fmt.Sprintf("ref:nango/connection/%s-%s-4%s-8%s-%s", text[:8], text[8:12], text[13:16], text[17:20], text[20:32])
	built, err := request(integration, target, collection.ProviderSaaS, collection.CredentialNangoConnection, reference, "saas_tenant")
	if err != nil {
		return Snapshot{}, err
	}
	outcome, err := client.CollectWithCredential(ctx, built, []byte(reference))
	return finish(integration, outcome, err, transport)
}
