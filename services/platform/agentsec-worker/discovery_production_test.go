package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductionDiscoveryCollectorBindsJobBeforeCredentialOrProviderUse(t *testing.T) {
	scope := workerScope(t)
	input := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	expected, ok := collectionRequest(scope, input)
	if !ok {
		t.Fatal("valid job input did not produce a collection request")
	}
	provider := &recordingJobProviderClient{outcome: workerCompleteOutcome(t, input)}
	providers := testFirstPartyCollectionFactory(t, provider)
	credentials := &recordingJobCredentialMaterialResolver{credential: []byte("job-scoped-credential-material")}
	factory, err := newProductionDiscoveryCollectorFactory(providers, credentials)
	if err != nil {
		t.Fatalf("newProductionDiscoveryCollectorFactory() error = %v", err)
	}
	binding := discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-01", LeaseToken: "lease-token-must-not-escape"}

	otherScope, scopeErr := domain.NewScope(workerID(t, "pid_10000020-0000-4000-8000-000000000020"), scope.WorkspaceID(), scope.EnvironmentID())
	if scopeErr != nil {
		t.Fatal(scopeErr)
	}
	for name, mutate := range map[string]func(*collection.Request){
		"scope":             func(request *collection.Request) { request.Scope = otherScope },
		"integration":       func(request *collection.Request) { request.IntegrationID = request.JobID },
		"connection":        func(request *collection.Request) { request.ConnectionID = request.JobID },
		"job":               func(request *collection.Request) { request.JobID = request.IntegrationID },
		"attempt":           func(request *collection.Request) { request.Attempt++ },
		"provider":          func(request *collection.Request) { request.Provider = collection.ProviderGitHub },
		"credential class":  func(request *collection.Request) { request.CredentialClass = collection.CredentialGitHubInstallation },
		"credential ref":    func(request *collection.Request) { request.CredentialReference = "ref:aws/connection/customer-9999" },
		"expected subject":  func(request *collection.Request) { request.ExpectedSubject.ID = "999999999999" },
		"parser version":    func(request *collection.Request) { request.ParserVersion = "parser_v2" },
		"tool version":      func(request *collection.Request) { request.ToolVersion = "tool_v2" },
		"collector version": func(request *collection.Request) { request.CollectorVersion = "collector_v2" },
		"cursor":            func(request *collection.Request) { request.Cursor.Value = "different" },
	} {
		t.Run("rejects "+name+" drift", func(t *testing.T) {
			wrongCollector, buildErr := factory.BuildDiscoveryCollector(context.Background(), binding)
			if buildErr != nil {
				t.Fatalf("BuildDiscoveryCollector(wrong) error = %v", buildErr)
			}
			wrong := expected
			mutate(&wrong)
			_, collectErr := wrongCollector.Collect(context.Background(), wrong)
			if !errors.Is(collectErr, collection.ErrContract) || credentials.callCount() != 0 || provider.callCount() != 0 || strings.Contains(collectErr.Error(), binding.LeaseToken) {
				t.Fatalf("wrong request error=%q credential calls=%d provider calls=%d", collectErr, credentials.callCount(), provider.callCount())
			}
		})
	}

	collector, err := factory.BuildDiscoveryCollector(context.Background(), binding)
	if err != nil {
		t.Fatalf("BuildDiscoveryCollector(exact) error = %v", err)
	}
	outcome, err := collector.Collect(context.Background(), expected)
	if err != nil || outcome == nil {
		t.Fatalf("Collect(exact) outcome/error = %#v / %v", outcome, err)
	}
	if credentials.callCount() != 1 || provider.callCount() != 1 || !provider.sawRequest(expected) || provider.credentialText() != "job-scoped-credential-material" {
		t.Fatalf("exact calls credential=%d provider=%d request=%#v credential=%q", credentials.callCount(), provider.callCount(), provider.request(), provider.credentialText())
	}
	resolution := credentials.request()
	if resolution.Scope != scope || !reflect.DeepEqual(resolution.Input, input) || resolution.WorkerID != binding.WorkerID || !credentials.sawLeaseToken() || resolution.Credential != credentialRequestForCollection(expected) {
		t.Fatalf("credential resolution binding drifted: %#v", resolution)
	}
	if strings.Contains(fmt.Sprintf("%#v", provider.request()), binding.LeaseToken) || strings.Contains(fmt.Sprintf("%#v", outcome), binding.LeaseToken) {
		t.Fatal("lease token entered provider request or collection outcome")
	}
	if _, err := collector.Collect(context.Background(), expected); !errors.Is(err, collection.ErrContract) || credentials.callCount() != 1 || provider.callCount() != 1 {
		t.Fatalf("second Collect error=%v credential calls=%d provider calls=%d", err, credentials.callCount(), provider.callCount())
	}
	if material := credentials.material(); material == nil || !errors.Is(material.Use(credentialRequestForCollection(expected), func([]byte) error { return nil }), collection.ErrCredential) {
		t.Fatal("credential material remained usable after collection")
	}
}

func TestProductionDiscoveryCollectorPreservesRetainedPartialCursor(t *testing.T) {
	scope := workerScope(t)
	input := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	retained := "retained-partial-page-17"
	input.CursorValue = &retained
	input.CheckpointVersion = 1
	input.CheckpointDigest = bytes.Repeat([]byte{7}, 32)
	input.CheckpointManifestReference = "s3://zasp-evidence/organizations/checkpoint/pid_80100002-0000-4000-8000-000000000002"
	input.CheckpointManifestKey = "organizations/checkpoint/pid_80100002-0000-4000-8000-000000000002"
	input.CheckpointManifestVersionID = "version-0001"
	input.CheckpointManifestChecksum = bytes.Repeat([]byte{8}, 32)
	input.CheckpointManifestSizeBytes = 128
	input.CheckpointManifestMediaType = "application/json"
	input.CheckpointManifestSchemaVersion = "manifest_v1"
	expected, ok := collectionRequest(scope, input)
	if !ok {
		t.Fatal("retained input did not produce a collection request")
	}
	partial, err := collection.NewPartialResult(expected, expected.ExpectedSubject, collection.Cursor{Provider: expected.Provider, Version: "cursor_v1", Value: "next-page-18"}, workerManifest(t, expected), collection.FailurePartial)
	if err != nil {
		t.Fatalf("NewPartialResult() error = %v", err)
	}
	provider := &recordingJobProviderClient{outcome: partial}
	credentials := &recordingJobCredentialMaterialResolver{credential: []byte("job-scoped-credential-material")}
	factory, err := newProductionDiscoveryCollectorFactory(testFirstPartyCollectionFactory(t, provider), credentials)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-01", LeaseToken: "lease-token-must-not-escape"})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := collector.Collect(context.Background(), expected)
	result, isPartial := outcome.(collection.PartialResult)
	if err != nil || !isPartial || result.NextCursor().Value != "next-page-18" || provider.request().Cursor != (collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: retained}) {
		t.Fatalf("retained collection outcome/error/request = %#v / %v / %#v", outcome, err, provider.request())
	}
	seed := provider.resumeSeed()
	if seed.Cursor != expected.Cursor || seed.ManifestReference != input.CheckpointManifestReference || seed.ManifestVersionID != input.CheckpointManifestVersionID || !bytes.Equal(seed.CheckpointDigest, input.CheckpointDigest) || !bytes.Equal(seed.ManifestChecksum, input.CheckpointManifestChecksum) {
		t.Fatalf("resume seed drifted: %#v", seed)
	}
}

func TestProductionDiscoveryCollectorDestroysBindingsOnDependencyFailurePanicAndCancel(t *testing.T) {
	scope := workerScope(t)
	input := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	expected, ok := collectionRequest(scope, input)
	if !ok {
		t.Fatal("valid input did not produce a collection request")
	}
	for name, setup := range map[string]func(*recordingJobProviderClient, *recordingJobCredentialMaterialResolver) context.Context{
		"provider error": func(provider *recordingJobProviderClient, _ *recordingJobCredentialMaterialResolver) context.Context {
			provider.err = errors.New("provider-secret-must-not-escape")
			return context.Background()
		},
		"provider panic": func(provider *recordingJobProviderClient, _ *recordingJobCredentialMaterialResolver) context.Context {
			provider.panicCall = true
			return context.Background()
		},
		"resolver error": func(_ *recordingJobProviderClient, resolver *recordingJobCredentialMaterialResolver) context.Context {
			resolver.err = errors.New("resolver-secret-must-not-escape")
			return context.Background()
		},
		"resolver panic": func(_ *recordingJobProviderClient, resolver *recordingJobCredentialMaterialResolver) context.Context {
			resolver.panicCall = true
			return context.Background()
		},
		"cancel": func(_ *recordingJobProviderClient, _ *recordingJobCredentialMaterialResolver) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := &recordingJobProviderClient{outcome: workerCompleteOutcome(t, input)}
			credentials := &recordingJobCredentialMaterialResolver{credential: []byte("job-scoped-credential-material")}
			ctx := setup(provider, credentials)
			factory, err := newProductionDiscoveryCollectorFactory(testFirstPartyCollectionFactory(t, provider), credentials)
			if err != nil {
				t.Fatal(err)
			}
			collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-01", LeaseToken: "lease-token-must-not-escape"})
			if err != nil {
				t.Fatal(err)
			}
			_, collectErr := collector.Collect(ctx, expected)
			if collectErr == nil || strings.Contains(collectErr.Error(), "secret") || strings.Contains(collectErr.Error(), "lease-token") {
				t.Fatalf("Collect error = %q", collectErr)
			}
			credentialCalls, providerCalls := credentials.callCount(), provider.callCount()
			if _, repeatErr := collector.Collect(context.Background(), expected); !errors.Is(repeatErr, collection.ErrContract) || credentials.callCount() != credentialCalls || provider.callCount() != providerCalls {
				t.Fatalf("repeat error/calls = %v / %d / %d", repeatErr, credentials.callCount(), provider.callCount())
			}
			if material := credentials.material(); material != nil && !errors.Is(material.Use(credentialRequestForCollection(expected), func([]byte) error { return nil }), collection.ErrCredential) {
				t.Fatal("credential material remained usable after failed collection")
			}
		})
	}
}

func TestProductionDiscoveryCollectorIsolatesConcurrentJobs(t *testing.T) {
	scope := workerScope(t)
	first := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	second := workerExecutionInput(scope, "pid_10000013-0000-4000-8000-000000000013")
	second.SyncID = "pid_10000014-0000-4000-8000-000000000014"
	second.SnapshotID = "pid_10000018-0000-4000-8000-000000000018"
	firstRequest, firstOK := collectionRequest(scope, first)
	secondRequest, secondOK := collectionRequest(scope, second)
	if !firstOK || !secondOK {
		t.Fatal("valid concurrent inputs did not produce collection requests")
	}
	provider := &recordingJobProviderClient{outcomes: map[string]collection.Outcome{
		first.JobID: workerCompleteOutcome(t, first), second.JobID: workerCompleteOutcome(t, second),
	}}
	credentials := &recordingJobCredentialMaterialResolver{credential: []byte("job-scoped-credential-material")}
	factory, err := newProductionDiscoveryCollectorFactory(testFirstPartyCollectionFactory(t, provider), credentials)
	if err != nil {
		t.Fatal(err)
	}
	firstCollector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: first, WorkerID: "discovery-01", LeaseToken: "lease-token-for-job-0001"})
	if err != nil {
		t.Fatal(err)
	}
	secondCollector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: second, WorkerID: "discovery-01", LeaseToken: "lease-token-for-job-0002"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	for _, call := range []struct {
		collector discoveryJobCollector
		request   collection.Request
	}{{firstCollector, firstRequest}, {secondCollector, secondRequest}} {
		call := call
		go func() {
			<-start
			_, callErr := call.collector.Collect(context.Background(), call.request)
			errorsSeen <- callErr
		}()
	}
	close(start)
	for range 2 {
		if callErr := <-errorsSeen; callErr != nil {
			t.Fatalf("concurrent Collect error = %v", callErr)
		}
	}
	requests := provider.requestsCopy()
	if len(requests) != 2 || credentials.callCount() != 2 || credentials.leaseToken(first.JobID) != "lease-token-for-job-0001" || credentials.leaseToken(second.JobID) != "lease-token-for-job-0002" {
		t.Fatalf("concurrent bindings requests=%#v credential calls=%d tokens=%q/%q", requests, credentials.callCount(), credentials.leaseToken(first.JobID), credentials.leaseToken(second.JobID))
	}
	seen := map[string]bool{}
	for _, request := range requests {
		seen[request.JobID.String()] = true
	}
	if !seen[first.JobID] || !seen[second.JobID] {
		t.Fatalf("provider requests crossed job boundary: %#v", requests)
	}
}

func TestFirstPartyCollectionFactoryRejectsRegistrationDriftAtConstruction(t *testing.T) {
	valid := testFirstPartyRegistrations(&recordingJobProviderClient{})
	for name, mutate := range map[string]func([]firstPartyProviderClientRegistration){
		"duplicate provider": func(registrations []firstPartyProviderClientRegistration) {
			registrations[3].Provider = collection.ProviderAWS
			registrations[3].CredentialClass = collection.CredentialAWSAssumeRole
		},
		"wrong credential class": func(registrations []firstPartyProviderClientRegistration) {
			registrations[0].CredentialClass = collection.CredentialGitHubInstallation
		},
		"malformed collector version": func(registrations []firstPartyProviderClientRegistration) {
			registrations[0].CollectorVersion = "bad version"
		},
		"short readiness timeout": func(registrations []firstPartyProviderClientRegistration) {
			registrations[0].ReadinessTimeout = 99 * time.Millisecond
		},
		"long readiness timeout": func(registrations []firstPartyProviderClientRegistration) {
			registrations[0].ReadinessTimeout = 10*time.Second + time.Nanosecond
		},
	} {
		t.Run(name, func(t *testing.T) {
			registrations := append([]firstPartyProviderClientRegistration(nil), valid...)
			mutate(registrations)
			if factory, err := newFirstPartyCollectionFactory(registrations); !errors.Is(err, errWorkerExecution) || factory != nil {
				t.Fatalf("newFirstPartyCollectionFactory() = %#v, %v", factory, err)
			}
		})
	}
}

type recordingJobProviderClient struct {
	mu         sync.Mutex
	calls      int
	requests   []collection.Request
	credential []byte
	outcome    collection.Outcome
	outcomes   map[string]collection.Outcome
	err        error
	panicCall  bool
	resume     []collection.ResumeSeed
}

func (client *recordingJobProviderClient) WithResumeSeed(seed collection.ResumeSeed) (collection.ProviderClient, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	seed.CheckpointDigest = bytes.Clone(seed.CheckpointDigest)
	seed.ManifestChecksum = bytes.Clone(seed.ManifestChecksum)
	client.resume = append(client.resume, seed)
	return client, nil
}

func (client *recordingJobProviderClient) CollectWithCredential(_ context.Context, request collection.Request, credential []byte) (collection.Outcome, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.calls++
	client.requests = append(client.requests, request)
	client.credential = bytes.Clone(credential)
	if client.panicCall {
		panic("provider-secret-must-not-escape")
	}
	outcome := client.outcome
	if client.outcomes != nil {
		outcome = client.outcomes[request.JobID.String()]
	}
	return outcome, client.err
}

func (client *recordingJobProviderClient) callCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.calls
}

func (client *recordingJobProviderClient) request() collection.Request {
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.requests) == 0 {
		return collection.Request{}
	}
	return client.requests[len(client.requests)-1]
}

func (client *recordingJobProviderClient) sawRequest(want collection.Request) bool {
	return client.request() == want
}

func (client *recordingJobProviderClient) requestsCopy() []collection.Request {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]collection.Request(nil), client.requests...)
}

func (client *recordingJobProviderClient) credentialText() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return string(client.credential)
}

func (client *recordingJobProviderClient) resumeSeed() collection.ResumeSeed {
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.resume) == 0 {
		return collection.ResumeSeed{}
	}
	return client.resume[len(client.resume)-1]
}

type recordingJobCredentialMaterialResolver struct {
	mu         sync.Mutex
	calls      int
	credential []byte
	requests   []discoveryCredentialMaterialRequest
	materials  []*collection.CredentialMaterial
	err        error
	panicCall  bool
	sawLease   bool
	leaseByJob map[string]string
}

func (resolver *recordingJobCredentialMaterialResolver) ResolveDiscoveryCredential(_ context.Context, request discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls++
	resolver.sawLease = string(request.LeaseToken) == "lease-token-must-not-escape"
	if resolver.leaseByJob == nil {
		resolver.leaseByJob = map[string]string{}
	}
	resolver.leaseByJob[request.Input.JobID] = string(request.LeaseToken)
	stored := request
	stored.Input = cloneExecutionJobInput(request.Input)
	stored.LeaseToken = nil
	resolver.requests = append(resolver.requests, stored)
	if resolver.panicCall {
		panic("resolver-secret-must-not-escape")
	}
	if resolver.err != nil {
		return nil, resolver.err
	}
	material, err := collection.NewCredentialMaterial(request.Credential, resolver.credential, time.Now().Add(time.Minute))
	resolver.materials = append(resolver.materials, material)
	return material, err
}

func (resolver *recordingJobCredentialMaterialResolver) callCount() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls
}

func (resolver *recordingJobCredentialMaterialResolver) request() discoveryCredentialMaterialRequest {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.requests[len(resolver.requests)-1]
}

func (resolver *recordingJobCredentialMaterialResolver) sawLeaseToken() bool {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.sawLease
}

func (resolver *recordingJobCredentialMaterialResolver) leaseToken(jobID string) string {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.leaseByJob[jobID]
}

func (resolver *recordingJobCredentialMaterialResolver) material() *collection.CredentialMaterial {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if len(resolver.materials) == 0 {
		return nil
	}
	return resolver.materials[len(resolver.materials)-1]
}

type staticCollectionReadiness struct {
	provider collection.Provider
	version  string
}

func (probe staticCollectionReadiness) Check(context.Context) collection.Readiness {
	return collection.Readiness{Provider: probe.provider, CollectorVersion: probe.version, Ready: true, Code: collection.ReadinessReady, CheckedAt: time.Now().UTC()}
}

func testFirstPartyCollectionFactory(t *testing.T, aws collection.ProviderClient) collection.CollectorFactory {
	t.Helper()
	registrations := testFirstPartyRegistrations(aws)
	factory, err := newFirstPartyCollectionFactory(registrations)
	if err != nil {
		t.Fatalf("newFirstPartyCollectionFactory() error = %v", err)
	}
	return factory
}

func testFirstPartyRegistrations(aws collection.ProviderClient) []firstPartyProviderClientRegistration {
	registrations := []firstPartyProviderClientRegistration{
		{Provider: collection.ProviderAWS, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialAWSAssumeRole, Client: aws},
		{Provider: collection.ProviderKubernetes, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialKubernetesCluster, Client: &recordingJobProviderClient{}},
		{Provider: collection.ProviderGitHub, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialGitHubInstallation, Client: &recordingJobProviderClient{}},
		{Provider: collection.ProviderOkta, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialOktaRefresh, Client: &recordingJobProviderClient{}},
	}
	for index := range registrations {
		registrations[index].Readiness = staticCollectionReadiness{provider: registrations[index].Provider, version: registrations[index].CollectorVersion}
		registrations[index].ReadinessTimeout = time.Second
	}
	return registrations
}

func credentialRequestForCollection(request collection.Request) collection.CredentialRequest {
	return collection.CredentialRequest{Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt, Provider: request.Provider, Class: request.CredentialClass, Reference: request.CredentialReference, ExpectedSubject: request.ExpectedSubject}
}
