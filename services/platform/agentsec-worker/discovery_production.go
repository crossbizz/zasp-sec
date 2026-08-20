package main

import (
	"bytes"
	"context"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var discoveryCollectorVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)

type discoveryCredentialMaterialRequest struct {
	Scope      domain.Scope
	Input      apiserver.ExecutionJobInput
	WorkerID   string
	LeaseToken []byte
	Credential collection.CredentialRequest
}

type discoveryCredentialMaterialResolver interface {
	ResolveDiscoveryCredential(context.Context, discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error)
}

type productionDiscoveryCollectorFactory struct {
	providers   collection.CollectorFactory
	credentials discoveryCredentialMaterialResolver
}

func newProductionDiscoveryCollectorFactory(providers collection.CollectorFactory, credentials discoveryCredentialMaterialResolver) (*productionDiscoveryCollectorFactory, error) {
	if nilWorkerDependency(providers) || nilWorkerDependency(credentials) {
		return nil, errWorkerExecution
	}
	return &productionDiscoveryCollectorFactory{providers: providers, credentials: credentials}, nil
}

func (factory *productionDiscoveryCollectorFactory) BuildDiscoveryCollector(ctx context.Context, binding discoveryCollectorBinding) (discoveryJobCollector, error) {
	if factory == nil || nilWorkerDependency(factory.providers) || nilWorkerDependency(factory.credentials) || ctx == nil || ctx.Err() != nil || !validDiscoveryExecutionInput(binding.Scope, binding.Input.JobID, binding.Input) || !workerIdentityPattern.MatchString(binding.WorkerID) || len(binding.LeaseToken) < 16 || len(binding.LeaseToken) > 128 {
		return nil, errWorkerExecution
	}
	expected, ok := collectionRequest(binding.Scope, binding.Input)
	if !ok {
		return nil, errWorkerExecution
	}
	resolver := &jobBoundCredentialResolver{
		resolver: factory.credentials,
		request: discoveryCredentialMaterialRequest{
			Scope: binding.Scope, Input: cloneExecutionJobInput(binding.Input), WorkerID: binding.WorkerID, LeaseToken: []byte(binding.LeaseToken), Credential: credentialRequestForJob(expected),
		},
	}
	delegate, err := buildCollectionCollector(factory.providers, resolver)
	if err != nil || nilWorkerDependency(delegate) {
		resolver.Destroy()
		return nil, errWorkerExecution
	}
	return &jobBoundDiscoveryCollector{expected: expected, delegate: delegate, resolver: resolver}, nil
}

type jobBoundDiscoveryCollector struct {
	mu        sync.Mutex
	expected  collection.Request
	delegate  collection.Collector
	resolver  *jobBoundCredentialResolver
	used      bool
	destroyed bool
}

func (collector *jobBoundDiscoveryCollector) Collect(ctx context.Context, request collection.Request) (collection.Outcome, error) {
	if collector == nil {
		return nil, collection.ErrContract
	}
	collector.mu.Lock()
	if collector.destroyed || collector.used {
		collector.mu.Unlock()
		return nil, collection.ErrContract
	}
	collector.used = true
	if request != collector.expected {
		collector.mu.Unlock()
		collector.Destroy()
		return nil, collection.ErrContract
	}
	delegate := collector.delegate
	collector.mu.Unlock()
	defer collector.Destroy()
	return callBoundCollectionCollector(delegate, ctx, request)
}

func (collector *jobBoundDiscoveryCollector) Destroy() {
	if collector == nil {
		return
	}
	collector.mu.Lock()
	if collector.destroyed {
		collector.mu.Unlock()
		return
	}
	collector.destroyed = true
	resolver := collector.resolver
	collector.expected = collection.Request{}
	collector.delegate = nil
	collector.resolver = nil
	collector.mu.Unlock()
	resolver.Destroy()
}

type jobBoundCredentialResolver struct {
	mu        sync.Mutex
	resolver  discoveryCredentialMaterialResolver
	request   discoveryCredentialMaterialRequest
	used      bool
	destroyed bool
}

func (resolver *jobBoundCredentialResolver) ResolveCollectionCredential(ctx context.Context, request collection.CredentialRequest) (*collection.CredentialMaterial, error) {
	if resolver == nil {
		return nil, collection.ErrCredential
	}
	resolver.mu.Lock()
	if resolver.destroyed || resolver.used || request != resolver.request.Credential {
		resolver.mu.Unlock()
		return nil, collection.ErrCredential
	}
	resolver.used = true
	delegate := resolver.resolver
	bound := cloneDiscoveryCredentialMaterialRequest(resolver.request)
	resolver.mu.Unlock()
	defer destroyDiscoveryCredentialMaterialRequest(&bound)
	return callDiscoveryCredentialResolver(delegate, ctx, bound)
}

func (resolver *jobBoundCredentialResolver) Destroy() {
	if resolver == nil {
		return
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.destroyed {
		return
	}
	resolver.destroyed = true
	destroyDiscoveryCredentialMaterialRequest(&resolver.request)
	resolver.resolver = nil
}

type firstPartyProviderClientRegistration struct {
	Provider         collection.Provider
	CollectorVersion string
	CredentialClass  collection.CredentialClass
	Client           collection.ProviderClient
	Readiness        collection.ReadinessProbe
	ReadinessTimeout time.Duration
}

type firstPartyCollectionFactory struct {
	registrations []firstPartyProviderClientRegistration
}

func newFirstPartyCollectionFactory(registrations []firstPartyProviderClientRegistration) (collection.CollectorFactory, error) {
	if len(registrations) != 4 {
		return nil, errWorkerExecution
	}
	copyOfRegistrations := append([]firstPartyProviderClientRegistration(nil), registrations...)
	expectedClasses := map[collection.Provider]collection.CredentialClass{
		collection.ProviderAWS: collection.CredentialAWSAssumeRole, collection.ProviderKubernetes: collection.CredentialKubernetesCluster,
		collection.ProviderGitHub: collection.CredentialGitHubInstallation, collection.ProviderOkta: collection.CredentialOktaRefresh,
	}
	seen := make(map[collection.Provider]struct{}, len(copyOfRegistrations))
	for _, registration := range copyOfRegistrations {
		expectedClass, knownProvider := expectedClasses[registration.Provider]
		_, duplicate := seen[registration.Provider]
		if !knownProvider || duplicate || registration.CredentialClass != expectedClass || !discoveryCollectorVersionPattern.MatchString(registration.CollectorVersion) || registration.ReadinessTimeout < 100*time.Millisecond || registration.ReadinessTimeout > 10*time.Second || nilWorkerDependency(registration.Client) || nilWorkerDependency(registration.Readiness) {
			return nil, errWorkerExecution
		}
		seen[registration.Provider] = struct{}{}
	}
	return &firstPartyCollectionFactory{registrations: copyOfRegistrations}, nil
}

func (factory *firstPartyCollectionFactory) BuildCollectionCollector(resolver collection.WorkerCredentialResolver) (collection.Collector, error) {
	if factory == nil || nilWorkerDependency(resolver) || len(factory.registrations) != 4 {
		return nil, collection.ErrContract
	}
	registrations := make([]collection.Registration, 0, len(factory.registrations))
	for _, configured := range factory.registrations {
		adapter, err := collection.NewProviderAdapter(configured.Provider, configured.CredentialClass, resolver, configured.Client)
		if err != nil {
			return nil, collection.ErrContract
		}
		registrations = append(registrations, collection.Registration{
			Provider: configured.Provider, CollectorVersion: configured.CollectorVersion, CredentialClass: configured.CredentialClass,
			Collector: adapter, Readiness: configured.Readiness, ReadinessTimeout: configured.ReadinessTimeout,
		})
	}
	return collection.NewRegistry(registrations)
}

func credentialRequestForJob(request collection.Request) collection.CredentialRequest {
	return collection.CredentialRequest{
		Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt,
		Provider: request.Provider, Class: request.CredentialClass, Reference: request.CredentialReference, ExpectedSubject: request.ExpectedSubject,
	}
}

func buildCollectionCollector(factory collection.CollectorFactory, resolver collection.WorkerCredentialResolver) (collector collection.Collector, resultErr error) {
	defer func() {
		if recover() != nil {
			collector = nil
			resultErr = collection.ErrContract
		}
	}()
	return factory.BuildCollectionCollector(resolver)
}

func callBoundCollectionCollector(collector collection.Collector, ctx context.Context, request collection.Request) (outcome collection.Outcome, resultErr error) {
	defer func() {
		if recover() != nil {
			outcome = nil
			resultErr = collection.ErrContract
		}
	}()
	return collector.Collect(ctx, request)
}

func callDiscoveryCredentialResolver(resolver discoveryCredentialMaterialResolver, ctx context.Context, request discoveryCredentialMaterialRequest) (material *collection.CredentialMaterial, resultErr error) {
	defer func() {
		if recover() != nil {
			material = nil
			resultErr = collection.ErrCredential
		}
	}()
	return resolver.ResolveDiscoveryCredential(ctx, request)
}

func cloneDiscoveryCredentialMaterialRequest(request discoveryCredentialMaterialRequest) discoveryCredentialMaterialRequest {
	request.Input = cloneExecutionJobInput(request.Input)
	request.LeaseToken = bytes.Clone(request.LeaseToken)
	return request
}

func destroyDiscoveryCredentialMaterialRequest(request *discoveryCredentialMaterialRequest) {
	if request == nil {
		return
	}
	clear(request.LeaseToken)
	clear(request.Input.Configuration)
	clear(request.Input.CheckpointDigest)
	clear(request.Input.CheckpointManifestChecksum)
	*request = discoveryCredentialMaterialRequest{}
}

func cloneExecutionJobInput(input apiserver.ExecutionJobInput) apiserver.ExecutionJobInput {
	input.Configuration = bytes.Clone(input.Configuration)
	input.CheckpointDigest = bytes.Clone(input.CheckpointDigest)
	input.CheckpointManifestChecksum = bytes.Clone(input.CheckpointManifestChecksum)
	if input.CursorProvider != nil {
		value := *input.CursorProvider
		input.CursorProvider = &value
	}
	if input.CursorVersion != nil {
		value := *input.CursorVersion
		input.CursorVersion = &value
	}
	if input.CursorValue != nil {
		value := *input.CursorValue
		input.CursorValue = &value
	}
	return input
}

func nilWorkerDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
