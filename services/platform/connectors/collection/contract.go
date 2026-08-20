// Package collection defines the worker-only boundary between first-party
// provider collectors and the durable discovery pipeline. It deliberately owns
// no queue, artifact store, database, or provider implementation.
package collection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumRegistrations = 32
	maximumRawObjects    = 10_000
	maximumRawBytes      = 512 * 1024 * 1024
	maximumSnapshotBytes = 64 * 1024 * 1024
)

var (
	ErrContract      = errors.New("collection contract rejected")
	ErrCredential    = errors.New("collection credential rejected")
	versionPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
	tokenPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	checksumPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	referencePattern = regexp.MustCompile(`^ref:(aws|kubernetes|github|okta)/[a-z0-9][a-z0-9_./:-]{7,507}$`)
)

type Provider string

const (
	ProviderAWS        Provider = "aws"
	ProviderKubernetes Provider = "kubernetes"
	ProviderGitHub     Provider = "github"
	ProviderOkta       Provider = "okta"
)

func (provider Provider) valid() bool {
	switch provider {
	case ProviderAWS, ProviderKubernetes, ProviderGitHub, ProviderOkta:
		return true
	default:
		return false
	}
}

type CredentialClass string

const (
	CredentialAWSAssumeRole      CredentialClass = "aws_assume_role"
	CredentialKubernetesCluster  CredentialClass = "kubernetes_cluster"
	CredentialGitHubInstallation CredentialClass = "github_installation"
	CredentialOktaRefresh        CredentialClass = "okta_refresh"
)

func credentialMatchesProvider(class CredentialClass, provider Provider) bool {
	switch provider {
	case ProviderAWS:
		return class == CredentialAWSAssumeRole
	case ProviderKubernetes:
		return class == CredentialKubernetesCluster
	case ProviderGitHub:
		return class == CredentialGitHubInstallation
	case ProviderOkta:
		return class == CredentialOktaRefresh
	default:
		return false
	}
}

type Cursor struct {
	Provider Provider
	Version  string
	Value    string
}

func (cursor Cursor) valid(provider Provider) bool {
	if cursor == (Cursor{}) {
		return true
	}
	return cursor.Provider == provider && versionPattern.MatchString(cursor.Version) && boundedText(cursor.Value, 2048)
}

func (cursor Cursor) validResult(provider Provider) bool {
	return cursor != (Cursor{}) && cursor.valid(provider)
}

type Bounds struct {
	MaxPages    int
	MaxItems    int
	MaxRawBytes int64
	Timeout     time.Duration
}

func (bounds Bounds) valid() bool {
	return bounds.MaxPages >= 1 && bounds.MaxPages <= 10_000 && bounds.MaxItems >= 1 && bounds.MaxItems <= 100_000 &&
		bounds.MaxRawBytes >= 1 && bounds.MaxRawBytes <= maximumRawBytes && bounds.Timeout >= 100*time.Millisecond && bounds.Timeout <= 15*time.Minute
}

type Request struct {
	Scope               domain.Scope
	IntegrationID       domain.ProductID
	ConnectionID        domain.ProductID
	JobID               domain.ProductID
	Attempt             int
	Provider            Provider
	CollectorVersion    string
	CredentialClass     CredentialClass
	CredentialReference string
	Cursor              Cursor
	ParserVersion       string
	ToolVersion         string
	Bounds              Bounds
}

func (request Request) Validate() error {
	if request.Scope.Validate() != nil || !validProductID(request.IntegrationID) || !validProductID(request.ConnectionID) || !validProductID(request.JobID) ||
		request.IntegrationID == request.ConnectionID || request.IntegrationID == request.JobID || request.ConnectionID == request.JobID ||
		request.Attempt < 1 || request.Attempt > 100 || !request.Provider.valid() || !versionPattern.MatchString(request.CollectorVersion) ||
		!credentialMatchesProvider(request.CredentialClass, request.Provider) || !validCredentialReference(request.Provider, request.CredentialReference) ||
		!request.Cursor.valid(request.Provider) || !versionPattern.MatchString(request.ParserVersion) || !versionPattern.MatchString(request.ToolVersion) || !request.Bounds.valid() {
		return ErrContract
	}
	return nil
}

type SubjectBinding struct {
	Kind string
	ID   string
}

func (binding SubjectBinding) valid(provider Provider) bool {
	want := map[Provider]string{ProviderAWS: "aws_account", ProviderKubernetes: "kubernetes_cluster", ProviderGitHub: "github_installation", ProviderOkta: "okta_tenant"}[provider]
	return binding.Kind == want && boundedText(binding.ID, 512)
}

type RawObject struct {
	reference domain.EvidenceRef
	checksum  [sha256.Size]byte
	size      int64
	mediaType string
	schema    string
	parser    string
	tool      string
}

func NewRawObject(reference domain.EvidenceRef, checksum [sha256.Size]byte, size int64, mediaType, schemaVersion, parserVersion, toolVersion string) (RawObject, error) {
	value := RawObject{reference: reference, checksum: checksum, size: size, mediaType: mediaType, schema: schemaVersion, parser: parserVersion, tool: toolVersion}
	if !value.valid() {
		return RawObject{}, ErrContract
	}
	return value, nil
}

func (object RawObject) Reference() domain.EvidenceRef { return object.reference }
func (object RawObject) Checksum() [sha256.Size]byte   { return object.checksum }
func (object RawObject) Size() int64                   { return object.size }
func (object RawObject) MediaType() string             { return object.mediaType }
func (object RawObject) SchemaVersion() string         { return object.schema }
func (object RawObject) ParserVersion() string         { return object.parser }
func (object RawObject) ToolVersion() string           { return object.tool }

func (object RawObject) valid() bool {
	return object.reference.Validate() == nil && object.checksum != ([sha256.Size]byte{}) && object.size >= 1 && object.size <= maximumRawBytes &&
		validMediaType(object.mediaType) && versionPattern.MatchString(object.schema) && versionPattern.MatchString(object.parser) && versionPattern.MatchString(object.tool)
}

type RawManifest struct {
	manifest RawObject
	objects  []RawObject
}

func NewRawManifest(manifest RawObject, objects []RawObject) (RawManifest, error) {
	value := RawManifest{manifest: manifest, objects: append([]RawObject(nil), objects...)}
	if !value.valid() {
		return RawManifest{}, ErrContract
	}
	return value, nil
}

func (manifest RawManifest) Descriptor() RawObject { return manifest.manifest }
func (manifest RawManifest) Objects() []RawObject {
	return append([]RawObject(nil), manifest.objects...)
}

func (manifest RawManifest) valid() bool {
	if !manifest.manifest.valid() || manifest.manifest.mediaType != "application/json" || len(manifest.objects) < 1 || len(manifest.objects) > maximumRawObjects {
		return false
	}
	last := ""
	for _, object := range manifest.objects {
		current := object.reference.String()
		if !object.valid() || current <= last || current == manifest.manifest.reference.String() {
			return false
		}
		last = current
	}
	return true
}

type SnapshotCandidate struct {
	source        Provider
	parser        string
	tool          string
	entities      []byte
	relationships []byte
	evidence      []byte
	entityCount   int
	relationCount int
	evidenceCount int
	digest        [sha256.Size]byte
}

type normalizedEntity struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	DisplayName    string          `json:"display_name"`
	StableFields   json.RawMessage `json:"stable_fields"`
	Attributes     json.RawMessage `json:"attributes"`
}

type normalizedRelationship struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
	Attributes     json.RawMessage `json:"attributes"`
}

type normalizedEvidence struct {
	ID              string `json:"id"`
	EntityID        string `json:"entity_id,omitempty"`
	FindingID       string `json:"finding_id,omitempty"`
	ObjectReference string `json:"object_reference"`
	ChecksumHex     string `json:"checksum_hex"`
	MediaType       string `json:"media_type"`
	SchemaVersion   string `json:"schema_version"`
	ParserVersion   string `json:"parser_version"`
}

func NewSnapshotCandidate(source Provider, parserVersion, toolVersion string, entities, relationships, evidence []byte) (SnapshotCandidate, error) {
	entityCopy, entityItems, entityIDs, ok := normalizedEntities(entities)
	if !ok {
		return SnapshotCandidate{}, ErrContract
	}
	relationshipCopy, relationshipItems, ok := normalizedRelationships(relationships, entityIDs)
	if !ok {
		return SnapshotCandidate{}, ErrContract
	}
	evidenceCopy, evidenceItems, ok := normalizedEvidenceItems(evidence, entityIDs)
	if !ok || !source.valid() || !versionPattern.MatchString(parserVersion) || !versionPattern.MatchString(toolVersion) || len(entityCopy)+len(relationshipCopy)+len(evidenceCopy) > maximumSnapshotBytes {
		return SnapshotCandidate{}, ErrContract
	}
	hash := sha256.New()
	for _, part := range [][]byte{[]byte(source), []byte(parserVersion), []byte(toolVersion), entityCopy, relationshipCopy, evidenceCopy} {
		_, _ = hash.Write(part)
		_, _ = hash.Write([]byte{0x1f})
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return SnapshotCandidate{source: source, parser: parserVersion, tool: toolVersion, entities: entityCopy, relationships: relationshipCopy, evidence: evidenceCopy, entityCount: len(entityItems), relationCount: len(relationshipItems), evidenceCount: len(evidenceItems), digest: digest}, nil
}

func (candidate SnapshotCandidate) Source() Provider      { return candidate.source }
func (candidate SnapshotCandidate) ParserVersion() string { return candidate.parser }
func (candidate SnapshotCandidate) ToolVersion() string   { return candidate.tool }
func (candidate SnapshotCandidate) Entities() []byte      { return bytes.Clone(candidate.entities) }
func (candidate SnapshotCandidate) Relationships() []byte {
	return bytes.Clone(candidate.relationships)
}
func (candidate SnapshotCandidate) Evidence() []byte          { return bytes.Clone(candidate.evidence) }
func (candidate SnapshotCandidate) EntityCount() int          { return candidate.entityCount }
func (candidate SnapshotCandidate) RelationshipCount() int    { return candidate.relationCount }
func (candidate SnapshotCandidate) EvidenceCount() int        { return candidate.evidenceCount }
func (candidate SnapshotCandidate) Digest() [sha256.Size]byte { return candidate.digest }

func (candidate SnapshotCandidate) valid(request Request) bool {
	return candidate.source == request.Provider && candidate.parser == request.ParserVersion && candidate.tool == request.ToolVersion && candidate.digest != ([sha256.Size]byte{}) &&
		candidate.entityCount <= request.Bounds.MaxItems && candidate.relationCount <= request.Bounds.MaxItems*2 && candidate.evidenceCount <= request.Bounds.MaxItems*2
}

type Outcome interface {
	collectionOutcome()
	validFor(Request) bool
	clone() Outcome
}

type ApplicableResult interface {
	Outcome
	Snapshot() SnapshotCandidate
}

type CompleteResult struct {
	binding  SubjectBinding
	cursor   Cursor
	manifest RawManifest
	snapshot SnapshotCandidate
}

func NewCompleteResult(request Request, binding SubjectBinding, cursor Cursor, manifest RawManifest, snapshot SnapshotCandidate) (CompleteResult, error) {
	value := CompleteResult{binding: binding, cursor: cursor, manifest: cloneManifest(manifest), snapshot: cloneSnapshot(snapshot)}
	if !value.validFor(request) {
		return CompleteResult{}, ErrContract
	}
	return value, nil
}

func (CompleteResult) collectionOutcome()                 {}
func (result CompleteResult) Subject() SubjectBinding     { return result.binding }
func (result CompleteResult) NextCursor() Cursor          { return result.cursor }
func (result CompleteResult) Manifest() RawManifest       { return cloneManifest(result.manifest) }
func (result CompleteResult) Snapshot() SnapshotCandidate { return cloneSnapshot(result.snapshot) }
func (result CompleteResult) validFor(request Request) bool {
	return request.Validate() == nil && result.binding.valid(request.Provider) && result.cursor.validResult(request.Provider) && result.manifest.valid() && result.snapshot.valid(request) && manifestFitsRequest(result.manifest, request)
}
func (result CompleteResult) clone() Outcome {
	result.manifest = cloneManifest(result.manifest)
	result.snapshot = cloneSnapshot(result.snapshot)
	return result
}

type PartialResult struct {
	binding  SubjectBinding
	cursor   Cursor
	manifest RawManifest
	reason   FailureCode
}

func NewPartialResult(request Request, binding SubjectBinding, cursor Cursor, manifest RawManifest, reason FailureCode) (PartialResult, error) {
	value := PartialResult{binding: binding, cursor: cursor, manifest: cloneManifest(manifest), reason: reason}
	if !value.validFor(request) {
		return PartialResult{}, ErrContract
	}
	return value, nil
}

func (PartialResult) collectionOutcome()             {}
func (result PartialResult) Subject() SubjectBinding { return result.binding }
func (result PartialResult) NextCursor() Cursor      { return result.cursor }
func (result PartialResult) Manifest() RawManifest   { return cloneManifest(result.manifest) }
func (result PartialResult) Reason() FailureCode     { return result.reason }
func (result PartialResult) validFor(request Request) bool {
	return request.Validate() == nil && result.reason == FailurePartial && result.binding.valid(request.Provider) && result.cursor.validResult(request.Provider) && result.manifest.valid() && manifestFitsRequest(result.manifest, request)
}
func (result PartialResult) clone() Outcome {
	result.manifest = cloneManifest(result.manifest)
	return result
}

type FailureCode string

const (
	FailureRetryable      FailureCode = "retryable"
	FailureRateLimited    FailureCode = "rate_limited"
	FailureDenied         FailureCode = "denied"
	FailureRevoked        FailureCode = "revoked"
	FailureMalformed      FailureCode = "malformed"
	FailurePartial        FailureCode = "partial"
	FailureTerminal       FailureCode = "terminal"
	FailureCancelled      FailureCode = "cancelled"
	FailureOutcomeUnknown FailureCode = "outcome_unknown"
)

type Failure struct {
	code    FailureCode
	retryAt time.Time
}

func NewFailure(code FailureCode, retryAt time.Time) (*Failure, error) {
	if !code.valid() || code == FailureRateLimited && retryAt.IsZero() || code != FailureRateLimited && !retryAt.IsZero() {
		return nil, ErrContract
	}
	return &Failure{code: code, retryAt: retryAt.UTC()}, nil
}

func (failure *Failure) Error() string {
	if failure == nil || !failure.code.valid() {
		return "collection failed"
	}
	return "collection failed: " + string(failure.code)
}
func (failure *Failure) Code() FailureCode {
	if failure == nil {
		return ""
	}
	return failure.code
}
func (failure *Failure) RetryAt() time.Time {
	if failure == nil {
		return time.Time{}
	}
	return failure.retryAt
}
func (code FailureCode) valid() bool {
	switch code {
	case FailureRetryable, FailureRateLimited, FailureDenied, FailureRevoked, FailureMalformed, FailurePartial, FailureTerminal, FailureCancelled, FailureOutcomeUnknown:
		return true
	default:
		return false
	}
}

type CredentialRequest struct {
	Scope         domain.Scope
	IntegrationID domain.ProductID
	ConnectionID  domain.ProductID
	JobID         domain.ProductID
	Attempt       int
	Provider      Provider
	Class         CredentialClass
	Reference     string
}

func (request CredentialRequest) valid() bool {
	return request.Scope.Validate() == nil && validProductID(request.IntegrationID) && validProductID(request.ConnectionID) && validProductID(request.JobID) && request.Attempt >= 1 && request.Attempt <= 100 &&
		credentialMatchesProvider(request.Class, request.Provider) && validCredentialReference(request.Provider, request.Reference)
}

type CredentialMaterial struct {
	mu        sync.Mutex
	request   CredentialRequest
	value     []byte
	expiresAt time.Time
	destroyed bool
}

func NewCredentialMaterial(request CredentialRequest, value []byte, expiresAt time.Time) (*CredentialMaterial, error) {
	if !request.valid() || len(value) < 1 || len(value) > 65_536 || !expiresAt.After(time.Now()) {
		return nil, ErrCredential
	}
	return &CredentialMaterial{request: request, value: bytes.Clone(value), expiresAt: expiresAt.UTC()}, nil
}

func (material *CredentialMaterial) Use(request CredentialRequest, use func([]byte) error) error {
	if material == nil || use == nil {
		return ErrCredential
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	if material.destroyed || material.request != request || !material.expiresAt.After(time.Now()) {
		return ErrCredential
	}
	borrowed := bytes.Clone(material.value)
	defer clear(borrowed)
	return use(borrowed)
}

func (material *CredentialMaterial) Destroy() {
	if material == nil {
		return
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	clear(material.value)
	material.value = nil
	material.destroyed = true
}

type WorkerCredentialResolver interface {
	ResolveCollectionCredential(context.Context, CredentialRequest) (*CredentialMaterial, error)
}

type ProviderClient interface {
	CollectWithCredential(context.Context, Request, []byte) (Outcome, error)
}

type ProviderAdapter struct {
	provider Provider
	class    CredentialClass
	resolver WorkerCredentialResolver
	client   ProviderClient
}

func NewProviderAdapter(provider Provider, class CredentialClass, resolver WorkerCredentialResolver, client ProviderClient) (*ProviderAdapter, error) {
	if !credentialMatchesProvider(class, provider) || nilInterface(resolver) || nilInterface(client) {
		return nil, ErrContract
	}
	return &ProviderAdapter{provider: provider, class: class, resolver: resolver, client: client}, nil
}

func (adapter *ProviderAdapter) Collect(ctx context.Context, request Request) (Outcome, error) {
	if adapter == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || request.Provider != adapter.provider || request.CredentialClass != adapter.class {
		return nil, ErrContract
	}
	bounded, cancel := context.WithTimeout(ctx, request.Bounds.Timeout)
	defer cancel()
	credentialRequest := CredentialRequest{
		Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID,
		Attempt: request.Attempt, Provider: request.Provider, Class: request.CredentialClass, Reference: request.CredentialReference,
	}
	material, err := adapter.resolver.ResolveCollectionCredential(bounded, credentialRequest)
	if err != nil || material == nil || bounded.Err() != nil {
		if material != nil {
			material.Destroy()
		}
		return nil, collectionDependencyError(err)
	}
	defer material.Destroy()
	var outcome Outcome
	err = material.Use(credentialRequest, func(credential []byte) error {
		var callErr error
		outcome, callErr = callProviderClient(adapter.client, bounded, request, credential)
		return callErr
	})
	if err != nil || bounded.Err() != nil {
		return nil, collectionDependencyError(err)
	}
	return outcome, nil
}

func callProviderClient(client ProviderClient, ctx context.Context, request Request, credential []byte) (outcome Outcome, resultErr error) {
	defer func() {
		if recover() != nil {
			outcome = nil
			resultErr = ErrContract
		}
	}()
	return client.CollectWithCredential(ctx, request, credential)
}

func collectionDependencyError(err error) error {
	var failure *Failure
	if errors.As(err, &failure) && failure != nil && failure.code.valid() {
		return failure
	}
	return ErrContract
}

type Collector interface {
	Collect(context.Context, Request) (Outcome, error)
}

type CollectorFactory interface {
	BuildCollectionCollector(WorkerCredentialResolver) (Collector, error)
}

type ReadinessCode string

const (
	ReadinessReady                 ReadinessCode = "ready"
	ReadinessDependencyUnavailable ReadinessCode = "dependency_unavailable"
	ReadinessUnconfigured          ReadinessCode = "unconfigured"
	ReadinessCancelled             ReadinessCode = "cancelled"
	ReadinessContractInvalid       ReadinessCode = "contract_invalid"
)

type Readiness struct {
	Provider         Provider
	CollectorVersion string
	Ready            bool
	Code             ReadinessCode
	CheckedAt        time.Time
}

type ReadinessProbe interface {
	Check(context.Context) Readiness
}

type Registration struct {
	Provider         Provider
	CollectorVersion string
	CredentialClass  CredentialClass
	Collector        Collector
	Readiness        ReadinessProbe
	ReadinessTimeout time.Duration
}

type registryKey struct {
	provider Provider
	version  string
}

type Registry struct {
	registrations map[registryKey]Registration
}

func NewRegistry(registrations []Registration) (*Registry, error) {
	if len(registrations) < 4 || len(registrations) > maximumRegistrations {
		return nil, ErrContract
	}
	registry := &Registry{registrations: make(map[registryKey]Registration, len(registrations))}
	providers := map[Provider]bool{}
	for _, registration := range registrations {
		if !registration.Provider.valid() || !versionPattern.MatchString(registration.CollectorVersion) || !credentialMatchesProvider(registration.CredentialClass, registration.Provider) || nilInterface(registration.Collector) || nilInterface(registration.Readiness) || registration.ReadinessTimeout < 100*time.Millisecond || registration.ReadinessTimeout > 10*time.Second {
			return nil, ErrContract
		}
		key := registryKey{provider: registration.Provider, version: registration.CollectorVersion}
		if _, duplicate := registry.registrations[key]; duplicate {
			return nil, ErrContract
		}
		registry.registrations[key] = registration
		providers[registration.Provider] = true
	}
	for _, provider := range []Provider{ProviderAWS, ProviderKubernetes, ProviderGitHub, ProviderOkta} {
		if !providers[provider] {
			return nil, ErrContract
		}
	}
	return registry, nil
}

func (registry *Registry) Collect(ctx context.Context, request Request) (Outcome, error) {
	if registry == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil {
		return nil, ErrContract
	}
	registration, ok := registry.registrations[registryKey{provider: request.Provider, version: request.CollectorVersion}]
	if !ok || registration.CredentialClass != request.CredentialClass {
		return nil, ErrContract
	}
	outcome, err := callCollector(registration.Collector, ctx, request)
	if err != nil {
		failure, ok := err.(*Failure)
		if !ok || failure == nil || !failure.code.valid() {
			return nil, ErrContract
		}
		return nil, failure
	}
	if nilInterface(outcome) || !outcome.validFor(request) {
		return nil, ErrContract
	}
	return outcome.clone(), nil
}

func (registry *Registry) CheckReadiness(ctx context.Context, provider Provider, collectorVersion string) Readiness {
	missing := Readiness{Provider: provider, CollectorVersion: collectorVersion, Code: ReadinessUnconfigured}
	if registry == nil || ctx == nil || !provider.valid() || !versionPattern.MatchString(collectorVersion) {
		return missing
	}
	if ctx.Err() != nil {
		missing.Code = ReadinessCancelled
		return missing
	}
	registration, ok := registry.registrations[registryKey{provider: provider, version: collectorVersion}]
	if !ok {
		return missing
	}
	bounded, cancel := context.WithTimeout(ctx, registration.ReadinessTimeout)
	defer cancel()
	result := make(chan Readiness, 1)
	go func() { result <- callReadiness(registration.Readiness, bounded) }()
	var status Readiness
	select {
	case status = <-result:
	case <-bounded.Done():
		code := ReadinessDependencyUnavailable
		if ctx.Err() != nil {
			code = ReadinessCancelled
		}
		return Readiness{Provider: provider, CollectorVersion: collectorVersion, Code: code, CheckedAt: time.Now().UTC()}
	}
	if status.Provider != provider || status.CollectorVersion != collectorVersion || status.CheckedAt.IsZero() || status.CheckedAt.Location() != time.UTC {
		return Readiness{Provider: provider, CollectorVersion: collectorVersion, Code: ReadinessContractInvalid}
	}
	if status.Ready {
		if status.Code != "" && status.Code != ReadinessReady {
			return Readiness{Provider: provider, CollectorVersion: collectorVersion, Code: ReadinessContractInvalid}
		}
		status.Code = ReadinessReady
		return status
	}
	if status.Code != ReadinessDependencyUnavailable && status.Code != ReadinessUnconfigured && status.Code != ReadinessCancelled {
		return Readiness{Provider: provider, CollectorVersion: collectorVersion, Code: ReadinessContractInvalid}
	}
	return status
}

func callCollector(collector Collector, ctx context.Context, request Request) (outcome Outcome, resultErr error) {
	defer func() {
		if recover() != nil {
			outcome = nil
			resultErr = ErrContract
		}
	}()
	return collector.Collect(ctx, request)
}

func callReadiness(probe ReadinessProbe, ctx context.Context) (status Readiness) {
	defer func() {
		if recover() != nil {
			status = Readiness{}
		}
	}()
	return probe.Check(ctx)
}

func manifestFitsRequest(manifest RawManifest, request Request) bool {
	if len(manifest.objects) > request.Bounds.MaxPages || manifest.manifest.parser != request.ParserVersion || manifest.manifest.tool != request.ToolVersion {
		return false
	}
	total := manifest.manifest.size
	for _, object := range manifest.objects {
		if object.parser != request.ParserVersion || object.tool != request.ToolVersion {
			return false
		}
		total += object.size
		if total > request.Bounds.MaxRawBytes {
			return false
		}
	}
	return true
}

func normalizedEntities(value []byte) ([]byte, []normalizedEntity, map[string]struct{}, bool) {
	var items []normalizedEntity
	canonical, ok := decodeCanonicalArray(value, &items)
	if !ok {
		return nil, nil, nil, false
	}
	ids := make(map[string]struct{}, len(items))
	sourceIDs := make(map[string]struct{}, len(items))
	for _, item := range items {
		if !validProductIDText(item.ID) || !tokenPattern.MatchString(item.Kind) || !boundedText(item.SourceNativeID, 1024) || !boundedText(item.DisplayName, 256) || !canonicalJSONObject(item.StableFields, 65_536) || !canonicalJSONObject(item.Attributes, 65_536) {
			return nil, nil, nil, false
		}
		if _, duplicate := ids[item.ID]; duplicate {
			return nil, nil, nil, false
		}
		if _, duplicate := sourceIDs[item.SourceNativeID]; duplicate {
			return nil, nil, nil, false
		}
		ids[item.ID] = struct{}{}
		sourceIDs[item.SourceNativeID] = struct{}{}
	}
	return canonical, items, ids, true
}

func normalizedRelationships(value []byte, entityIDs map[string]struct{}) ([]byte, []normalizedRelationship, bool) {
	var items []normalizedRelationship
	canonical, ok := decodeCanonicalArray(value, &items)
	if !ok {
		return nil, nil, false
	}
	ids := make(map[string]struct{}, len(items))
	sourceIDs := make(map[string]struct{}, len(items))
	for _, item := range items {
		_, fromExists := entityIDs[item.FromEntityID]
		_, toExists := entityIDs[item.ToEntityID]
		if !validProductIDText(item.ID) || !tokenPattern.MatchString(item.Kind) || !boundedText(item.SourceNativeID, 1024) || !fromExists || !toExists || !canonicalJSONObject(item.Attributes, 65_536) {
			return nil, nil, false
		}
		if _, duplicate := ids[item.ID]; duplicate {
			return nil, nil, false
		}
		if _, duplicate := sourceIDs[item.SourceNativeID]; duplicate {
			return nil, nil, false
		}
		ids[item.ID] = struct{}{}
		sourceIDs[item.SourceNativeID] = struct{}{}
	}
	return canonical, items, true
}

func normalizedEvidenceItems(value []byte, entityIDs map[string]struct{}) ([]byte, []normalizedEvidence, bool) {
	var items []normalizedEvidence
	canonical, ok := decodeCanonicalArray(value, &items)
	if !ok {
		return nil, nil, false
	}
	ids := make(map[string]struct{}, len(items))
	for _, item := range items {
		_, entityExists := entityIDs[item.EntityID]
		if !validProductIDText(item.ID) || (item.EntityID != "") == (item.FindingID != "") || item.EntityID != "" && !entityExists || item.FindingID != "" && !validProductIDText(item.FindingID) ||
			!boundedText(item.ObjectReference, 2048) || !strings.HasPrefix(item.ObjectReference, "s3://") || strings.ContainsAny(item.ObjectReference, "?#") || !checksumPattern.MatchString(item.ChecksumHex) ||
			!validMediaType(item.MediaType) || !versionPattern.MatchString(item.SchemaVersion) || !versionPattern.MatchString(item.ParserVersion) {
			return nil, nil, false
		}
		if _, duplicate := ids[item.ID]; duplicate {
			return nil, nil, false
		}
		ids[item.ID] = struct{}{}
	}
	return canonical, items, true
}

func decodeCanonicalArray(value []byte, destination any) ([]byte, bool) {
	if len(value) < 2 || len(value) > maximumSnapshotBytes || !json.Valid(value) {
		return nil, false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, value) != nil || !bytes.Equal(compact.Bytes(), value) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || reflect.ValueOf(destination).Elem().IsNil() {
		return nil, false
	}
	encoded, err := json.Marshal(reflect.ValueOf(destination).Elem().Interface())
	if err != nil || !bytes.Equal(encoded, value) {
		return nil, false
	}
	return bytes.Clone(value), true
}

func canonicalJSONObject(value []byte, maximum int) bool {
	if len(value) < 2 || len(value) > maximum || !json.Valid(value) || value[0] != '{' || value[len(value)-1] != '}' {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded map[string]any
	if decoder.Decode(&decoded) != nil || decoded == nil {
		return false
	}
	encoded, err := json.Marshal(decoded)
	return err == nil && bytes.Equal(encoded, value)
}

func cloneManifest(manifest RawManifest) RawManifest {
	manifest.objects = append([]RawObject(nil), manifest.objects...)
	return manifest
}

func cloneSnapshot(candidate SnapshotCandidate) SnapshotCandidate {
	candidate.entities = bytes.Clone(candidate.entities)
	candidate.relationships = bytes.Clone(candidate.relationships)
	candidate.evidence = bytes.Clone(candidate.evidence)
	return candidate
}

func validCredentialReference(provider Provider, value string) bool {
	matches := referencePattern.FindStringSubmatch(value)
	return len(matches) == 2 && matches[1] == string(provider) && !strings.Contains(value, "//") && !strings.Contains(value, "..")
}

func validProductID(value domain.ProductID) bool {
	parsed, err := domain.ParseProductID(value.String())
	return err == nil && parsed == value
}

func validProductIDText(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validMediaType(value string) bool {
	switch value {
	case "application/json", "application/octet-stream", "application/gzip", "text/plain":
		return true
	default:
		return false
	}
}

func boundedText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func nilInterface(value any) bool {
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
