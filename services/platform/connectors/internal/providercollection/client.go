package providercollection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	rawSchemaVersion      = "raw_v1"
	manifestSchemaVersion = "manifest_v1"
	redactedPageVersion   = "redacted_page_v1"
	maximumArtifactBytes  = 64 * 1024 * 1024
)

var (
	errConfiguration = errors.New("provider collection configuration rejected")
	versionPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
)

type API interface {
	FetchCollectionPage(context.Context, []byte, PageRequest) (Page, error)
	CheckCollectionReadiness(context.Context) error
}

type ArtifactAuthority = artifactstore.ObjectReferencingArtifactStore

type PageRequest struct {
	Provider       collection.Provider
	Subject        collection.SubjectBinding
	Cursor         collection.Cursor
	Page           int
	RemainingItems int
	RemainingBytes int64
}

type Page struct {
	Subject       collection.SubjectBinding
	Cursor        collection.Cursor
	Raw           []byte
	Entities      []json.RawMessage
	Relationships []json.RawMessage
	Complete      bool
}

type redactedPageDocument struct {
	Version       string              `json:"version"`
	Provider      collection.Provider `json:"provider"`
	Subject       manifestSubject     `json:"subject"`
	Cursor        redactedPageCursor  `json:"cursor"`
	Complete      bool                `json:"complete"`
	Entities      []json.RawMessage   `json:"entities"`
	Relationships []json.RawMessage   `json:"relationships"`
}

type redactedPageCursor struct {
	Provider collection.Provider `json:"provider"`
	Version  string              `json:"version"`
	Value    string              `json:"value"`
}

type normalizedPageEntity struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	DisplayName    string          `json:"display_name"`
	StableFields   json.RawMessage `json:"stable_fields"`
	Attributes     json.RawMessage `json:"attributes"`
}

type normalizedPageRelationship struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
	Attributes     json.RawMessage `json:"attributes"`
}

func NewPage(provider collection.Provider, subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) (Page, error) {
	if !validProvider(provider) || !validCursor(cursor, provider) || !validNormalizedInventory(provider, entities, relationships) {
		return Page{}, collection.ErrContract
	}
	page := Page{Subject: subject, Cursor: cursor, Entities: cloneRawMessages(entities), Relationships: cloneRawMessages(relationships), Complete: complete}
	body, err := canonicalPageBody(provider, page)
	if err != nil || len(body) > maximumArtifactBytes {
		return Page{}, collection.ErrContract
	}
	page.Raw = body
	return page, nil
}

type Config struct {
	Provider         collection.Provider
	API              API
	Artifacts        ArtifactAuthority
	CollectorVersion string
	ParserVersion    string
	ToolVersion      string
	Clock            func() time.Time
}

type Client struct {
	provider         collection.Provider
	api              API
	artifacts        ArtifactAuthority
	collectorVersion string
	parserVersion    string
	toolVersion      string
	clock            func() time.Time
	resume           *ResumeSeed
}

func New(config Config) (*Client, error) {
	if !validProvider(config.Provider) || nilInterface(config.API) || nilInterface(config.Artifacts) || config.Clock == nil ||
		!versionPattern.MatchString(config.CollectorVersion) || !versionPattern.MatchString(config.ParserVersion) || !versionPattern.MatchString(config.ToolVersion) {
		return nil, errConfiguration
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errConfiguration
	}
	return &Client{provider: config.Provider, api: config.API, artifacts: config.Artifacts, collectorVersion: config.CollectorVersion, parserVersion: config.ParserVersion, toolVersion: config.ToolVersion, clock: config.Clock}, nil
}

func (client *Client) Check(ctx context.Context) collection.Readiness {
	status := collection.Readiness{Code: collection.ReadinessUnconfigured}
	if client == nil {
		return status
	}
	status.Provider = client.provider
	status.CollectorVersion = client.collectorVersion
	checkedAt := client.clock()
	if checkedAt.IsZero() || checkedAt.Location() != time.UTC {
		status.Code = collection.ReadinessContractInvalid
		return status
	}
	status.CheckedAt = checkedAt
	if ctx == nil {
		status.Code = collection.ReadinessContractInvalid
		return status
	}
	if ctx.Err() != nil {
		status.Code = collection.ReadinessCancelled
		return status
	}
	if err := checkReadiness(client.api, ctx); err != nil {
		if ctx.Err() != nil {
			status.Code = collection.ReadinessCancelled
		} else if errors.Is(err, collection.ErrContract) {
			status.Code = collection.ReadinessContractInvalid
		} else {
			status.Code = collection.ReadinessDependencyUnavailable
		}
		return status
	}
	if ctx.Err() != nil {
		status.Code = collection.ReadinessCancelled
		return status
	}
	status.Ready = true
	status.Code = collection.ReadinessReady
	return status
}

func (client *Client) CollectWithCredential(ctx context.Context, request collection.Request, credential []byte) (collection.Outcome, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ClassifyProviderError(ctx, ctx.Err())
	}
	if client == nil || ctx == nil || request.Validate() != nil || request.Provider != client.provider || request.CollectorVersion != client.collectorVersion || request.ParserVersion != client.parserVersion || request.ToolVersion != client.toolVersion || len(credential) < 16 || len(credential) > 65_536 {
		return nil, collection.ErrContract
	}
	if now := client.clock(); now.IsZero() || now.Location() != time.UTC {
		return nil, collection.ErrContract
	}

	cursor := request.Cursor
	descriptorReserve, err := nextManifestDescriptorReserve(request)
	if err != nil {
		return nil, collection.ErrContract
	}
	remainingRawBytes := request.Bounds.MaxRawBytes
	remainingItems := request.Bounds.MaxItems
	remainingRelationships := request.Bounds.MaxItems * 2
	objects := make([]collection.RawObject, 0, request.Bounds.MaxPages)
	entities := make([]json.RawMessage, 0)
	relationships := make([]json.RawMessage, 0)
	entityObjects := make(map[string]collection.RawObject)
	entitySourceIDs := make(map[string]struct{})
	relationshipIDs := make(map[string]struct{})
	relationshipSourceIDs := make(map[string]struct{})
	snapshotLimit := newSnapshotBudget(maximumArtifactBytes)
	complete := false
	seededPages := 0
	if client.resume != nil {
		seed, seedErr := client.loadResumeSeed(ctx, request)
		if seedErr != nil {
			return nil, outcomeUnknown()
		}
		objects = seed.objects
		entities = seed.entities
		relationships = seed.relationships
		entityObjects = seed.entityObjects
		entitySourceIDs = seed.entitySourceIDs
		relationshipIDs = seed.relationshipIDs
		relationshipSourceIDs = seed.relationshipSourceIDs
		remainingRawBytes -= seed.rawBytes
		remainingItems -= len(seed.entities)
		remainingRelationships -= len(seed.relationships)
		seededPages = len(seed.objects)
		for index, page := range seed.pages {
			if !snapshotLimit.addPage(page.Entities, page.Relationships, seed.evidenceLengths[index]) {
				return nil, outcomeUnknown()
			}
		}
		if remainingRawBytes < 1 || remainingItems < 0 || remainingRelationships < 0 || seededPages > request.Bounds.MaxPages {
			return nil, outcomeUnknown()
		}
	}

	for pageNumber := seededPages + 1; pageNumber <= request.Bounds.MaxPages; pageNumber++ {
		if remainingItems < 1 {
			if len(objects) == 0 {
				return nil, collection.ErrContract
			}
			break
		}
		manifestBody, err := marshalManifest(request, cursor, objects)
		if err != nil || len(manifestBody) > maximumArtifactBytes {
			return nil, collection.ErrContract
		}
		remainingBytes := remainingRawBytes - int64(len(manifestBody)) - descriptorReserve
		if remainingBytes < 1 {
			if len(objects) == 0 {
				return nil, collection.ErrContract
			}
			break
		}
		pageRequest := PageRequest{Provider: request.Provider, Subject: request.ExpectedSubject, Cursor: cursor, Page: pageNumber, RemainingItems: remainingItems, RemainingBytes: remainingBytes}
		borrowed := bytes.Clone(credential)
		page, err := fetchPage(client.api, ctx, borrowed, pageRequest)
		clear(borrowed)
		if err != nil {
			if errors.Is(err, collection.ErrContract) {
				return nil, malformedFailure()
			}
			return nil, err
		}
		if !validPage(page, request, cursor, credential, remainingItems, remainingRelationships, remainingBytes) {
			return nil, malformedFailure()
		}
		nextManifestBody, nextManifestErr := marshalManifest(request, page.Cursor, objects)
		nextRemainingBytes := remainingRawBytes - int64(len(nextManifestBody)) - descriptorReserve
		if nextManifestErr != nil || len(nextManifestBody) > maximumArtifactBytes {
			return nil, collection.ErrContract
		}
		if nextRemainingBytes < 1 || int64(len(page.Raw)) > nextRemainingBytes {
			if len(objects) == 0 {
				return nil, collection.ErrContract
			}
			break
		}
		pageEntityIDs := make([]string, len(page.Entities))
		pageEntitySources := make([]string, len(page.Entities))
		for index, entity := range page.Entities {
			identity, source, ok := entityIdentity(entity)
			if !ok {
				return nil, malformedFailure()
			}
			if _, exists := entityObjects[identity]; exists {
				return nil, malformedFailure()
			}
			if _, exists := entitySourceIDs[source]; exists {
				return nil, malformedFailure()
			}
			pageEntityIDs[index] = identity
			pageEntitySources[index] = source
		}
		pageRelationshipIDs := make([]string, len(page.Relationships))
		pageRelationshipSources := make([]string, len(page.Relationships))
		for index, relationship := range page.Relationships {
			identity, source, _, _, ok := relationshipIdentity(relationship)
			if !ok {
				return nil, malformedFailure()
			}
			if _, exists := relationshipIDs[identity]; exists {
				return nil, malformedFailure()
			}
			if _, exists := relationshipSourceIDs[source]; exists {
				return nil, malformedFailure()
			}
			pageRelationshipIDs[index] = identity
			pageRelationshipSources[index] = source
		}

		reference, err := deterministicEvidenceReference(request, fmt.Sprintf("raw-page-%06d", pageNumber))
		if err != nil {
			return nil, collection.ErrContract
		}
		locator := artifactstore.Locator{Scope: request.Scope, Reference: reference}
		artifact, err := putArtifact(client.artifacts, ctx, artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: bytes.Clone(page.Raw)})
		if err != nil {
			return nil, outcomeUnknown()
		}
		object, err := rawObjectFromArtifact(request, locator, artifact, rawSchemaVersion, client.artifacts)
		if err != nil {
			return nil, outcomeUnknown()
		}
		evidenceLengths := make([]int, len(pageEntityIDs))
		for index, identity := range pageEntityIDs {
			item, itemErr := evidenceForEntity(request, identity, object)
			encoded, encodeErr := json.Marshal(item)
			if itemErr != nil || encodeErr != nil {
				return nil, collection.ErrContract
			}
			evidenceLengths[index] = len(encoded)
		}
		if !snapshotLimit.addPage(page.Entities, page.Relationships, evidenceLengths) {
			return nil, malformedFailure()
		}
		objects = append(objects, object)
		for index, entity := range page.Entities {
			entityObjects[pageEntityIDs[index]] = object
			entitySourceIDs[pageEntitySources[index]] = struct{}{}
			entities = append(entities, bytes.Clone(entity))
		}
		for index, relationship := range page.Relationships {
			relationshipIDs[pageRelationshipIDs[index]] = struct{}{}
			relationshipSourceIDs[pageRelationshipSources[index]] = struct{}{}
			relationships = append(relationships, bytes.Clone(relationship))
		}
		remainingItems -= len(page.Entities)
		remainingRelationships -= len(page.Relationships)
		remainingRawBytes -= artifact.Size
		cursor = page.Cursor
		complete = page.Complete
		if complete {
			break
		}
	}

	sort.Slice(objects, func(left, right int) bool {
		return objects[left].Reference().String() < objects[right].Reference().String()
	})
	if complete && !relationshipsResolve(relationships, entityObjects) {
		return nil, malformedFailure()
	}
	manifestBody, err := marshalManifest(request, cursor, objects)
	if err != nil || len(manifestBody) > maximumArtifactBytes || int64(len(manifestBody)) > remainingRawBytes {
		return nil, collection.ErrContract
	}
	manifestReference, err := deterministicEvidenceReference(request, "manifest")
	if err != nil {
		return nil, collection.ErrContract
	}
	manifestLocator := artifactstore.Locator{Scope: request.Scope, Reference: manifestReference}
	manifestArtifact, err := putArtifact(client.artifacts, ctx, artifactstore.PutRequest{Locator: manifestLocator, MediaType: "application/json", Body: manifestBody})
	if err != nil {
		return nil, outcomeUnknown()
	}
	manifestObject, err := rawObjectFromArtifact(request, manifestLocator, manifestArtifact, manifestSchemaVersion, client.artifacts)
	if err != nil {
		return nil, outcomeUnknown()
	}
	manifest, err := collection.NewRawManifest(manifestObject, objects)
	if err != nil {
		return nil, collection.ErrContract
	}
	if !complete {
		result, resultErr := collection.NewPartialResult(request, request.ExpectedSubject, cursor, manifest, collection.FailurePartial)
		if resultErr != nil {
			return nil, collection.ErrContract
		}
		return result, nil
	}

	entityBody, relationshipBody, evidenceBody, err := snapshotBodies(request, entities, relationships, entityObjects)
	if err != nil {
		return nil, malformedFailure()
	}
	snapshot, err := collection.NewSnapshotCandidate(request.Provider, request.ParserVersion, request.ToolVersion, entityBody, relationshipBody, evidenceBody)
	if err != nil {
		return nil, malformedFailure()
	}
	result, err := collection.NewCompleteResult(request, request.ExpectedSubject, cursor, manifest, snapshot)
	if err != nil {
		return nil, collection.ErrContract
	}
	return result, nil
}

func validPage(page Page, request collection.Request, prior collection.Cursor, credential []byte, remainingItems, remainingRelationships int, remainingBytes int64) bool {
	canonical, err := canonicalPageBody(request.Provider, page)
	if page.Subject != request.ExpectedSubject || !validCursor(page.Cursor, request.Provider) || page.Cursor == prior || err != nil || len(page.Raw) == 0 || len(page.Raw) > maximumArtifactBytes || int64(len(page.Raw)) > remainingBytes || !bytes.Equal(canonical, page.Raw) || bytes.Contains(page.Raw, credential) || len(page.Entities) > remainingItems || len(page.Relationships) > remainingRelationships {
		return false
	}
	return validNormalizedInventory(request.Provider, page.Entities, page.Relationships)
}

func canonicalPageBody(provider collection.Provider, page Page) ([]byte, error) {
	if !validNormalizedInventory(provider, page.Entities, page.Relationships) {
		return nil, collection.ErrContract
	}
	return json.Marshal(redactedPageDocument{
		Version: redactedPageVersion, Provider: provider, Subject: manifestSubject{Kind: page.Subject.Kind, ID: page.Subject.ID},
		Cursor: redactedPageCursor{Provider: page.Cursor.Provider, Version: page.Cursor.Version, Value: page.Cursor.Value}, Complete: page.Complete,
		Entities: cloneRawMessages(page.Entities), Relationships: cloneRawMessages(page.Relationships),
	})
}

func validNormalizedInventory(provider collection.Provider, entities, relationships []json.RawMessage) bool {
	if len(entities) > 100_000 || len(relationships) > 200_000 {
		return false
	}
	var total int64
	entityIDs := make(map[string]struct{}, len(entities))
	entitySourceIDs := make(map[string]struct{}, len(entities))
	for _, entity := range entities {
		total += int64(len(entity))
		if total > maximumArtifactBytes {
			return false
		}
		if !validProviderEntity(provider, entity) {
			return false
		}
		identity, source, ok := entityIdentity(entity)
		if !ok {
			return false
		}
		if _, duplicate := entityIDs[identity]; duplicate {
			return false
		}
		if _, duplicate := entitySourceIDs[source]; duplicate {
			return false
		}
		entityIDs[identity] = struct{}{}
		entitySourceIDs[source] = struct{}{}
	}
	relationshipIDs := make(map[string]struct{}, len(relationships))
	relationshipSourceIDs := make(map[string]struct{}, len(relationships))
	for _, relationship := range relationships {
		total += int64(len(relationship))
		if total > maximumArtifactBytes {
			return false
		}
		if !validProviderRelationship(relationship) {
			return false
		}
		identity, source, _, _, ok := relationshipIdentity(relationship)
		if !ok {
			return false
		}
		if _, duplicate := relationshipIDs[identity]; duplicate {
			return false
		}
		if _, duplicate := relationshipSourceIDs[source]; duplicate {
			return false
		}
		relationshipIDs[identity] = struct{}{}
		relationshipSourceIDs[source] = struct{}{}
	}
	return true
}

func validProviderEntity(provider collection.Provider, raw json.RawMessage) bool {
	var entity normalizedPageEntity
	if !decodeExactObject(raw, &entity) || !validProductIDText(entity.ID) || !boundedInventoryText(entity.SourceNativeID, 1024) || !boundedInventoryText(entity.DisplayName, 256) {
		return false
	}
	kinds, stable, attributes := providerEntitySchema(provider)
	if !kinds[entity.Kind] || !validScalarObject(entity.StableFields, stable) || !validScalarObject(entity.Attributes, attributes) {
		return false
	}
	if provider == collection.ProviderKubernetes && entity.Kind == "kubernetes_resource" {
		var fields map[string]any
		if json.Unmarshal(entity.StableFields, &fields) != nil || strings.EqualFold(fmt.Sprint(fields["resource_kind"]), "Secret") {
			return false
		}
	}
	return true
}

func providerEntitySchema(provider collection.Provider) (map[string]bool, map[string]bool, map[string]bool) {
	switch provider {
	case collection.ProviderAWS:
		return tokenSet("aws_account", "aws_role", "aws_resource", "aws_service"), tokenSet("account_id", "arn", "region", "resource_type", "service", "name"), tokenSet("state", "status")
	case collection.ProviderKubernetes:
		return tokenSet("kubernetes_cluster", "kubernetes_namespace", "kubernetes_resource", "kubernetes_workload"), tokenSet("cluster", "namespace", "api_group", "api_version", "resource_kind", "name"), tokenSet("state", "status", "namespaced")
	case collection.ProviderGitHub:
		return tokenSet("github_installation", "github_organization", "github_repository"), tokenSet("installation_id", "owner", "repository", "visibility", "name"), tokenSet("archived", "default_branch", "state")
	case collection.ProviderOkta:
		return tokenSet("okta_tenant", "okta_application", "okta_group", "okta_user"), tokenSet("tenant", "object_type", "name"), tokenSet("status", "state")
	default:
		return nil, nil, nil
	}
}

func validProviderRelationship(raw json.RawMessage) bool {
	var relationship normalizedPageRelationship
	if !decodeExactObject(raw, &relationship) || !validProductIDText(relationship.ID) || !validProductIDText(relationship.FromEntityID) || !validProductIDText(relationship.ToEntityID) || relationship.FromEntityID == relationship.ToEntityID || !boundedInventoryText(relationship.SourceNativeID, 1024) {
		return false
	}
	return tokenSet("contains", "member_of", "attached_to", "manages", "owns", "trusts", "depends_on")[relationship.Kind] && validScalarObject(relationship.Attributes, tokenSet("state", "type"))
}

func boundedInventoryText(value string, maximum int) bool {
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

func validScalarObject(raw json.RawMessage, allowed map[string]bool) bool {
	if !validJSONObject(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fields map[string]any
	if decoder.Decode(&fields) != nil || fields == nil {
		return false
	}
	for key, value := range fields {
		if !allowed[key] {
			return false
		}
		switch scalar := value.(type) {
		case string:
			if len(scalar) > 2048 || !utf8.ValidString(scalar) {
				return false
			}
		case bool, json.Number:
		default:
			return false
		}
	}
	return true
}

func decodeExactObject(raw json.RawMessage, destination any) bool {
	if !validJSONObject(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return false
	}
	encoded, err := json.Marshal(destination)
	return err == nil && bytes.Equal(encoded, raw)
}

func tokenSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	result := make([]json.RawMessage, len(values))
	for index := range values {
		result[index] = bytes.Clone(values[index])
	}
	return result
}

func validProductIDText(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func outcomeUnknown() error {
	failure, _ := collection.NewFailure(collection.FailureOutcomeUnknown, time.Time{})
	return failure
}

func malformedFailure() error {
	failure, _ := collection.NewFailure(collection.FailureMalformed, time.Time{})
	return failure
}

type snapshotBudget struct {
	limit             int64
	entityBytes       int64
	entityCount       int
	relationshipBytes int64
	relationshipCount int
	evidenceBytes     int64
	evidenceCount     int
}

func newSnapshotBudget(limit int64) *snapshotBudget {
	return &snapshotBudget{limit: limit}
}

func (budget *snapshotBudget) addPage(entities, relationships []json.RawMessage, evidenceLengths []int) bool {
	if budget == nil || budget.limit < 6 || len(evidenceLengths) != len(entities) {
		return false
	}
	entityBytes := budget.entityBytes + rawArrayContribution(entities, budget.entityCount)
	relationshipBytes := budget.relationshipBytes + rawArrayContribution(relationships, budget.relationshipCount)
	evidenceBytes := budget.evidenceBytes + lengthArrayContribution(evidenceLengths, budget.evidenceCount)
	if 6+entityBytes+relationshipBytes+evidenceBytes > budget.limit {
		return false
	}
	budget.entityBytes = entityBytes
	budget.entityCount += len(entities)
	budget.relationshipBytes = relationshipBytes
	budget.relationshipCount += len(relationships)
	budget.evidenceBytes = evidenceBytes
	budget.evidenceCount += len(evidenceLengths)
	return true
}

func rawArrayContribution(values []json.RawMessage, priorCount int) int64 {
	lengths := make([]int, len(values))
	for index := range values {
		lengths[index] = len(values[index])
	}
	return lengthArrayContribution(lengths, priorCount)
}

func lengthArrayContribution(lengths []int, priorCount int) int64 {
	var total int64
	for index, length := range lengths {
		total += int64(length)
		if priorCount > 0 || index > 0 {
			total++
		}
	}
	return total
}

func entityIdentity(value json.RawMessage) (string, string, bool) {
	var entity normalizedPageEntity
	if !decodeExactObject(value, &entity) || !validProductIDText(entity.ID) || !boundedInventoryText(entity.SourceNativeID, 1024) {
		return "", "", false
	}
	return entity.ID, entity.SourceNativeID, true
}

func relationshipIdentity(value json.RawMessage) (string, string, string, string, bool) {
	var relationship normalizedPageRelationship
	if !decodeExactObject(value, &relationship) || !validProductIDText(relationship.ID) || !boundedInventoryText(relationship.SourceNativeID, 1024) || !validProductIDText(relationship.FromEntityID) || !validProductIDText(relationship.ToEntityID) {
		return "", "", "", "", false
	}
	return relationship.ID, relationship.SourceNativeID, relationship.FromEntityID, relationship.ToEntityID, true
}

func relationshipsResolve(relationships []json.RawMessage, entities map[string]collection.RawObject) bool {
	for _, raw := range relationships {
		_, _, from, to, ok := relationshipIdentity(raw)
		if !ok {
			return false
		}
		if _, exists := entities[from]; !exists {
			return false
		}
		if _, exists := entities[to]; !exists {
			return false
		}
	}
	return true
}

func snapshotBodies(request collection.Request, entities, relationships []json.RawMessage, entityObjects map[string]collection.RawObject) ([]byte, []byte, []byte, error) {
	sort.Slice(entities, func(left, right int) bool { return identityForSort(entities[left]) < identityForSort(entities[right]) })
	sort.Slice(relationships, func(left, right int) bool {
		return identityForSort(relationships[left]) < identityForSort(relationships[right])
	})
	evidence := make([]evidenceItem, 0, len(entities))
	for _, entity := range entities {
		entityID, ok := itemIdentity(entity)
		object, exists := entityObjects[entityID]
		if !ok || !exists {
			return nil, nil, nil, collection.ErrContract
		}
		item, err := evidenceForEntity(request, entityID, object)
		if err != nil {
			return nil, nil, nil, err
		}
		evidence = append(evidence, item)
	}
	sort.Slice(evidence, func(left, right int) bool { return evidence[left].ID < evidence[right].ID })
	entityBody, entityErr := json.Marshal(entities)
	relationshipBody, relationshipErr := json.Marshal(relationships)
	evidenceBody, evidenceErr := json.Marshal(evidence)
	if entityErr != nil || relationshipErr != nil || evidenceErr != nil {
		return nil, nil, nil, collection.ErrContract
	}
	return entityBody, relationshipBody, evidenceBody, nil
}

func evidenceForEntity(request collection.Request, entityID string, object collection.RawObject) (evidenceItem, error) {
	checksum := object.Checksum()
	evidenceReference, err := deterministicEvidenceReference(request, "evidence:"+entityID+":"+object.Reference().String())
	if err != nil {
		return evidenceItem{}, err
	}
	return evidenceItem{
		ID: evidenceReference.String(), EntityID: entityID, ObjectReference: object.ObjectReference(), ArtifactReference: object.Reference().String(),
		ArtifactKey: object.Key(), ArtifactVersionID: object.VersionID(), ChecksumHex: hex.EncodeToString(checksum[:]), SizeBytes: object.Size(), MediaType: object.MediaType(),
		SchemaVersion: object.SchemaVersion(), ParserVersion: object.ParserVersion(), ToolVersion: object.ToolVersion(),
	}, nil
}

type evidenceItem struct {
	ID                string `json:"id"`
	EntityID          string `json:"entity_id"`
	ObjectReference   string `json:"object_reference"`
	ArtifactReference string `json:"artifact_reference"`
	ArtifactKey       string `json:"artifact_key"`
	ArtifactVersionID string `json:"artifact_version_id"`
	ChecksumHex       string `json:"checksum_hex"`
	SizeBytes         int64  `json:"size_bytes"`
	MediaType         string `json:"media_type"`
	SchemaVersion     string `json:"schema_version"`
	ParserVersion     string `json:"parser_version"`
	ToolVersion       string `json:"tool_version"`
}

type manifestDocument struct {
	Version          string               `json:"version"`
	RequestDigest    string               `json:"request_digest"`
	Provider         collection.Provider  `json:"provider"`
	Subject          manifestSubject      `json:"subject"`
	IntegrationID    string               `json:"integration_id"`
	ConnectionID     string               `json:"connection_id"`
	JobID            string               `json:"job_id"`
	Attempt          int                  `json:"attempt"`
	CollectorVersion string               `json:"collector_version"`
	CursorProvider   collection.Provider  `json:"cursor_provider"`
	CursorVersion    string               `json:"cursor_version"`
	CursorValue      string               `json:"cursor_value"`
	ParserVersion    string               `json:"parser_version"`
	ToolVersion      string               `json:"tool_version"`
	Objects          []manifestDescriptor `json:"objects"`
}

type manifestDescriptor struct {
	Reference       string `json:"reference"`
	Key             string `json:"key"`
	VersionID       string `json:"version_id"`
	ObjectReference string `json:"object_reference"`
	ChecksumHex     string `json:"checksum_hex"`
	SizeBytes       int64  `json:"size_bytes"`
	MediaType       string `json:"media_type"`
	SchemaVersion   string `json:"schema_version"`
}

type manifestSubject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func nextManifestDescriptorReserve(request collection.Request) (int64, error) {
	reference, err := deterministicEvidenceReference(request, "raw-page-010000")
	if err != nil {
		return 0, err
	}
	key := artifactKey(request.Scope, reference)
	maximumBucket := strings.Repeat("a", 63)
	encoded, err := json.Marshal(manifestDescriptor{
		Reference: reference.String(), Key: key, VersionID: strings.Repeat("<", 1024), ObjectReference: "s3://" + maximumBucket + "/" + key,
		ChecksumHex: strings.Repeat("f", sha256.Size*2), SizeBytes: request.Bounds.MaxRawBytes, MediaType: "application/json", SchemaVersion: rawSchemaVersion,
	})
	if err != nil || len(encoded) >= maximumArtifactBytes {
		return 0, collection.ErrContract
	}
	return int64(len(encoded) + 1), nil
}

func marshalManifest(request collection.Request, cursor collection.Cursor, objects []collection.RawObject) ([]byte, error) {
	requestDigest, err := collectionRequestDigest(request)
	if err != nil {
		return nil, err
	}
	descriptors := make([]manifestDescriptor, len(objects))
	for index, object := range objects {
		checksum := object.Checksum()
		descriptors[index] = manifestDescriptor{Reference: object.Reference().String(), Key: object.Key(), VersionID: object.VersionID(), ObjectReference: object.ObjectReference(), ChecksumHex: hex.EncodeToString(checksum[:]), SizeBytes: object.Size(), MediaType: object.MediaType(), SchemaVersion: object.SchemaVersion()}
	}
	return json.Marshal(manifestDocument{Version: manifestSchemaVersion, RequestDigest: hex.EncodeToString(requestDigest[:]), Provider: request.Provider, Subject: manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}, IntegrationID: request.IntegrationID.String(), ConnectionID: request.ConnectionID.String(), JobID: request.JobID.String(), Attempt: request.Attempt, CollectorVersion: request.CollectorVersion, CursorProvider: cursor.Provider, CursorVersion: cursor.Version, CursorValue: cursor.Value, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Objects: descriptors})
}

func rawObjectFromArtifact(request collection.Request, expected artifactstore.Locator, artifact artifactstore.Artifact, schema string, authority ArtifactAuthority) (collection.RawObject, error) {
	key := artifactKey(request.Scope, artifact.Reference)
	if artifact.Scope != expected.Scope || artifact.Reference != expected.Reference || expected.VersionID != "" || artifact.VersionID == "" || artifact.MediaType != "application/json" || artifact.Size != int64(len(artifact.Body)) || artifact.SHA256 != sha256.Sum256(artifact.Body) {
		return collection.RawObject{}, collection.ErrContract
	}
	objectReference, err := artifactObjectReference(authority, artifact.Locator)
	if err != nil {
		return collection.RawObject{}, collection.ErrContract
	}
	return collection.NewRawObject(request.Scope, artifact.Reference, key, artifact.VersionID, objectReference, artifact.SHA256, artifact.Size, artifact.MediaType, schema, request.ParserVersion, request.ToolVersion)
}

func deterministicEvidenceReference(request collection.Request, suffix string) (domain.EvidenceRef, error) {
	requestDigest, err := collectionRequestDigest(request)
	if err != nil {
		return domain.EvidenceRef{}, err
	}
	digest := sha256.Sum256(append(append([]byte{}, requestDigest[:]...), []byte("\x1f"+suffix)...))
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80
	text := fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
	id, err := domain.ParseProductID(text)
	if err != nil {
		return domain.EvidenceRef{}, err
	}
	return domain.NewEvidenceRef(id)
}

func collectionRequestDigest(request collection.Request) ([sha256.Size]byte, error) {
	type digestScope struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
	}
	type digestCursor struct {
		Provider collection.Provider `json:"provider"`
		Version  string              `json:"version"`
		Value    string              `json:"value"`
	}
	type digestBounds struct {
		MaxPages    int   `json:"max_pages"`
		MaxItems    int   `json:"max_items"`
		MaxRawBytes int64 `json:"max_raw_bytes"`
		TimeoutNS   int64 `json:"timeout_ns"`
	}
	type digestRequest struct {
		Scope               digestScope                `json:"scope"`
		IntegrationID       string                     `json:"integration_id"`
		ConnectionID        string                     `json:"connection_id"`
		JobID               string                     `json:"job_id"`
		Attempt             int                        `json:"attempt"`
		Provider            collection.Provider        `json:"provider"`
		CollectorVersion    string                     `json:"collector_version"`
		CredentialClass     collection.CredentialClass `json:"credential_class"`
		CredentialReference string                     `json:"credential_reference"`
		ExpectedSubject     collection.SubjectBinding  `json:"expected_subject"`
		Cursor              digestCursor               `json:"cursor"`
		ParserVersion       string                     `json:"parser_version"`
		ToolVersion         string                     `json:"tool_version"`
		Bounds              digestBounds               `json:"bounds"`
	}
	encoded, err := json.Marshal(digestRequest{
		Scope:         digestScope{OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String()},
		IntegrationID: request.IntegrationID.String(), ConnectionID: request.ConnectionID.String(), JobID: request.JobID.String(), Attempt: request.Attempt,
		Provider: request.Provider, CollectorVersion: request.CollectorVersion, CredentialClass: request.CredentialClass, CredentialReference: request.CredentialReference,
		ExpectedSubject: request.ExpectedSubject, Cursor: digestCursor{Provider: request.Cursor.Provider, Version: request.Cursor.Version, Value: request.Cursor.Value},
		ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion,
		Bounds: digestBounds{MaxPages: request.Bounds.MaxPages, MaxItems: request.Bounds.MaxItems, MaxRawBytes: request.Bounds.MaxRawBytes, TimeoutNS: int64(request.Bounds.Timeout)},
	})
	if err != nil {
		return [sha256.Size]byte{}, collection.ErrContract
	}
	return sha256.Sum256(encoded), nil
}

func artifactKey(scope domain.Scope, reference domain.EvidenceRef) string {
	return "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + reference.String()
}

func itemIdentity(value json.RawMessage) (string, bool) {
	var identity struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(value, &identity) != nil {
		return "", false
	}
	_, err := domain.ParseProductID(identity.ID)
	return identity.ID, err == nil
}

func identityForSort(value json.RawMessage) string {
	identity, _ := itemIdentity(value)
	return identity
}

func validJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' && safeJSON(trimmed)
}

func safeJSON(value []byte) bool {
	if !json.Valid(value) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded any
	return decoder.Decode(&decoded) == nil && noSecretFields(decoded)
}

func noSecretFields(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			switch compactJSONKey(key) {
			case "accesstoken", "refreshtoken", "sessiontoken", "idtoken", "bearertoken", "webidentitytoken", "clientsecret", "privatekey", "password", "credential", "credentials", "secret", "secretvalue", "apikey", "authorization", "cookie", "setcookie":
				return false
			}
			if !noSecretFields(child) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !noSecretFields(child) {
				return false
			}
		}
	}
	return true
}

func compactJSONKey(value string) string {
	var result strings.Builder
	result.Grow(len(value))
	for _, character := range strings.ToLower(value) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func validCursor(cursor collection.Cursor, provider collection.Provider) bool {
	if cursor.Provider != provider || !versionPattern.MatchString(cursor.Version) || len(cursor.Value) < 1 || len(cursor.Value) > 2048 || !utf8.ValidString(cursor.Value) || strings.TrimSpace(cursor.Value) != cursor.Value {
		return false
	}
	for _, character := range cursor.Value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validProvider(provider collection.Provider) bool {
	switch provider {
	case collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub, collection.ProviderOkta:
		return true
	default:
		return false
	}
}

func fetchPage(api API, ctx context.Context, credential []byte, request PageRequest) (page Page, resultErr error) {
	defer func() {
		if recover() != nil {
			page = Page{}
			resultErr = collection.ErrContract
		}
	}()
	return api.FetchCollectionPage(ctx, credential, request)
}

func checkReadiness(api API, ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = collection.ErrContract
		}
	}()
	return api.CheckCollectionReadiness(ctx)
}

func putArtifact(store artifactstore.ArtifactStore, ctx context.Context, request artifactstore.PutRequest) (artifact artifactstore.Artifact, resultErr error) {
	defer func() {
		if recover() != nil {
			artifact = artifactstore.Artifact{}
			resultErr = collection.ErrContract
		}
	}()
	return store.Put(ctx, request)
}

func artifactObjectReference(authority ArtifactAuthority, locator artifactstore.Locator) (reference string, resultErr error) {
	defer func() {
		if recover() != nil {
			reference = ""
			resultErr = collection.ErrContract
		}
	}()
	return authority.ObjectReference(locator)
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
