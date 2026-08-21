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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
)

const (
	rawSchemaVersion      = "raw_v1"
	manifestSchemaVersion = "manifest_v1"
	redactedPageVersion   = "redacted_page_v1"
	maximumArtifactBytes  = 64 * 1024 * 1024
)

var (
	errConfiguration             = errors.New("provider collection configuration rejected")
	ErrPageCapacity              = errors.New("provider collection page capacity reached")
	versionPattern               = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
	findingCheckPattern          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	credentialFingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type API interface {
	FetchCollectionPage(context.Context, []byte, PageRequest) (Page, error)
	CheckCollectionReadiness(context.Context) error
}

type ArtifactAuthority = artifactstore.ObjectReferencingArtifactStore

type PageRequest struct {
	Provider               collection.Provider
	Subject                collection.SubjectBinding
	Cursor                 collection.Cursor
	Page                   int
	RemainingItems         int
	RemainingRelationships int
	RemainingFindings      int
	RemainingBytes         int64
}

type Page struct {
	Subject       collection.SubjectBinding
	Cursor        collection.Cursor
	Raw           []byte
	Entities      []json.RawMessage
	Relationships []json.RawMessage
	Findings      []json.RawMessage
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
	Findings      []json.RawMessage   `json:"findings,omitempty"`
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

type typedSnapshotEntity struct {
	ID                      string          `json:"id"`
	Kind                    string          `json:"kind"`
	SourceNativeID          string          `json:"source_native_id"`
	DisplayName             string          `json:"display_name"`
	StableFields            json.RawMessage `json:"stable_fields"`
	Attributes              json.RawMessage `json:"attributes"`
	IdentityNamespace       string          `json:"identity_namespace"`
	IdentityRuleVersion     int             `json:"identity_rule_version"`
	IdentityPriority        int             `json:"identity_priority"`
	ProductKind             string          `json:"product_kind"`
	ConfidenceBasisPoints   int             `json:"confidence_basis_points"`
	ObservedAt              string          `json:"observed_at"`
	FreshUntil              string          `json:"fresh_until"`
	EvidenceID              string          `json:"evidence_id"`
	SourceProjectionVersion int             `json:"source_projection_version"`
}

type normalizedPageRelationship struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
	Attributes     json.RawMessage `json:"attributes"`
}

type normalizedPageFinding struct {
	ID         string `json:"id"`
	EntityID   string `json:"entity_id"`
	CheckID    string `json:"check_id"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	ObservedAt string `json:"observed_at"`
}

type inventoryFieldRule struct {
	kind     string
	required bool
	values   map[string]bool
}

type inventoryObjectSchema map[string]inventoryFieldRule

type providerEntityDefinition struct {
	stable     inventoryObjectSchema
	attributes inventoryObjectSchema
}

func NewPage(provider collection.Provider, subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) (Page, error) {
	return NewPageWithFindings(provider, subject, cursor, complete, entities, relationships, nil)
}

func NewPageWithFindings(provider collection.Provider, subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships, findings []json.RawMessage) (Page, error) {
	if !validProvider(provider) || !validCursor(cursor, provider) || !validNormalizedInventory(provider, entities, relationships) || !validProviderFindings(provider, findings) {
		return Page{}, collection.ErrContract
	}
	page := Page{Subject: subject, Cursor: cursor, Entities: cloneRawMessages(entities), Relationships: cloneRawMessages(relationships), Findings: cloneRawMessages(findings), Complete: complete}
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
	remainingEvidence := request.Bounds.MaxItems
	objects := make([]collection.RawObject, 0, request.Bounds.MaxPages)
	entities := make([]json.RawMessage, 0)
	relationships := make([]json.RawMessage, 0)
	findings := make([]json.RawMessage, 0)
	entityObjects := make(map[string]collection.RawObject)
	findingObjects := make(map[string]collection.RawObject)
	entitySourceIDs := make(map[string]struct{})
	entityBodies := make(map[string]json.RawMessage)
	findingIDs := make(map[string]struct{})
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
		findings = seed.findings
		entityObjects = seed.entityObjects
		findingObjects = seed.findingObjects
		entitySourceIDs = seed.entitySourceIDs
		entityBodies = seed.entityBodies
		relationshipIDs = seed.relationshipIDs
		relationshipSourceIDs = seed.relationshipSourceIDs
		remainingRawBytes -= seed.rawBytes
		remainingItems -= len(seed.entities)
		remainingRelationships -= len(seed.relationships)
		remainingEvidence -= len(seed.entities) + len(seed.findings)
		findingIDs = seed.findingIDs
		seededPages = len(seed.objects)
		for index, page := range seed.pages {
			typedEntities, evidenceLengths, typedErr := snapshotPageBudgetBodies(request, seed.budgetEntities[index], page.Findings, seed.entityObjects, seed.findingObjects)
			if typedErr != nil || len(evidenceLengths) != len(seed.evidenceLengths[index]) || !snapshotLimit.addPage(typedEntities, page.Relationships, evidenceLengths) {
				return nil, outcomeUnknown()
			}
		}
		if remainingRawBytes < 1 || remainingItems < 0 || remainingRelationships < 0 || remainingEvidence < 0 || seededPages > request.Bounds.MaxPages {
			return nil, outcomeUnknown()
		}
	}

	for pageNumber := seededPages + 1; pageNumber <= request.Bounds.MaxPages; pageNumber++ {
		if remainingItems < 1 || remainingRelationships < 1 {
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
		pageRequest := PageRequest{Provider: request.Provider, Subject: request.ExpectedSubject, Cursor: cursor, Page: pageNumber, RemainingItems: remainingItems, RemainingRelationships: remainingRelationships, RemainingFindings: remainingEvidence, RemainingBytes: remainingBytes}
		borrowed := bytes.Clone(credential)
		page, err := fetchPage(client.api, ctx, borrowed, pageRequest)
		clear(borrowed)
		if err != nil {
			if errors.Is(err, ErrPageCapacity) && len(objects) > 0 {
				break
			}
			if errors.Is(err, collection.ErrContract) {
				return nil, malformedFailure()
			}
			return nil, err
		}
		if !validPage(page, request, cursor, credential, remainingItems, remainingRelationships, remainingEvidence, remainingBytes) {
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
		pageEntityIDs := make([]string, 0, len(page.Entities))
		pageEntitySources := make([]string, 0, len(page.Entities))
		pageEntities := make([]json.RawMessage, 0, len(page.Entities))
		for _, entity := range page.Entities {
			identity, source, ok := entityIdentity(entity)
			if !ok {
				return nil, malformedFailure()
			}
			if _, exists := entityObjects[identity]; exists {
				if !coalescibleKubernetesPrincipal(request.Provider, entity) || !bytes.Equal(entityBodies[identity], entity) {
					return nil, malformedFailure()
				}
				if _, sourceExists := entitySourceIDs[source]; !sourceExists {
					return nil, malformedFailure()
				}
				continue
			}
			if _, exists := entitySourceIDs[source]; exists {
				return nil, malformedFailure()
			}
			pageEntityIDs = append(pageEntityIDs, identity)
			pageEntitySources = append(pageEntitySources, source)
			pageEntities = append(pageEntities, entity)
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
		pageFindingIDs := make([]string, len(page.Findings))
		for index, finding := range page.Findings {
			identity, entityID, ok := findingIdentity(finding)
			if !ok {
				return nil, malformedFailure()
			}
			if _, exists := findingIDs[identity]; exists {
				return nil, malformedFailure()
			}
			if _, exists := entityObjects[entityID]; !exists && !stringSliceContains(pageEntityIDs, entityID) {
				return nil, malformedFailure()
			}
			pageFindingIDs[index] = identity
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
		pageEntityObjects := make(map[string]collection.RawObject, len(pageEntityIDs))
		for _, identity := range pageEntityIDs {
			pageEntityObjects[identity] = object
		}
		pageFindingObjects := make(map[string]collection.RawObject, len(pageFindingIDs))
		for _, identity := range pageFindingIDs {
			pageFindingObjects[identity] = object
		}
		typedEntities, evidenceLengths, typedErr := snapshotPageBudgetBodies(request, pageEntities, page.Findings, pageEntityObjects, pageFindingObjects)
		if typedErr != nil || !snapshotLimit.addPage(typedEntities, page.Relationships, evidenceLengths) {
			return nil, malformedFailure()
		}
		objects = append(objects, object)
		for index, entity := range pageEntities {
			entityObjects[pageEntityIDs[index]] = object
			entitySourceIDs[pageEntitySources[index]] = struct{}{}
			entityBodies[pageEntityIDs[index]] = bytes.Clone(entity)
			entities = append(entities, bytes.Clone(entity))
		}
		for index, relationship := range page.Relationships {
			relationshipIDs[pageRelationshipIDs[index]] = struct{}{}
			relationshipSourceIDs[pageRelationshipSources[index]] = struct{}{}
			relationships = append(relationships, bytes.Clone(relationship))
		}
		for index, finding := range page.Findings {
			findingIDs[pageFindingIDs[index]] = struct{}{}
			findingObjects[pageFindingIDs[index]] = object
			findings = append(findings, bytes.Clone(finding))
		}
		remainingItems -= len(pageEntities)
		remainingRelationships -= len(page.Relationships)
		remainingEvidence -= len(pageEntities) + len(page.Findings)
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
	if complete {
		var resolved bool
		relationships, resolved = relationshipsResolve(request.Provider, request.ExpectedSubject, relationships, entities, entityObjects)
		if !resolved {
			return nil, malformedFailure()
		}
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

	entityBody, relationshipBody, evidenceBody, err := snapshotBodies(request, entities, relationships, findings, entityObjects, findingObjects)
	if err != nil {
		return nil, malformedFailure()
	}
	var snapshot collection.SnapshotCandidate
	if request.ObservationTime.IsZero() {
		snapshot, err = collection.NewSnapshotCandidate(request.Provider, request.ParserVersion, request.ToolVersion, entityBody, relationshipBody, evidenceBody)
	} else {
		snapshot, err = collection.NewTypedSnapshotCandidate(request.Provider, request.ParserVersion, request.ToolVersion, entityBody, relationshipBody, evidenceBody)
	}
	if err != nil {
		return nil, malformedFailure()
	}
	result, err := collection.NewCompleteResult(request, request.ExpectedSubject, cursor, manifest, snapshot)
	if err != nil {
		return nil, collection.ErrContract
	}
	return result, nil
}

func validPage(page Page, request collection.Request, prior collection.Cursor, credential []byte, remainingItems, remainingRelationships, remainingEvidence int, remainingBytes int64) bool {
	canonical, err := canonicalPageBody(request.Provider, page)
	if page.Subject != request.ExpectedSubject || !validCursor(page.Cursor, request.Provider) || page.Cursor == prior || err != nil || len(page.Raw) == 0 || len(page.Raw) > maximumArtifactBytes || int64(len(page.Raw)) > remainingBytes || !bytes.Equal(canonical, page.Raw) || bytes.Contains(page.Raw, credential) || len(page.Entities) > remainingItems || len(page.Relationships) > remainingRelationships || len(page.Entities)+len(page.Findings) > remainingEvidence {
		return false
	}
	return validNormalizedInventory(request.Provider, page.Entities, page.Relationships) && validProviderFindings(request.Provider, page.Findings)
}

func canonicalPageBody(provider collection.Provider, page Page) ([]byte, error) {
	if !validNormalizedInventory(provider, page.Entities, page.Relationships) {
		return nil, collection.ErrContract
	}
	return json.Marshal(redactedPageDocument{
		Version: redactedPageVersion, Provider: provider, Subject: manifestSubject{Kind: page.Subject.Kind, ID: page.Subject.ID},
		Cursor: redactedPageCursor{Provider: page.Cursor.Provider, Version: page.Cursor.Version, Value: page.Cursor.Value}, Complete: page.Complete,
		Entities: cloneRawMessages(page.Entities), Relationships: cloneRawMessages(page.Relationships), Findings: cloneRawMessages(page.Findings),
	})
}

func validProviderFindings(provider collection.Provider, findings []json.RawMessage) bool {
	if len(findings) == 0 {
		return true
	}
	if provider != collection.ProviderAWS || len(findings) > 100_000 {
		return false
	}
	seen := make(map[string]struct{}, len(findings))
	previous := ""
	var total int64
	for _, raw := range findings {
		total += int64(len(raw))
		identity, _, ok := findingIdentity(raw)
		if !ok || identity <= previous || total > maximumArtifactBytes {
			return false
		}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
		previous = identity
	}
	return true
}

func findingIdentity(raw json.RawMessage) (string, string, bool) {
	var finding normalizedPageFinding
	if !decodeExactObject(raw, &finding) || !validProductIDText(finding.ID) || !validProductIDText(finding.EntityID) || !findingCheckPattern.MatchString(finding.CheckID) || finding.Severity != "high" || finding.Status != "PASS" && finding.Status != "FAIL" {
		return "", "", false
	}
	observed, err := time.Parse(time.RFC3339, finding.ObservedAt)
	if err != nil || observed.Location() != time.UTC || observed.Nanosecond() != 0 || observed.Format(time.RFC3339) != finding.ObservedAt {
		return "", "", false
	}
	return finding.ID, finding.EntityID, true
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validNormalizedInventory(provider collection.Provider, entities, relationships []json.RawMessage) bool {
	if len(entities) > 100_000 || len(relationships) > 200_000 {
		return false
	}
	var total int64
	entityIDs := make(map[string]struct{}, len(entities))
	entitySourceIDs := make(map[string]struct{}, len(entities))
	entityKinds := make(map[string]string, len(entities))
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
		var normalized normalizedPageEntity
		if !decodeExactObject(entity, &normalized) {
			return false
		}
		entityKinds[identity] = normalized.Kind
	}
	relationshipIDs := make(map[string]struct{}, len(relationships))
	relationshipSourceIDs := make(map[string]struct{}, len(relationships))
	for _, relationship := range relationships {
		total += int64(len(relationship))
		if total > maximumArtifactBytes {
			return false
		}
		if !validProviderRelationship(provider, relationship) {
			return false
		}
		identity, source, from, to, ok := relationshipIdentity(relationship)
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
		fromKind, fromPresent := entityKinds[from]
		toKind, toPresent := entityKinds[to]
		if fromPresent && toPresent && !validProviderRelationshipEndpointKinds(provider, relationship, fromKind, toKind) {
			return false
		}
	}
	return true
}

func validProviderEntity(provider collection.Provider, raw json.RawMessage) bool {
	var entity normalizedPageEntity
	if !decodeExactObject(raw, &entity) || !validProductIDText(entity.ID) || !boundedInventoryText(entity.SourceNativeID, 1024) || !boundedInventoryText(entity.DisplayName, 256) {
		return false
	}
	definition, ok := providerEntitySchema(provider, entity.Kind)
	if !ok || !validInventoryObject(entity.StableFields, definition.stable) || !validInventoryObject(entity.Attributes, definition.attributes) {
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

func providerEntitySchema(provider collection.Provider, kind string) (providerEntityDefinition, bool) {
	state := optionalStringFields("state", "status")
	switch provider {
	case collection.ProviderAWS:
		switch kind {
		case "aws_account":
			return providerEntityDefinition{stable: requiredStringFields("account_id"), attributes: state}, true
		case "aws_policy":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("account_id", "arn", "name"), inventoryObjectSchema{"policy_type": enumInventoryField(true, "managed", "inline", "resource")}), attributes: state}, true
		case "aws_role":
			return providerEntityDefinition{stable: requiredStringFields("account_id", "arn", "name"), attributes: state}, true
		case "aws_resource":
			return providerEntityDefinition{stable: requiredStringFields("account_id", "arn", "name", "region", "resource_type"), attributes: state}, true
		case "aws_service":
			return providerEntityDefinition{stable: requiredStringFields("account_id", "name", "service"), attributes: state}, true
		}
	case collection.ProviderKubernetes:
		namespaced := mergeInventorySchemas(inventoryObjectSchema{"namespaced": boolInventoryField(true, true)}, state)
		clusterScoped := mergeInventorySchemas(inventoryObjectSchema{"namespaced": boolInventoryField(true, false)}, state)
		switch kind {
		case "kubernetes_cluster":
			return providerEntityDefinition{stable: requiredStringFields("cluster", "name"), attributes: state}, true
		case "kubernetes_namespace":
			return providerEntityDefinition{stable: requiredStringFields("cluster", "name", "namespace"), attributes: state}, true
		case "kubernetes_resource", "kubernetes_service_account":
			return providerEntityDefinition{stable: requiredStringFields("api_group", "api_version", "cluster", "name", "namespace", "resource_kind"), attributes: namespaced}, true
		case "kubernetes_agent":
			return providerEntityDefinition{stable: requiredStringFields("api_group", "api_version", "cluster", "name", "namespace", "resource_kind", "service_account"), attributes: mergeInventorySchemas(namespaced, inventoryObjectSchema{"posture": kubernetesAgentPostureInventoryField(true)})}, true
		case "kubernetes_workload":
			return providerEntityDefinition{stable: requiredStringFields("api_group", "api_version", "cluster", "name", "namespace", "resource_kind", "service_account"), attributes: namespaced}, true
		case "kubernetes_role":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("api_group", "api_version", "cluster", "name", "namespace", "resource_kind"), inventoryObjectSchema{"scope": enumInventoryField(true, "namespace")}), attributes: mergeInventorySchemas(namespaced, inventoryObjectSchema{"rules": kubernetesRulesInventoryField(true)})}, true
		case "kubernetes_cluster_role":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("api_group", "api_version", "cluster", "name", "resource_kind"), inventoryObjectSchema{"scope": enumInventoryField(true, "cluster")}), attributes: mergeInventorySchemas(clusterScoped, inventoryObjectSchema{"rules": kubernetesRulesInventoryField(true)})}, true
		case "kubernetes_role_binding":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("api_group", "api_version", "cluster", "name", "namespace", "resource_kind", "role"), inventoryObjectSchema{"scope": enumInventoryField(true, "namespace")}), attributes: namespaced}, true
		case "kubernetes_cluster_role_binding":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("api_group", "api_version", "cluster", "name", "resource_kind", "role"), inventoryObjectSchema{"scope": enumInventoryField(true, "cluster")}), attributes: clusterScoped}, true
		case "kubernetes_user":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("cluster", "name"), inventoryObjectSchema{"scope": enumInventoryField(true, "cluster"), "subject_type": enumInventoryField(true, "User")}), attributes: state}, true
		case "kubernetes_group":
			return providerEntityDefinition{stable: mergeInventorySchemas(requiredStringFields("cluster", "name"), inventoryObjectSchema{"scope": enumInventoryField(true, "cluster"), "subject_type": enumInventoryField(true, "Group")}), attributes: state}, true
		}
	case collection.ProviderGitHub:
		installation := inventoryObjectSchema{"installation_id": numberInventoryField(true)}
		switch kind {
		case "github_installation":
			return providerEntityDefinition{stable: mergeInventorySchemas(installation, requiredStringFields("owner")), attributes: inventoryObjectSchema{}}, true
		case "github_organization", "github_app":
			return providerEntityDefinition{stable: mergeInventorySchemas(installation, requiredStringFields("name", "owner")), attributes: state}, true
		case "github_repository":
			return providerEntityDefinition{stable: mergeInventorySchemas(installation, requiredStringFields("name", "owner", "repository"), inventoryObjectSchema{"visibility": enumInventoryField(true, "public", "private", "internal")}), attributes: mergeInventorySchemas(inventoryObjectSchema{"archived": boolInventoryField(true), "default_branch": stringInventoryField(true)}, state)}, true
		case "github_workflow":
			return providerEntityDefinition{stable: mergeInventorySchemas(installation, requiredStringFields("name", "owner", "repository", "workflow")), attributes: state}, true
		case "github_environment":
			return providerEntityDefinition{stable: mergeInventorySchemas(installation, requiredStringFields("name", "owner", "repository")), attributes: state}, true
		case "github_permission":
			return providerEntityDefinition{stable: mergeInventorySchemas(installation, requiredStringFields("name", "owner", "permission", "repository", "scope")), attributes: state}, true
		}
	case collection.ProviderOkta:
		switch kind {
		case "okta_tenant":
			return providerEntityDefinition{stable: requiredStringFields("name", "tenant"), attributes: inventoryObjectSchema{}}, true
		case "okta_user", "okta_group", "okta_application", "okta_service_principal":
			return providerEntityDefinition{stable: requiredStringFields("name", "object_type", "tenant"), attributes: inventoryObjectSchema{"status": stringInventoryField(true), "state": stringInventoryField(false)}}, true
		case "okta_role":
			return providerEntityDefinition{stable: requiredStringFields("name", "object_type", "role", "scope", "tenant"), attributes: state}, true
		}
	}
	return providerEntityDefinition{}, false
}

func validProviderRelationship(provider collection.Provider, raw json.RawMessage) bool {
	var relationship normalizedPageRelationship
	if !decodeExactObject(raw, &relationship) || !validProductIDText(relationship.ID) || !validProductIDText(relationship.FromEntityID) || !validProductIDText(relationship.ToEntityID) || relationship.FromEntityID == relationship.ToEntityID || !boundedInventoryText(relationship.SourceNativeID, 1024) {
		return false
	}
	var kinds map[string]bool
	attributes := optionalStringFields("state", "type")
	switch provider {
	case collection.ProviderAWS:
		kinds = tokenSet("belongs_to", "contains", "depends_on", "trusts", "uses_policy")
	case collection.ProviderKubernetes:
		kinds = tokenSet("assigned_to", "attached_to", "binds", "contains", "uses_identity")
		attributes["type"] = stringInventoryField(true)
	case collection.ProviderGitHub:
		kinds = tokenSet("belongs_to", "contains", "depends_on", "has_permission", "owns", "uses_identity")
		attributes["type"] = stringInventoryField(true)
	case collection.ProviderOkta:
		kinds = tokenSet("assigned_to", "contains", "has_permission", "member_of")
		attributes["type"] = stringInventoryField(true)
	default:
		return false
	}
	return kinds[relationship.Kind] && validInventoryObject(relationship.Attributes, attributes)
}

func validProviderRelationshipEndpointKinds(provider collection.Provider, raw json.RawMessage, fromKind, toKind string) bool {
	var relationship normalizedPageRelationship
	if !decodeExactObject(raw, &relationship) {
		return false
	}
	key := fromKind + "|" + relationship.Kind + "|" + toKind
	allowed := map[collection.Provider]map[string]bool{
		collection.ProviderAWS: tokenSet(
			"aws_account|contains|aws_policy", "aws_account|contains|aws_resource", "aws_account|contains|aws_role", "aws_account|contains|aws_service",
			"aws_resource|belongs_to|aws_account", "aws_resource|belongs_to|aws_service", "aws_resource|depends_on|aws_resource", "aws_role|trusts|aws_role", "aws_role|uses_policy|aws_policy",
		),
		collection.ProviderKubernetes: tokenSet(
			"kubernetes_cluster|contains|kubernetes_cluster_role", "kubernetes_cluster|contains|kubernetes_cluster_role_binding", "kubernetes_cluster|contains|kubernetes_namespace",
			"kubernetes_namespace|attached_to|kubernetes_agent", "kubernetes_namespace|attached_to|kubernetes_resource", "kubernetes_namespace|attached_to|kubernetes_workload",
			"kubernetes_namespace|contains|kubernetes_role", "kubernetes_namespace|contains|kubernetes_role_binding", "kubernetes_namespace|contains|kubernetes_service_account",
			"kubernetes_role_binding|binds|kubernetes_cluster_role", "kubernetes_role_binding|binds|kubernetes_role", "kubernetes_cluster_role_binding|binds|kubernetes_cluster_role",
			"kubernetes_group|assigned_to|kubernetes_cluster_role_binding", "kubernetes_group|assigned_to|kubernetes_role_binding", "kubernetes_service_account|assigned_to|kubernetes_cluster_role_binding", "kubernetes_service_account|assigned_to|kubernetes_role_binding", "kubernetes_user|assigned_to|kubernetes_cluster_role_binding", "kubernetes_user|assigned_to|kubernetes_role_binding",
			"kubernetes_agent|uses_identity|kubernetes_service_account", "kubernetes_workload|uses_identity|kubernetes_service_account",
		),
		collection.ProviderGitHub: tokenSet(
			"github_installation|contains|github_app", "github_installation|owns|github_repository", "github_organization|owns|github_repository", "github_repository|contains|github_environment", "github_repository|contains|github_permission", "github_repository|contains|github_workflow", "github_workflow|depends_on|github_repository", "github_workflow|uses_identity|github_app", "github_app|has_permission|github_permission",
		),
		collection.ProviderOkta: tokenSet(
			"okta_tenant|contains|okta_application", "okta_tenant|contains|okta_group", "okta_tenant|contains|okta_role", "okta_tenant|contains|okta_service_principal", "okta_tenant|contains|okta_user", "okta_group|assigned_to|okta_application", "okta_service_principal|assigned_to|okta_application", "okta_user|assigned_to|okta_application", "okta_service_principal|assigned_to|okta_role", "okta_user|assigned_to|okta_role", "okta_group|assigned_to|okta_role", "okta_service_principal|member_of|okta_group", "okta_user|member_of|okta_group",
		),
	}
	return allowed[provider][key]
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

func validInventoryObject(raw json.RawMessage, schema inventoryObjectSchema) bool {
	if !validJSONObject(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fields map[string]any
	if decoder.Decode(&fields) != nil || fields == nil {
		return false
	}
	for name, rule := range schema {
		if _, present := fields[name]; rule.required && !present {
			return false
		}
	}
	for name, value := range fields {
		rule, allowed := schema[name]
		if !allowed {
			return false
		}
		switch rule.kind {
		case "string":
			text, ok := value.(string)
			if !ok || !boundedInventoryText(text, 2048) || len(rule.values) > 0 && !rule.values[text] || !validInventoryFieldText(name, text) {
				return false
			}
		case "number":
			number, ok := value.(json.Number)
			integer, err := number.Int64()
			if !ok || err != nil || integer < 1 || integer > 1<<53 || len(rule.values) > 0 && !rule.values[number.String()] {
				return false
			}
		case "bool":
			boolean, ok := value.(bool)
			if !ok || len(rule.values) > 0 && !rule.values[strconv.FormatBool(boolean)] {
				return false
			}
		case "kubernetes_rules":
			if !validCanonicalKubernetesRules(value) {
				return false
			}
		case "kubernetes_agent_posture":
			if !validKubernetesAgentPosture(value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validInventoryFieldText(name, value string) bool {
	switch name {
	case "account_id":
		return len(value) == 12 && strings.IndexFunc(value, func(character rune) bool { return character < '0' || character > '9' }) == -1
	case "arn":
		return strings.HasPrefix(value, "arn:") && strings.Count(value, ":") >= 5
	case "resource_kind":
		return !strings.EqualFold(value, "Secret")
	default:
		return true
	}
}

func requiredStringFields(names ...string) inventoryObjectSchema {
	result := make(inventoryObjectSchema, len(names))
	for _, name := range names {
		result[name] = stringInventoryField(true)
	}
	return result
}

func optionalStringFields(names ...string) inventoryObjectSchema {
	result := make(inventoryObjectSchema, len(names))
	for _, name := range names {
		result[name] = stringInventoryField(false)
	}
	return result
}

func stringInventoryField(required bool) inventoryFieldRule {
	return inventoryFieldRule{kind: "string", required: required}
}

func numberInventoryField(required bool) inventoryFieldRule {
	return inventoryFieldRule{kind: "number", required: required}
}

func boolInventoryField(required bool, values ...bool) inventoryFieldRule {
	allowed := make(map[string]bool, len(values))
	for _, value := range values {
		allowed[strconv.FormatBool(value)] = true
	}
	return inventoryFieldRule{kind: "bool", required: required, values: allowed}
}

func kubernetesRulesInventoryField(required bool) inventoryFieldRule {
	return inventoryFieldRule{kind: "kubernetes_rules", required: required}
}

func kubernetesAgentPostureInventoryField(required bool) inventoryFieldRule {
	return inventoryFieldRule{kind: "kubernetes_agent_posture", required: required}
}

func validKubernetesAgentPosture(value any) bool {
	posture, ok := value.(map[string]any)
	if !ok || len(posture) != 18 {
		return false
	}
	credentialFingerprint, ok := posture["credential_fingerprint"].(string)
	if !ok || credentialFingerprint != "" && !credentialFingerprintPattern.MatchString(credentialFingerprint) {
		return false
	}
	for _, field := range []string{
		"human_credential", "untrusted_input", "production_write", "shell_execution", "production_credential",
		"unrestricted_egress", "sensitive_data_reach", "unapproved_remote_tool", "destructive_tool", "runtime_control",
		"production_agent", "runtime_policy_supported", "host_filesystem", "privileged", "cicd_write",
		"production_secret_reach", "credential_active",
	} {
		if _, ok := posture[field].(bool); !ok {
			return false
		}
	}
	return true
}

func validCanonicalKubernetesRules(value any) bool {
	rules, ok := value.([]any)
	if !ok || len(rules) > 64 {
		return false
	}
	prior := ""
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok || len(rule) != 5 {
			return false
		}
		for _, field := range []string{"api_groups", "non_resource_urls", "resource_names", "resources", "verbs"} {
			if !validSortedKubernetesRuleValues(rule[field], field == "api_groups") {
				return false
			}
		}
		verbs := rule["verbs"].([]any)
		resources := rule["resources"].([]any)
		nonResourceURLs := rule["non_resource_urls"].([]any)
		if len(verbs) == 0 || len(resources) == 0 && len(nonResourceURLs) == 0 || len(nonResourceURLs) > 0 && (len(resources) > 0 || len(rule["resource_names"].([]any)) > 0 || len(rule["api_groups"].([]any)) > 0) {
			return false
		}
		encoded, err := json.Marshal(rule)
		if err != nil || prior != "" && string(encoded) <= prior {
			return false
		}
		prior = string(encoded)
	}
	return true
}

func validSortedKubernetesRuleValues(value any, allowEmpty bool) bool {
	values, ok := value.([]any)
	if !ok || len(values) > 32 {
		return false
	}
	prior := ""
	for index, raw := range values {
		text, ok := raw.(string)
		if !ok || text == "" && !allowEmpty || text != "" && !boundedInventoryText(text, 256) || index > 0 && text <= prior {
			return false
		}
		prior = text
	}
	return true
}

func enumInventoryField(required bool, values ...string) inventoryFieldRule {
	return inventoryFieldRule{kind: "string", required: required, values: tokenSet(values...)}
}

func mergeInventorySchemas(schemas ...inventoryObjectSchema) inventoryObjectSchema {
	result := inventoryObjectSchema{}
	for _, schema := range schemas {
		for name, rule := range schema {
			result[name] = rule
		}
	}
	return result
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
	if budget == nil || budget.limit < 6 || len(evidenceLengths) < len(entities) {
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

func coalescibleKubernetesPrincipal(provider collection.Provider, value json.RawMessage) bool {
	if provider != collection.ProviderKubernetes {
		return false
	}
	var entity normalizedPageEntity
	if !decodeExactObject(value, &entity) {
		return false
	}
	switch entity.Kind {
	case "kubernetes_user", "kubernetes_group", "kubernetes_service_account":
		return true
	default:
		return false
	}
}

func relationshipIdentity(value json.RawMessage) (string, string, string, string, bool) {
	var relationship normalizedPageRelationship
	if !decodeExactObject(value, &relationship) || !validProductIDText(relationship.ID) || !boundedInventoryText(relationship.SourceNativeID, 1024) || !validProductIDText(relationship.FromEntityID) || !validProductIDText(relationship.ToEntityID) {
		return "", "", "", "", false
	}
	return relationship.ID, relationship.SourceNativeID, relationship.FromEntityID, relationship.ToEntityID, true
}

func relationshipsResolve(provider collection.Provider, subject collection.SubjectBinding, relationships, rawEntities []json.RawMessage, entities map[string]collection.RawObject) ([]json.RawMessage, bool) {
	items := make(map[string]normalizedPageEntity, len(rawEntities))
	for _, raw := range rawEntities {
		var entity normalizedPageEntity
		if !decodeExactObject(raw, &entity) {
			return nil, false
		}
		items[entity.ID] = entity
	}
	resolved := make([]json.RawMessage, 0, len(relationships))
	for _, raw := range relationships {
		_, _, from, to, ok := relationshipIdentity(raw)
		if !ok {
			return nil, false
		}
		_, fromExists := entities[from]
		_, toExists := entities[to]
		if !fromExists || !toExists {
			if provider == collection.ProviderKubernetes && validExplicitKubernetesUnresolvedRelationship(raw, subject, fromExists, toExists, items) {
				continue
			}
			return nil, false
		}
		if !validProviderRelationshipEndpointKinds(provider, raw, items[from].Kind, items[to].Kind) {
			return nil, false
		}
		resolved = append(resolved, raw)
	}
	return resolved, true
}

func validExplicitKubernetesUnresolvedRelationship(raw json.RawMessage, subject collection.SubjectBinding, fromExists, toExists bool, items map[string]normalizedPageEntity) bool {
	var relationship normalizedPageRelationship
	if !decodeExactObject(raw, &relationship) || !fromExists || toExists {
		return false
	}
	source, ok := items[relationship.FromEntityID]
	if !ok {
		return false
	}
	var attributes struct {
		Type string `json:"type"`
	}
	if !decodeExactObject(relationship.Attributes, &attributes) {
		return false
	}
	switch relationship.Kind {
	case "binds":
		stable, ok := inventoryStringValues(source.StableFields, "role")
		if attributes.Type != "binding_role" || !ok {
			return false
		}
		roleKind, roleName, found := strings.Cut(stable["role"], "/")
		if !found || roleName == "" {
			return false
		}
		var targetKind, nativeID string
		switch roleKind {
		case "Role":
			namespace, namespaceOK := inventoryStringValues(source.StableFields, "namespace")
			if source.Kind != "kubernetes_role_binding" || !namespaceOK {
				return false
			}
			targetKind, nativeID = "kubernetes_role", namespace["namespace"]+"/"+roleName
		case "ClusterRole":
			if source.Kind != "kubernetes_role_binding" && source.Kind != "kubernetes_cluster_role_binding" {
				return false
			}
			targetKind, nativeID = "kubernetes_cluster_role", roleName
		default:
			return false
		}
		return relationship.ToEntityID == deterministicKubernetesReferenceID(subject, targetKind, nativeID)
	case "uses_identity":
		stable, ok := inventoryStringValues(source.StableFields, "namespace", "service_account")
		return attributes.Type == "workload_service_account" && (source.Kind == "kubernetes_agent" || source.Kind == "kubernetes_workload") &&
			ok && stable["namespace"] != "" && stable["service_account"] != "" &&
			relationship.ToEntityID == deterministicKubernetesReferenceID(subject, "kubernetes_service_account", stable["namespace"]+"/"+stable["service_account"])
	default:
		return false
	}
}

func inventoryStringValues(raw json.RawMessage, keys ...string) (map[string]string, bool) {
	var object map[string]json.RawMessage
	if !decodeExactObject(raw, &object) {
		return nil, false
	}
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		value, exists := object[key]
		var decoded string
		if !exists || json.Unmarshal(value, &decoded) != nil || decoded == "" {
			return nil, false
		}
		result[key] = decoded
	}
	return result, true
}

func deterministicKubernetesReferenceID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("kubernetes\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func snapshotBodies(request collection.Request, entities, relationships, findings []json.RawMessage, entityObjects, findingObjects map[string]collection.RawObject) ([]byte, []byte, []byte, error) {
	sort.Slice(entities, func(left, right int) bool { return identityForSort(entities[left]) < identityForSort(entities[right]) })
	sort.Slice(relationships, func(left, right int) bool {
		return identityForSort(relationships[left]) < identityForSort(relationships[right])
	})
	sort.Slice(findings, func(left, right int) bool { return identityForSort(findings[left]) < identityForSort(findings[right]) })
	evidence := make([]evidenceItem, 0, len(entities)+len(findings))
	snapshotEntities := make([]json.RawMessage, 0, len(entities))
	for _, entity := range entities {
		entityID, ok := itemIdentity(entity)
		object, exists := entityObjects[entityID]
		if !ok || !exists {
			return nil, nil, nil, collection.ErrContract
		}
		typed, item, err := snapshotEntity(request, entity, object)
		if err != nil {
			return nil, nil, nil, err
		}
		evidence = append(evidence, item)
		snapshotEntities = append(snapshotEntities, typed)
	}
	for _, finding := range findings {
		findingID, _, ok := findingIdentity(finding)
		object, exists := findingObjects[findingID]
		if !ok || !exists {
			return nil, nil, nil, collection.ErrContract
		}
		item, itemErr := evidenceForFinding(request, finding, object)
		if itemErr != nil {
			return nil, nil, nil, itemErr
		}
		evidence = append(evidence, item)
	}
	sort.Slice(evidence, func(left, right int) bool { return evidence[left].ID < evidence[right].ID })
	entityBody, entityErr := json.Marshal(snapshotEntities)
	relationshipBody, relationshipErr := json.Marshal(relationships)
	evidenceBody, evidenceErr := json.Marshal(evidence)
	if entityErr != nil || relationshipErr != nil || evidenceErr != nil {
		return nil, nil, nil, collection.ErrContract
	}
	return entityBody, relationshipBody, evidenceBody, nil
}

func snapshotPageBudgetBodies(request collection.Request, entities, findings []json.RawMessage, entityObjects, findingObjects map[string]collection.RawObject) ([]json.RawMessage, []int, error) {
	typed := make([]json.RawMessage, len(entities))
	evidenceLengths := make([]int, 0, len(entities)+len(findings))
	for index, entity := range entities {
		identity, ok := itemIdentity(entity)
		object, exists := entityObjects[identity]
		if !ok || !exists {
			return nil, nil, collection.ErrContract
		}
		value, evidence, err := snapshotEntity(request, entity, object)
		encodedEvidence, encodeErr := json.Marshal(evidence)
		if err != nil || encodeErr != nil {
			return nil, nil, collection.ErrContract
		}
		typed[index] = value
		evidenceLengths = append(evidenceLengths, len(encodedEvidence))
	}
	for _, finding := range findings {
		identity, _, ok := findingIdentity(finding)
		object, exists := findingObjects[identity]
		if !ok || !exists {
			return nil, nil, collection.ErrContract
		}
		item, err := evidenceForFinding(request, finding, object)
		encoded, encodeErr := json.Marshal(item)
		if err != nil || encodeErr != nil {
			return nil, nil, collection.ErrContract
		}
		evidenceLengths = append(evidenceLengths, len(encoded))
	}
	return typed, evidenceLengths, nil
}

func snapshotEntity(request collection.Request, entity json.RawMessage, object collection.RawObject) (json.RawMessage, evidenceItem, error) {
	entityID, ok := itemIdentity(entity)
	if !ok {
		return nil, evidenceItem{}, collection.ErrContract
	}
	item, err := evidenceForEntity(request, entityID, object)
	if err != nil {
		return nil, evidenceItem{}, err
	}
	if request.ObservationTime.IsZero() {
		return bytes.Clone(entity), item, nil
	}
	var raw normalizedPageEntity
	if !decodeExactObject(entity, &raw) {
		return nil, evidenceItem{}, collection.ErrContract
	}
	rule, exists := inventoryprojection.LookupRule(string(request.Provider), raw.Kind)
	if !exists {
		return nil, evidenceItem{}, collection.ErrContract
	}
	typed, marshalErr := json.Marshal(typedSnapshotEntity{
		ID: raw.ID, Kind: raw.Kind, SourceNativeID: raw.SourceNativeID, DisplayName: raw.DisplayName, StableFields: raw.StableFields, Attributes: raw.Attributes,
		IdentityNamespace: rule.Namespace, IdentityRuleVersion: rule.Version, IdentityPriority: rule.Priority, ProductKind: string(rule.ProductKind), ConfidenceBasisPoints: rule.ConfidenceBasisPoints,
		ObservedAt: request.ObservationTime.Format(time.RFC3339), FreshUntil: request.ObservationTime.Add(rule.Freshness).Format(time.RFC3339), EvidenceID: item.ID, SourceProjectionVersion: rule.Version,
	})
	if marshalErr != nil {
		return nil, evidenceItem{}, collection.ErrContract
	}
	return typed, item, nil
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

func evidenceForFinding(request collection.Request, raw json.RawMessage, object collection.RawObject) (evidenceItem, error) {
	var finding normalizedPageFinding
	if !decodeExactObject(raw, &finding) {
		return evidenceItem{}, collection.ErrContract
	}
	checksum := object.Checksum()
	evidenceReference, err := deterministicEvidenceReference(request, "finding:"+finding.ID+":"+object.Reference().String())
	if err != nil {
		return evidenceItem{}, err
	}
	return evidenceItem{
		ID: evidenceReference.String(), EntityID: finding.EntityID, FindingID: finding.ID, CheckID: finding.CheckID,
		Severity: finding.Severity, Status: finding.Status, ObservedAt: finding.ObservedAt,
		ObjectReference: object.ObjectReference(), ArtifactReference: object.Reference().String(), ArtifactKey: object.Key(),
		ArtifactVersionID: object.VersionID(), ChecksumHex: hex.EncodeToString(checksum[:]), SizeBytes: object.Size(),
		MediaType: object.MediaType(), SchemaVersion: object.SchemaVersion(), ParserVersion: object.ParserVersion(), ToolVersion: object.ToolVersion(),
	}, nil
}

type evidenceItem struct {
	ID                string `json:"id"`
	EntityID          string `json:"entity_id"`
	FindingID         string `json:"finding_id,omitempty"`
	CheckID           string `json:"check_id,omitempty"`
	Severity          string `json:"severity,omitempty"`
	Status            string `json:"status,omitempty"`
	ObservedAt        string `json:"observed_at,omitempty"`
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
		ObservationTime     string                     `json:"observation_time,omitempty"`
		Bounds              digestBounds               `json:"bounds"`
	}
	observationTime := ""
	if !request.ObservationTime.IsZero() {
		observationTime = request.ObservationTime.Format(time.RFC3339)
	}
	encoded, err := json.Marshal(digestRequest{
		Scope:         digestScope{OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String()},
		IntegrationID: request.IntegrationID.String(), ConnectionID: request.ConnectionID.String(), JobID: request.JobID.String(), Attempt: request.Attempt,
		Provider: request.Provider, CollectorVersion: request.CollectorVersion, CredentialClass: request.CredentialClass, CredentialReference: request.CredentialReference,
		ExpectedSubject: request.ExpectedSubject, Cursor: digestCursor{Provider: request.Cursor.Provider, Version: request.Cursor.Version, Value: request.Cursor.Value},
		ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, ObservationTime: observationTime,
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
