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
	maximumArtifactBytes  = 64 * 1024 * 1024
)

var (
	errConfiguration = errors.New("provider collection configuration rejected")
	versionPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
	bucketPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

type API interface {
	FetchCollectionPage(context.Context, []byte, PageRequest) (Page, error)
	CheckCollectionReadiness(context.Context) error
}

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

type Config struct {
	Provider         collection.Provider
	API              API
	Artifacts        artifactstore.ArtifactStore
	Bucket           string
	CollectorVersion string
	Clock            func() time.Time
}

type Client struct {
	provider         collection.Provider
	api              API
	artifacts        artifactstore.ArtifactStore
	bucket           string
	collectorVersion string
	clock            func() time.Time
}

func New(config Config) (*Client, error) {
	if !validProvider(config.Provider) || nilInterface(config.API) || nilInterface(config.Artifacts) || config.Clock == nil || !validBucket(config.Bucket) || !versionPattern.MatchString(config.CollectorVersion) {
		return nil, errConfiguration
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errConfiguration
	}
	return &Client{provider: config.Provider, api: config.API, artifacts: config.Artifacts, bucket: config.Bucket, collectorVersion: config.CollectorVersion, clock: config.Clock}, nil
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
		} else {
			status.Code = collection.ReadinessDependencyUnavailable
		}
		return status
	}
	status.Ready = true
	status.Code = collection.ReadinessReady
	return status
}

func (client *Client) CollectWithCredential(ctx context.Context, request collection.Request, credential []byte) (collection.Outcome, error) {
	if client == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || request.Provider != client.provider || len(credential) < 16 || len(credential) > 65_536 {
		return nil, collection.ErrContract
	}
	if now := client.clock(); now.IsZero() || now.Location() != time.UTC {
		return nil, collection.ErrContract
	}

	cursor := request.Cursor
	remainingBytes := request.Bounds.MaxRawBytes
	remainingItems := request.Bounds.MaxItems
	remainingRelationships := request.Bounds.MaxItems * 2
	objects := make([]collection.RawObject, 0, request.Bounds.MaxPages)
	entities := make([]json.RawMessage, 0)
	relationships := make([]json.RawMessage, 0)
	entityObjects := make(map[string]collection.RawObject)
	complete := false

	for pageNumber := 1; pageNumber <= request.Bounds.MaxPages; pageNumber++ {
		pageRequest := PageRequest{Provider: request.Provider, Subject: request.ExpectedSubject, Cursor: cursor, Page: pageNumber, RemainingItems: remainingItems, RemainingBytes: remainingBytes}
		borrowed := bytes.Clone(credential)
		page, err := fetchPage(client.api, ctx, borrowed, pageRequest)
		clear(borrowed)
		if err != nil {
			return nil, err
		}
		if !validPage(page, request, cursor, credential, remainingItems, remainingRelationships, remainingBytes) {
			return nil, collection.ErrContract
		}
		pageEntityIDs := make([]string, len(page.Entities))
		for index, entity := range page.Entities {
			identity, ok := itemIdentity(entity)
			if !ok {
				return nil, collection.ErrContract
			}
			if _, exists := entityObjects[identity]; exists {
				return nil, collection.ErrContract
			}
			pageEntityIDs[index] = identity
		}

		reference, err := deterministicEvidenceReference(request, fmt.Sprintf("raw-page-%06d", pageNumber))
		if err != nil {
			return nil, collection.ErrContract
		}
		artifact, err := putArtifact(client.artifacts, ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: request.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(page.Raw)})
		if err != nil {
			return nil, outcomeUnknown()
		}
		object, err := rawObjectFromArtifact(request, client.bucket, artifact, rawSchemaVersion)
		if err != nil {
			return nil, outcomeUnknown()
		}
		objects = append(objects, object)
		for index, entity := range page.Entities {
			entityObjects[pageEntityIDs[index]] = object
			entities = append(entities, bytes.Clone(entity))
		}
		for _, relationship := range page.Relationships {
			relationships = append(relationships, bytes.Clone(relationship))
		}
		remainingItems -= len(page.Entities)
		remainingRelationships -= len(page.Relationships)
		remainingBytes -= artifact.Size
		cursor = page.Cursor
		complete = page.Complete
		if complete {
			break
		}
	}

	sort.Slice(objects, func(left, right int) bool {
		return objects[left].Reference().String() < objects[right].Reference().String()
	})
	manifestBody, err := marshalManifest(request, cursor, objects)
	if err != nil || len(manifestBody) > maximumArtifactBytes || int64(len(manifestBody)) > remainingBytes {
		return nil, collection.ErrContract
	}
	manifestReference, err := deterministicEvidenceReference(request, "manifest")
	if err != nil {
		return nil, collection.ErrContract
	}
	manifestArtifact, err := putArtifact(client.artifacts, ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: request.Scope, Reference: manifestReference}, MediaType: "application/json", Body: manifestBody})
	if err != nil {
		return nil, outcomeUnknown()
	}
	manifestObject, err := rawObjectFromArtifact(request, client.bucket, manifestArtifact, manifestSchemaVersion)
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
		return nil, collection.ErrContract
	}
	snapshot, err := collection.NewSnapshotCandidate(request.Provider, request.ParserVersion, request.ToolVersion, entityBody, relationshipBody, evidenceBody)
	if err != nil {
		return nil, collection.ErrContract
	}
	result, err := collection.NewCompleteResult(request, request.ExpectedSubject, cursor, manifest, snapshot)
	if err != nil {
		return nil, collection.ErrContract
	}
	return result, nil
}

func validPage(page Page, request collection.Request, prior collection.Cursor, credential []byte, remainingItems, remainingRelationships int, remainingBytes int64) bool {
	if page.Subject != request.ExpectedSubject || !validCursor(page.Cursor, request.Provider) || page.Cursor == prior || len(page.Raw) == 0 || len(page.Raw) > maximumArtifactBytes || int64(len(page.Raw)) > remainingBytes || !safeJSON(page.Raw) || bytes.Contains(page.Raw, credential) || len(page.Entities) > remainingItems || len(page.Relationships) > remainingRelationships {
		return false
	}
	for _, item := range page.Entities {
		if !validJSONObject(item) || bytes.Contains(item, credential) {
			return false
		}
	}
	for _, item := range page.Relationships {
		if !validJSONObject(item) || bytes.Contains(item, credential) {
			return false
		}
	}
	return true
}

func outcomeUnknown() error {
	failure, _ := collection.NewFailure(collection.FailureOutcomeUnknown, time.Time{})
	return failure
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
		checksum := object.Checksum()
		evidenceReference, err := deterministicEvidenceReference(request, "evidence:"+entityID+":"+object.Reference().String())
		if err != nil {
			return nil, nil, nil, err
		}
		evidence = append(evidence, evidenceItem{
			ID: evidenceReference.String(), EntityID: entityID, ObjectReference: object.ObjectReference(), ArtifactReference: object.Reference().String(),
			ArtifactKey: object.Key(), ArtifactVersionID: object.VersionID(), ChecksumHex: hex.EncodeToString(checksum[:]), SizeBytes: object.Size(), MediaType: object.MediaType(),
			SchemaVersion: object.SchemaVersion(), ParserVersion: object.ParserVersion(), ToolVersion: object.ToolVersion(),
		})
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
	Version        string               `json:"version"`
	Provider       collection.Provider  `json:"provider"`
	Subject        manifestSubject      `json:"subject"`
	IntegrationID  string               `json:"integration_id"`
	ConnectionID   string               `json:"connection_id"`
	JobID          string               `json:"job_id"`
	CursorProvider collection.Provider  `json:"cursor_provider"`
	CursorVersion  string               `json:"cursor_version"`
	CursorValue    string               `json:"cursor_value"`
	ParserVersion  string               `json:"parser_version"`
	ToolVersion    string               `json:"tool_version"`
	Objects        []manifestDescriptor `json:"objects"`
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

func marshalManifest(request collection.Request, cursor collection.Cursor, objects []collection.RawObject) ([]byte, error) {
	descriptors := make([]manifestDescriptor, len(objects))
	for index, object := range objects {
		checksum := object.Checksum()
		descriptors[index] = manifestDescriptor{Reference: object.Reference().String(), Key: object.Key(), VersionID: object.VersionID(), ObjectReference: object.ObjectReference(), ChecksumHex: hex.EncodeToString(checksum[:]), SizeBytes: object.Size(), MediaType: object.MediaType(), SchemaVersion: object.SchemaVersion()}
	}
	return json.Marshal(manifestDocument{Version: manifestSchemaVersion, Provider: request.Provider, Subject: manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}, IntegrationID: request.IntegrationID.String(), ConnectionID: request.ConnectionID.String(), JobID: request.JobID.String(), CursorProvider: cursor.Provider, CursorVersion: cursor.Version, CursorValue: cursor.Value, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Objects: descriptors})
}

func rawObjectFromArtifact(request collection.Request, bucket string, artifact artifactstore.Artifact, schema string) (collection.RawObject, error) {
	key := artifactKey(request.Scope, artifact.Reference)
	if artifact.Scope != request.Scope || artifact.Reference.Validate() != nil || artifact.VersionID == "" || artifact.MediaType != "application/json" || artifact.Size != int64(len(artifact.Body)) || artifact.SHA256 != sha256.Sum256(artifact.Body) {
		return collection.RawObject{}, collection.ErrContract
	}
	return collection.NewRawObject(request.Scope, artifact.Reference, key, artifact.VersionID, "s3://"+bucket+"/"+key, artifact.SHA256, artifact.Size, artifact.MediaType, schema, request.ParserVersion, request.ToolVersion)
}

func deterministicEvidenceReference(request collection.Request, suffix string) (domain.EvidenceRef, error) {
	seed := strings.Join([]string{request.Scope.OrganizationID().String(), request.Scope.WorkspaceID().String(), request.Scope.EnvironmentID().String(), request.IntegrationID.String(), request.JobID.String(), string(request.Provider), suffix}, "\x1f")
	digest := sha256.Sum256([]byte(seed))
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80
	text := fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
	id, err := domain.ParseProductID(text)
	if err != nil {
		return domain.EvidenceRef{}, err
	}
	return domain.NewEvidenceRef(id)
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

func validBucket(value string) bool {
	return bucketPattern.MatchString(value) && !strings.Contains(value, "..")
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
