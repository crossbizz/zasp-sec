package providercollection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ResumeSeed = collection.ResumeSeed

func (client *Client) WithResumeSeed(seed collection.ResumeSeed) (collection.ProviderClient, error) {
	if client == nil || !validResumeSeed(seed) {
		return nil, collection.ErrContract
	}
	clone := *client
	copyOfSeed := seed
	copyOfSeed.CheckpointDigest = bytes.Clone(seed.CheckpointDigest)
	copyOfSeed.ManifestChecksum = bytes.Clone(seed.ManifestChecksum)
	clone.resume = &copyOfSeed
	return &clone, nil
}

func validResumeSeed(seed collection.ResumeSeed) bool {
	return seed.CheckpointVersion >= 1 && seed.CheckpointVersion <= 10_000 && len(seed.CheckpointDigest) == sha256.Size && !bytes.Equal(seed.CheckpointDigest, make([]byte, sha256.Size)) &&
		seed.Cursor.Provider != "" && seed.Cursor.Version != "" && seed.Cursor.Value != "" && len(seed.ManifestReference) > len(seed.ManifestKey)+1 && strings.HasSuffix(seed.ManifestReference, "/"+seed.ManifestKey) &&
		len(seed.ManifestVersionID) >= 1 && len(seed.ManifestVersionID) <= 1024 && len(seed.ManifestChecksum) == sha256.Size && !bytes.Equal(seed.ManifestChecksum, make([]byte, sha256.Size)) &&
		seed.ManifestSizeBytes >= 1 && seed.ManifestSizeBytes <= maximumArtifactBytes && seed.ManifestMediaType == "application/json" && seed.ManifestSchema == manifestSchemaVersion &&
		versionPattern.MatchString(seed.ParserVersion) && versionPattern.MatchString(seed.ToolVersion)
}

type resumeState struct {
	objects               []collection.RawObject
	pages                 []Page
	entities              []json.RawMessage
	relationships         []json.RawMessage
	entityObjects         map[string]collection.RawObject
	entitySourceIDs       map[string]struct{}
	relationshipIDs       map[string]struct{}
	relationshipSourceIDs map[string]struct{}
	evidenceLengths       [][]int
	rawBytes              int64
}

func (client *Client) loadResumeSeed(ctx context.Context, request collection.Request) (resumeState, error) {
	seed := client.resume
	if seed == nil || !validResumeSeed(*seed) || seed.Cursor != request.Cursor || seed.ParserVersion != request.ParserVersion || seed.ToolVersion != request.ToolVersion {
		return resumeState{}, collection.ErrContract
	}
	manifestReference, err := evidenceReferenceFromKey(seed.ManifestKey)
	if err != nil {
		return resumeState{}, collection.ErrContract
	}
	locator := artifactstore.Locator{Scope: request.Scope, Reference: manifestReference, VersionID: seed.ManifestVersionID}
	manifestArtifact, err := client.artifacts.Get(ctx, locator)
	var expectedChecksum [sha256.Size]byte
	copy(expectedChecksum[:], seed.ManifestChecksum)
	if err != nil || !exactResumeArtifact(manifestArtifact, locator, seed.ManifestMediaType, seed.ManifestSizeBytes, expectedChecksum) {
		return resumeState{}, collection.ErrContract
	}
	objectReference, err := client.artifacts.ObjectReference(locator)
	if err != nil || objectReference != seed.ManifestReference {
		return resumeState{}, collection.ErrContract
	}
	var document manifestDocument
	if !decodeExactObject(manifestArtifact.Body, &document) || !validResumeManifest(document, request, *seed) {
		return resumeState{}, collection.ErrContract
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, manifestArtifact.Body) {
		return resumeState{}, collection.ErrContract
	}
	state := resumeState{
		objects: make([]collection.RawObject, 0, len(document.Objects)), pages: make([]Page, 0, len(document.Objects)), entities: make([]json.RawMessage, 0), relationships: make([]json.RawMessage, 0),
		entityObjects: make(map[string]collection.RawObject), entitySourceIDs: make(map[string]struct{}), relationshipIDs: make(map[string]struct{}), relationshipSourceIDs: make(map[string]struct{}), evidenceLengths: make([][]int, 0, len(document.Objects)),
	}
	lastReference := ""
	cursorMatches := 0
	for _, descriptor := range document.Objects {
		if descriptor.Reference <= lastReference {
			return resumeState{}, collection.ErrContract
		}
		lastReference = descriptor.Reference
		object, page, loadErr := client.loadResumePage(ctx, request, descriptor)
		if loadErr != nil || page.Complete {
			return resumeState{}, collection.ErrContract
		}
		if page.Cursor == seed.Cursor {
			cursorMatches++
		}
		state.objects = append(state.objects, object)
		state.pages = append(state.pages, page)
		state.rawBytes += object.Size()
		lengths := make([]int, len(page.Entities))
		for index, entity := range page.Entities {
			identity, source, ok := entityIdentity(entity)
			if !ok {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.entityObjects[identity]; exists {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.entitySourceIDs[source]; exists {
				return resumeState{}, collection.ErrContract
			}
			state.entityObjects[identity] = object
			state.entitySourceIDs[source] = struct{}{}
			item, itemErr := evidenceForEntity(request, identity, object)
			encoded, encodeErr := json.Marshal(item)
			if itemErr != nil || encodeErr != nil {
				return resumeState{}, collection.ErrContract
			}
			lengths[index] = len(encoded)
			state.entities = append(state.entities, bytes.Clone(entity))
		}
		for _, relationship := range page.Relationships {
			identity, source, _, _, ok := relationshipIdentity(relationship)
			if !ok {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.relationshipIDs[identity]; exists {
				return resumeState{}, collection.ErrContract
			}
			if _, exists := state.relationshipSourceIDs[source]; exists {
				return resumeState{}, collection.ErrContract
			}
			state.relationshipIDs[identity] = struct{}{}
			state.relationshipSourceIDs[source] = struct{}{}
			state.relationships = append(state.relationships, bytes.Clone(relationship))
		}
		state.evidenceLengths = append(state.evidenceLengths, lengths)
	}
	if len(state.objects) == 0 || cursorMatches != 1 {
		return resumeState{}, collection.ErrContract
	}
	return state, nil
}

func (client *Client) loadResumePage(ctx context.Context, request collection.Request, descriptor manifestDescriptor) (collection.RawObject, Page, error) {
	reference, err := evidenceReferenceFromKey(descriptor.Key)
	checksumBytes, checksumErr := hex.DecodeString(descriptor.ChecksumHex)
	if err != nil || checksumErr != nil || len(checksumBytes) != sha256.Size || descriptor.Reference != reference.String() || descriptor.SchemaVersion != rawSchemaVersion || descriptor.MediaType != "application/json" {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	locator := artifactstore.Locator{Scope: request.Scope, Reference: reference, VersionID: descriptor.VersionID}
	artifact, err := client.artifacts.Get(ctx, locator)
	var checksum [sha256.Size]byte
	copy(checksum[:], checksumBytes)
	if err != nil || !exactResumeArtifact(artifact, locator, descriptor.MediaType, descriptor.SizeBytes, checksum) {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	objectReference, err := client.artifacts.ObjectReference(locator)
	if err != nil || objectReference != descriptor.ObjectReference {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	var document redactedPageDocument
	if !decodeExactObject(artifact.Body, &document) || document.Version != redactedPageVersion || document.Provider != request.Provider || document.Subject != (manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}) {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	page := Page{Subject: request.ExpectedSubject, Cursor: collection.Cursor{Provider: document.Cursor.Provider, Version: document.Cursor.Version, Value: document.Cursor.Value}, Complete: document.Complete, Entities: cloneRawMessages(document.Entities), Relationships: cloneRawMessages(document.Relationships), Raw: bytes.Clone(artifact.Body)}
	canonical, canonicalErr := canonicalPageBody(request.Provider, page)
	if canonicalErr != nil || !bytes.Equal(canonical, artifact.Body) {
		return collection.RawObject{}, Page{}, collection.ErrContract
	}
	object, err := collection.NewRawObject(request.Scope, reference, descriptor.Key, descriptor.VersionID, descriptor.ObjectReference, checksum, descriptor.SizeBytes, descriptor.MediaType, descriptor.SchemaVersion, request.ParserVersion, request.ToolVersion)
	return object, page, err
}

func validResumeManifest(document manifestDocument, request collection.Request, seed collection.ResumeSeed) bool {
	digest, err := hex.DecodeString(document.RequestDigest)
	return err == nil && len(digest) == sha256.Size && !bytes.Equal(digest, make([]byte, sha256.Size)) && document.Version == manifestSchemaVersion && document.Provider == request.Provider &&
		document.Subject == (manifestSubject{Kind: request.ExpectedSubject.Kind, ID: request.ExpectedSubject.ID}) && document.IntegrationID == request.IntegrationID.String() && document.ConnectionID == request.ConnectionID.String() && document.JobID == request.JobID.String() &&
		document.Attempt >= 1 && document.Attempt <= request.Attempt && document.CollectorVersion == request.CollectorVersion && document.CursorProvider == seed.Cursor.Provider && document.CursorVersion == seed.Cursor.Version && document.CursorValue == seed.Cursor.Value &&
		document.ParserVersion == seed.ParserVersion && document.ToolVersion == seed.ToolVersion && len(document.Objects) >= 1 && len(document.Objects) <= request.Bounds.MaxPages
}

func exactResumeArtifact(artifact artifactstore.Artifact, locator artifactstore.Locator, mediaType string, size int64, checksum [sha256.Size]byte) bool {
	return artifact.Locator == locator && artifact.MediaType == mediaType && artifact.Size == size && artifact.Size == int64(len(artifact.Body)) && artifact.SHA256 == checksum && sha256.Sum256(artifact.Body) == checksum
}

func evidenceReferenceFromKey(key string) (domain.EvidenceRef, error) {
	last := strings.LastIndexByte(key, '/')
	if last < 0 || last == len(key)-1 {
		return domain.EvidenceRef{}, collection.ErrContract
	}
	id, err := domain.ParseProductID(key[last+1:])
	if err != nil {
		return domain.EvidenceRef{}, collection.ErrContract
	}
	return domain.NewEvidenceRef(id)
}
