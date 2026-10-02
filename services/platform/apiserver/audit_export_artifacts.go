package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Only reads and configured-reference derivation are available to retrieval.
// There is deliberately no caller-selected URL fetch, write or delete method.
type auditExportArtifactReader interface {
	Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error)
	ObjectReference(artifactstore.Locator) (string, error)
}

func readAuditExportArtifact(ctx context.Context, store auditExportArtifactReader, scope domain.Scope, artifactID, objectReference, versionID, digest string, size, maximum int64) (body []byte, resultErr error) {
	// A provider panic is an unavailable artifact, never a public panic detail.
	defer func() {
		if recover() != nil {
			body = nil
			resultErr = ErrRepositoryUnavailable
		}
	}()
	if ctx == nil || nilInterface(store) || scope.Validate() != nil || !validProductID(artifactID) || !validAuditExportSHA256(digest) || size < 1 || maximum < 1 || maximum > 1<<20 || size > maximum || versionID == "" || versionID == "null" || len(versionID) > 1024 || !utf8.ValidString(versionID) {
		return nil, ErrRepositoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, character := range versionID {
		if character < 0x21 || character > 0x7e {
			return nil, ErrRepositoryUnavailable
		}
	}
	id, err := domain.ParseProductID(artifactID)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	reference, err := domain.NewEvidenceRef(id)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	locator := artifactstore.Locator{Scope: scope, Reference: reference, VersionID: versionID}
	expectedReference, err := store.ObjectReference(locator)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil || objectReference == "" || expectedReference != objectReference {
		return nil, ErrRepositoryUnavailable
	}
	object, err := store.Get(ctx, locator)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil || object.Locator != locator || object.MediaType != "application/json" || object.Size != size || int64(len(object.Body)) != size {
		return nil, ErrRepositoryUnavailable
	}
	hash := sha256.Sum256(object.Body)
	if object.SHA256 != hash || hex.EncodeToString(hash[:]) != digest {
		return nil, ErrRepositoryUnavailable
	}
	return bytes.Clone(object.Body), nil
}
