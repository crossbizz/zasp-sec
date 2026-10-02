package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
)

type auditExportHTTPRepository interface {
	Create(context.Context, RequestIdentity, AuditExportCreate) (AuditExportDescriptor, error)
	Get(context.Context, RequestIdentity, AuditExportRead) (auditExportReadResult, error)
}

type auditExportHTTPHandler struct {
	repository auditExportHTTPRepository
	storage    *auditExportStorageRegistry
	cursor     *auditExportCursorCodec
	newID      func() (string, error)
}

func newAuditExportHTTPHandler(repository auditExportHTTPRepository, storage *auditExportStorageRegistry, key []byte, newID func() (string, error)) (*auditExportHTTPHandler, error) {
	if nilInterface(repository) || storage == nil || len(storage.entries) == 0 || newID == nil {
		return nil, ErrRepositoryConfiguration
	}
	cursor, err := newAuditExportCursorCodec(key)
	if err != nil {
		return nil, err
	}
	return &auditExportHTTPHandler{repository: repository, storage: storage, cursor: cursor, newID: newID}, nil
}

func (handler *auditExportHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	bound := *handler
	codec := *handler.cursor
	codec.signingKey = authorizationCursorKey(request.Context(), handler.cursor.signingKey)
	bound.cursor = &codec
	handler = &bound
	writer.Header().Set("Cache-Control", "no-store")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	credential, browser, credentialOK := requestCredential(request)
	sessionCookies := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == browserSessionCookie {
			sessionCookies++
		}
	}
	if sessionCookies != 1 {
		credentialOK = false
	}
	if !identityOK || !routedOK || !credentialOK || !browser || identity.CredentialKind != CredentialBrowserSession || !validRequestIdentity(identity, true) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if !currentRequestHasPermission(request.Context(), identity, "view_audit") {
		writeAuditExportHTTPError(writer, request, ErrAuditExportForbidden)
		return
	}
	if routed.OperationID == "getAuditExport" {
		handler.get(writer, request, identity, routed, credential)
		return
	}
	if routed.OperationID != "createAuditExport" {
		writeAuditExportHTTPError(writer, request, ErrRepositoryNotFound)
		return
	}
	if request.Method != http.MethodPost || request.URL.RawQuery != "" {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	if !identity.FreshAuthenticated || len(request.Header.Values("X-CSRF-Token")) != 1 || request.Header.Get("X-CSRF-Token") != identity.CSRFToken {
		writeAuditExportHTTPError(writer, request, ErrAuditExportForbidden)
		return
	}
	keys := request.Header.Values("Idempotency-Key")
	media, _, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if len(keys) != 1 || !validPublicIdempotency(keys[0]) || len(request.Header.Values("Content-Type")) != 1 || mediaErr != nil || media != "application/json" || request.Body == nil {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1025))
	if err != nil || len(body) > 1024 {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	if _, err := auditExportClosedObject(body, 1024); err != nil {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	ids := make([]string, 3)
	seen := map[string]bool{identity.Scope.OrganizationID().String(): true, identity.Scope.WorkspaceID().String(): true, identity.Scope.EnvironmentID().String(): true, identity.PrincipalID.String(): true}
	for index := range ids {
		id, err := handler.newID()
		if err != nil || !validProductID(id) || seen[id] {
			writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
			return
		}
		ids[index] = id
		seen[id] = true
	}
	digest := sha256.Sum256([]byte(credential.Value))
	descriptor, err := handler.repository.Create(request.Context(), identity, AuditExportCreate{ExportID: ids[0], AuditID: ids[1], OutboxID: ids[2], IdempotencyKey: keys[0], SessionDigest: digest[:]})
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	if err := request.Context().Err(); err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	writeJSONValue(writer, request, http.StatusCreated, descriptor, nil)
}

func (handler *auditExportHTTPHandler) get(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation, credential Credential) {
	id := routed.PathParameters["id"]
	if request.Method != http.MethodGet || !validProductID(id) || request.ContentLength > 0 {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	if request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(request.Body, 1))
		if err != nil || len(body) != 0 {
			writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
			return
		}
	}
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": auditExportMaximumCursorBytes})
	if !ok {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	input := AuditExportRead{ExportID: id, SessionDigest: digest[:], ChunkOrdinal: 1}
	if values, present := query["cursor"]; present {
		ordinal, pin, err := handler.cursor.Decode(values[0], identity, id)
		if err != nil {
			writeAuditExportHTTPError(writer, request, ErrRepositoryNotFound)
			return
		}
		input.ChunkOrdinal = ordinal
		input.ManifestSHA256 = pin
	}
	result, err := handler.repository.Get(request.Context(), identity, input)
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	if result.export.ID != id || result.export.OrganizationID != identity.Scope.OrganizationID().String() {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	var store auditExportArtifactReader
	if result.authority != nil {
		store, err = handler.storage.Resolve(result.authority.StoragePolicy)
		if err != nil {
			writeAuditExportHTTPError(writer, request, err)
			return
		}
	}
	verified, err := verifyAuditExportContents(request.Context(), store, result)
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	var contents any
	if verified != nil {
		pageInfo := map[string]any{"next_cursor": nil, "has_more": false}
		var chunkDigest any
		if verified.chunk != nil {
			chunkDigest = verified.chunkSHA256
			if verified.chunk.Ordinal < verified.manifest.ChunkCount {
				pin, err := hex.DecodeString(result.export.ManifestSHA256)
				if err != nil {
					writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
					return
				}
				cursor, err := handler.cursor.Encode(identity, id, pin, verified.chunk.Ordinal+1)
				if err != nil {
					writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
					return
				}
				pageInfo["next_cursor"] = cursor
				pageInfo["has_more"] = true
			}
		}
		contents = map[string]any{"manifest": verified.manifest, "chunk": verified.chunk, "chunk_sha256": chunkDigest, "page_info": pageInfo}
	}
	if err := request.Context().Err(); err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"export": result.export, "contents": contents}, nil)
}

func writeAuditExportHTTPError(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, ErrAuditExportForbidden) {
		writeProductionStatusError(writer, request, http.StatusForbidden, "forbidden", "Operation forbidden", false)
		return
	}
	writeProductionError(writer, request, err)
}
