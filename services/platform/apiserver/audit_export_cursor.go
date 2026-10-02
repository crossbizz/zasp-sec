package apiserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

const auditExportMaximumCursorBytes = 1024

// This codec binds pagination, not authorization. Each GET must still
// authenticate the current session and recheck its current SQL membership.
type auditExportCursorCodec struct{ signingKey []byte }

type auditExportCursorPayload struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	PrincipalID    string `json:"p"`
	Operation      string `json:"op"`
	ExportID       string `json:"x"`
	ManifestSHA256 string `json:"m"`
	NextOrdinal    int64  `json:"n"`
}

func newAuditExportCursorCodec(signingKey []byte) (*auditExportCursorCodec, error) {
	if !validAuditExportCursorKey(signingKey) {
		return nil, ErrRepositoryConfiguration
	}
	return &auditExportCursorCodec{signingKey: bytes.Clone(signingKey)}, nil
}

func (codec *auditExportCursorCodec) Encode(identity RequestIdentity, exportID string, manifestSHA256 []byte, nextOrdinal int64) (string, error) {
	if codec == nil || !validAuditExportCursorKey(codec.signingKey) || !validRequestIdentity(identity, false) || !validProductID(exportID) || !nonzeroAuditExportDigest(manifestSHA256) || nextOrdinal < 2 || nextOrdinal > 1<<53-1 {
		return "", ErrRepositoryOperation
	}
	payload, err := json.Marshal(auditExportCursorPayload{Version: 1, OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), PrincipalID: identity.PrincipalID.String(), Operation: "getAuditExport", ExportID: exportID, ManifestSHA256: hex.EncodeToString(manifestSHA256), NextOrdinal: nextOrdinal})
	if err != nil {
		return "", ErrRepositoryOperation
	}
	mac := hmac.New(sha256.New, codec.signingKey)
	_, _ = mac.Write(payload)
	value := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if len(value) > auditExportMaximumCursorBytes {
		return "", ErrRepositoryOperation
	}
	return value, nil
}

func (codec *auditExportCursorCodec) Decode(value string, identity RequestIdentity, exportID string) (int64, []byte, error) {
	if codec == nil || !validAuditExportCursorKey(codec.signingKey) || !validRequestIdentity(identity, false) || !validProductID(exportID) || len(value) < 2 || len(value) > auditExportMaximumCursorBytes {
		return 0, nil, ErrRepositoryOperation
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return 0, nil, ErrRepositoryOperation
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, codec.signingKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return 0, nil, ErrRepositoryOperation
	}
	var cursor auditExportCursorPayload
	if json.Unmarshal(payload, &cursor) != nil || cursor.Version != 1 || cursor.Operation != "getAuditExport" || cursor.OrganizationID != identity.Scope.OrganizationID().String() || cursor.WorkspaceID != identity.Scope.WorkspaceID().String() || cursor.EnvironmentID != identity.Scope.EnvironmentID().String() || cursor.PrincipalID != identity.PrincipalID.String() || cursor.ExportID != exportID || cursor.NextOrdinal < 2 || cursor.NextOrdinal > 1<<53-1 || !validAuditExportSHA256(cursor.ManifestSHA256) {
		return 0, nil, ErrRepositoryOperation
	}
	// Byte equality closes encoding/json's duplicate/alias/unknown-key behavior,
	// alternate escapes, whitespace, field order and numeric representations.
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, payload) {
		return 0, nil, ErrRepositoryOperation
	}
	pin, err := hex.DecodeString(cursor.ManifestSHA256)
	if err != nil || !nonzeroAuditExportDigest(pin) {
		return 0, nil, ErrRepositoryOperation
	}
	return cursor.NextOrdinal, pin, nil
}

func validAuditExportCursorKey(key []byte) bool {
	if len(key) < 32 || len(key) > 4096 {
		return false
	}
	for _, value := range key {
		if value != 0 {
			return true
		}
	}
	return false
}
