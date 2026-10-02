package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol"
)

const postgresComplianceExportGrantSQL = `SELECT public.zasp_compliance_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
const compliancePackageMaximum = 8 << 20

var errComplianceIntegrity = errors.Join(ErrRepositoryUnavailable, artifactstore.ErrIntegrity)

type complianceArtifactReader interface {
	Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error)
}
type complianceGrantResult struct {
	ExpiresAt time.Time `json:"expires_at"`
	Consumed  bool      `json:"consumed"`
}
type complianceReadReceipt struct {
	Reference        string    `json:"reference"`
	Version          string    `json:"version"`
	Size             int64     `json:"size"`
	SHA256           string    `json:"sha256"`
	RendererRevision string    `json:"renderer_revision"`
	ReadExpiresAt    time.Time `json:"read_expires_at"`
}

func (r *ComplianceExportsRepository) grant(ctx context.Context, identity RequestIdentity, digest []byte, id, token, format, operation string) (json.RawMessage, error) {
	if r == nil || r.source == nil || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || !compliancePermissions(ctx, identity) || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) || !validProductID(id) || !validExistingTestPublicDigest(token) || !stringIn(format, "json", "csv", "readable") || !stringIn(operation, "issue", "read", "consume", "integrity_failure") {
		return nil, ErrRepositoryOperation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := r.source.database.QueryJSON(ctx, postgresComplianceExportGrantSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(digest), id, token, format, operation, r.source.checksum, r.source.fingerprint)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, complianceExportError(err)
	}
	return raw, nil
}
func (r *ComplianceExportsRepository) grantAction(ctx context.Context, identity RequestIdentity, digest []byte, id, token, format, operation string) (complianceGrantResult, error) {
	raw, err := r.grant(ctx, identity, digest, id, token, format, operation)
	if err != nil {
		return complianceGrantResult{}, err
	}
	var result complianceGrantResult
	if _, err := auditExportClosedObject(raw, 1024, "expires_at", "consumed"); err != nil || json.Unmarshal(raw, &result) != nil || result.ExpiresAt.IsZero() || result.Consumed != (operation == "consume" || operation == "integrity_failure") {
		return result, ErrRepositoryUnavailable
	}
	return result, nil
}
func (r *ComplianceExportsRepository) readGrant(ctx context.Context, identity RequestIdentity, digest []byte, id, token, format string) (complianceReadReceipt, error) {
	raw, err := r.grant(ctx, identity, digest, id, token, format, "read")
	if err != nil {
		return complianceReadReceipt{}, err
	}
	var result complianceReadReceipt
	if _, err := auditExportClosedObject(raw, 4096, "reference", "version", "size", "sha256", "renderer_revision", "read_expires_at"); err != nil || json.Unmarshal(raw, &result) != nil || !validProductID(result.Reference) || !complianceVersion(result.Version) || result.Size < 1 || result.Size > compliancePackageMaximum || !validExistingTestPublicDigest(result.SHA256) || result.RendererRevision != "compliance-envelope-v1" || result.ReadExpiresAt.IsZero() {
		return result, ErrRepositoryUnavailable
	}
	return result, nil
}
func complianceVersion(v string) bool {
	return len(v) > 0 && len(v) <= 1024 && strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// A persisted v1 package is decoded, never re-rendered. Old renderer bytes are
// authoritative once their exact immutable receipt has been verified.
func readComplianceDownload(ctx context.Context, reader complianceArtifactReader, identity RequestIdentity, id, format string, pin complianceReadReceipt) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(reader) || !pin.ReadExpiresAt.After(time.Now()) {
		return nil, ErrRepositoryUnavailable
	}
	ref, err := domain.ParseEvidenceRef(pin.Reference)
	if err != nil {
		return nil, errComplianceIntegrity
	}
	locator := artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: pin.Version}
	artifact, err := reader.Get(ctx, locator)
	if ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	if err != nil {
		if errors.Is(err, artifactstore.ErrIntegrity) {
			return nil, errComplianceIntegrity
		}
		return nil, ErrRepositoryUnavailable
	}
	if artifact.Locator != locator || artifact.MediaType != "application/json" || artifact.Size != pin.Size || int64(len(artifact.Body)) != pin.Size || len(artifact.Body) > compliancePackageMaximum {
		return nil, errComplianceIntegrity
	}
	actual := sha256.Sum256(artifact.Body)
	if actual != artifact.SHA256 || hex.EncodeToString(actual[:]) != pin.SHA256 {
		return nil, errComplianceIntegrity
	}
	envelope, err := auditExportClosedObject(artifact.Body, compliancePackageMaximum, "version", "id", "json", "csv", "human")
	if err != nil {
		return nil, errComplianceIntegrity
	}
	var version int
	var storedID, csv, human string
	if json.Unmarshal(envelope["version"], &version) != nil || version != 1 || json.Unmarshal(envelope["id"], &storedID) != nil || storedID != id || json.Unmarshal(envelope["csv"], &csv) != nil || json.Unmarshal(envelope["human"], &human) != nil || csv == "" || human == "" || len(csv) > 4<<20 || len(human) > 4<<20 || !utf8.ValidString(csv) || !utf8.ValidString(human) || len(envelope["json"]) > 4<<20 || !validCompliancePersistedEvidence(envelope["json"], identity) {
		return nil, errComplianceIntegrity
	}
	switch format {
	case "json":
		return bytes.Clone(envelope["json"]), nil
	case "csv":
		return []byte(csv), nil
	case "human":
		return []byte(human), nil
	}
	return nil, ErrRepositoryOperation
}

func validCompliancePersistedEvidence(raw json.RawMessage, identity RequestIdentity) bool {
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) > 500 {
		return false
	}
	for _, entry := range entries {
		object, ok := complianceClosedObject(entry, []string{"snapshot_context"}, "control", "evidence", "freshness")
		if !ok {
			return false
		}
		if _, err := auditExportClosedObject(object["control"], 65536, "id", "framework", "name", "evidence_ids", "fresh_until"); err != nil {
			return false
		}
		var value sessioncontrol.ComplianceEvidence
		if decodeStrictDiscovery(entry, &value) != nil || !complianceSafeText(value.Control.ID, 128) || !complianceSafeText(value.Control.Framework, 64) || !complianceSafeText(value.Control.Name, 256) || value.Control.FreshUntil.IsZero() || len(value.Control.EvidenceIDs) > 100 || !stringIn(value.Freshness, "fresh", "stale", "missing") || len(value.Evidence) > 100 {
			return false
		}
		if contextRaw, present := object["snapshot_context"]; present {
			if _, err := auditExportClosedObject(contextRaw, 2048, "organization_id", "workspace_id", "environment_id", "mapping_revision", "snapshot_at"); err != nil {
				return false
			}
			c := value.SnapshotContext
			if c == nil || c.OrganizationID != identity.Scope.OrganizationID().String() || c.WorkspaceID != identity.Scope.WorkspaceID().String() || c.EnvironmentID != identity.Scope.EnvironmentID().String() || c.MappingRevision != "product-evidence-v1" || c.SnapshotAt.IsZero() {
				return false
			}
		}
		var records []json.RawMessage
		if json.Unmarshal(object["evidence"], &records) != nil {
			return false
		}
		for i, record := range records {
			fields, ok := complianceClosedObject(record, []string{"target", "metadata"}, "id", "asset_id", "source", "at")
			if !ok {
				return false
			}
			v := value.Evidence[i]
			if !complianceSafeText(v.ID, 128) || !complianceSafeText(v.AssetID, 128) || !complianceSafeText(v.Source, 64) || v.At.IsZero() {
				return false
			}
			_, hasTarget := fields["target"]
			_, hasMetadata := fields["metadata"]
			if hasTarget != hasMetadata {
				return false
			}
			if hasTarget {
				if _, err := auditExportClosedObject(fields["target"], 1024, "source_kind", "source_id", "source_version"); err != nil || v.Target == nil || v.Metadata == nil {
					return false
				}
				metadata := fields["metadata"]
				if v.Target.SourceKind == "finding" {
					m, ok := complianceClosedObject(metadata, []string{"evidence_ids"}, "status", "severity")
					if !ok {
						return false
					}
					if m["evidence_ids"] == nil {
						m["evidence_ids"] = json.RawMessage(`[]`)
					}
					metadata, _ = json.Marshal(m)
				}
				internal := map[string]any{"id": v.ID, "asset": v.AssetID, "source": v.Source, "timestamp": v.At.UTC().Format(time.RFC3339Nano), "organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "target": json.RawMessage(fields["target"]), "freshness": "stale", "metadata": json.RawMessage(metadata)}
				encoded, _ := json.Marshal(internal)
				if _, err := decodeComplianceEvidence(encoded, identity); err != nil {
					return false
				}
			}
		}
	}
	return true
}
