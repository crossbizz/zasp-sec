package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type SecurityAgentExportSelection struct {
	Kind              string `json:"source_kind"`
	ID                string `json:"source_id"`
	Version           int64  `json:"source_version"`
	AssociationDigest string `json:"association_digest"`
}
type SecurityAgentExportBinding struct {
	RunID     string                         `json:"run_id"`
	StepID    string                         `json:"step_id"`
	Selection []SecurityAgentExportSelection `json:"selection"`
}
type securityAgentExportReadReceipt struct {
	complianceReadReceipt
	Binding SecurityAgentExportBinding `json:"binding"`
}

func readSecurityAgentExportDownload(ctx context.Context, reader complianceArtifactReader, identity RequestIdentity, exportID, format string, pin securityAgentExportReadReceipt) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(reader) || identity.Scope.Validate() != nil || !validProductID(exportID) || pin.Reference != exportID || !complianceVersion(pin.Version) || pin.Size < 1 || pin.Size > 8<<20 || !validExistingTestPublicDigest(pin.SHA256) || pin.RendererRevision != "security-agent-evidence-envelope-v1" || !pin.ReadExpiresAt.After(time.Now()) || !stringIn(format, "json", "csv", "human") || !validAgentExportDownloadBinding(pin.Binding) {
		return nil, ErrRepositoryUnavailable
	}
	bounded, cancel := context.WithDeadline(ctx, pin.ReadExpiresAt)
	defer cancel()
	ref, err := domain.ParseEvidenceRef(pin.Reference)
	if err != nil {
		return nil, errComplianceIntegrity
	}
	locator := artifactstore.Locator{Scope: identity.Scope, Reference: ref, VersionID: pin.Version}
	a, err := reader.Get(bounded, locator)
	if bounded.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	if err != nil {
		if errors.Is(err, artifactstore.ErrIntegrity) {
			return nil, errComplianceIntegrity
		}
		return nil, ErrRepositoryUnavailable
	}
	hash := sha256.Sum256(a.Body)
	if a.Locator != locator || a.MediaType != "application/json" || a.Size != pin.Size || int64(len(a.Body)) != pin.Size || len(a.Body) > 8<<20 || a.SHA256 != hash || hex.EncodeToString(hash[:]) != pin.SHA256 {
		return nil, errComplianceIntegrity
	}
	e, err := auditExportClosedObject(a.Body, 8<<20, "version", "id", "json", "csv", "human")
	if err != nil {
		return nil, errComplianceIntegrity
	}
	var version int
	var id, csv, human string
	if json.Unmarshal(e["version"], &version) != nil || version != 1 || json.Unmarshal(e["id"], &id) != nil || id != exportID || json.Unmarshal(e["csv"], &csv) != nil || json.Unmarshal(e["human"], &human) != nil || len(csv) < 1 || len(csv) > 4<<20 || len(human) < 1 || len(human) > 4<<20 || !utf8.ValidString(csv) || !utf8.ValidString(human) || !validAgentExportDownloadManifest(e["json"], identity, pin.Binding) {
		return nil, errComplianceIntegrity
	}
	if bounded.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	switch format {
	case "json":
		return bytes.Clone(e["json"]), nil
	case "csv":
		return []byte(csv), nil
	default:
		return []byte(human), nil
	}
}

func validAgentExportDownloadBinding(b SecurityAgentExportBinding) bool {
	return validProductID(b.RunID) && validProductID(b.StepID) && validSecurityAgentExportSelection(b.Selection)
}

func validSecurityAgentExportSelection(selection []SecurityAgentExportSelection) bool {
	if len(selection) < 1 || len(selection) > 100 {
		return false
	}
	seen := make(map[string]bool, len(selection))
	for _, s := range selection {
		validID := validProductID(s.ID)
		if s.Kind == "manual" {
			validID = validExistingTestPublicDigest(s.ID)
		}
		key := s.Kind + "/" + s.ID
		if !stringIn(s.Kind, "finding", "attack_path", "runtime_decision", "run_audit", "existing_test", "attack_lab", "manual") || !validID || s.Version < 1 || s.Version > 9007199254740991 || !strings.HasPrefix(s.AssociationDigest, "sha256:") || !validExistingTestPublicDigest(strings.TrimPrefix(s.AssociationDigest, "sha256:")) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func validAgentExportDownloadManifest(raw json.RawMessage, identity RequestIdentity, b SecurityAgentExportBinding) bool {
	f, err := auditExportClosedObject(raw, 4<<20, "mapping_revision", "snapshot_at", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "records", "renderer_revision")
	if err != nil {
		return false
	}
	for key, want := range map[string]string{"mapping_revision": "security-agent-run-evidence-v1", "renderer_revision": "security-agent-evidence-envelope-v1", "organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "run_id": b.RunID, "step_id": b.StepID} {
		var got string
		if json.Unmarshal(f[key], &got) != nil || got != want {
			return false
		}
	}
	var stamp string
	if json.Unmarshal(f["snapshot_at"], &stamp) != nil {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != stamp {
		return false
	}
	var records []json.RawMessage
	if json.Unmarshal(f["records"], &records) != nil || len(records) != len(b.Selection) {
		return false
	}
	for i, rawRecord := range records {
		r, err := auditExportClosedObject(rawRecord, 4<<20, "source_kind", "source_id", "source_version", "association_digest", "content_sha256", "content_json")
		if err != nil {
			return false
		}
		var s SecurityAgentExportSelection
		if json.Unmarshal(r["source_kind"], &s.Kind) != nil || json.Unmarshal(r["source_id"], &s.ID) != nil || json.Unmarshal(r["source_version"], &s.Version) != nil || json.Unmarshal(r["association_digest"], &s.AssociationDigest) != nil || s != b.Selection[i] {
			return false
		}
		var content, digest string
		if json.Unmarshal(r["content_json"], &content) != nil || json.Unmarshal(r["content_sha256"], &digest) != nil || !validExistingTestPublicDigest(digest) || !validAgentExportContentJSON(content) {
			return false
		}
		h := sha256.Sum256([]byte(content))
		if hex.EncodeToString(h[:]) != digest {
			return false
		}
	}
	return true
}

// Content is opaque redacted source data, but must be one bounded object without
// duplicate keys at any depth. It is never treated as new retrieval authority.
func validAgentExportContentJSON(content string) bool {
	if len(content) < 2 || len(content) > 65536 || !utf8.ValidString(content) || !strings.HasPrefix(strings.TrimSpace(content), "{") {
		return false
	}
	d := json.NewDecoder(strings.NewReader(content))
	d.UseNumber()
	if !agentExportContentValue(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func agentExportContentValue(d *json.Decoder, depth int) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	if depth >= 32 {
		return false
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			token, err := d.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return false
			}
			seen[key] = true
			if !agentExportContentValue(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !agentExportContentValue(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	}
	return false
}
