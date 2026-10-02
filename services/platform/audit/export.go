package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const ExportChunkSchema = "audit-export-chunk-v1"
const ExportManifestSchema = "audit-export-manifest-v1"
const ExportMaximumChunkBytes = 1 << 20
const ExportMaximumChunkEvents = 1000

// ExportMaximumEventBytes covers worst-case JSON escaping of the bounded public
// fields (32 metadata entries, 64-byte keys, 512-byte values), not 128 KiB raw text.
const ExportMaximumEventBytes = 128 << 10
const ExportZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

const exportTimeLayout = "2006-01-02T15:04:05.000000Z"
const exportMaximumInteger int64 = 1<<53 - 1
const exportMaximumManifestBytes = 2048

var ErrExport = errors.New("audit export rejected")

// ExportBinding identifies the artifact destination, not a filter on the source:
// an organization-wide export can contain other workspace/environment scopes.
type ExportBinding struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	ExportID       string `json:"export_id"`
	CaptureID      string `json:"capture_id"`
}

// ExportEvent is the frozen public projection of a zasp_admin_audit row.
// Ordinals are one-based, ordered by occurred_at DESC, id DESC (bytewise IDs).
// The wire timestamp is UTC with exactly six fractional digits. No rounding or
// alternate timezone/string representation is accepted by this codec.
type ExportEvent struct {
	Ordinal        int64             `json:"ordinal"`
	ID             string            `json:"id"`
	OrganizationID string            `json:"organization_id"`
	WorkspaceID    string            `json:"workspace_id"`
	EnvironmentID  string            `json:"environment_id"`
	ActorID        string            `json:"actor_id"`
	Action         string            `json:"action"`
	TargetID       string            `json:"target_id"`
	Outcome        string            `json:"outcome"`
	Metadata       map[string]string `json:"metadata"`
	OccurredAt     string            `json:"occurred_at"`
}

// ExportChunk carries contiguous event ordinals. PreviousDigest is the SHA-256
// of the preceding canonical chunk bytes, or ExportZeroDigest for chunk one.
// The final chunk's SHA-256 is the manifest ChainRoot. This binds all chunk bytes
// transitively, including each chunk's schema, destination and capture identity.
type ExportChunk struct {
	Schema         string        `json:"schema"`
	Binding        ExportBinding `json:"binding"`
	Ordinal        int64         `json:"ordinal"`
	FirstEvent     int64         `json:"first_event"`
	EventCount     int64         `json:"event_count"`
	PreviousDigest string        `json:"previous_digest"`
	Events         []ExportEvent `json:"events"`
}

// ExportManifest has no unbounded receipt array. ChunkBytes is the sum of complete
// encoded chunk sizes. Receipt authority must prove global coverage and uniqueness;
// a syntactically valid manifest alone is not proof that an export is complete.
type ExportManifest struct {
	Schema     string        `json:"schema"`
	Binding    ExportBinding `json:"binding"`
	EventCount int64         `json:"event_count"`
	ChunkCount int64         `json:"chunk_count"`
	ChunkBytes int64         `json:"chunk_bytes"`
	ChainRoot  string        `json:"chain_root"`
}

// ExportChunkExpectation must come from immutable persisted authority, never
// from the untrusted chunk being verified. SHA256 binds even a well-formed subset
// or a change to event contents that an unkeyed codec cannot detect by itself.
type ExportChunkExpectation struct {
	Binding                         ExportBinding
	Ordinal, FirstEvent, EventCount int64
	PreviousDigest, SHA256          string
}

// ProjectExportEvent maps the stored rejected outcome to public denied and
// applies the existing metadata-key redaction policy, making an independent copy.
// Encode/Decode refuse unredacted values; they never silently change frozen bytes.
func ProjectExportEvent(event ExportEvent) (ExportEvent, error) {
	for key, value := range event.Metadata {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return ExportEvent{}, ErrExport
		}
	}
	if event.Outcome == "rejected" {
		event.Outcome = "denied"
	}
	metadata, err := redactMetadata(event.Metadata)
	if err != nil {
		return ExportEvent{}, ErrExport
	}
	event.Metadata = metadata
	if !validExportEvent(event) {
		return ExportEvent{}, ErrExport
	}
	return event, nil
}

// Canonical JSON contract shared with future SQL snapshot serialization:
// UTF-8 without BOM/whitespace/newline; object fields in the declared struct
// order, all present; metadata keys sorted by UTF-8 bytes; base-10 integers with
// no exponent; JSON string escaping as encoding/json.Marshal (including lowercase
// \\u003c/003e/0026 and U+2028/U+2029 escapes); no Unicode normalization. SQL must
// reproduce these bytes, NOT use jsonb::text (different spaces/key order). Freeze
// EncodeExportEvent bytes or a byte-identical SQL implementation verified against
// the golden test vector. Future SQL capture must freeze canonical bytes from
// source rows; PrepareChunk must check bytes AND ordered frozen source identities,
// never trust a worker-provided digest. An independent SQL -> Go fixture must
// cover <>&, quotes, backslashes, U+2028/U+2029, non-ASCII metadata and fractional
// timestamps. Stripping whitespace from jsonb::text is not serialization and
// corrupts spaces inside strings. This is a versioned contract, not RFC 8785 JCS.
func EncodeExportEvent(event ExportEvent) ([]byte, error) {
	if !validExportEvent(event) {
		return nil, ErrExport
	}
	return json.Marshal(event)
}

func DecodeExportEvent(body []byte) (ExportEvent, error) {
	var event ExportEvent
	if !decodeExportJSON(body, ExportMaximumEventBytes, &event) {
		return ExportEvent{}, ErrExport
	}
	canonical, err := EncodeExportEvent(event)
	if err != nil || !bytes.Equal(body, canonical) {
		return ExportEvent{}, ErrExport
	}
	return event, nil
}

func EncodeExportChunk(chunk ExportChunk) ([]byte, error) {
	if chunk.Schema != ExportChunkSchema || !validExportBinding(chunk.Binding) ||
		!exportPositive(chunk.Ordinal) || !exportPositive(chunk.FirstEvent) ||
		chunk.EventCount < 1 || chunk.EventCount > ExportMaximumChunkEvents ||
		int64(len(chunk.Events)) != chunk.EventCount ||
		chunk.FirstEvent > exportMaximumInteger-chunk.EventCount+1 ||
		chunk.Ordinal > chunk.FirstEvent || !validExportDigest(chunk.PreviousDigest) {
		return nil, ErrExport
	}
	if chunk.Ordinal == 1 {
		if chunk.FirstEvent != 1 || chunk.PreviousDigest != ExportZeroDigest {
			return nil, ErrExport
		}
	} else if chunk.PreviousDigest == ExportZeroDigest || (chunk.FirstEvent-2)/ExportMaximumChunkEvents+1 > chunk.Ordinal-1 {
		return nil, ErrExport
	}
	// Account for the wire envelope and separators before allocating the final
	// chunk. Each individual event is bounded by its validated metadata/text sizes.
	header := chunk
	header.Events = []ExportEvent{}
	prefix, _ := json.Marshal(header)
	total := len(prefix)
	seen := make(map[string]struct{}, len(chunk.Events))
	for index, event := range chunk.Events {
		if event.OrganizationID != chunk.Binding.OrganizationID || event.Ordinal != chunk.FirstEvent+int64(index) {
			return nil, ErrExport
		}
		if _, exists := seen[event.ID]; exists {
			return nil, ErrExport
		}
		seen[event.ID] = struct{}{}
		if index > 0 && !exportEventBefore(chunk.Events[index-1], event) {
			return nil, ErrExport
		}
		body, err := EncodeExportEvent(event)
		if err != nil {
			return nil, ErrExport
		}
		total += len(body)
		if index > 0 {
			total++
		}
		if total > ExportMaximumChunkBytes {
			return nil, ErrExport
		}
	}
	return json.Marshal(chunk)
}

func DecodeExportChunk(body []byte) (ExportChunk, error) {
	var chunk ExportChunk
	if !boundedExportChunkArray(body) || !decodeExportJSON(body, ExportMaximumChunkBytes, &chunk) {
		return ExportChunk{}, ErrExport
	}
	canonical, err := EncodeExportChunk(chunk)
	if err != nil || !bytes.Equal(body, canonical) {
		return ExportChunk{}, ErrExport
	}
	return chunk, nil
}

// Reject an overlong array before encoding/json can allocate a large []ExportEvent
// from a small array of nulls. Check every root occurrence, so duplicate/case-alias
// events fields cannot hide an oversized earlier array from this preflight.
func boundedExportChunkArray(body []byte) bool {
	if len(body) == 0 || len(body) > ExportMaximumChunkBytes || !utf8.Valid(body) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		switch name {
		case "schema", "binding", "ordinal", "first_event", "event_count", "previous_digest":
			var raw json.RawMessage
			if decoder.Decode(&raw) != nil {
				return false
			}
		case "events":
			array, err := decoder.Token()
			if err != nil || array != json.Delim('[') {
				return false
			}
			count := 0
			for decoder.More() {
				count++
				if count > ExportMaximumChunkEvents {
					return false
				}
				var raw json.RawMessage
				if decoder.Decode(&raw) != nil {
					return false
				}
				if _, err := DecodeExportEvent(raw); err != nil {
					return false
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return false
			}
		default:
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && end == json.Delim('}') && seen["events"]
}

func VerifyExportChunk(body []byte, expected ExportChunkExpectation) (ExportChunk, error) {
	if !exportBodyMatches(body, expected.SHA256, ExportMaximumChunkBytes) {
		return ExportChunk{}, ErrExport
	}
	chunk, err := DecodeExportChunk(body)
	if err != nil || chunk.Binding != expected.Binding || chunk.Ordinal != expected.Ordinal ||
		chunk.FirstEvent != expected.FirstEvent || chunk.EventCount != expected.EventCount || chunk.PreviousDigest != expected.PreviousDigest {
		return ExportChunk{}, ErrExport
	}
	return chunk, nil
}

func EncodeExportManifest(manifest ExportManifest) ([]byte, error) {
	if manifest.Schema != ExportManifestSchema || !validExportBinding(manifest.Binding) ||
		manifest.EventCount < 0 || manifest.EventCount > exportMaximumInteger ||
		manifest.ChunkCount < 0 || manifest.ChunkCount > exportMaximumInteger ||
		manifest.ChunkBytes < 0 || manifest.ChunkBytes > exportMaximumInteger || !validExportDigest(manifest.ChainRoot) {
		return nil, ErrExport
	}
	if manifest.EventCount == 0 {
		if manifest.ChunkCount != 0 || manifest.ChunkBytes != 0 || manifest.ChainRoot != ExportZeroDigest {
			return nil, ErrExport
		}
	} else if manifest.ChunkCount < 1 || manifest.ChunkCount > manifest.EventCount ||
		(manifest.EventCount-1)/ExportMaximumChunkEvents+1 > manifest.ChunkCount ||
		manifest.ChunkBytes < manifest.ChunkCount || (manifest.ChunkBytes-1)/ExportMaximumChunkBytes+1 > manifest.ChunkCount ||
		manifest.ChainRoot == ExportZeroDigest {
		return nil, ErrExport
	}
	return json.Marshal(manifest)
}

func DecodeExportManifest(body []byte) (ExportManifest, error) {
	var manifest ExportManifest
	if !decodeExportJSON(body, exportMaximumManifestBytes, &manifest) {
		return ExportManifest{}, ErrExport
	}
	canonical, err := EncodeExportManifest(manifest)
	if err != nil || !bytes.Equal(body, canonical) {
		return ExportManifest{}, ErrExport
	}
	return manifest, nil
}

// VerifyExportManifest checks a persisted expected manifest and its pinned body
// digest. DecodeExportManifest alone checks structure, not receipt-set completeness.
func VerifyExportManifest(body []byte, expected ExportManifest, digest string) (ExportManifest, error) {
	if !exportBodyMatches(body, digest, exportMaximumManifestBytes) {
		return ExportManifest{}, ErrExport
	}
	manifest, err := DecodeExportManifest(body)
	if err != nil || manifest != expected {
		return ExportManifest{}, ErrExport
	}
	return manifest, nil
}

func validExportBinding(binding ExportBinding) bool {
	if !validExportScope(binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID) || !exportID(binding.ExportID) || !exportID(binding.CaptureID) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range []string{binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, binding.ExportID, binding.CaptureID} {
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validExportScope(org, workspace, environment string) bool {
	o, e1 := domain.ParseProductID(org)
	w, e2 := domain.ParseProductID(workspace)
	e, e3 := domain.ParseProductID(environment)
	if e1 != nil || e2 != nil || e3 != nil {
		return false
	}
	_, err := domain.NewScope(o, w, e)
	return err == nil
}

func exportID(value string) bool      { _, err := domain.ParseProductID(value); return err == nil }
func exportPositive(value int64) bool { return value > 0 && value <= exportMaximumInteger }

// Published schema19 identity mutations retain these exact action bytes. This
// reader compatibility rule does not widen the generic new-event emitter.
func validPersistedExportAction(action string) bool {
	switch action {
	case "identity_provider.createSSOConnection", "identity_provider.deleteSSOConnection", "identity_provider.testSSOConnection", "identity_provider.createSCIMConnection", "identity_provider.deleteSCIMConnection":
		return true
	default:
		return validAction(action)
	}
}

func validExportEvent(event ExportEvent) bool {
	if !exportPositive(event.Ordinal) || !exportID(event.ID) || !exportID(event.ActorID) ||
		!validExportScope(event.OrganizationID, event.WorkspaceID, event.EnvironmentID) || !validPersistedExportAction(event.Action) ||
		!validOutcome(Outcome(event.Outcome)) || !utf8.ValidString(event.TargetID) || !validMetadataPart(event.TargetID, 128) || event.Metadata == nil {
		return false
	}
	stamp, err := time.Parse(exportTimeLayout, event.OccurredAt)
	if err != nil || stamp.IsZero() || stamp.Year() < 1 || stamp.Format(exportTimeLayout) != event.OccurredAt {
		return false
	}
	redacted, err := redactMetadata(event.Metadata)
	if err != nil {
		return false
	}
	for key, value := range event.Metadata {
		if !utf8.ValidString(key) || !utf8.ValidString(value) || value != redacted[key] {
			return false
		}
	}
	return true
}

func exportEventBefore(first, second ExportEvent) bool {
	return first.OccurredAt > second.OccurredAt || first.OccurredAt == second.OccurredAt && first.ID > second.ID
}

func validExportDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func exportBodyMatches(body []byte, digest string, maximum int) bool {
	if len(body) == 0 || len(body) > maximum || !validExportDigest(digest) {
		return false
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) == digest
}

func decodeExportJSON(body []byte, maximum int, target any) bool {
	if len(body) == 0 || len(body) > maximum || !utf8.Valid(body) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	// Exact re-encoding at the caller rejects duplicates, case aliases, alternate
	// escapes/number forms, missing fields, whitespace and trailing JSON values.
	return decoder.Decode(target) == nil
}
