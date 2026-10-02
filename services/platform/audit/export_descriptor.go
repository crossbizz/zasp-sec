package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// ExportDescriptor is public job state, without provider coordinates.
type ExportDescriptor struct {
	ID                 string `json:"id"`
	OrganizationID     string `json:"organization_id"`
	WorkspaceID        string `json:"workspace_id"`
	EnvironmentID      string `json:"environment_id"`
	CreatedAt          string `json:"created_at"`
	AuditCorrelationID string `json:"audit_correlation_id"`
	Status             string `json:"status"`
	EventCount         *int64 `json:"event_count"`
	CapturedAt         string `json:"captured_at,omitempty"`
	ChunkCount         *int64 `json:"chunk_count,omitempty"`
	ChunkBytes         *int64 `json:"chunk_bytes,omitempty"`
	ManifestSHA256     string `json:"manifest_sha256,omitempty"`
	FailureCode        string `json:"failure_code,omitempty"`
}

func DecodeExportDescriptor(payload []byte) (ExportDescriptor, error) {
	var descriptor ExportDescriptor
	if len(payload) == 0 || len(payload) > 8192 || !utf8.Valid(payload) {
		return descriptor, ErrExport
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return descriptor, ErrExport
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || fields[name] != nil {
			return descriptor, ErrExport
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return descriptor, ErrExport
		}
		fields[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || !decodeExportJSON(payload, 8192, &descriptor) {
		return ExportDescriptor{}, ErrExport
	}
	required := []string{"id", "organization_id", "workspace_id", "environment_id", "created_at", "audit_correlation_id", "status", "event_count"}
	switch descriptor.Status {
	case "queued", "processing":
		if descriptor.EventCount != nil {
			return ExportDescriptor{}, ErrExport
		}
	case "failed":
		required = append(required, "failure_code")
		if descriptor.EventCount != nil || !slices.Contains([]string{"capacity_exceeded", "invalid_source", "execution_failed"}, descriptor.FailureCode) {
			return ExportDescriptor{}, ErrExport
		}
	case "ready":
		required = append(required, "captured_at", "chunk_count", "chunk_bytes", "manifest_sha256")
		if !validExportDescriptorTimestamp(descriptor.CapturedAt) || !validExportDigest(descriptor.ManifestSHA256) || descriptor.EventCount == nil || descriptor.ChunkCount == nil || descriptor.ChunkBytes == nil {
			return ExportDescriptor{}, ErrExport
		}
		for _, count := range []int64{*descriptor.EventCount, *descriptor.ChunkCount, *descriptor.ChunkBytes} {
			if count < 0 || count > 1<<53-1 {
				return ExportDescriptor{}, ErrExport
			}
		}
		if *descriptor.EventCount == 0 {
			if *descriptor.ChunkCount != 0 || *descriptor.ChunkBytes != 0 {
				return ExportDescriptor{}, ErrExport
			}
		} else if *descriptor.ChunkCount < 1 || *descriptor.ChunkCount > *descriptor.EventCount || *descriptor.ChunkBytes < *descriptor.ChunkCount || (*descriptor.EventCount-1)/1000+1 > *descriptor.ChunkCount || (*descriptor.ChunkBytes-1)/(1<<20)+1 > *descriptor.ChunkCount {
			return ExportDescriptor{}, ErrExport
		}
	default:
		return ExportDescriptor{}, ErrExport
	}
	if len(fields) != len(required) {
		return ExportDescriptor{}, ErrExport
	}
	for _, name := range required {
		if fields[name] == nil {
			return ExportDescriptor{}, ErrExport
		}
	}
	org, e1 := domain.ParseProductID(descriptor.OrganizationID)
	workspace, e2 := domain.ParseProductID(descriptor.WorkspaceID)
	environment, e3 := domain.ParseProductID(descriptor.EnvironmentID)
	_, scopeErr := domain.NewScope(org, workspace, environment)
	if e1 != nil || e2 != nil || e3 != nil || scopeErr != nil || !exportID(descriptor.ID) || !exportID(descriptor.AuditCorrelationID) || !validExportDescriptorTimestamp(descriptor.CreatedAt) {
		return ExportDescriptor{}, ErrExport
	}
	return descriptor, nil
}

func validExportDescriptorTimestamp(value string) bool {
	const layout = "2006-01-02T15:04:05.000000Z"
	stamp, err := time.Parse(layout, value)
	return err == nil && !stamp.IsZero() && stamp.Year() >= 1 && stamp.Format(layout) == value
}
