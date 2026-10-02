package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const securityAgentExportRendererRevision = "security-agent-evidence-envelope-v1"
const securityAgentExportFormatLimit = 4 << 20

type securityAgentExportSelection struct {
	Kind              string
	ID                string
	Version           int64
	AssociationDigest string
}
type securityAgentExportBinding struct {
	RunID     string
	StepID    string
	Selection []securityAgentExportSelection
}

type securityAgentExportRecord struct {
	Kind              string `json:"source_kind"`
	ID                string `json:"source_id"`
	Version           int64  `json:"source_version"`
	AssociationDigest string `json:"association_digest"`
	ContentSHA256     string `json:"content_sha256"`
	ContentJSON       string `json:"content_json"`
}

type securityAgentExportSnapshot struct {
	Revision     string                      `json:"mapping_revision"`
	At           string                      `json:"snapshot_at"`
	Organization string                      `json:"organization_id"`
	Workspace    string                      `json:"workspace_id"`
	Environment  string                      `json:"environment_id"`
	RunID        string                      `json:"run_id"`
	StepID       string                      `json:"step_id"`
	Records      []securityAgentExportRecord `json:"records"`
}

// This boundary accepts only a trusted, already redacted collector snapshot.
// Selection equality is not membership or principal authorization.
func renderSecurityAgentEvidenceExportPackage(ctx context.Context, lease complianceExportLease, binding securityAgentExportBinding, raw json.RawMessage) (compliancePreparedArtifact, error) {
	if ctx == nil || ctx.Err() != nil || lease.Scope.Validate() != nil || !securityAgentExportProductID(lease.ExportID) || !securityAgentExportProductID(binding.RunID) || !securityAgentExportProductID(binding.StepID) || len(binding.Selection) < 1 || len(binding.Selection) > 100 {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	if securityAgentExportCheckJSON(raw, securityAgentExportFormatLimit, "snapshot") != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	var snapshot securityAgentExportSnapshot
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.Revision != "security-agent-run-evidence-v1" || snapshot.Organization != lease.Scope.OrganizationID().String() || snapshot.Workspace != lease.Scope.WorkspaceID().String() || snapshot.Environment != lease.Scope.EnvironmentID().String() || snapshot.RunID != binding.RunID || snapshot.StepID != binding.StepID || len(snapshot.Records) != len(binding.Selection) {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	at, err := time.Parse(time.RFC3339Nano, snapshot.At)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != snapshot.At {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	seen := make(map[string]bool, len(snapshot.Records))
	for i, r := range snapshot.Records {
		s := binding.Selection[i]
		key := r.Kind + "/" + r.ID
		validID := securityAgentExportProductID(r.ID)
		if r.Kind == "manual" {
			validID = securityAgentExportDigest(r.ID)
		}
		if !slices.Contains([]string{"finding", "attack_path", "runtime_decision", "run_audit", "existing_test", "attack_lab", "manual"}, r.Kind) || !validID || r.Version < 1 || r.Version > 9007199254740991 || !strings.HasPrefix(r.AssociationDigest, "sha256:") || !securityAgentExportDigest(strings.TrimPrefix(r.AssociationDigest, "sha256:")) || !securityAgentExportDigest(r.ContentSHA256) || seen[key] || s.Kind != r.Kind || s.ID != r.ID || s.Version != r.Version || s.AssociationDigest != r.AssociationDigest {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
		seen[key] = true
		if securityAgentExportCheckJSON([]byte(r.ContentJSON), 65536, "content") != nil {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
		hash := sha256.Sum256([]byte(r.ContentJSON))
		if hex.EncodeToString(hash[:]) != r.ContentSHA256 {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
	}
	manifestJSON, err := json.Marshal(struct {
		securityAgentExportSnapshot
		RendererRevision string `json:"renderer_revision"`
	}{snapshot, securityAgentExportRendererRevision})
	if err != nil || len(manifestJSON) > securityAgentExportFormatLimit {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	csvBytes := &securityAgentExportBuffer{limit: securityAgentExportFormatLimit}
	w := csv.NewWriter(csvBytes)
	header := []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "snapshot_at", "renderer_revision", "source_kind", "source_id", "source_version", "association_digest", "content_sha256", "content_json"}
	if w.Write(header) != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	for _, r := range snapshot.Records {
		row := []string{snapshot.Organization, snapshot.Workspace, snapshot.Environment, snapshot.RunID, snapshot.StepID, snapshot.At, securityAgentExportRendererRevision, r.Kind, r.ID, strconv.FormatInt(r.Version, 10), r.AssociationDigest, r.ContentSHA256, r.ContentJSON}
		for i := range row {
			row[i] = securityAgentExportCSVCell(row[i])
		}
		if w.Write(row) != nil {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
	}
	w.Flush()
	if w.Error() != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	human := &securityAgentExportBuffer{limit: securityAgentExportFormatLimit}
	_, err = fmt.Fprint(human, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Run evidence export</title></head><body><h1>Run evidence export</h1><p>This export does not establish remediation.</p><dl>")
	manifestValues := []string{snapshot.Organization, snapshot.Workspace, snapshot.Environment, snapshot.RunID, snapshot.StepID, snapshot.At, securityAgentExportRendererRevision}
	for i, value := range manifestValues {
		if err == nil {
			_, err = fmt.Fprintf(human, "<dt>%s</dt><dd>%s</dd>", header[i], html.EscapeString(value))
		}
	}
	if err == nil {
		_, err = fmt.Fprintf(human, "<dt>mapping_revision</dt><dd>%s</dd></dl>", html.EscapeString(snapshot.Revision))
	}
	for _, r := range snapshot.Records {
		if err != nil {
			break
		}
		_, err = fmt.Fprint(human, "<section><h2>Record</h2><dl>")
		values := []string{r.Kind, r.ID, strconv.FormatInt(r.Version, 10), r.AssociationDigest, r.ContentSHA256}
		for i, value := range values {
			if err == nil {
				_, err = fmt.Fprintf(human, "<dt>%s</dt><dd>%s</dd>", header[i+7], html.EscapeString(value))
			}
		}
		if err == nil {
			_, err = fmt.Fprintf(human, "</dl><pre>%s</pre></section>", html.EscapeString(r.ContentJSON))
		}
	}
	if err == nil {
		_, err = fmt.Fprint(human, "</body></html>")
	}
	if err != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	body, err := json.Marshal(struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		JSON    json.RawMessage `json:"json"`
		CSV     string          `json:"csv"`
		Human   string          `json:"human"`
	}{1, lease.ExportID, manifestJSON, csvBytes.String(), human.String()})
	if err != nil || len(body) > 8<<20 || ctx.Err() != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	hash := sha256.Sum256(body)
	return compliancePreparedArtifact{Bytes: body, RendererRevision: securityAgentExportRendererRevision, Reference: lease.ExportID, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(body)), FormatSizes: map[string]int64{"json": int64(len(manifestJSON)), "csv": int64(csvBytes.Len()), "readable": int64(human.Len())}}, nil
}

func securityAgentExportCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " ")
	if len(trimmed) > 0 && strings.ContainsRune("=+-@\t\r\n", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func securityAgentExportProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func securityAgentExportDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// A cap is checked before each buffer growth; no format is truncated on overflow.
type securityAgentExportBuffer struct {
	bytes.Buffer
	limit int
}

func (b *securityAgentExportBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errWorkerExecution
	}
	return b.Buffer.Write(p)
}

// Token validation precedes decoding into structs, bounding record allocation
// and rejecting duplicate/aliased/missing fields which encoding/json accepts.
func securityAgentExportCheckJSON(raw []byte, max int, schema string) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return errWorkerExecution
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if securityAgentExportJSONValue(d, 0, schema) != nil {
		return errWorkerExecution
	}
	if _, err := d.Token(); err != io.EOF {
		return errWorkerExecution
	}
	return nil
}

func securityAgentExportJSONValue(d *json.Decoder, depth int, schema string) error {
	token, err := d.Token()
	if err != nil {
		return errWorkerExecution
	}
	if schema == "records" && token != json.Delim('[') || (schema == "snapshot" || schema == "record" || schema == "content") && token != json.Delim('{') {
		return errWorkerExecution
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth >= 32 {
		return errWorkerExecution
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		var fields []string
		if schema == "snapshot" {
			fields = []string{"mapping_revision", "snapshot_at", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "records"}
		}
		if schema == "record" {
			fields = []string{"source_kind", "source_id", "source_version", "association_digest", "content_sha256", "content_json"}
		}
		for d.More() {
			t, err := d.Token()
			key, ok := t.(string)
			if err != nil || !ok || seen[key] || fields != nil && !slices.Contains(fields, key) {
				return errWorkerExecution
			}
			seen[key] = true
			child := ""
			if schema == "snapshot" && key == "records" {
				child = "records"
			}
			if securityAgentExportJSONValue(d, depth+1, child) != nil {
				return errWorkerExecution
			}
		}
		if fields != nil && len(seen) != len(fields) {
			return errWorkerExecution
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errWorkerExecution
		}
	case '[':
		n := 0
		for d.More() {
			n++
			child := ""
			if schema == "records" {
				if n > 100 {
					return errWorkerExecution
				}
				child = "record"
			}
			if securityAgentExportJSONValue(d, depth+1, child) != nil {
				return errWorkerExecution
			}
		}
		if schema == "records" && n == 0 {
			return errWorkerExecution
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errWorkerExecution
		}
	default:
		return errWorkerExecution
	}
	return nil
}
