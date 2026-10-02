package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol"
)

type complianceHTTPHandler struct {
	source     *ComplianceRepository
	exports    *ComplianceExportsRepository
	reader     complianceArtifactReader
	signingKey []byte
}

func compliancePermissions(ctx context.Context, i RequestIdentity) bool {
	for _, p := range []string{"view", "view_audit", "view_compliance"} {
		if !currentRequestHasPermission(ctx, i, p) {
			return false
		}
	}
	return true
}
func (h *complianceHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, current := requestAuthorizationFromContext(r.Context()); current && !validAuditExportCursorKey(h.signingKey) {
		writeComplianceError(w, r, ErrRepositoryUnavailable)
		return
	}
	identity, ok := IdentityFromRequest(r)
	route, routed := RoutedOperationFromRequest(r)
	credential, browser, auth := requestCredential(r)
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == browserSessionCookie {
			count++
		}
	}
	if !ok || !routed || !auth || !browser || count != 1 || identity.CredentialKind != CredentialBrowserSession || !validRequestIdentity(identity, false) {
		writeComplianceError(w, r, ErrRepositoryAuthentication)
		return
	}
	if !compliancePermissions(r.Context(), identity) {
		writeComplianceError(w, r, ErrComplianceForbidden)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	if r.Method == http.MethodGet {
		h.get(w, r, identity, digest[:], route)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || len(r.Header.Values("X-CSRF-Token")) != 1 || r.Header.Get("X-CSRF-Token") != identity.CSRFToken {
		writeComplianceError(w, r, ErrRepositoryOperation)
		return
	}
	body, err := complianceRequestBody(r)
	if err != nil {
		writeComplianceError(w, r, err)
		return
	}
	switch route.OperationID {
	case "createComplianceExport":
		if !identity.FreshAuthenticated {
			writeComplianceError(w, r, ErrComplianceForbidden)
			return
		}
		object, valid := complianceClosedObject(body, []string{"framework", "control_id"})
		var input ComplianceExportRequest
		if !valid || decodeStrictDiscovery(body, &input) != nil || !complianceFilterFields(object) || len(r.Header.Values("Idempotency-Key")) != 1 {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
		// Empty fields and omitted fields have one canonical request digest in SQL.
		job, err := h.exports.Create(r.Context(), identity, digest[:], r.Header.Get("Idempotency-Key"), input)
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		writeJSONValue(w, r, http.StatusCreated, compliancePublicJob(job), nil)
	case "createComplianceDownloadGrant", "downloadComplianceExport":
		fields := []string{"format"}
		if route.OperationID == "downloadComplianceExport" {
			fields = append(fields, "token")
		}
		object, err := auditExportClosedObject(body, 1024, fields...)
		var format, token string
		if err != nil || json.Unmarshal(object["format"], &format) != nil || !stringIn(format, "json", "csv", "human") || !validProductID(route.PathParameters["id"]) {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
		sqlFormat := format
		if format == "human" {
			sqlFormat = "readable"
		}
		id := route.PathParameters["id"]
		if route.OperationID == "createComplianceDownloadGrant" {
			random := make([]byte, 32)
			if _, err := rand.Read(random); err != nil {
				writeComplianceError(w, r, ErrRepositoryUnavailable)
				return
			}
			token = hex.EncodeToString(random)
			grant, err := h.exports.grantAction(r.Context(), identity, digest[:], id, token, sqlFormat, "issue")
			if err != nil {
				writeComplianceError(w, r, err)
				return
			}
			writeJSONValue(w, r, http.StatusCreated, map[string]any{"token": token, "format": format, "expires_at": grant.ExpiresAt}, nil)
			return
		}
		if json.Unmarshal(object["token"], &token) != nil || !validExistingTestPublicDigest(token) {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
		pin, err := h.exports.readGrant(r.Context(), identity, digest[:], id, token, sqlFormat)
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		// The same deadline bounds storage and the final database authority check.
		ctx, cancel := context.WithDeadline(r.Context(), pin.ReadExpiresAt)
		defer cancel()
		bytes, err := readComplianceDownload(ctx, h.reader, identity, id, format, pin)
		if err != nil {
			// Only verified mismatches are corruption incidents. Provider failures
			// retain the bounded read lease without a false integrity audit.
			if errors.Is(err, artifactstore.ErrIntegrity) {
				_, _ = h.exports.grantAction(ctx, identity, digest[:], id, token, sqlFormat, "integrity_failure")
			}
			writeComplianceError(w, r, ErrRepositoryUnavailable)
			return
		}
		if _, err = h.exports.grantAction(ctx, identity, digest[:], id, token, sqlFormat, "consume"); err != nil {
			writeComplianceError(w, r, err)
			return
		}
		if ctx.Err() != nil {
			writeComplianceError(w, r, ctx.Err())
			return
		}
		media, extension := "application/json", "json"
		if format == "csv" {
			media, extension = "text/csv; charset=utf-8", "csv"
		}
		if format == "human" {
			media, extension = "text/plain; charset=utf-8", "txt"
		}
		w.Header().Set("Content-Type", media)
		w.Header().Set("Content-Disposition", `attachment; filename="compliance-`+id+`.`+extension+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes)
	default:
		writeComplianceError(w, r, ErrRepositoryNotFound)
	}
}
func complianceFilterFields(o map[string]json.RawMessage) bool {
	for _, raw := range o {
		var v string
		if string(raw) == "null" || json.Unmarshal(raw, &v) != nil {
			return false
		}
	}
	return true
}
func complianceClosedObject(raw []byte, optional []string, required ...string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (!slices.Contains(optional, key) && !slices.Contains(required, key)) || fields[key] != nil {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		fields[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	for _, key := range required {
		if fields[key] == nil {
			return nil, false
		}
	}
	return fields, true
}
func complianceRequestBody(r *http.Request) ([]byte, error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 || r.Body == nil {
		return nil, ErrRepositoryOperation
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil || len(b) > 1024 {
		return nil, ErrRepositoryOperation
	}
	return b, nil
}
func (h *complianceHTTPHandler) get(w http.ResponseWriter, r *http.Request, identity RequestIdentity, digest []byte, route RoutedOperation) {
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) > 0 {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
	}
	switch route.OperationID {
	case "getComplianceExport":
		if r.URL.RawQuery != "" {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
		job, err := h.exports.Get(r.Context(), identity, digest, route.PathParameters["id"])
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		writeJSONValue(w, r, 200, compliancePublicJob(job), nil)
	case "getComplianceEvidence":
		query, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"source_version": 15})
		if !ok {
			writeComplianceError(w, r, ErrRepositoryOperation)
			return
		}
		target := ComplianceTarget{SourceKind: route.PathParameters["sourceKind"], SourceID: route.PathParameters["id"]}
		if v := query.Get("source_version"); v != "" {
			version, err := strconv.ParseInt(v, 10, 64)
			if err != nil || version < 1 || strconv.FormatInt(version, 10) != v {
				writeComplianceError(w, r, ErrRepositoryOperation)
				return
			}
			target.SourceVersion = version
		}
		value, err := h.source.GetEvidence(r.Context(), identity, digest, target)
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		writeJSONValue(w, r, 200, map[string]any{"record": compliancePublicRecord(value), "freshness": value.Freshness, "organization_id": value.OrganizationID, "workspace_id": value.WorkspaceID, "environment_id": value.EnvironmentID}, nil)
	case "listComplianceControls", "listComplianceEvidence":
		options, err := complianceHTTPListOptions(r, identity, route.OperationID, h.signingKey)
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		if route.OperationID == "listComplianceControls" {
			page, err := h.source.ListControls(r.Context(), identity, digest, options)
			if err != nil {
				writeComplianceError(w, r, err)
				return
			}
			values := make([]any, 0, len(page.Items))
			for _, c := range page.Items {
				evidence, err := h.source.ListEvidence(r.Context(), identity, digest, ComplianceListOptions{Framework: c.Framework, ControlID: c.ControlID, Limit: 100})
				if err != nil {
					writeComplianceError(w, r, err)
					return
				}
				control := compliancePublicControl(c, evidence.Items)
				values = append(values, control)
			}
			writeJSONValue(w, r, 200, h.publicPage(r, values, page.NextCursor), nil)
			return
		}
		page, err := h.source.ListEvidence(r.Context(), identity, digest, options)
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		framework := options.Framework
		if framework == "" && options.ControlID != "" {
			framework = strings.Split(options.ControlID, "-")[0]
		}
		if framework == "" {
			framework = "soc2_security"
		}
		controls, err := h.source.ListControls(r.Context(), identity, digest, ComplianceListOptions{Framework: framework, ControlID: options.ControlID, Limit: 100})
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		values := make([]any, 0, len(page.Items))
		for _, v := range page.Items {
			var matched *ComplianceControl
			for i := range controls.Items {
				c := &controls.Items[i]
				if slices.Contains(c.RequiredSources, v.Source) {
					matched = c
					break
				}
			}
			if matched == nil {
				writeComplianceError(w, r, ErrRepositoryUnavailable)
				return
			}
			values = append(values, map[string]any{"control": compliancePublicControl(*matched, []ComplianceEvidence{v}), "freshness": v.Freshness, "evidence": []any{compliancePublicRecord(v)}})
		}
		writeJSONValue(w, r, 200, h.publicPage(r, values, page.NextCursor), nil)
	default:
		writeComplianceError(w, r, ErrRepositoryNotFound)
	}
}
func complianceHTTPListOptions(r *http.Request, identity RequestIdentity, operation string, signingKeys ...[]byte) (ComplianceListOptions, error) {
	// The repository's 4096-byte cursor plus a SHA-256 MAC, base64url encoded.
	q, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"framework": 32, "control_id": 128, "cursor": 5504, "limit": 3})
	if !ok {
		return ComplianceListOptions{}, ErrRepositoryOperation
	}
	o := ComplianceListOptions{Framework: q.Get("framework"), ControlID: q.Get("control_id")}
	if text := q.Get("limit"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || strconv.Itoa(n) != text {
			return o, ErrRepositoryOperation
		}
		o.Limit = n
	}
	if text := q.Get("cursor"); text != "" {
		raw, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != text {
			return o, ErrRepositoryOperation
		}
		if _, current := requestAuthorizationFromContext(r.Context()); current {
			if len(signingKeys) != 1 || !validAuditExportCursorKey(signingKeys[0]) || len(raw) <= sha256.Size {
				return o, ErrRepositoryOperation
			}
			payload, signature := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
			mac := hmac.New(sha256.New, authorizationCursorKey(r.Context(), signingKeys[0]))
			_, _ = mac.Write(payload)
			if !hmac.Equal(signature, mac.Sum(nil)) {
				return o, ErrRepositoryOperation
			}
			raw = payload
		}
		o.Cursor = raw
	}
	internal := "listControls"
	if operation == "listComplianceEvidence" {
		internal = "listEvidence"
	}
	if !validComplianceList(identity, o, internal) {
		return o, ErrRepositoryOperation
	}
	return o, nil
}

// Live aggregate authority is separate from frozen formatter semantics.
type complianceLiveControl struct {
	sessioncontrol.ComplianceControl
	Freshness string `json:"freshness"`
}

func compliancePublicControl(c ComplianceControl, records []ComplianceEvidence) complianceLiveControl {
	ids := []string{}
	for _, r := range records {
		if !slices.Contains(ids, r.ID) {
			ids = append(ids, r.ID)
		}
	}
	slices.Sort(ids)
	until, _ := time.Parse(time.RFC3339Nano, c.FreshUntil)
	return complianceLiveControl{ComplianceControl: sessioncontrol.ComplianceControl{ID: c.ControlID, Framework: c.Framework, Name: c.Label, EvidenceIDs: ids, FreshUntil: until}, Freshness: c.Freshness}
}
func compliancePublicRecord(v ComplianceEvidence) map[string]any {
	raw, _ := json.Marshal(v.Metadata)
	var metadata map[string]any
	_ = json.Unmarshal(raw, &metadata)
	if v.Source == "finding" {
		ids := v.Metadata.EvidenceIDs
		if ids == nil {
			ids = []string{}
		}
		metadata["evidence_ids"] = ids
	}
	return map[string]any{"id": v.ID, "asset_id": v.Asset, "source": v.Source, "at": v.Timestamp, "target": v.Target, "metadata": metadata}
}
func compliancePublicPage(values []any, next json.RawMessage) map[string]any {
	var cursor any
	if len(next) > 0 {
		cursor = base64.RawURLEncoding.EncodeToString(next)
	}
	return map[string]any{"items": values, "page_info": map[string]any{"next_cursor": cursor, "has_more": len(next) > 0}}
}

func (h *complianceHTTPHandler) publicPage(r *http.Request, values []any, next json.RawMessage) map[string]any {
	if _, current := requestAuthorizationFromContext(r.Context()); current && len(next) > 0 {
		mac := hmac.New(sha256.New, authorizationCursorKey(r.Context(), h.signingKey))
		_, _ = mac.Write(next)
		next = append(append([]byte(nil), next...), mac.Sum(nil)...)
	}
	return compliancePublicPage(values, next)
}
func compliancePublicJob(j ComplianceExportJob) map[string]any {
	return map[string]any{"id": j.ExportID, "status": j.State, "formats": []string{"json", "csv", "human"}, "created_at": j.CreatedAt, "expires_at": j.RetrievalExpiresAt, "failure_code": j.FailureCode, "mapping_revision": j.MappingRevision}
}
func writeComplianceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrComplianceForbidden):
		writeProductionStatusError(w, r, 403, "forbidden", "Operation forbidden", false)
	case errors.Is(err, ErrComplianceSourceChanged):
		writeProductionStatusError(w, r, 409, "source_changed", "Evidence source changed", false)
	case errors.Is(err, ErrComplianceCapacity):
		writeProductionStatusError(w, r, 429, "capacity_exhausted", "Compliance export capacity exhausted", true)
	default:
		writeProductionError(w, r, err)
	}
}
