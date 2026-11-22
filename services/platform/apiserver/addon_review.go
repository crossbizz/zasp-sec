package apiserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Findings submissions contain a closed rule catalog and aggregate counts only.
// A caller cannot smuggle source, paths or a claim of verified provenance through a finding.
const (
	addonInstallationsSQL      = `SELECT zasp_authorization80.addon_installations($1,$2,$3,$4,$5,NULLIF($6,''))`
	addonScanReadSQL           = `SELECT zasp_authorization80.addon_scan_get($1,$2,$3,$4)`
	addonListSQL               = `SELECT zasp_authorization80.addon_versions_list($1,$2,$3,$4,NULLIF($5,''))`
	permissionSubmitAddonScans = "submit_addon_scans"
	addonSubmitSQL             = `SELECT zasp_authorization80.addon_scan_submit($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`
	addonVersionSQL            = `SELECT zasp_authorization80.addon_version_get($1,$2,$3,$4)`
	addonReviewSQL             = `SELECT zasp_authorization80.addon_version_review($1,$2,$3,$4,$5,$6,$7,$8)`
)

var addonInstallCursor = regexp.MustCompile(`^pid_[a-f0-9-]{36}\.[a-f0-9]{64}\.[a-f0-9]{64}$`)
var addonDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type addonFindingCount struct {
	Rule  string `json:"rule_id"`
	Count int    `json:"count"`
}

type privateUploadBinding struct {
	ID     string `json:"id"`
	Digest string `json:"archive_digest"`
	Size   int64  `json:"archive_bytes"`
}
type addonSubmission struct {
	Upload         *privateUploadBinding `json:"private_upload,omitempty"`
	EnvironmentID  string                `json:"environment_id"`
	SchemaVersion  string                `json:"schema_version"`
	Ruleset        string                `json:"ruleset"`
	ManifestMethod string                `json:"manifest_method"`
	ManifestDigest *string               `json:"manifest_digest"`
	Completeness   string                `json:"completeness"`
	Origin         string                `json:"origin"`
	Findings       []addonFindingCount   `json:"findings"`
	SkippedCount   *int                  `json:"skipped_count"`
}

func (s *addonSubmission) UnmarshalJSON(raw []byte) error {
	if !validAgentExportContentJSON(string(raw)) {
		return ErrRepositoryOperation
	}
	var fields struct {
		Findings []json.RawMessage `json:"findings"`
		Origin   string            `json:"origin"`
		Upload   json.RawMessage   `json:"private_upload"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	names := []string{"schema_version", "environment_id", "manifest_method", "ruleset", "completeness", "manifest_digest", "origin", "findings", "skipped_count"}
	if fields.Origin == "private_worker" {
		names = append(names, "private_upload")
		if !exactJSONFields(fields.Upload, "id", "archive_digest", "archive_bytes") {
			return ErrRepositoryOperation
		}
	}
	if !exactJSONFields(raw, names...) {
		return ErrRepositoryOperation
	}
	for _, f := range fields.Findings {
		if !exactJSONFields(f, "rule_id", "count") {
			return ErrRepositoryOperation
		}
	}
	type plain addonSubmission
	return json.Unmarshal(raw, (*plain)(s))
}

func (s addonSubmission) valid() bool {
	if s.SchemaVersion != "zasp-addon-findings.v1" || s.Ruleset != "zasp-static.v1" || s.ManifestMethod != "addon-manifest.v1" || !stringIn(s.Origin, "local", "ci", "private_worker") || s.SkippedCount == nil || *s.SkippedCount < 0 || *s.SkippedCount > 1000000 || !stringIn(s.Completeness, "complete", "partial") || s.Findings == nil || len(s.Findings) > 6 {
		return false
	}
	if s.Origin == "private_worker" && (s.Upload == nil || !validProductID(s.Upload.ID) || !addonDigest.MatchString(s.Upload.Digest) || s.Upload.Size < 1 || s.Upload.Size > 8<<20) {
		return false
	}
	if s.Completeness == "complete" && (s.ManifestDigest == nil || !addonDigest.MatchString(*s.ManifestDigest) || *s.SkippedCount != 0) || s.Completeness == "partial" && s.ManifestDigest != nil {
		return false
	}
	seen := map[string]bool{}
	for _, f := range s.Findings {
		if !stringIn(f.Rule, "dependency.unpinned", "script.shell_execution", "script.network_access", "instruction.hidden_text", "mcp.unpinned_launcher", "mcp.remote_endpoint") || seen[f.Rule] || f.Count < 1 || f.Count > 1000000 {
			return false
		}
		seen[f.Rule] = true
	}
	return true
}

type addonReviewHandler struct {
	database     JSONDatabase
	newProductID func() (string, error)
}

func (h *addonReviewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	if route.OperationID == "getAddonCIOrigin" || route.OperationID == "attestAddonScan" {
		h.serveCI(w, r, route)
		return
	}
	identity, ok := IdentityFromRequest(r)
	if !ok {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	if route.OperationID != "listAddonVersions" && route.OperationID != "listAddonVersionInstallations" && r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := identity.Scope
	o, ws, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	actor := identity.PrincipalID.String()
	id := route.PathParameters["id"]
	var raw json.RawMessage
	var err error
	switch route.OperationID {
	case "submitAddonScan":
		keys := r.Header.Values("Idempotency-Key")
		var submission addonSubmission
		if identity.CredentialKind != CredentialBearerToken || len(identity.credentialBinding.PATCeiling) != 1 || identity.credentialBinding.PATCeiling[0] != permissionSubmitAddonScans {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		if r.Method != http.MethodPost || len(keys) != 1 || !validPublicIdempotency(keys[0]) || decodeProductionJSON(r, &submission) != nil || submission.EnvironmentID != e || !submission.valid() {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		sort.Slice(submission.Findings, func(i, j int) bool { return submission.Findings[i].Rule < submission.Findings[j].Rule })
		scanID, scanErr := h.newProductID()
		versionID, versionErr := h.newProductID()
		if scanErr != nil || versionErr != nil || !validProductID(scanID) || !validProductID(versionID) || scanID == versionID {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		report, _ := json.Marshal(submission)
		raw, err = h.database.QueryJSON(r.Context(), addonSubmitSQL, o, ws, e, actor, keys[0], scanID, versionID, string(report))
	case "listAddonVersions", "listAddonVersionInstallations":
		q, parseErr := url.ParseQuery(r.URL.RawQuery)
		n := 25
		if q.Has("limit") {
			n, err = strconv.Atoi(q.Get("limit"))
		}
		cursor := q.Get("cursor")
		for key, values := range q {
			if (key != "cursor" && key != "limit") || len(values) != 1 {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
		}
		validCursor := validProductID(cursor)
		if route.OperationID == "listAddonVersionInstallations" {
			validCursor = addonInstallCursor.MatchString(cursor) && validProductID(strings.SplitN(cursor, ".", 2)[0])
			if !validProductID(id) {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
		}
		if r.Method != http.MethodGet || identity.CredentialKind != CredentialBrowserSession || parseErr != nil || err != nil || n < 1 || n > 100 || q.Has("cursor") && !validCursor {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		if route.OperationID == "listAddonVersionInstallations" {
			raw, err = h.database.QueryJSON(r.Context(), addonInstallationsSQL, o, ws, e, id, n, cursor)
		} else {
			raw, err = h.database.QueryJSON(r.Context(), addonListSQL, o, ws, e, n, cursor)
		}
	case "getAddonVersion", "getAddonScan":
		if r.Method != http.MethodGet || !validProductID(id) || identity.CredentialKind != CredentialBrowserSession {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		sql := addonVersionSQL
		if route.OperationID == "getAddonScan" {
			sql = addonScanReadSQL
		}
		raw, err = h.database.QueryJSON(r.Context(), sql, o, ws, e, id)
	case "reviewAddonVersion":
		if identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		key, expected, valid := discoveryMutationHeaders(r, true)
		var input struct {
			State string `json:"state"`
		}
		if r.Method != http.MethodPost || !valid || !validProductID(id) || decodeProductionJSON(r, &input) != nil || !stringIn(input.State, "approved", "rejected", "revoked") {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		raw, err = h.database.QueryJSON(r.Context(), addonReviewSQL, o, ws, e, actor, id, key, expected, input.State)
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	if securityAgentStatementRefused(err, "registered upload worker required") {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	if string(raw) == `"conflict"` {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	if !json.Valid(raw) || len(raw) == 0 || raw[0] != '{' {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}

func addonEnvAllowed(g RequestAuthorization, _ []any) bool {
	return authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
}
func init() {
	productStatementRules[addonInstallationsSQL] = productStatementRule{operations: []string{"listAddonVersionInstallations"}, arguments: 6, scope: 1, object: 4, browserOnly: true, check: addonEnvAllowed}
	productStatementRules[addonScanReadSQL] = productStatementRule{operations: []string{"getAddonScan"}, arguments: 4, scope: 1, object: 4, browserOnly: true, check: addonEnvAllowed}
	productStatementRules[addonListSQL] = productStatementRule{operations: []string{"listAddonVersions"}, arguments: 5, scope: 1, browserOnly: true, check: addonEnvAllowed}
	productStatementRules[addonSubmitSQL] = productStatementRule{operations: []string{"submitAddonScan"}, arguments: 8, scope: 1, actor: 4, check: func(g RequestAuthorization, args []any) bool {
		return addonEnvAllowed(g, args) && g.Identity.CredentialKind == CredentialBearerToken && len(g.Credential.PATCeiling) == 1 && g.Credential.PATCeiling[0] == permissionSubmitAddonScans
	}}
	productStatementRules[addonVersionSQL] = productStatementRule{operations: []string{"getAddonVersion"}, arguments: 4, scope: 1, object: 4, browserOnly: true, check: addonEnvAllowed}
	productStatementRules[addonReviewSQL] = productStatementRule{operations: []string{"reviewAddonVersion"}, arguments: 8, scope: 1, actor: 4, object: 5, browserOnly: true, fresh: true, check: addonEnvAllowed}
}
