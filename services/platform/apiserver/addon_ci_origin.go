package apiserver

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	addonCIBindingSQL = `SELECT zasp_authorization80.addon_ci_binding($1,$2,$3,$4,$5,$6,$7,false)`
	addonCIRecordSQL  = `SELECT zasp_authorization80.addon_ci_record($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	addonCIOriginSQL  = `SELECT zasp_authorization80.addon_ci_origin($1,$2,$3,$4)`
)

var ciKeyID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ciRepository = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}$`)
var ciCommit = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

type ciEvidence struct {
	EnvironmentID  string              `json:"environment_id"`
	CredentialID   string              `json:"credential_id"`
	ScanID         string              `json:"scan_id"`
	ManifestDigest string              `json:"manifest_digest"`
	Ruleset        string              `json:"ruleset"`
	Findings       []addonFindingCount `json:"findings"`
	KeyID          string              `json:"key_id"`
	Repository     string              `json:"repository"`
	PublicKey      string              `json:"public_key"`
	Commit         string              `json:"commit"`
	Signature      string              `json:"signature"`
	Direct         bool                `json:"direct"`
}

// Each field is bounded to a single ASCII line. Each finding uses the closed
// rule catalog, sorted on submission; a new grammar requires a new domain.
func (v ciEvidence) message() []byte {
	fields := []string{"zasp-ci-manifest-attestation.v1", v.EnvironmentID, v.CredentialID, v.ScanID, v.KeyID, v.Repository, v.Commit, v.ManifestDigest, v.Ruleset}
	for _, f := range v.Findings {
		fields = append(fields, f.Rule+"="+strconv.Itoa(f.Count))
	}
	return []byte(strings.Join(fields, "\n") + "\n")
}
func (v ciEvidence) verified() bool {
	key, err := hex.DecodeString(v.PublicKey)
	sig, sigErr := hex.DecodeString(v.Signature)
	if err != nil || sigErr != nil || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !validProductID(v.EnvironmentID) || !validProductID(v.CredentialID) || !validProductID(v.ScanID) || !ciKeyID.MatchString(v.KeyID) || !ciRepository.MatchString(v.Repository) || !ciCommit.MatchString(v.Commit) || !addonDigest.MatchString(v.ManifestDigest) || addonevidence.Rules(v.Ruleset) == nil {
		return false
	}
	digest := sha256.Sum256(key)
	if hex.EncodeToString(digest[:]) != v.KeyID {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), v.message(), sig)
}

type ciOriginView struct {
	Status     string  `json:"status"`
	Match      *string `json:"match"`
	Repository *string `json:"repository"`
	Commit     *string `json:"commit"`
	ScanID     *string `json:"scan_id"`
}

func (h *addonReviewHandler) serveCI(w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	identity, ok := IdentityFromRequest(r)
	if !ok {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	id := route.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := identity.Scope
	o, ws, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	if route.OperationID == "getAddonCIOrigin" {
		if r.Method != http.MethodGet || identity.CredentialKind != CredentialBrowserSession {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		raw, err := h.database.QueryJSON(r.Context(), addonCIOriginSQL, o, ws, e, id)
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		if string(raw) == "null" {
			writeProductionError(w, r, ErrRepositoryNotFound)
			return
		}
		var candidates []ciEvidence
		if err := json.Unmarshal(raw, &candidates); err != nil || candidates == nil || len(candidates) > 16 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		view := ciOriginView{Status: "unknown"}
		for _, candidate := range candidates {
			if candidate.EnvironmentID != e || !candidate.verified() {
				continue
			}
			match := "same_manifest"
			if candidate.Direct {
				match = "direct"
			}
			view = ciOriginView{Status: "verified", Match: &match, Repository: &candidate.Repository, Commit: &candidate.Commit, ScanID: &candidate.ScanID}
			break
		}
		writeJSONValue(w, r, http.StatusOK, view, nil)
		return
	}
	if route.OperationID != "attestAddonScan" || r.Method != http.MethodPost || identity.CredentialKind != CredentialBearerToken || len(identity.credentialBinding.PATCeiling) != 1 || identity.credentialBinding.PATCeiling[0] != permissionSubmitAddonScans {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	var input struct {
		KeyID      string `json:"key_id"`
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Signature  string `json:"signature"`
	}
	if decodeProductionJSON(r, &input) != nil || !ciKeyID.MatchString(input.KeyID) || !ciRepository.MatchString(input.Repository) || !ciCommit.MatchString(input.Commit) || len(input.Signature) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(input.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	actor := identity.PrincipalID.String()
	raw, err := h.database.QueryJSON(r.Context(), addonCIBindingSQL, o, ws, e, actor, id, input.KeyID, input.Repository)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	var record ciEvidence
	if json.Unmarshal(raw, &record) != nil || record.EnvironmentID != e || record.CredentialID != identity.credentialBinding.ID || record.ScanID != id || record.Repository != input.Repository || record.KeyID != input.KeyID {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	record.Commit, record.Signature = input.Commit, hex.EncodeToString(signature)
	if !record.verified() {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	raw, err = h.database.QueryJSON(r.Context(), addonCIRecordSQL, o, ws, e, actor, id, input.KeyID, input.Repository, input.Commit, signature)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
	default:
		if !exactJSONFields(raw, "scan_id", "repository", "commit") {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(w, r, http.StatusOK, raw, nil)
	}
}
func init() {
	narrow := func(g RequestAuthorization, args []any) bool {
		return addonEnvAllowed(g, args) && g.Identity.CredentialKind == CredentialBearerToken && len(g.Credential.PATCeiling) == 1 && g.Credential.PATCeiling[0] == permissionSubmitAddonScans
	}
	productStatementRules[addonCIBindingSQL] = productStatementRule{operations: []string{"attestAddonScan"}, arguments: 7, scope: 1, actor: 4, object: 5, check: narrow}
	productStatementRules[addonCIRecordSQL] = productStatementRule{operations: []string{"attestAddonScan"}, arguments: 9, scope: 1, actor: 4, object: 5, check: narrow}
	productStatementRules[addonCIOriginSQL] = productStatementRule{operations: []string{"getAddonCIOrigin"}, arguments: 4, scope: 1, object: 4, browserOnly: true, check: addonEnvAllowed}
}
