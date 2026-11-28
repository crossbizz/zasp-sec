package apiserver

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const privateAddonUploadSQL = `SELECT zasp_authorization80.private_addon_upload_consent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

// Wire format is an Ed25519 signature over the domain separator and payload.
// Each deployment worker pins its key and audience independently of submissions.
type privateArchiveGrant struct {
	Version     string `json:"version"`
	Audience    string `json:"audience"`
	Scope       string `json:"scope"`
	Actor       string `json:"actor"`
	ID          string `json:"id"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Expires     int64  `json:"expires"`
	Registry    bool   `json:"registry,omitempty"`
	RetainUntil int64  `json:"retain_until,omitempty"`
}

func privateArchiveSigner(seed []byte, scope string) ed25519.PrivateKey {
	m := hmac.New(sha256.New, seed)
	m.Write([]byte("zasp-private-addon-signer.v1\x00" + scope))
	return ed25519.NewKeyFromSeed(m.Sum(nil))
}
func privateWorkerOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Path == "" && raw == u.Scheme+"://"+u.Host
}

type privateScanConfiguration struct {
	mode     string
	origin   string
	reporter string
	repo     *PostgresRepository
}

// The settings read advertises configured transfer modes. Grant issuance still
// checks the caller, the collection policy, and the selected archive.
func (h *identityHTTPHandler) privateScanConfig(partition string) privateScanConfiguration {
	repo, postgres := h.repository.(*PostgresRepository)
	origin := os.Getenv("ZASP_PRIVATE_ADDON_WORKER_ORIGIN")
	reporter := os.Getenv("ZASP_PRIVATE_ADDON_RESULT_CREDENTIAL")
	if !postgres || len(h.tokenRevealKey) != 32 || !privateWorkerOrigin(origin) ||
		partition != os.Getenv("ZASP_PRIVATE_ADDON_WORKER_SCOPE") || (reporter != "" && !validProductID(reporter)) {
		return privateScanConfiguration{mode: "unconfigured"}
	}
	mode := "memory_only"
	if partition == os.Getenv("ZASP_PRIVATE_ADDON_RETAINED_SCOPE") {
		mode = "encrypted_24h"
	}
	return privateScanConfiguration{mode: mode, origin: origin, reporter: reporter, repo: repo}
}

func (h *identityHTTPHandler) servePrivateAddonUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := IdentityFromRequest(r)
	if !ok || id.CredentialKind != CredentialBrowserSession || !id.FreshAuthenticated {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	scope := id.Scope
	o, ws, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	partition := o + "/" + ws + "/" + e
	config := h.privateScanConfig(partition)
	if config.mode == "unconfigured" {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	var in struct {
		Mode      string `json:"mode"`
		Retention string `json:"retention"`
		Digest    string `json:"archive_digest"`
		Size      int64  `json:"archive_bytes"`
	}
	key := r.Header.Values("Idempotency-Key")
	if r.Method != "POST" || r.URL.RawQuery != "" || !decodeCLIInput(r, &in, "mode", "retention", "archive_digest", "archive_bytes") || in.Mode != "private_upload" || (in.Retention != "memory_only" && in.Retention != "encrypted_24h") || !addonDigest.MatchString(in.Digest) || in.Size <= 0 || in.Size > 8<<20 || len(key) != 1 || !validPublicIdempotency(key[0]) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if in.Retention == "encrypted_24h" && config.mode != "encrypted_24h" {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	candidate, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	raw, err := config.repo.database.QueryJSON(r.Context(), privateAddonUploadSQL, o, ws, e, id.PrincipalID.String(), key[0], candidate, in.Digest, in.Size, config.reporter, in.Retention)
	if securityAgentStatementRefused(err, "extended collection required") {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var result struct {
		ID          string     `json:"id"`
		Expires     time.Time  `json:"expires_at"`
		RetainUntil *time.Time `json:"retain_until,omitempty"`
	}
	fields := []string{"id", "expires_at"}
	if in.Retention == "encrypted_24h" {
		fields = append(fields, "retain_until")
	}
	if !exactJSONFields(raw, fields...) || json.Unmarshal(raw, &result) != nil || !validProductID(result.ID) || !result.Expires.After(h.now()) || result.Expires.After(h.now().Add(6*time.Minute)) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	claim := privateArchiveGrant{Version: "private-addon-upload.v1", Audience: config.origin, Scope: partition, Actor: id.PrincipalID.String(), ID: result.ID, SHA256: in.Digest, Size: in.Size, Expires: result.Expires.Unix(), Registry: config.reporter != ""}
	if in.Retention == "encrypted_24h" {
		if result.RetainUntil == nil || !result.RetainUntil.Equal(result.Expires.Add(24*time.Hour-5*time.Minute)) {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		claim.Version = "private-addon-upload-retained.v1"
		claim.RetainUntil = result.RetainUntil.Unix()
	}
	payload, _ := json.Marshal(claim)
	signer := privateArchiveSigner(h.tokenRevealKey, partition)
	sig := ed25519.Sign(signer, append([]byte("zasp-private-addon-upload.v1\x00"), payload...))
	token := strings.Join([]string{base64.RawURLEncoding.EncodeToString(payload), base64.RawURLEncoding.EncodeToString(sig)}, ".")
	delivery := "browser_only"
	if config.reporter != "" {
		delivery = "registry"
	}
	response := map[string]any{"id": result.ID, "upload_url": config.origin + "/v1/uploads/" + result.ID, "upload_grant": token, "expires_at": result.Expires, "retention": in.Retention, "result_delivery": delivery, "verification_key": base64.RawURLEncoding.EncodeToString(signer.Public().(ed25519.PublicKey))}
	if result.RetainUntil != nil {
		response["retain_until"] = result.RetainUntil
	}
	out, _ := json.Marshal(response)
	writeProductionResponse(w, r, http.StatusOK, out, nil)
}
func init() {
	productStatementRules[privateAddonUploadSQL] = productStatementRule{operations: []string{"createPrivateAddonUpload"}, arguments: 10, scope: 1, actor: 4, browserOnly: true, fresh: true, check: addonEnvAllowed}
}
