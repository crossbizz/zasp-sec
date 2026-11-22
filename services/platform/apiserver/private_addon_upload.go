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

const privateAddonUploadSQL = `SELECT zasp_authorization80.private_addon_upload_with_reporter($1,$2,$3,$4,$5,$6,$7,$8,$9)`

// Wire format is an Ed25519 signature over the domain separator and payload.
// Each deployment worker pins its key and audience independently of submissions.
type privateArchiveGrant struct {
	Version  string `json:"version"`
	Audience string `json:"audience"`
	Scope    string `json:"scope"`
	Actor    string `json:"actor"`
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Expires  int64  `json:"expires"`
	Registry bool   `json:"registry,omitempty"`
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

func (h *identityHTTPHandler) servePrivateAddonUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := IdentityFromRequest(r)
	if !ok || id.CredentialKind != CredentialBrowserSession || !id.FreshAuthenticated {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	scope := id.Scope
	o, ws, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	partition := o + "/" + ws + "/" + e
	origin := os.Getenv("ZASP_PRIVATE_ADDON_WORKER_ORIGIN")
	repo, ok := h.repository.(*PostgresRepository)
	if !ok || len(h.tokenRevealKey) != 32 || !privateWorkerOrigin(origin) || partition != os.Getenv("ZASP_PRIVATE_ADDON_WORKER_SCOPE") {
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
	if r.Method != "POST" || r.URL.RawQuery != "" || !decodeCLIInput(r, &in, "mode", "retention", "archive_digest", "archive_bytes") || in.Mode != "private_upload" || in.Retention != "memory_only" || !addonDigest.MatchString(in.Digest) || in.Size <= 0 || in.Size > 8<<20 || len(key) != 1 || !validPublicIdempotency(key[0]) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	candidate, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	reporter := os.Getenv("ZASP_PRIVATE_ADDON_RESULT_CREDENTIAL")
	if reporter != "" && !validProductID(reporter) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	raw, err := repo.database.QueryJSON(r.Context(), privateAddonUploadSQL, o, ws, e, id.PrincipalID.String(), key[0], candidate, in.Digest, in.Size, reporter)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var result struct {
		ID      string    `json:"id"`
		Expires time.Time `json:"expires_at"`
	}
	if !exactJSONFields(raw, "id", "expires_at") || json.Unmarshal(raw, &result) != nil || !validProductID(result.ID) || !result.Expires.After(h.now()) || result.Expires.After(h.now().Add(6*time.Minute)) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	payload, _ := json.Marshal(privateArchiveGrant{"private-addon-upload.v1", origin, partition, id.PrincipalID.String(), result.ID, in.Digest, in.Size, result.Expires.Unix(), reporter != ""})
	signer := privateArchiveSigner(h.tokenRevealKey, partition)
	sig := ed25519.Sign(signer, append([]byte("zasp-private-addon-upload.v1\x00"), payload...))
	token := strings.Join([]string{base64.RawURLEncoding.EncodeToString(payload), base64.RawURLEncoding.EncodeToString(sig)}, ".")
	delivery := "browser_only"
	if reporter != "" {
		delivery = "registry"
	}
	out, _ := json.Marshal(map[string]any{"id": result.ID, "upload_url": origin + "/v1/uploads/" + result.ID, "upload_grant": token, "expires_at": result.Expires, "retention": "memory_only", "result_delivery": delivery, "verification_key": base64.RawURLEncoding.EncodeToString(signer.Public().(ed25519.PublicKey))})
	writeProductionResponse(w, r, http.StatusOK, out, nil)
}
func init() {
	productStatementRules[privateAddonUploadSQL] = productStatementRule{operations: []string{"createPrivateAddonUpload"}, arguments: 9, scope: 1, actor: 4, browserOnly: true, fresh: true, check: addonEnvAllowed}
}
