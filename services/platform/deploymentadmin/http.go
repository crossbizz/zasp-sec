package deploymentadmin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	basePath        = "/api/v1/deployment-admin/"
	cookieName      = "__Host-zasp_deployment_admin"
	sessionLifetime = 30 * time.Minute
)

type console struct {
	config        *Config
	db            store
	clientAddress func(*http.Request) string
	now           func() time.Time
}
type session struct {
	DeploymentID string    `json:"deployment_id"`
	CSRF         string    `json:"csrf_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Mount keeps the tenant request handler and operator sessions independent.
// clientAddress is the canonical client IP verified by the outer edge middleware.
func Mount(ctx context.Context, config *Config, next http.Handler, clientAddress func(*http.Request) string) (http.Handler, io.Closer, error) {
	var s *console
	var closer io.Closer
	if config != nil {
		db, err := openPostgres(ctx, config)
		if err != nil {
			return nil, nil, err
		}
		s = &console{config: config, db: db, clientAddress: clientAddress, now: time.Now}
		closer = db
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, basePath) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if s == nil {
			failure(w, 503, "console_unavailable")
			return
		}
		s.ServeHTTP(w, r)
	}), closer, nil
}
func jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func failure(w http.ResponseWriter, status int, code string) {
	jsonResponse(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		failure(w, 415, "json_required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil || decoder.Decode(new(any)) != io.EOF {
		failure(w, 400, "invalid_request")
		return false
	}
	return true
}
func (c *console) derive(label, token string) []byte {
	mac := hmac.New(sha256.New, c.config.passwordHash[:])
	for _, s := range []string{label, c.config.id, c.config.origin, token} {
		mac.Write([]byte(s))
		mac.Write([]byte{0})
	}
	return mac.Sum(nil)
}
func (c *console) snapshot(token string, expiry time.Time) session {
	return session{DeploymentID: c.config.id, CSRF: base64.RawURLEncoding.EncodeToString(c.derive("csrf", token)), ExpiresAt: expiry.UTC()}
}
func sessionCookie(token string, expiry time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{Name: cookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expiry, MaxAge: maxAge}
}
func (c *console) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	peer := c.clientAddress(r)
	if peer == "" {
		failure(w, 403, "request_rejected")
		return
	}
	allowed, err := c.db.attempt(r.Context(), base64.RawURLEncoding.EncodeToString(c.derive("client", peer)))
	if err != nil {
		failure(w, 503, "console_unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		failure(w, 429, "rate_limited")
		return
	}
	got := sha256.Sum256([]byte(input.Password))
	if subtle.ConstantTimeCompare(got[:], c.config.passwordHash[:]) != 1 {
		failure(w, 401, "authentication_required")
		return
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		failure(w, 503, "console_unavailable")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	expiry := c.now().UTC().Add(sessionLifetime).Truncate(time.Second)
	if err = c.db.start(r.Context(), c.derive("session", token), expiry); err != nil {
		failure(w, 503, "console_unavailable")
		return
	}
	http.SetCookie(w, sessionCookie(token, expiry, int(sessionLifetime.Seconds())))
	jsonResponse(w, 200, c.snapshot(token, expiry))
}
func (c *console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessions := r.URL.Path == basePath+"session"
	settings := r.URL.Path == basePath+"settings"
	if !sessions && !settings {
		failure(w, 404, "not_found")
		return
	}
	if r.URL.RawQuery != "" {
		failure(w, 400, "invalid_request")
		return
	}
	if r.Host != strings.TrimPrefix(c.config.origin, "https://") || r.Method != http.MethodGet && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != c.config.origin) {
		failure(w, 403, "origin_rejected")
		return
	}
	if sessions && r.Method == http.MethodPost {
		c.login(w, r)
		return
	}
	if r.Method != http.MethodGet && !(sessions && r.Method == http.MethodDelete || settings && r.Method == http.MethodPut) {
		if sessions {
			w.Header().Set("Allow", "GET, POST, DELETE")
		} else {
			w.Header().Set("Allow", "GET, PUT")
		}
		failure(w, 405, "method_not_allowed")
		return
	}
	cookies := r.CookiesNamed(cookieName)
	if len(cookies) != 1 || len(cookies[0].Value) != 43 {
		failure(w, 401, "authentication_required")
		return
	}
	token := cookies[0].Value
	digest := c.derive("session", token)
	expiry, err := c.db.expiration(r.Context(), digest)
	if errors.Is(err, pgx.ErrNoRows) {
		failure(w, 401, "authentication_required")
		return
	}
	if err != nil {
		failure(w, 503, "console_unavailable")
		return
	}
	if !expiry.After(c.now()) {
		failure(w, 401, "authentication_required")
		return
	}
	current := c.snapshot(token, expiry)
	if r.Method != http.MethodGet && (len(r.Header.Values("X-CSRF-Token")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(current.CSRF)) != 1) {
		failure(w, 403, "csrf_rejected")
		return
	}
	if sessions {
		if r.Method == http.MethodGet {
			jsonResponse(w, 200, current)
			return
		}
		if err = c.db.revoke(r.Context(), digest); err != nil {
			failure(w, 503, "console_unavailable")
			return
		}
		http.SetCookie(w, sessionCookie("", time.Unix(1, 0), -1))
		w.WriteHeader(204)
		return
	}
	if r.Method == http.MethodGet {
		value, err := c.db.settings(r.Context())
		if err != nil {
			failure(w, 503, "console_unavailable")
			return
		}
		jsonResponse(w, 200, value)
		return
	}
	var input struct {
		Version    int64    `json:"version"`
		Nango      *Pointer `json:"nango"`
		OpenSearch *Pointer `json:"opensearch"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Version < 1 || input.Nango == nil || input.OpenSearch == nil || !input.Nango.valid() || !input.OpenSearch.valid() {
		failure(w, 400, "invalid_settings")
		return
	}
	value, err := c.db.update(r.Context(), input.Version, Pointers{Nango: *input.Nango, OpenSearch: *input.OpenSearch})
	if errors.Is(err, errConflict) {
		failure(w, 409, "version_conflict")
		return
	}
	if err != nil {
		failure(w, 503, "console_unavailable")
		return
	}
	jsonResponse(w, 200, value)
}
