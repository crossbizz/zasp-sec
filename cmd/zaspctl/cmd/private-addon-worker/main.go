// private-addon-worker is a single-Environment, static archive scanner.
// Only a separately signed retention grant can send bytes to encrypted storage.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

var productID = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var archiveDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type grant struct {
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
type worker struct {
	reporter        *reporter
	retentionSocket string
	uiOrigin        string
	origin          string
	scope           string
	key             ed25519.PublicKey
	markers         *os.Root
	seats           chan struct{}
}

func (w *worker) verify(token, id string, now time.Time) (grant, bool) {
	var g grant
	if len(token) > 3072 || !productID.MatchString(id) {
		return g, false
	}
	body, signed, ok := strings.Cut(token, ".")
	if !ok {
		return g, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return g, false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signed)
	if err != nil || !ed25519.Verify(w.key, append([]byte("zasp-private-addon-upload.v1\x00"), raw...), signature) {
		return g, false
	}
	if json.Unmarshal(raw, &g) != nil {
		return g, false
	}
	profileOK := (g.Version == "private-addon-upload.v1" && g.RetainUntil == 0) || (g.Version == "private-addon-upload-retained.v1" && g.RetainUntil == g.Expires+int64((24*time.Hour-5*time.Minute)/time.Second))
	return g, profileOK && g.Audience == w.origin && g.Scope == w.scope && g.ID == id && productID.MatchString(g.Actor) && archiveDigest.MatchString(g.SHA256) && g.Size > 0 && g.Size <= addons.MaxArchiveBytes && g.Expires > now.Unix() && g.Expires <= now.Unix()+300
}
func (w *worker) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("X-Content-Type-Options", "nosniff")
	if origin := r.Header.Get("Origin"); origin != "" {
		if w.uiOrigin == "" || origin != w.uiOrigin {
			http.Error(out, "Origin rejected", 403)
			return
		}
		out.Header().Set("Access-Control-Allow-Origin", origin)
		out.Header().Set("Vary", "Origin")
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/v1/uploads/")
	if !ok || r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path || !productID.MatchString(id) {
		http.Error(out, "Unknown upload", 404)
		return
	}
	if r.Method == http.MethodOptions && w.uiOrigin != "" && r.Header.Get("Origin") == w.uiOrigin && r.Header.Get("Access-Control-Request-Method") == "PUT" {
		out.Header().Set("Access-Control-Allow-Methods", "PUT")
		out.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		out.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPut {
		out.Header().Set("Allow", "PUT")
		http.Error(out, "Use PUT", 405)
		return
	}
	h := r.Header.Values("Authorization")
	if len(h) != 1 || !strings.HasPrefix(h[0], "Bearer ") {
		http.Error(out, "Grant required", 401)
		return
	}
	g, ok := w.verify(strings.TrimPrefix(h[0], "Bearer "), id, time.Now())
	if !ok {
		http.Error(out, "Grant invalid or expired", 403)
		return
	}
	if g.RetainUntil != 0 && w.retentionSocket == "" {
		http.Error(out, "Retained storage unavailable", 503)
		return
	}
	if g.Registry && w.reporter == nil {
		http.Error(out, "Configured review registry unavailable", 503)
		return
	}
	if r.ContentLength != g.Size || r.Header.Get("Content-Type") != "application/zip" || r.Header.Get("Content-Encoding") != "" {
		http.Error(out, "Archive metadata differs from grant", 400)
		return
	}
	select {
	case w.seats <- struct{}{}:
		defer func() { <-w.seats }()
	default:
		out.Header().Set("Retry-After", "2")
		http.Error(out, "Worker busy", 503)
		return
	}
	// O_EXCL on the operator-owned persistent volume serializes replay across
	// restarts. The receipt's name contains only a random grant ID.
	err := claimGrant(w.markers, id)
	if errors.Is(err, os.ErrExist) {
		http.Error(out, "Grant already used", 409)
		return
	}
	if err != nil {
		http.Error(out, "Grant tracking unavailable", 503)
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	if expiry := time.Unix(g.Expires, 0); expiry.Before(deadline) {
		deadline = expiry
	}
	_ = http.NewResponseController(out).SetReadDeadline(deadline)
	var retained bytes.Buffer
	var input io.Reader = r.Body
	if g.RetainUntil != 0 {
		retained.Grow(int(g.Size))
		input = io.TeeReader(io.LimitReader(r.Body, g.Size+1), &retained)
		defer func() { clear(retained.Bytes()) }()
	}
	report := addons.ScanArchive(input, g.Size, g.SHA256)
	if !time.Now().Before(time.Unix(g.Expires, 0)) {
		http.Error(out, "Grant expired", 403)
		return
	}
	for _, skip := range report.Skipped {
		if skip.Reason == "archive_digest_mismatch" || skip.Reason == "archive_size_mismatch" {
			http.Error(out, "Archive differs from grant", 422)
			return
		}
	}
	var retainedReceipt *retentionReceipt
	if g.RetainUntil != 0 {
		var err error
		retainedReceipt, err = retainViaSocket(r.Context(), w.retentionSocket, strings.TrimPrefix(h[0], "Bearer "), g, retained.Bytes())
		if err != nil {
			http.Error(out, "Encrypted retention unconfirmed", 503)
			return
		}
	}
	result := report.PrivateSummary()
	state := "transient"
	var ack *receipt
	if g.Registry {
		var persisted bool
		ack, persisted = w.publish(g, result)
		if !persisted {
			http.Error(out, "Result storage unavailable", 503)
			return
		}
		state = "queued"
		if ack != nil {
			state = "recorded"
		}
	}
	out.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(out).Encode(struct {
		GrantID   string                `json:"grant_id"`
		Result    addons.PrivateSummary `json:"result"`
		Registry  string                `json:"registry_status"`
		Receipt   *receipt              `json:"receipt,omitempty"`
		Retention *retentionReceipt     `json:"retention,omitempty"`
	}{id, result, state, ack, retainedReceipt})
}
func (w *worker) expireMarkers(now time.Time) {
	// Markers outlive the maximum grant and request lifetime by an hour.
	d, err := w.markers.Open(".")
	if err != nil {
		return
	}
	defer d.Close()
	for {
		items, err := d.ReadDir(128)
		for _, item := range items {
			name := item.Name()
			// Failed temporary writes and pending reports must also expire if
			// registry reporting is disabled after a worker restart.
			id, age := name, time.Hour
			if stem, ok := strings.CutSuffix(name, ".pending"); ok {
				id, age = stem, 65*time.Minute
			} else if stem, ok := strings.CutSuffix(name, ".claiming"); ok {
				id = stem
			} else if stem, ok := strings.CutSuffix(name, ".writing"); ok {
				id = stem
			}
			if !productID.MatchString(id) || !item.Type().IsRegular() {
				continue
			}
			meta, err := w.markers.Lstat(item.Name())
			if err == nil && meta.Mode().IsRegular() && now.Sub(meta.ModTime()) > age {
				_ = w.markers.Remove(item.Name())
			}
		}
		if err == io.EOF || err != nil {
			return
		}
	}
}

// A local smoke or developer instance may bind one IPv4/IPv6 loopback
// address. All managed deployments retain the documented service listener.
func workerListenAddress(environment, override string) (string, error) {
	if override == "" {
		return ":8443", nil
	}
	host, rawPort, err := net.SplitHostPort(override)
	port, portErr := strconv.Atoi(rawPort)
	ip := net.ParseIP(host)
	if (environment != "local" && environment != "test") || err != nil || portErr != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return "", errors.New("invalid local worker listener")
	}
	return override, nil
}

func run() error {
	listen, err := workerListenAddress(os.Getenv("ZASP_ENVIRONMENT"), os.Getenv("ZASP_PRIVATE_ADDON_LISTEN_ADDRESS"))
	if err != nil {
		return err
	}
	origin := os.Getenv("ZASP_PRIVATE_ADDON_WORKER_ORIGIN")
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || origin != u.Scheme+"://"+u.Host {
		return errors.New("invalid private worker HTTPS origin")
	}
	scope := os.Getenv("ZASP_PRIVATE_ADDON_WORKER_SCOPE")
	parts := strings.Split(scope, "/")
	if len(parts) != 3 || !productID.MatchString(parts[0]) || !productID.MatchString(parts[1]) || !productID.MatchString(parts[2]) {
		return errors.New("invalid private worker scope")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(os.Getenv("ZASP_PRIVATE_ADDON_VERIFY_KEY"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("invalid pinned public key")
	}
	markers, err := os.OpenRoot(os.Getenv("ZASP_PRIVATE_ADDON_MARKER_DIR"))
	if err != nil {
		return errors.New("private marker volume unavailable")
	}
	defer markers.Close()
	if !privateSpool(markers) {
		return errors.New("private marker volume owner and access controls rejected")
	}
	ui := os.Getenv("ZASP_PRIVATE_ADDON_UI_ORIGIN")
	if ui != "" {
		u, err := url.Parse(ui)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || ui != u.Scheme+"://"+u.Host {
			return errors.New("invalid UI origin")
		}
	}
	q, err := newReporter()
	if err != nil {
		return err
	}
	socket := os.Getenv("ZASP_PRIVATE_ADDON_RETENTION_UPLOAD_SOCKET")
	if socket != "" && !filepath.IsAbs(socket) {
		return errors.New("invalid retention socket")
	}
	w := &worker{retentionSocket: socket, reporter: q, uiOrigin: ui, origin: origin, scope: scope, key: ed25519.PublicKey(raw), markers: markers, seats: make(chan struct{}, 2)}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		w.expireMarkers(time.Now())
		w.retryReports(time.Now())
		timer := time.NewTicker(time.Minute)
		defer timer.Stop()
		for {
			select {
			case at := <-timer.C:
				w.expireMarkers(at)
				w.retryReports(at)
			case <-stop:
				return
			}
		}
	}()
	server := &http.Server{Addr: listen, Handler: w, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return server.ListenAndServeTLS(os.Getenv("ZASP_PRIVATE_ADDON_TLS_CERT"), os.Getenv("ZASP_PRIVATE_ADDON_TLS_KEY"))
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Private worker unavailable. Check scoped configuration, marker volume and TLS files.")
		os.Exit(1)
	}
}
