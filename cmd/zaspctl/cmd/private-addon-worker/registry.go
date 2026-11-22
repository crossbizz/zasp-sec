package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

type reporter struct {
	origin         string
	credentialFile string
	transport      http.RoundTripper
}
type pending struct {
	Expires     int64                 `json:"expires"`
	Environment string                `json:"environment"`
	ID          string                `json:"id"`
	Digest      string                `json:"digest"`
	Size        int64                 `json:"size"`
	Summary     addons.PrivateSummary `json:"summary"`
}
type receipt struct {
	ScanID         string  `json:"scan_id"`
	VersionID      *string `json:"version_id"`
	ManifestDigest *string `json:"manifest_digest"`
	Completeness   string  `json:"completeness"`
	Review         *string `json:"review_path"`
}

func newReporter() (*reporter, error) {
	origin, secret := os.Getenv("ZASP_PRIVATE_ADDON_RESULT_API_ORIGIN"), os.Getenv("ZASP_PRIVATE_ADDON_RESULT_TOKEN_FILE")
	if origin == "" && secret == "" {
		return nil, nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || origin != u.Scheme+"://"+u.Host || secret == "" {
		return nil, errors.New("invalid reporting configuration")
	}
	return &reporter{origin: origin, credentialFile: secret, transport: http.DefaultTransport}, nil
}
func (q *reporter) token() (string, error) {
	f, err := os.Open(q.credentialFile)
	if err != nil {
		return "", errors.New("credential unavailable")
	}
	defer f.Close()
	meta, err := f.Stat()
	if err != nil || !meta.Mode().IsRegular() || meta.Size() > 513 {
		return "", errors.New("invalid credential file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 514))
	if err != nil {
		return "", err
	}
	secret := strings.TrimSuffix(string(b), "\n")
	if len(secret) < 32 || len(secret) > 512 || strings.ContainsAny(secret, " \r\n\t") {
		return "", errors.New("invalid credential")
	}
	return secret, nil
}
func (q *reporter) send(p pending) (receipt, error) {
	empty := receipt{}
	token, err := q.token()
	if err != nil {
		return empty, err
	}
	ids := make([]string, 0, len(p.Summary.Counts))
	for id := range p.Summary.Counts {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	type finding struct {
		ID    string `json:"rule_id"`
		Count int    `json:"count"`
	}
	findings := make([]finding, 0, len(ids))
	for _, id := range ids {
		findings = append(findings, finding{id, p.Summary.Counts[id]})
	}
	skipped := 0
	for _, n := range p.Summary.Skipped {
		skipped += n
	}
	var manifest *string
	if p.Summary.Status == "complete" {
		manifest = &p.Summary.Digest
	}
	body, err := json.Marshal(map[string]any{"schema_version": "zasp-addon-findings.v1", "environment_id": p.Environment, "manifest_method": p.Summary.Method,
		"ruleset": p.Summary.Rules, "manifest_digest": manifest, "completeness": p.Summary.Status, "origin": "private_worker", "findings": findings, "skipped_count": skipped,
		"private_upload": map[string]any{"id": p.ID, "archive_digest": p.Digest, "archive_bytes": p.Size}})
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", q.origin+"/api/v1/addon-scans", bytes.NewReader(body))
	if err != nil {
		return empty, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "private-upload-"+p.ID)
	client := http.Client{Transport: q.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return empty, errors.New("report unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("report HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	var v receipt
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &v) != nil || !productID.MatchString(v.ScanID) || v.Completeness != p.Summary.Status {
		return empty, errors.New("invalid receipt")
	}
	if manifest == nil {
		if v.Review != nil || v.VersionID != nil || v.ManifestDigest != nil {
			return empty, errors.New("unexpected partial version")
		}
	} else if v.ManifestDigest == nil || *v.ManifestDigest != *manifest || v.VersionID == nil || !productID.MatchString(*v.VersionID) || v.Review == nil || *v.Review != "/inventory/tools?addon="+*v.VersionID {
		return empty, errors.New("incorrect receipt binding")
	}
	return v, nil
}

// publish first fsyncs only aggregate metadata. Losing the HTTP response does
// not lose the job: replay uses the same grant-bound idempotency key.
func (w *worker) publish(g grant, result addons.PrivateSummary) (*receipt, bool) {
	p := pending{Expires: g.Expires + 3600, Environment: strings.Split(w.scope, "/")[2], ID: g.ID, Digest: g.SHA256, Size: g.Size, Summary: result}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, false
	}
	tmp := g.ID + ".writing"
	f, err := w.markers.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, false
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || w.markers.Rename(tmp, g.ID+".pending") != nil {
		return nil, false
	}
	dir, err := w.markers.Open(".")
	if err != nil {
		return nil, false
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return nil, false
	}
	ack, err := w.reporter.send(p)
	if err != nil {
		return nil, true
	}
	_ = w.markers.Remove(g.ID + ".pending")
	return &ack, true
}
func (w *worker) retryReports(now time.Time) {
	if w.reporter == nil {
		return
	}
	d, err := w.markers.Open(".")
	if err != nil {
		return
	}
	defer d.Close()
	// Bound repair work per interval and limit response delay on outages.
	attempts := 0
	for attempts < 20 {
		entries, readErr := d.ReadDir(128)
		for _, entry := range entries {
			id, ok := strings.CutSuffix(entry.Name(), ".pending")
			if !ok || !productID.MatchString(id) {
				continue
			}
			meta, err := w.markers.Lstat(entry.Name())
			if err != nil || !meta.Mode().IsRegular() || meta.Size() > 32768 {
				continue
			}
			data, err := w.markers.ReadFile(entry.Name())
			var p pending
			if err != nil || json.Unmarshal(data, &p) != nil || p.ID != id || p.Environment != strings.Split(w.scope, "/")[2] {
				continue
			}
			if p.Expires <= now.Unix() {
				_ = w.markers.Remove(entry.Name())
				continue
			}
			attempts++
			if _, err = w.reporter.send(p); err == nil {
				_ = w.markers.Remove(entry.Name())
			}
			if attempts >= 20 {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}
