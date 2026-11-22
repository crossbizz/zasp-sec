package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

func TestWorkerRetriesAggregateReportAcrossRestart(t *testing.T) {
	const id = "pid_45d20ba8-ac12-4c2a-8bfa-72946ee3bc5c"
	const version = "pid_f1c84742-a2b1-46fb-84f7-ff879fc76f98"
	digest := "sha256:" + strings.Repeat("c", 64)
	archive := "sha256:" + strings.Repeat("b", 64)
	token := "local-test-token-" + strings.Repeat("a", 32)
	secret := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(secret, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	var available atomic.Bool
	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		var input map[string]any
		if r.Method != "POST" || r.URL.Path != "/api/v1/addon-scans" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Idempotency-Key") != "private-upload-"+id || json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("incorrect request binding")
			http.Error(w, "bad request", 400)
			return
		}
		binding, _ := input["private_upload"].(map[string]any)
		if len(input) != 10 || len(binding) != 3 || input["environment_id"] != id || input["origin"] != "private_worker" || binding["id"] != id || binding["archive_digest"] != archive || binding["archive_bytes"] != float64(80) || input["manifest_digest"] != digest || input["skipped_count"] != float64(0) {
			t.Errorf("incorrect report: %v", input)
		}
		if !available.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		path := "/inventory/tools?addon=" + version
		_ = json.NewEncoder(w).Encode(receipt{ScanID: id, VersionID: ptr(version), ManifestDigest: ptr(digest), Completeness: "complete", Review: &path})
	}))
	defer server.Close()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &reporter{origin: server.URL, credentialFile: secret, transport: server.Client().Transport}
	w := &worker{scope: strings.Join([]string{id, id, id}, "/"), markers: root, reporter: cfg}
	g := grant{ID: id, Expires: time.Now().Unix() + 270, SHA256: archive, Size: 80, Registry: true}
	result := addons.PrivateSummary{Schema: "zasp-private-scan.v1", Status: "complete", Method: "addon-manifest.v1", Rules: "zasp-static.v1", Digest: digest, Counts: map[string]int{"script.network_access": 1}, Skipped: map[string]int{}, Advisory: "unevaluated"}
	if ack, queued := w.publish(g, result); ack != nil || !queued {
		t.Fatal("outage did not produce a durable queued status")
	}
	data, err := root.ReadFile(id + ".pending")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]interface{}
	if json.Unmarshal(data, &envelope) != nil || len(envelope) != 6 || strings.Contains(string(data), token) {
		t.Fatalf("unexpected spool shape: %s", data)
	}
	root.Close()
	root, err = os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	w = &worker{scope: w.scope, markers: root, reporter: cfg}
	available.Store(true)
	w.retryReports(time.Now())
	w.retryReports(time.Now())
	if _, err = root.Stat(id + ".pending"); !os.IsNotExist(err) || attempts.Load() != 2 {
		t.Fatalf("durable retry not completed: %v %d", err, attempts.Load())
	}
	if err := root.WriteFile(id+".writing", []byte("partial metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	w.expireMarkers(time.Now().Add(2 * time.Hour))
	if _, err = root.Stat(id + ".writing"); !os.IsNotExist(err) {
		t.Fatal("interrupted write retained")
	}
}
func ptr(s string) *string { return &s }
