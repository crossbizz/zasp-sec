package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCalibrationExportDownloadsVerifiedJSONL(t *testing.T) {
	env := "pid_11111111-1111-4111-8111-111111111111"
	id := "pid_22222222-2222-4222-8222-222222222222"
	grant := strings.Repeat("a", 64)
	token := "scoped-test-credential"
	data := "{\"schema_version\":\"zasp.calibration.v1\",\"samples\":0}\n"
	digest := sha256.Sum256([]byte(data))
	checksum := hex.EncodeToString(digest[:])
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct{ Grant string }
		if r.URL.Path != "/api/v1/calibration/exports/"+id+"/download" || r.Header.Get("Authorization") != "Bearer "+token || r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Grant != grant {
			t.Error("wrong download contract")
		}
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"environment_id": env, "filename": "calibration-" + id + ".jsonl", "sha256": checksum, "jsonl": data})
	}))
	defer server.Close()
	t.Setenv("ZASP_API_URL", server.URL)
	t.Setenv("ZASP_API_TOKEN", token)
	path := filepath.Join(t.TempDir(), "snapshot.jsonl")
	args := []string{"--environment", env, "--output", path, "--export-id", id}
	var out, errs bytes.Buffer
	run := func() int {
		return calibrationExport(args, strings.NewReader(grant+"\n"), &out, &errs, server.Client().Transport)
	}
	if run() != 0 {
		t.Fatal(errs.String())
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != data {
		t.Fatal("wrong artifact", err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("permissions", err)
	}
	if run() == 0 || requests != 1 {
		t.Fatal("overwrote existing file or consumed another grant")
	}
	os.Remove(path)
	checksum = strings.Repeat("1", 64)
	if run() == 0 {
		t.Fatal("accepted corrupted receipt")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("partial output")
	}
	if strings.Contains(out.String()+errs.String(), grant) || strings.Contains(out.String()+errs.String(), token) {
		t.Fatal("credential in output")
	}
}
