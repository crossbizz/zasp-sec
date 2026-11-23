package share

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

const envID = "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
const versionID = "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const scanID = "pid_00000000-0000-4000-8000-000000000001"

func localScan(t *testing.T) []byte {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("Private title\n<!-- private draft -->\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scan := addons.Scan(root)
	if scan.Status != "complete" {
		t.Fatalf("scan %v", scan)
	}
	envelope := map[string]any{"schema_version": "zaspctl.local.v1", "command": "scan", "status": scan.Status, "coverage": map[string]string{"mode": "local_only"}, "result": scan}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSubmitRestrictsWireAndVerifiesReviewLink(t *testing.T) {
	raw := localScan(t)
	body, err := project(bytes.NewReader(raw), envID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	var firstKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/addon-scans" || r.Header.Get("Authorization") != "Bearer test-only" {
			t.Error("unexpected request")
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" || (firstKey != "" && firstKey != key) {
			t.Error("unstable key")
		}
		firstKey = key
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		for _, field := range []string{"SKILL.md", "Private title", "private draft", "remediation", "test-only", "dependencies", "files"} {
			if bytes.Contains(data, []byte(field)) {
				t.Errorf("unexpected field %s", field)
			}
		}
		var out submission
		if json.Unmarshal(data, &out) != nil || len(out.Findings) != 1 || out.Findings[0] != (finding{"instruction.hidden_text", 1}) || out.EnvironmentID != envID {
			t.Error("incorrect aggregate")
		}
		id := versionID
		path := "/inventory/tools?addon=" + id
		_ = json.NewEncoder(w).Encode(receipt{scanID, &id, out.ManifestDigest, "complete", &path})
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	for range 2 {
		receipt, _, err := send(context.Background(), server.Client().Transport, u, "test-only", body)
		if err != nil || receipt.VersionID == nil {
			t.Fatalf("receipt %v %v", receipt, err)
		}
	}
}

func TestSubmitRejectsRedirectAndForgedReceipt(t *testing.T) {
	body, err := project(bytes.NewReader(localScan(t)), envID, "local")
	if err != nil {
		t.Fatal(err)
	}
	var targetCalls int
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls++ }))
	defer other.Close()
	for _, mode := range []string{"redirect", "forged"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
					return
				}
				id := versionID
				path := other.URL
				_ = json.NewEncoder(w).Encode(receipt{scanID, &id, body.ManifestDigest, "complete", &path})
			}))
			defer s.Close()
			u, _ := url.Parse(s.URL)
			if _, _, err := send(context.Background(), s.Client().Transport, u, "test-only", body); err == nil {
				t.Fatal("accepted redirect or forged URL")
			}
		})
	}
	if targetCalls != 0 {
		t.Fatal("forwarded to another host")
	}
}
func TestPreviewIsLocalAndClosedToUnknownRuleIDs(t *testing.T) {
	raw := localScan(t)
	file := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{file, "--environment", envID, "--mode", "findings-only", "--dry-run"}
	var out, diagnostic bytes.Buffer
	t.Setenv("ZASP_API_URL", "")
	t.Setenv("ZASP_API_TOKEN", "")
	if code := Submit(args, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "instruction.hidden_text") {
		t.Fatalf("%d %s %s", code, out.String(), diagnostic.String())
	}
	if _, err := project(strings.NewReader(strings.ReplaceAll(string(raw), "instruction.hidden_text", "unapproved.name")), envID, "local"); err == nil {
		t.Fatal("accepted an arbitrary finding id")
	}
}

func TestPartialSubmitPrintsScopedReceiptLinkAndPreservesJSON(t *testing.T) {
	var report map[string]any
	if err := json.Unmarshal(localScan(t), &report); err != nil {
		t.Fatal(err)
	}
	result := report["result"].(map[string]any)
	report["status"] = "partial"
	result["status"] = "partial"
	delete(result, "manifest_digest")
	result["skipped"] = []any{map[string]string{"path": "omitted", "reason": "unreadable"}}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "partial.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body submission
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Completeness != "partial" || body.EnvironmentID != envID {
			t.Error("unexpected projected submission")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(receipt{ScanID: scanID, Completeness: "partial"})
	}))
	defer server.Close()
	prev := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = prev })
	t.Setenv("ZASP_API_URL", server.URL)
	t.Setenv("ZASP_API_TOKEN", "test")
	args := []string{file, "--mode", "findings-only", "--environment", envID}
	var out, errOut bytes.Buffer
	code := Submit(args, &out, &errOut)
	if code != 3 || !strings.Contains(out.String(), server.URL+"/inventory/tools?scan="+scanID+"&environment_id="+envID) {
		t.Fatalf("code %d, output %q, error %q", code, out.String(), errOut.String())
	}
	out.Reset()
	code = Submit(append(args, "--json"), &out, &errOut)
	var value receipt
	if code != 3 || json.Unmarshal(out.Bytes(), &value) != nil || value.ScanID != scanID || value.ReviewPath != nil || value.VersionID != nil {
		t.Fatalf("code %d, receipt %s", code, out.String())
	}
}
