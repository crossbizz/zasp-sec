package apiserver

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
)

// Exercise a real CLI and TLS transport with an isolated root certificate.
// PostgreSQL authenticates its PAT and evaluates the checked request's fence.
// Linux's SSL_CERT_FILE avoids modifying the runner's global trust store.
func exerciseAddonCLIReview(t *testing.T, b *installedBaseline, repo *PostgresRepository, surface http.Handler, reviewer installedPrincipal, token string) {
	t.Helper()
	dir := t.TempDir()
	cli := filepath.Join(dir, "zaspctl")
	build := exec.CommandContext(b.ctx, "go", "build", "-C", "../../../cmd/zaspctl", "-mod=readonly", "-o", cli, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build offline CLI: %v, %s", err, out)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/addon-scans" {
			http.NotFound(w, r)
			return
		}
		cred, _, ok := requestCredential(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identity, err := repo.Authenticate(r.Context(), cred)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx, err := b.checked(installedPrincipal{identity: identity, binding: identity.credentialBinding}, RoutedOperation{OperationID: "submitAddonScan", PathParameters: map[string]string{}})
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		surface.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer server.Close()
	trust := filepath.Join(dir, "ca.pem")
	write := func(path string, bytes []byte) {
		t.Helper()
		if err := os.WriteFile(path, bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(b.ctx, cli, args...)
		cmd.Env = append(os.Environ(), "ZASP_API_URL="+server.URL, "ZASP_API_TOKEN="+token, "SSL_CERT_FILE="+trust)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %s: %v, %s", args[1], err, out)
		}
		return out
	}
	bundle := filepath.Join(dir, "ticket-helper")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(bundle, "SKILL.md"), []byte("# Synthetic local ticket helper\n"))
	previousDigest := ""
	for _, declaration := range []string{`{"dependencies":{"private-example":"^1.0.0"}}`, `{"dependencies":{"private-example":"2.0.0"}}`} {
		write(filepath.Join(bundle, "package.json"), []byte(declaration))
		report := run("addons", "scan", bundle, "--local", "--json")
		var local struct {
			Result struct {
				Digest   string `json:"manifest_digest"`
				Findings []struct {
					Refs []addonevidence.Reference `json:"framework_evidence"`
				} `json:"findings"`
			} `json:"result"`
		}
		if json.Unmarshal(report, &local) != nil || local.Result.Digest == "" || local.Result.Digest == previousDigest {
			t.Fatal("missing or reused manifest digest")
		}
		reportPath := filepath.Join(dir, "report.json")
		write(reportPath, report)
		out := run("addons", "submit", reportPath, "--environment", b.e, "--mode", "findings-only", "--json")
		var receipt struct {
			VersionID string `json:"version_id"`
			Digest    string `json:"manifest_digest"`
			Path      string `json:"review_path"`
		}
		if json.Unmarshal(out, &receipt) != nil || !validProductID(receipt.VersionID) || receipt.Digest != local.Result.Digest || receipt.Path != "/inventory/tools?addon="+receipt.VersionID {
			t.Fatal("invalid exact-version receipt")
		}
		review := b.serve(surface, reviewer, "getAddonVersion", http.MethodGet, "/api/v1/addon-versions/"+receipt.VersionID, map[string]string{"id": receipt.VersionID}, "", nil)
		var row struct {
			Digest string                    `json:"manifest_digest"`
			Refs   []addonevidence.Reference `json:"framework_evidence"`
		}
		if review.Code != 200 || json.Unmarshal(review.Body.Bytes(), &row) != nil || row.Digest != receipt.Digest || bytes.Contains(review.Body.Bytes(), []byte("private-example")) {
			t.Fatal("review lost its scope, digest or redaction")
		}
		if previousDigest == "" {
			if len(local.Result.Findings) != 1 || len(row.Refs) == 0 || !reflect.DeepEqual(row.Refs, local.Result.Findings[0].Refs) {
				t.Fatal("local and authorized static mappings disagree")
			}
			exerciseSharedAddonCoverage(t, b, reviewer, receipt.VersionID, local.Result.Digest, row.Refs)
		} else if len(row.Refs) != 0 || len(local.Result.Findings) != 0 {
			t.Fatal("edited pinned version inherited evidence")
		}
		previousDigest = receipt.Digest
	}
}
