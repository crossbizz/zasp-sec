package share

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIOriginAttestsReceiptFromGitOverTLS(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git fixture: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	if err := os.Mkdir(filepath.Join(dir, "fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture", "SKILL.md"), []byte("---\nname: internal\n---\nRead a ticket."), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "fixture")
	git("-c", "user.email=ci@example.invalid", "-c", "user.name=Fixture", "-c", "commit.gpgsign=false", "commit", "-qm", "test")
	rev := git("rev-parse", "HEAD")
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "signing.pem")
	if err := writeTestCIKey(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(public)
	kid := hex.EncodeToString(h[:])
	repo := "example/private-skills"
	report, err := scanCommit(context.Background(), dir, "fixture", rev)
	if err != nil {
		t.Fatal(err)
	}
	receiptFile := filepath.Join(t.TempDir(), "receipt.json")
	body, _ := json.Marshal(receipt{ScanID: scanID, Completeness: "complete", ManifestDigest: &report.ManifestDigest})
	if err := os.WriteFile(receiptFile, body, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/addon-scans/"+scanID+"/ci-attestation" || r.Header.Get("Authorization") != "Bearer fixture-pat" {
			http.Error(w, "scope", 403)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var wire map[string]string
		if json.Unmarshal(raw, &wire) != nil || len(wire) != 4 || wire["repository"] != repo || wire["key_id"] != kid || wire["commit"] != rev {
			http.Error(w, "wire", 400)
			return
		}
		sig, _ := base64.RawURLEncoding.Strict().DecodeString(wire["signature"])
		canonical := strings.Join([]string{"zasp-ci-manifest-attestation.v1", envID, versionID, scanID, kid, repo, rev, report.ManifestDigest, report.Ruleset, ""}, "\n")
		if !ed25519.Verify(public, []byte(canonical), sig) {
			http.Error(w, "signature", 403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID, "repository": repo, "commit": rev})
	}))
	defer server.Close()
	t.Setenv("ZASP_API_URL", server.URL)
	t.Setenv("ZASP_API_TOKEN", "fixture-pat")
	var stdout, stderr bytes.Buffer
	if exit := attest([]string{receiptFile, "--repo-dir", dir, "--bundle", "fixture", "--environment", envID, "--credential-id", versionID, "--repository", repo, "--commit", rev, "--key-file", keyFile}, &stdout, &stderr, server.Client().Transport); exit != 0 || !strings.Contains(stdout.String(), scanID) {
		t.Fatalf("exit %d, %s %s", exit, stdout.String(), stderr.String())
	}
}
