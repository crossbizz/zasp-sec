package share

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ciCommitID = regexp.MustCompile(`^([a-f0-9]{40}|[a-f0-9]{64})$`)
var ciRepoSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}$`)

func readCIKey(path string) (ed25519.PrivateKey, error) {
	f, err := openCIKey(path)
	if err != nil {
		return nil, errReport
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errReport
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errReport
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errReport
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errReport
	}
	return private, nil
}

// Attest independently scans immutable Git tree bytes before calling the
// authenticated endpoint. The signing key stays inside a protected CI job.
func Attest(args []string, stdout, stderr io.Writer) int {
	return attest(args, stdout, stderr, http.DefaultTransport)
}

func attest(args []string, stdout, stderr io.Writer, transport http.RoundTripper) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Provide the findings submission receipt and CI origin flags.")
		return 2
	}
	flags := flag.NewFlagSet("attest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	env := flags.String("environment", "", "target Environment")
	credential := flags.String("credential-id", "", "CI submitter ID")
	repo := flags.String("repository", "", "registered owner/repository")
	rev := flags.String("commit", "", "full immutable Git commit")
	dir := flags.String("repo-dir", ".", "local Git clone")
	bundle := flags.String("bundle", "", "skill directory relative to Git root")
	ruleset := flags.String("ruleset", addonevidence.CurrentRuleset, "ruleset used for this receipt")
	keyPath := flags.String("key-file", "", "private Ed25519 PKCS8 PEM file")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || addonevidence.Rules(*ruleset) == nil || !productID.MatchString(*env) || !productID.MatchString(*credential) || !ciRepoSlug.MatchString(*repo) || !ciCommitID.MatchString(*rev) || *bundle == "" || *keyPath == "" {
		fmt.Fprintln(stderr, "Use a registered Environment, credential, repository, full commit, bundle and signing key.")
		return 2
	}
	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "Cannot read the scan receipt.")
		return 2
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	var r receipt
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &r) != nil || !productID.MatchString(r.ScanID) || r.Completeness != "complete" || r.ManifestDigest == nil || !digestID.MatchString(*r.ManifestDigest) {
		fmt.Fprintln(stderr, "A complete scan receipt with a manifest digest is required.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := scanCommitWithRuleset(ctx, *dir, *bundle, *rev, *ruleset)
	if err != nil || report.ManifestDigest != *r.ManifestDigest {
		fmt.Fprintln(stderr, "The immutable Git bundle is incomplete or differs from the submitted manifest.")
		return 3
	}
	key, err := readCIKey(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, "Use an owner-only Ed25519 PKCS8 private key file.")
		return 2
	}
	pub := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(pub)
	kid := hex.EncodeToString(digest[:])
	counts := map[string]int{}
	for _, f := range report.Findings {
		counts[f.RuleID]++
	}
	fields := []string{"zasp-ci-manifest-attestation.v1", *env, *credential, r.ScanID, kid, *repo, *rev, report.ManifestDigest, report.Ruleset}
	for _, rule := range addonevidence.Rules(report.Ruleset) {
		if counts[rule] > 0 {
			fields = append(fields, rule+"="+strconv.Itoa(counts[rule]))
		}
	}
	sig := ed25519.Sign(key, []byte(strings.Join(fields, "\n")+"\n"))
	body, _ := json.Marshal(map[string]string{"key_id": kid, "repository": *repo, "commit": *rev, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	base, err := url.Parse(os.Getenv("ZASP_API_URL"))
	token := os.Getenv("ZASP_API_TOKEN")
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || (base.Path != "" && base.Path != "/") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		fmt.Fprintln(stderr, "Set the HTTPS ZASP_API_URL and the registered scoped ZASP_API_TOKEN.")
		return 2
	}
	base.Path = "/api/v1/addon-scans/" + r.ScanID + "/ci-attestation"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "Could not confirm the CI attestation. Retrying the same receipt is safe.")
		return 3
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var ack struct {
		ScanID     string `json:"scan_id"`
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	}
	if response.StatusCode != http.StatusOK || err != nil || len(result) > 4096 || json.Unmarshal(result, &ack) != nil || ack.ScanID != r.ScanID || ack.Commit != *rev || ack.Repository != *repo {
		fmt.Fprintln(stderr, "Zasp could not verify this attestation. Check the registered key, credential, and commit.")
		return 3
	}
	if json.NewEncoder(stdout).Encode(ack) != nil {
		return 2
	}
	return 0
}
