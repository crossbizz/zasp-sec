// Package share projects a local report onto the bounded findings-only wire format.
package share

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/cliauth"
	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
)

const maxReportBytes = 8 << 20

var productID = regexp.MustCompile("^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
var digestID = regexp.MustCompile("^sha256:[0-9a-f]{64}$")

type finding struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}
type submission struct {
	SchemaVersion  string    `json:"schema_version"`
	EnvironmentID  string    `json:"environment_id"`
	Ruleset        string    `json:"ruleset"`
	ManifestMethod string    `json:"manifest_method"`
	ManifestDigest *string   `json:"manifest_digest"`
	Completeness   string    `json:"completeness"`
	Origin         string    `json:"origin"`
	Findings       []finding `json:"findings"`
	SkippedCount   int       `json:"skipped_count"`
}
type receipt struct {
	ScanID         string  `json:"scan_id"`
	VersionID      *string `json:"version_id"`
	ManifestDigest *string `json:"manifest_digest"`
	Completeness   string  `json:"completeness"`
	ReviewPath     *string `json:"review_path"`
}

var errReport = errors.New("invalid local scan report")

func project(reader io.Reader, environment, origin string) (submission, error) {
	var local struct {
		SchemaVersion string         `json:"schema_version"`
		Command       string         `json:"command"`
		Status        string         `json:"status"`
		Result        *addons.Report `json:"result"`
		Coverage      struct {
			Mode string `json:"mode"`
		} `json:"coverage"`
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxReportBytes+1))
	if err != nil || len(data) > maxReportBytes || json.Unmarshal(data, &local) != nil || local.SchemaVersion != "zaspctl.local.v1" || local.Command != "scan" || local.Coverage.Mode != "local_only" || local.Result == nil {
		return submission{}, errReport
	}
	r := local.Result
	rules := addonevidence.Rules(r.Ruleset)
	if r.SchemaVersion != "zasp-addon-scan.v1" || r.ManifestMethod != "addon-manifest.v1" || rules == nil || r.Status != local.Status || (r.Status != "complete" && r.Status != "partial") || r.Skipped == nil || r.Findings == nil {
		return submission{}, errReport
	}
	out := submission{SchemaVersion: "zasp-addon-findings.v1", EnvironmentID: environment, Origin: origin, Ruleset: r.Ruleset, ManifestMethod: r.ManifestMethod, Completeness: r.Status, SkippedCount: len(r.Skipped), Findings: []finding{}}
	if r.Status == "complete" {
		if !digestID.MatchString(r.ManifestDigest) {
			return submission{}, errReport
		}
		out.ManifestDigest = &r.ManifestDigest
	} else if r.ManifestDigest != "" {
		return submission{}, errReport
	}
	counts := map[string]int{}
	for _, f := range r.Findings {
		if !slices.Contains(rules, f.RuleID) {
			return submission{}, errReport
		}
		counts[f.RuleID]++
	}
	for _, id := range rules {
		if count := counts[id]; count > 0 {
			out.Findings = append(out.Findings, finding{id, count})
		}
	}
	return out, nil
}

// Submit only sends the fields shown by --dry-run. Credentials are never arguments.
func Submit(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "Provide a scan report followed by --environment ID --mode findings-only.")
		return 2
	}
	flags := flag.NewFlagSet("submit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	environment := flags.String("environment", "", "target Environment ID")
	mode := flags.String("mode", "", "submission mode")
	origin := flags.String("origin", "local", "reported local or ci source")
	preview := flags.Bool("dry-run", false, "preview fields without contacting Zasp")
	asJSON := flags.Bool("json", false, "print the receipt as JSON")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !productID.MatchString(*environment) || *mode != "findings-only" || (*origin != "local" && *origin != "ci") {
		fmt.Fprintln(stderr, "Specify a valid --environment and --mode findings-only.")
		return 2
	}
	file, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "Cannot read the selected scan report.")
		return 2
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReportBytes {
		fmt.Fprintln(stderr, "Choose a regular local scan report under 8 MiB.")
		return 2
	}
	body, err := project(file, *environment, *origin)
	if err != nil {
		fmt.Fprintln(stderr, "Invalid report. Generate it with zaspctl addons scan --local --json.")
		return 2
	}
	if *preview {
		if json.NewEncoder(stdout).Encode(body) != nil {
			return 2
		}
		return 0
	}
	base, err := url.Parse(os.Getenv("ZASP_API_URL"))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		fmt.Fprintln(stderr, "Set ZASP_API_URL to the HTTPS origin of your Zasp deployment.")
		return 2
	}
	token := os.Getenv("ZASP_API_TOKEN")
	if token == "" {
		token, err = cliauth.Token(base.Scheme+"://"+base.Host, *environment)
		if err != nil {
			fmt.Fprintln(stderr, "Sign in using zaspctl auth login --environment ID, or set a scoped CI token.")
			return 2
		}
	}
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		fmt.Fprintln(stderr, "Set a scoped ZASP_API_TOKEN with findings-submission permission.")
		return 2
	}
	value, status, err := send(context.Background(), http.DefaultTransport, base, token, body)
	if err != nil {
		if status == 401 || status == 403 {
			fmt.Fprintln(stderr, "Submission was not authorized. Verify the token and selected Environment.")
			return 2
		}
		if status >= 400 && status < 500 {
			fmt.Fprintln(stderr, "Submission was rejected. Check the Environment and report contract.")
			return 2
		}
		fmt.Fprintln(stderr, "Submission could not be confirmed. Retry with the same report and Environment.")
		return 3
	}
	if *asJSON {
		err = json.NewEncoder(stdout).Encode(value)
	} else {
		_, err = fmt.Fprintf(stdout, "Submitted %s scan %s.\n", value.Completeness, value.ScanID)
		if err == nil && value.ReviewPath != nil {
			_, err = fmt.Fprintln(stdout, base.Scheme+"://"+base.Host+*value.ReviewPath)
		}
	}
	if err != nil {
		return 2
	}
	if body.Completeness == "partial" {
		return 3
	}
	return 0
}

func send(ctx context.Context, transport http.RoundTripper, base *url.URL, token string, body submission) (receipt, int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return receipt{}, 0, err
	}
	address := base.ResolveReference(&url.URL{Path: "/api/v1/addon-scans"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address.String(), bytes.NewReader(encoded))
	if err != nil {
		return receipt{}, 0, err
	}
	key := sha256.Sum256(encoded)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "addon_"+hex.EncodeToString(key[:]))
	client := http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return receipt{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return receipt{}, resp.StatusCode, errors.New("unexpected response status")
	}
	var result receipt
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &result) != nil || !productID.MatchString(result.ScanID) || result.Completeness != body.Completeness {
		return receipt{}, 0, errors.New("invalid receipt")
	}
	if body.ManifestDigest == nil {
		if result.ManifestDigest != nil || result.VersionID != nil || result.ReviewPath != nil {
			return receipt{}, 0, errors.New("invalid partial receipt")
		}
	} else if result.ManifestDigest == nil || *result.ManifestDigest != *body.ManifestDigest || result.VersionID == nil || !productID.MatchString(*result.VersionID) || result.ReviewPath == nil || *result.ReviewPath != "/inventory/tools?addon="+*result.VersionID {
		return receipt{}, 0, errors.New("invalid version receipt")
	}
	return result, resp.StatusCode, nil
}
