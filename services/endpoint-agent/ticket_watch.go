// Managed ticket regression consumes existing product approvals. Its only
// execution path is the fixed, private recorder used by prove-ticket.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/devicehttp"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
	"golang.org/x/sys/unix"
)

const watchCooldown = time.Hour

var watchDigest = regexp.MustCompile("^sha256:[a-f0-9]{64}$")
var watchLabel = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

type ticketConsent struct {
	Server            string    `json:"schema_server_id"`
	Version           string    `json:"schema_version"`
	Environment       string    `json:"environment_class"`
	Enabled           bool      `json:"enabled"`
	Binding           Binding   `json:"binding"`
	Definition        string    `json:"definition_id"`
	Target            string    `json:"target_id"`
	DefinitionVersion int64     `json:"definition_version"`
	ScheduleVersion   int64     `json:"schedule_version"`
	Cohort            string    `json:"cohort"`
	View              string    `json:"schema_view"`
	Expires           time.Time `json:"expires_at"`
}

func productID(s string) bool { _, err := domain.ParseProductID(s); return err == nil }
func (c ticketConsent) valid(b Binding, now time.Time) bool {
	return c.Version == "ticket-watch.v1" && (c.Environment == "staging" || c.Environment == "test") && c.Binding == b && b.valid() && productID(b.Organization) && productID(b.Workspace) && productID(b.Environment) && productID(b.Device) && productID(c.Definition) && productID(c.Target) && productID(c.Server) && c.DefinitionVersion > 0 && c.ScheduleVersion > 0 && watchLabel.MatchString(c.Cohort) && watchLabel.MatchString(c.View) && c.Expires.After(now) && !c.Expires.After(now.Add(30*24*time.Hour))
}

type watchRevision struct {
	Policy   uint64 `json:"policy_revision"`
	Artifact string `json:"artifact_sha256"`
	Input    string `json:"input_schema_sha256"`
	Output   string `json:"output_schema_sha256,omitempty"`
}

func watchKey(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

type watchRecord struct {
	Status   string        `json:"status"`
	Run      string        `json:"run_id,omitempty"`
	Revision watchRevision `json:"revision"`
	At       time.Time     `json:"at"`
}
type watchJournal struct {
	Version int                    `json:"version"`
	Consent string                 `json:"consent"`
	Pending string                 `json:"pending_revision,omitempty"`
	Since   time.Time              `json:"pending_since,omitempty"`
	Last    time.Time              `json:"last_attempt,omitempty"`
	Seen    map[string]watchRecord `json:"revisions"`
}
type watchResult struct {
	LastOutcome string `json:"last_outcome,omitempty"`
	Status      string `json:"status"`
	Revision    string `json:"revision,omitempty"`
	Run         string `json:"run_id,omitempty"`
	Directory   string `json:"proof_directory,omitempty"`
}
type watchApproval struct {
	Run    string
	Queued time.Time
}
type ticketWatcher struct {
	dir      string
	consent  ticketConsent
	now      func() time.Time
	approved func(context.Context, ticketConsent) (watchApproval, error)
	execute  func(context.Context, string, string, uint64) string
}

func consentID(c ticketConsent) string {
	// Extending the expiry or re-enabling the same consent cannot replay a revision.
	c.Expires = time.Time{}
	c.Enabled = true
	return watchKey(c)
}
func (w ticketWatcher) cycle(ctx context.Context, revision watchRevision) (watchResult, error) {
	fp := watchKey(revision)
	now := w.now().UTC()
	result := func(s string) watchResult { return watchResult{Status: s, Revision: fp} }
	if !w.consent.Enabled || !w.consent.Expires.After(now) {
		return result("disabled"), nil
	}
	if revision.Policy == 0 || !watchDigest.MatchString(revision.Artifact) || !watchDigest.MatchString(revision.Input) || revision.Output != "" && !watchDigest.MatchString(revision.Output) {
		return result("pending_local_evidence"), nil
	}
	if err := os.Mkdir(w.dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return watchResult{}, err
	}
	if checkOwned(w.dir, true, 0700) != nil {
		return watchResult{}, errInvalid
	}
	fd, err := unix.Open(filepath.Join(w.dir, "lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT, 0600)
	if err != nil {
		return watchResult{}, err
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return result("in_progress"), nil
		}
		return watchResult{}, err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	path := filepath.Join(w.dir, "journal.json")
	j := watchJournal{Version: 1, Consent: consentID(w.consent), Seen: map[string]watchRecord{}}
	raw, err := readFile(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		j.Seen[fp] = watchRecord{Status: "baseline", Revision: revision, At: now}
		return result("baseline"), saveWatchJournal(path, j)
	}
	if err != nil || checkOwned(path, false, 0600) != nil || strictJSON(raw, &j) != nil || j.Version != 1 || j.Consent != consentID(w.consent) || j.Seen == nil || len(j.Seen) > 1024 || j.Last.After(now) || j.Since.After(now) {
		return watchResult{}, errInvalid
	}
	if entry, seen := j.Seen[fp]; seen {
		if j.Pending != "" {
			j.Pending = ""
			j.Since = time.Time{}
			if err := saveWatchJournal(path, j); err != nil {
				return watchResult{}, err
			}
		}
		status := "already_observed"
		if entry.Status == "reserved" {
			status = "inconclusive_interrupted"
		}
		previous := watchResult{Status: status, Revision: fp, Run: entry.Run, LastOutcome: entry.Status}
		if productID(entry.Run) {
			dir := filepath.Join(w.dir, entry.Run)
			if checkOwned(dir, true, 0700) == nil {
				previous.Directory = dir
			}
		}
		return previous, nil
	}
	if len(j.Seen) >= 1024 {
		return result("journal_limit"), nil
	}
	if j.Pending != fp {
		j.Pending = fp
		j.Since = now
		if err := saveWatchJournal(path, j); err != nil {
			return watchResult{}, err
		}
	}
	if now.Sub(j.Last) < watchCooldown {
		return result("cooldown"), nil
	}
	approval, err := w.approved(ctx, w.consent)
	if err != nil || !productID(approval.Run) || approval.Queued.Before(j.Since) || approval.Queued.After(now) || now.Sub(approval.Queued) > 15*time.Minute {
		return result("pending_approved_schedule"), nil
	}
	for _, prior := range j.Seen {
		if prior.Run == approval.Run {
			return result("pending_unused_run"), nil
		}
	}
	j.Last = now
	j.Pending = ""
	j.Since = time.Time{}
	j.Seen[fp] = watchRecord{Status: "reserved", Run: approval.Run, Revision: revision, At: now}
	if err := saveWatchJournal(path, j); err != nil {
		return watchResult{}, err
	}
	dir := filepath.Join(w.dir, approval.Run)
	outcome := w.execute(ctx, dir, approval.Run, revision.Policy)
	switch outcome {
	case "passed", "inconclusive", "unsupported", "unexpected_effect":
	default:
		outcome = "inconclusive"
	}
	entry := j.Seen[fp]
	entry.Status = outcome
	j.Seen[fp] = entry
	recorded := watchResult{Status: outcome, Revision: fp, Run: approval.Run}
	if checkOwned(dir, true, 0700) == nil {
		recorded.Directory = dir
	}
	return recorded, saveWatchJournal(path, j)
}
func saveWatchJournal(path string, j watchJournal) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ticket-journal-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(j); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Only the selected tool's input/output digests participate. Other tools,
// list order and presentation metadata do not change the selected contract.
func ticketSchema(raw []byte, c ticketConsent) (string, string, error) {
	var s struct {
		Version string `json:"schema_version"`
		Source  string `json:"source"`
		Scope   struct {
			Environment string `json:"environment_id"`
			Server      string `json:"server_id"`
			View        string `json:"view"`
		} `json:"scope"`
		Tools []struct {
			Name     string `json:"name"`
			Input    string `json:"input_digest"`
			Output   string `json:"output_digest,omitempty"`
			Metadata string `json:"metadata_digest"`
		} `json:"tools"`
	}
	if len(raw) > 1<<20 || strictJSON(raw, &s) != nil || s.Version != "zasp.mcp-tool-contract.v1" || s.Source != "operator_supplied_tools_list" || s.Scope.Environment != c.Binding.Environment || s.Scope.Server != c.Server || s.Scope.View != c.View || len(s.Tools) > 256 {
		return "", "", errInvalid
	}
	var in, out string
	for _, t := range s.Tools {
		if t.Name == "update_ticket" {
			if in != "" || !watchDigest.MatchString(t.Input) || t.Output != "" && !watchDigest.MatchString(t.Output) {
				return "", "", errInvalid
			}
			in, out = t.Input, t.Output
		}
	}
	if in == "" {
		return "", "", errUnavailable
	}
	return in, out, nil
}

type ticketProductReader struct {
	client        *http.Client
	origin, token string
	binding       Binding
}

func (p ticketProductReader) get(ctx context.Context, path string, dst any) error {
	if !devicehttp.ValidOrigin(p.origin) || p.client == nil || p.token == "" {
		return errUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.origin+"/api/v1/"+path, nil)
	if err != nil {
		return errUnavailable
	}
	expected := strings.Join([]string{p.binding.Organization, p.binding.Workspace, p.binding.Environment}, "/")
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("X-Zasp-Expected-Scope", expected)
	req.Header.Set("Cache-Control", "no-store")
	res, err := p.client.Do(req)
	if err != nil {
		return errUnavailable
	}
	defer res.Body.Close()
	scope := res.Header.Values("X-Zasp-Verified-Scope")
	if res.StatusCode != 200 || len(scope) != 1 || scope[0] != expected {
		return errUnavailable
	}
	raw, err := boundedRead(res.Body, 256<<10)
	if err != nil || json.Unmarshal(raw, dst) != nil {
		return errUnavailable
	}
	return nil
}
func (p ticketProductReader) approval(ctx context.Context, c ticketConsent) (watchApproval, error) {
	var def struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
		Target  string `json:"target_id"`
		Kind    string `json:"target_kind"`
		Enabled bool   `json:"enabled"`
		Safety  struct {
			Environment string   `json:"environment"`
			Credential  string   `json:"credential_class"`
			Effects     []string `json:"expected_side_effects"`
		} `json:"safety"`
	}
	var schedule struct {
		Definition string    `json:"definition_id"`
		Version    int64     `json:"version"`
		Enabled    bool      `json:"enabled"`
		Run        string    `json:"last_run_id"`
		Outcome    string    `json:"last_outcome"`
		Fired      time.Time `json:"last_fired_at"`
	}
	var run struct {
		ID         string    `json:"id"`
		Definition string    `json:"definition_id"`
		Version    int64     `json:"definition_version"`
		Status     string    `json:"status"`
		Cancel     bool      `json:"cancel_requested"`
		Queued     time.Time `json:"queued_at"`
	}
	if !productID(c.Definition) || p.binding != c.Binding {
		return watchApproval{}, errInvalid
	}
	if p.get(ctx, "tests/"+c.Definition, &def) != nil || def.ID != c.Definition || !def.Enabled || def.Version != c.DefinitionVersion || def.Target != c.Target || (def.Kind != "agent_endpoint" && def.Kind != "mcp_server") || def.Safety.Environment != c.Environment || def.Safety.Credential != "test_write" || len(def.Safety.Effects) != 1 || def.Safety.Effects[0] != "synthetic_ticket_update" {
		return watchApproval{}, errUnavailable
	}
	if p.get(ctx, "tests/"+c.Definition+"/schedule", &schedule) != nil || schedule.Definition != c.Definition || !schedule.Enabled || schedule.Version != c.ScheduleVersion || schedule.Outcome != "queued" || !productID(schedule.Run) {
		return watchApproval{}, errUnavailable
	}
	if p.get(ctx, "test-runs/"+schedule.Run, &run) != nil || run.ID != schedule.Run || run.Definition != c.Definition || run.Version != c.DefinitionVersion || run.Cancel || run.Status != "queued" && run.Status != "leased" && run.Status != "complete" || run.Queued.IsZero() || !run.Queued.Equal(schedule.Fired) {
		return watchApproval{}, errUnavailable
	}
	return watchApproval{run.ID, run.Queued}, nil
}
func watchToken(c configuration) (string, error) {
	var raw []byte
	var err error
	if runtime.GOOS == "darwin" {
		raw, err = keychainSecret("ai.zasp.ticket-watch.read.v1", c.KeychainAccount)
	} else {
		path := filepath.Join(c.StateDir, "ticket-watch.read-token")
		if checkOwned(path, false, 0600) != nil {
			return "", errUnavailable
		}
		raw, err = readFile(path, 4096)
	}
	token := strings.TrimSpace(string(raw))
	if err != nil || len(token) < 12 || len(token) > 4096 || strings.ContainsAny(token, " \t\n\r") {
		return "", errUnavailable
	}
	return token, nil
}
func watchArtifact() (string, error) {
	// Hash this installed fixture/adapter executable. Never open an employee path.
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 128<<20 {
		return "", errInvalid
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if err != nil || n != st.Size() {
		return "", errInvalid
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func observedTicketRevision(ctx context.Context, d proofDevice, c ticketConsent, now time.Time) (watchRevision, error) {
	cfg := d.cfg
	b := &broker{binding: cfg.Binding, key: d.key, now: time.Now}
	remote, err := newRemote(*cfg.Remote, b)
	if err != nil {
		return watchRevision{}, err
	}
	token, err := remote.token()
	if err != nil {
		return watchRevision{}, err
	}
	// This read reauthorizes the device generation against current enrollment.
	var fetched struct {
		Bundle *Signed `json:"bundle"`
	}
	if err = remote.send(ctx, "fetchEndpointPolicy", http.MethodGet, "/devices/"+cfg.Binding.Device+"/policy-bundle", token, nil, &fetched); err != nil || fetched.Bundle == nil {
		return watchRevision{}, errUnavailable
	}
	policy, err := fetched.Bundle.policy(cfg.PolicyKey, cfg.Binding, now)
	if err != nil || !policy.ExpiresAt.After(now) || policy.Mode != "enforce" || policy.AllowedDestination != "internal" {
		return watchRevision{}, errUnavailable
	}
	applied, err := d.activeTicketRevision(ctx)
	if err != nil || applied != policy.Revision {
		return watchRevision{}, errUnavailable
	}
	path := filepath.Join(cfg.StateDir, "ticket-watch-schema.json")
	info, err := os.Lstat(path)
	if err != nil || checkOwned(path, false, 0600) != nil || info.ModTime().After(now) || now.Sub(info.ModTime()) > 24*time.Hour {
		return watchRevision{}, errUnavailable
	}
	raw, err := readFile(path, 1<<20)
	if err != nil {
		return watchRevision{}, err
	}
	in, out, err := ticketSchema(raw, c)
	if err != nil {
		return watchRevision{}, err
	}
	artifact, err := watchArtifact()
	return watchRevision{Policy: policy.Revision, Artifact: artifact, Input: in, Output: out}, err
}
func watchTicket(ctx context.Context, args []string, out, diag io.Writer) error {
	flags := flag.NewFlagSet("watch-ticket", flag.ContinueOnError)
	flags.SetOutput(diag)
	config := flags.String("managed-config", "", "enrolled managed endpoint configuration")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*config) {
		return errInvalid
	}
	emit := func(s string) error { return json.NewEncoder(out).Encode(watchResult{Status: s}) }
	cfg, err := loadConfig(*config)
	if err != nil || cfg.Remote == nil {
		return errInvalid
	}
	path := filepath.Join(cfg.StateDir, "ticket-watch.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return emit("disabled")
	}
	if checkOwned(path, false, 0600) != nil {
		return errInvalid
	}
	raw, err := readFile(path, 8192)
	var c ticketConsent
	if err != nil || strictJSON(raw, &c) != nil {
		return errInvalid
	}
	now := time.Now().UTC()
	if !c.Enabled || !c.Expires.After(now) {
		return emit("disabled")
	}
	if !c.valid(cfg.Binding, now) {
		return errInvalid
	}
	if runtime.GOOS != "darwin" && c.Environment != "test" {
		return emit("unsupported_staging_adapter")
	}
	readToken, err := watchToken(cfg)
	if err != nil {
		return emit("pending_product_authority")
	}
	device, closeDevice, err := openProofDevice(ctx, *config)
	if err != nil {
		return emit("pending_device_evidence")
	}
	defer closeDevice()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rev, err := observedTicketRevision(ctx, device, c, now)
	if err != nil {
		return emit("pending_local_evidence")
	}
	reader := ticketProductReader{devicehttp.New(), cfg.Remote.Origin, readToken, c.Binding}
	w := ticketWatcher{dir: filepath.Join(cfg.StateDir, "ticket-watch-"+consentID(c)), consent: c, now: time.Now, approved: reader.approval}
	w.execute = func(ctx context.Context, dir, run string, policy uint64) string {
		// Consent and observed evidence are checked again after the product reads.
		latest, err := readFile(path, 8192)
		if err != nil || checkOwned(path, false, 0600) != nil || !bytes.Equal(raw, latest) || !c.Expires.After(time.Now().Add(5*time.Second)) {
			return "inconclusive"
		}
		observed, err := observedTicketRevision(ctx, device, c, time.Now())
		if err != nil || observed != rev {
			return "inconclusive"
		}
		var receipt bytes.Buffer
		err = executeTicketProof(ctx, proofOptions{out: dir, managedConfig: *config, run: run, target: c.Target, cohort: c.Cohort, environment: c.Environment, window: 5 * time.Second, expectedRevision: policy, expectedBinding: &c.Binding}, &receipt)
		var result redteam.TicketVerification
		if strictJSON(receipt.Bytes(), &result) != nil || result.RunID != run || result.Verdict == "passed" && err != nil {
			return "inconclusive"
		}
		if result.Verdict == "passed" {
			final, err := observedTicketRevision(ctx, device, c, time.Now())
			if err != nil || final != rev {
				return "inconclusive"
			}
		}
		return result.Verdict
	}
	result, err := w.cycle(ctx, rev)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
