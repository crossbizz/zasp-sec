package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	custody "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentcustody"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

var gatewayEnrollmentNow = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
var errGatewayEnrollment = errors.New("gateway enrollment unresolved")
var gatewayDurationPattern = regexp.MustCompile(`^[1-9][0-9]*(s|m|h)$`)

const gatewayEnrollmentDefaultTTL = 24 * time.Hour
const gatewayEnrollmentDefaultTimeout = 10 * time.Second

type gatewayCommandOptions struct {
	action               string
	endpoint             string
	caFile               string
	custodyFile          string
	credentialFile       string
	associationStateFile string
	credentialOutput     string
	credentialTTL        time.Duration
	timeout              time.Duration
}
type gatewayCommandReport struct {
	State        string `json:"state"`
	Outcome      string `json:"outcome"`
	DeviceID     string `json:"device_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Source       string `json:"source,omitempty"`
	ObservedAt   string `json:"observed_at,omitempty"`
}

// gateway enroll reads only the protected token bundle from stdin. Enrollment
// stores its confirmed receipt; gateway export is an explicit separate action.
// Duration flags use one positive whole-number s/m/h unit. Defaults are 24h/10s.
func parseGatewayCommand(arguments []string) (gatewayCommandOptions, error) {
	if len(arguments) < 2 || arguments[0] != "gateway" {
		return gatewayCommandOptions{}, errInvalidArguments
	}
	q := gatewayCommandOptions{action: arguments[1], credentialTTL: gatewayEnrollmentDefaultTTL, timeout: gatewayEnrollmentDefaultTimeout}
	allowed := map[string]bool{"--custody-file": true}
	switch q.action {
	case "enroll":
		for _, k := range []string{"--endpoint", "--ca-bundle-file", "--credential-ttl", "--timeout"} {
			allowed[k] = true
		}
	case "status":
	case "accept-agent":
		allowed["--ca-bundle-file"] = true
		allowed["--timeout"] = true
		allowed["--credential-file"] = true
		allowed["--endpoint"] = true
		allowed["--association-state-file"] = true
	case "recover":
		for _, k := range []string{"--ca-bundle-file", "--timeout", "--credential-output"} {
			allowed[k] = true
		}
	case "export":
		allowed["--credential-output"] = true
	default:
		return gatewayCommandOptions{}, errInvalidArguments
	}
	values := map[string]string{}
	for i := 2; i < len(arguments); i += 2 {
		if i+1 >= len(arguments) || !allowed[arguments[i]] || values[arguments[i]] != "" || arguments[i+1] == "" {
			return gatewayCommandOptions{}, errInvalidArguments
		}
		values[arguments[i]] = arguments[i+1]
	}
	q.endpoint, q.caFile, q.custodyFile, q.credentialOutput = values["--endpoint"], values["--ca-bundle-file"], values["--custody-file"], values["--credential-output"]
	q.credentialFile, q.associationStateFile = values["--credential-file"], values["--association-state-file"]
	if q.action == "accept-agent" && (q.credentialFile != "" || q.associationStateFile != "" || q.endpoint != "") {
		if q.custodyFile != "" || !gatewayCommandAbsolutePath(q.credentialFile) || !gatewayCommandAbsolutePath(q.associationStateFile) || q.credentialFile == q.associationStateFile || !gatewayCommandEndpoint(q.endpoint) {
			return gatewayCommandOptions{}, errInvalidArguments
		}
	} else if !gatewayCommandAbsolutePath(q.custodyFile) {
		return gatewayCommandOptions{}, errInvalidArguments
	}
	if q.action == "export" && !gatewayCommandAbsolutePath(q.credentialOutput) {
		return gatewayCommandOptions{}, errInvalidArguments
	}
	if q.action == "recover" || q.action == "accept-agent" {
		if !gatewayCommandAbsolutePath(q.caFile) || (q.credentialOutput != "" && !gatewayCommandAbsolutePath(q.credentialOutput)) {
			return gatewayCommandOptions{}, errInvalidArguments
		}
	}
	if q.action == "enroll" || q.action == "recover" || q.action == "accept-agent" {
		if q.action == "enroll" && (!gatewayCommandEndpoint(q.endpoint) || !gatewayCommandAbsolutePath(q.caFile)) {
			return gatewayCommandOptions{}, errInvalidArguments
		}
		for _, item := range []struct {
			name     string
			target   *time.Duration
			min, max time.Duration
		}{{"--credential-ttl", &q.credentialTTL, time.Minute, 90 * 24 * time.Hour}, {"--timeout", &q.timeout, time.Second, 30 * time.Second}} {
			if raw := values[item.name]; raw != "" {
				parsed, err := time.ParseDuration(raw)
				if err != nil || !gatewayDurationPattern.MatchString(raw) || parsed < item.min || parsed > item.max {
					return gatewayCommandOptions{}, errInvalidArguments
				}
				*item.target = parsed
			}
		}
	}
	return q, nil
}
func gatewayCommandAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != "." && filepath.Base(path) != string(filepath.Separator) && !strings.ContainsRune(path, 0)
}
func gatewayCommandEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || u.String() != endpoint || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return false
		}
	}
	return !strings.ContainsAny(u.Host, "\r\n\t @")
}
func gatewayCommandCA(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 1<<20 {
		return nil, errGatewayEnrollment
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errGatewayEnrollment
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errGatewayEnrollment
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errGatewayEnrollment
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) {
		return nil, errGatewayEnrollment
	}
	return raw, nil
}
func newGatewayEnrollmentHTTPClient(q gatewayCommandOptions) (*http.Client, error) {
	raw, err := gatewayCommandCA(q.caFile)
	if err != nil {
		return nil, errGatewayEnrollment
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errGatewayEnrollment
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: q.timeout, ResponseHeaderTimeout: q.timeout, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 16 * 1024}
	return &http.Client{Transport: transport, Timeout: q.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errGatewayEnrollment }}, nil
}
func writeGatewayCommandReport(output io.Writer, snapshot custody.Snapshot, state string) error {
	outcome := "unknown"
	if snapshot.State == custody.StateAccepted {
		outcome = "confirmed"
	}
	if state == "" {
		state = string(snapshot.State)
	}
	return writeGatewayReport(output, gatewayCommandReport{State: state, Outcome: outcome, DeviceID: snapshot.Request.DeviceID, CredentialID: snapshot.Request.CredentialID})
}
func writeGatewayReport(output io.Writer, report gatewayCommandReport) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return errGatewayEnrollment
	}
	raw = append(raw, '\n')
	n, err := output.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}
func gatewayCommandUnresolved(output io.Writer, store *custody.Store) error {
	snapshot, err := store.Snapshot()
	if err == nil {
		state := string(snapshot.State)
		if snapshot.State == custody.StateAccepted {
			state = "unresolved"
		}
		// A retained earlier receipt is historical evidence, not acceptance of a
		// conflicting current command or a failed export destination.
		if writeErr := writeGatewayReport(output, gatewayCommandReport{State: state, Outcome: "unknown", DeviceID: snapshot.Request.DeviceID, CredentialID: snapshot.Request.CredentialID}); writeErr != nil {
			return writeErr
		}
	}
	return errGatewayEnrollment
}
func runGatewayCommand(output io.Writer, input io.Reader, arguments []string) error {
	if output == nil || input == nil {
		return errInvalidArguments
	}
	q, err := parseGatewayCommand(arguments)
	if err != nil {
		return err
	}
	if q.action == "accept-agent" {
		return runGatewayAgentAssociationCommand(output, input, q)
	}
	var bundle wire.TokenBundle
	var client *http.Client
	if q.action == "enroll" {
		raw, err := io.ReadAll(io.LimitReader(input, wire.MaximumBytes+1))
		if err != nil || len(raw) > wire.MaximumBytes {
			return errGatewayEnrollment
		}
		defer clear(raw)
		bundle, err = wire.ParseTokenBundle(raw)
		if err != nil {
			return errGatewayEnrollment
		}
		client, err = newGatewayEnrollmentHTTPClient(q)
		if err != nil {
			return errGatewayEnrollment
		}
		defer client.CloseIdleConnections()
	}
	if q.action == "recover" {
		client, err = newGatewayEnrollmentHTTPClient(q)
		if err != nil {
			return errGatewayEnrollment
		}
		defer client.CloseIdleConnections()
	}
	store, err := custody.Open(q.custodyFile)
	if err != nil {
		return errGatewayEnrollment
	}
	// Keep ownership through HTTP, receipt persistence and explicit export. Close
	// failures remain failures even if an earlier report was written.
	var operationErr error
	switch q.action {
	case "status":
		snapshot, err := store.Snapshot()
		if err != nil {
			operationErr = errGatewayEnrollment
		} else {
			operationErr = writeGatewayCommandReport(output, snapshot, "")
		}
	case "export":
		if err := store.ExportCredential(q.credentialOutput); err != nil {
			operationErr = gatewayCommandUnresolved(output, store)
		} else {
			snapshot, err := store.Snapshot()
			if err != nil {
				operationErr = errGatewayEnrollment
			} else {
				operationErr = writeGatewayCommandReport(output, snapshot, "exported")
			}
		}
	case "recover":
		operationErr = runGatewayAuthorityRecovery(output, store, client, q)
	case "enroll":
		operationErr = runGatewayEnrollment(output, store, client, q, bundle)
	}
	if err := store.Close(); err != nil && operationErr == nil {
		return errGatewayEnrollment
	}
	return operationErr
}
func runGatewayEnrollment(output io.Writer, store *custody.Store, client *http.Client, q gatewayCommandOptions, bundle wire.TokenBundle) error {
	now := gatewayEnrollmentNow()
	snapshot, err := store.Prepare(bundle, q.endpoint, q.credentialTTL, now)
	if err != nil {
		return gatewayCommandUnresolved(output, store)
	}
	if snapshot.State == custody.StateAccepted {
		return writeGatewayCommandReport(output, snapshot, "")
	}
	if snapshot.State != custody.StatePending || !bundle.EnrollmentExpiresAt.After(now) || !snapshot.Request.ExpiresAt.After(now) {
		return gatewayCommandUnresolved(output, store)
	}
	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, q.endpoint+wire.EnrollmentPath, bytes.NewReader(snapshot.RequestRaw))
	if err != nil {
		return gatewayCommandUnresolved(output, store)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", wire.AuthorizationScheme+" "+bundle.Locator+"."+bundle.Secret)
	request.Header.Set("Cache-Control", "no-store")
	if wire.SignRequest(request, snapshot.RequestRaw, store.Sign, now) != nil {
		return gatewayCommandUnresolved(output, store)
	}
	response, err := client.Do(request)
	if err != nil {
		return gatewayCommandUnresolved(output, store)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return gatewayCommandUnresolved(output, store)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaximumBytes+1))
	if err != nil || len(raw) > wire.MaximumBytes || ctx.Err() != nil {
		return gatewayCommandUnresolved(output, store)
	}
	receipt, err := wire.ParseReceipt(raw)
	if err != nil || !wire.ReceiptMatches(receipt, snapshot.Request, wire.Digest(snapshot.RequestRaw)) || store.Accept(receipt) != nil {
		return gatewayCommandUnresolved(output, store)
	}
	accepted, err := store.Snapshot()
	if err != nil || accepted.State != custody.StateAccepted {
		return gatewayCommandUnresolved(output, store)
	}
	return writeGatewayCommandReport(output, accepted, "")
}
