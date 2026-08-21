package awsdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	SecurityModeCartographyAWS SecurityMode = "cartography-aws-v1"
	SecurityModeProwlerAWS     SecurityMode = "prowler-aws-v1"

	cartographySecurityExecutable = "/opt/zasp/security/cartography/bin/security-worker"
	prowlerSecurityExecutable     = "/opt/zasp/security/prowler/bin/security-worker"
	maximumSecurityFrameBytes     = 16 * 1024 * 1024
	maximumSecurityStderrBytes    = 8 * 1024
	securityExitRetryable         = 10
	securityExitRateLimited       = 11
	securityExitDenied            = 12
	securityExitMalformed         = 13
)

var (
	securityAccountPattern     = regexp.MustCompile(`^[0-9]{12}$`)
	securityCredentialPattern  = regexp.MustCompile(`^\{"access_key_id":"((?:ASIA|AKIA)[A-Z0-9]{16})","expires_at":"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)","secret_access_key":"([A-Za-z0-9/+=]{40})","session_token":"([A-Za-z0-9/+=_-]{32,})"\}$`)
	securityRoleARNPattern     = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]{1,512})$`)
	securityPolicyARNPattern   = regexp.MustCompile(`^arn:aws:iam::(?:aws|[0-9]{12}):policy/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	securityInstanceARNPattern = regexp.MustCompile(`^arn:aws:ec2:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):instance/(i-[0-9a-f]{17})$`)
	securityNamePattern        = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
)

type SecurityMode string

type CollectionSecurityRequest struct {
	Mode                   SecurityMode
	Scope                  domain.Scope
	IntegrationID          domain.ProductID
	ConnectionID           domain.ProductID
	JobID                  domain.ProductID
	Attempt                int
	CursorLineage          int
	Subject                collection.SubjectBinding
	Phase                  string
	ObservedAt             time.Time
	CredentialExpiresAt    time.Time
	RemainingBytes         int64
	RemainingEntities      int
	RemainingRelationships int
	SourceDigest           [32]byte
	Source                 json.RawMessage
}

type CollectionSecurityResult struct {
	Mode         SecurityMode
	SourceDigest [32]byte
	Result       json.RawMessage
}

type SecurityRunner struct {
	process securityProcess
	timeout time.Duration
	clock   func() time.Time
}

type securityProcess interface {
	Run(context.Context, securityProcessSpec, []byte) ([]byte, error)
}

type securityProcessSpec struct {
	Executable  string
	Arguments   []string
	Environment []string
}

type securityProcessError struct {
	ExitCode int
}

func (failure *securityProcessError) Error() string { return "security process failed" }

type securityAuthority struct {
	Attempt                int    `json:"attempt"`
	CartographyVersion     string `json:"cartography_version"`
	ConnectionID           string `json:"connection_id"`
	CredentialExpiresAt    string `json:"credential_expires_at"`
	CursorLineage          int    `json:"cursor_lineage"`
	EnvironmentID          string `json:"environment_id"`
	IntegrationID          string `json:"integration_id"`
	JobID                  string `json:"job_id"`
	ObservedAt             string `json:"observed_at"`
	OrganizationID         string `json:"organization_id"`
	Phase                  string `json:"phase"`
	ProwlerVersion         string `json:"prowler_version"`
	RemainingBytes         int64  `json:"remaining_bytes"`
	RemainingEntities      int    `json:"remaining_entities"`
	RemainingRelationships int    `json:"remaining_relationships"`
	SourceDigest           string `json:"source_digest"`
	SubjectID              string `json:"subject_id"`
	SubjectKind            string `json:"subject_kind"`
	WorkspaceID            string `json:"workspace_id"`
}

type cartographySecurityEnvelope struct {
	Authority       securityAuthority `json:"authority"`
	ProtocolVersion int               `json:"protocol_version"`
	Source          json.RawMessage   `json:"source"`
}

type prowlerSecurityEnvelope struct {
	Authority       securityAuthority `json:"authority"`
	Credential      json.RawMessage   `json:"credential"`
	ProtocolVersion int               `json:"protocol_version"`
	Source          json.RawMessage   `json:"source"`
}

type securityResponseEnvelope struct {
	Authority       json.RawMessage `json:"authority"`
	ProtocolVersion int             `json:"protocol_version"`
	Result          json.RawMessage `json:"result"`
	SourceDigest    string          `json:"source_digest"`
}

type cartographySecurityResult struct {
	Policies []cartographySecurityPolicy `json:"policies"`
	Roles    []cartographySecurityRole   `json:"roles"`
	Version  string                      `json:"version"`
}

type cartographySecurityPolicy struct {
	ARN           string   `json:"arn"`
	Name          string   `json:"name"`
	PrincipalARNs []string `json:"principal_arns"`
}

type cartographySecurityRole struct {
	ARN             string   `json:"arn"`
	Name            string   `json:"name"`
	TrustedRoleARNs []string `json:"trusted_role_arns"`
}

type prowlerSecurityResult struct {
	Findings []prowlerSecurityFinding `json:"findings"`
	Version  string                   `json:"version"`
}

type prowlerSecurityFinding struct {
	CheckID     string `json:"check_id"`
	ResourceARN string `json:"resource_arn"`
	ResourceID  string `json:"resource_id"`
	Region      string `json:"region"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
}

func NewSecurityRunner(timeout time.Duration) (*SecurityRunner, error) {
	return newSecurityRunner(&execSecurityProcess{}, timeout, time.Now)
}

func newSecurityRunnerForTest(process securityProcess, timeout time.Duration, clock func() time.Time) *SecurityRunner {
	runner, err := newSecurityRunner(process, timeout, clock)
	if err != nil {
		panic(err)
	}
	return runner
}

func newSecurityRunner(process securityProcess, timeout time.Duration, clock func() time.Time) (*SecurityRunner, error) {
	if nilSecurityProcess(process) || clock == nil || timeout < 100*time.Millisecond || timeout > 15*time.Minute {
		return nil, ErrInvalid
	}
	return &SecurityRunner{process: process, timeout: timeout, clock: clock}, nil
}

func (runner *SecurityRunner) Collect(ctx context.Context, request CollectionSecurityRequest, credential []byte) (result CollectionSecurityResult, resultErr error) {
	if runner == nil || nilSecurityProcess(runner.process) || runner.clock == nil || ctx == nil || !validSecurityRunnerRequest(request, credential) {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	if ctx.Err() != nil {
		return CollectionSecurityResult{}, stableSecurityContextFailure(ctx.Err())
	}
	defer func() {
		if recover() != nil {
			result = CollectionSecurityResult{}
			resultErr = stableSecurityFailure(collection.FailureMalformed, time.Time{})
		}
	}()
	authority := securityAuthorityForRequest(request)
	authorityJSON, err := json.Marshal(authority)
	if err != nil {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	borrowedCredential := bytes.Clone(credential)
	defer clear(borrowedCredential)
	credentialFragments, err := securityCredentialFragments(request, borrowedCredential)
	if err != nil {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	defer func() {
		for _, fragment := range credentialFragments {
			clear(fragment)
		}
	}()
	privateHome, err := os.MkdirTemp("/tmp", "zasp-security-")
	if err != nil || os.Chmod(privateHome, 0o700) != nil {
		if privateHome != "" {
			_ = os.RemoveAll(privateHome)
		}
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureRetryable, time.Time{})
	}
	defer os.RemoveAll(privateHome)
	input, spec, encodedCredential, err := securityInput(request, authority, borrowedCredential, privateHome)
	if err != nil {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	defer clear(input)
	defer clear(encodedCredential)
	bounded, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()
	output, err := runner.process.Run(bounded, spec, input)
	if err != nil || bounded.Err() != nil {
		return CollectionSecurityResult{}, runner.classifyProcessFailure(ctx, bounded, err)
	}
	if len(output) < 6 || len(output) > maximumSecurityFrameBytes+4 || len(credential) != 0 && bytes.Contains(output, credential) || len(encodedCredential) != 0 && bytes.Contains(output, encodedCredential) || containsSecurityFragment(output, credentialFragments) {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	response, ok := decodeSecurityResponse(output, authorityJSON, request.SourceDigest)
	if !ok || !validSecurityResult(request, response.Result) {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	return CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: bytes.Clone(response.Result)}, nil
}

func securityCredentialFragments(request CollectionSecurityRequest, credential []byte) ([][]byte, error) {
	if request.Mode == SecurityModeCartographyAWS {
		return nil, nil
	}
	match := securityCredentialPattern.FindSubmatch(credential)
	if len(match) != 5 || len(match[4]) > 4096 || !bytes.Equal(match[2], []byte(request.CredentialExpiresAt.Format(time.RFC3339))) {
		return nil, ErrInvalid
	}
	return [][]byte{bytes.Clone(match[1]), bytes.Clone(match[3]), bytes.Clone(match[4])}, nil
}

func containsSecurityFragment(output []byte, fragments [][]byte) bool {
	for _, fragment := range fragments {
		if len(fragment) >= 8 && bytes.Contains(output, fragment) {
			return true
		}
	}
	return false
}

func validSecurityRunnerRequest(request CollectionSecurityRequest, credential []byte) bool {
	if request.Scope.Validate() != nil || request.IntegrationID.IsZero() || request.ConnectionID.IsZero() || request.JobID.IsZero() || request.Attempt < 1 || request.Attempt > 100 || request.CursorLineage < 1 || request.CursorLineage > 1_000_000 || request.Subject.Kind != "aws_account" || !securityAccountPattern.MatchString(request.Subject.ID) || request.RemainingBytes < 0 || request.RemainingBytes > 64*1024*1024 || request.RemainingEntities < 0 || request.RemainingEntities > 1_000 || request.RemainingRelationships < 0 || request.RemainingRelationships > 2_000 || request.SourceDigest == ([32]byte{}) || sha256.Sum256(request.Source) != request.SourceDigest || !exactUTCSecurityTime(request.ObservedAt) || !exactUTCSecurityTime(request.CredentialExpiresAt) || !request.CredentialExpiresAt.After(request.ObservedAt) || !canonicalSecurityObject(request.Source) {
		return false
	}
	switch request.Mode {
	case SecurityModeCartographyAWS:
		return request.Phase == "iam" && len(credential) == 0
	case SecurityModeProwlerAWS:
		return request.Phase == "posture" && len(credential) >= 12 && len(credential) <= 16*1024
	default:
		return false
	}
}

func validSecurityResult(request CollectionSecurityRequest, raw json.RawMessage) bool {
	if len(raw) > int(request.RemainingBytes) {
		return false
	}
	if request.Mode == SecurityModeCartographyAWS {
		var result cartographySecurityResult
		if !decodeExactSecurityResult(raw, &result) || result.Version != "0.139.1" || result.Policies == nil || result.Roles == nil || len(result.Policies)+len(result.Roles) > request.RemainingEntities {
			return false
		}
		roles := make(map[string]bool, len(result.Roles))
		previous := ""
		relationships := 0
		for _, role := range result.Roles {
			match := securityRoleARNPattern.FindStringSubmatch(role.ARN)
			if len(match) != 3 || match[1] != request.Subject.ID || !strings.HasSuffix(match[2], "/"+role.Name) && match[2] != role.Name || !securityNamePattern.MatchString(role.Name) || role.ARN <= previous || role.TrustedRoleARNs == nil {
				return false
			}
			previous = role.ARN
			roles[role.ARN] = true
		}
		for _, role := range result.Roles {
			prior := ""
			for _, trusted := range role.TrustedRoleARNs {
				if !roles[trusted] || trusted <= prior {
					return false
				}
				prior = trusted
				relationships++
			}
		}
		previous = ""
		for _, policy := range result.Policies {
			if !securityPolicyARNPattern.MatchString(policy.ARN) || policy.ARN <= previous || !securityNamePattern.MatchString(policy.Name) || !strings.HasSuffix(policy.ARN, "/"+policy.Name) || policy.PrincipalARNs == nil {
				return false
			}
			previous = policy.ARN
			prior := ""
			for _, principal := range policy.PrincipalARNs {
				if !roles[principal] || principal <= prior {
					return false
				}
				prior = principal
				relationships++
			}
		}
		return relationships <= request.RemainingRelationships
	}
	var result prowlerSecurityResult
	if !decodeExactSecurityResult(raw, &result) || result.Version != "5.39.1" || result.Findings == nil || len(result.Findings) > request.RemainingEntities {
		return false
	}
	previous := ""
	for _, finding := range result.Findings {
		identity := finding.CheckID + "\x00" + finding.ResourceARN
		if identity <= previous || finding.Severity != "high" || finding.Status != "PASS" && finding.Status != "FAIL" || !validProwlerSecurityResource(request.Subject.ID, finding) {
			return false
		}
		previous = identity
	}
	return true
}

func decodeExactSecurityResult(raw []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, err := json.Marshal(destination)
	return err == nil && bytes.Equal(canonical, raw)
}

func validProwlerSecurityResource(accountID string, finding prowlerSecurityFinding) bool {
	switch finding.CheckID {
	case "iam_role_administratoraccess_policy", "iam_role_cross_service_confused_deputy_prevention":
		match := securityRoleARNPattern.FindStringSubmatch(finding.ResourceARN)
		return len(match) == 3 && match[1] == accountID && finding.Region == "global" && securityNamePattern.MatchString(finding.ResourceID) && (match[2] == finding.ResourceID || strings.HasSuffix(match[2], "/"+finding.ResourceID))
	case "ec2_instance_imdsv2_enabled":
		match := securityInstanceARNPattern.FindStringSubmatch(finding.ResourceARN)
		return len(match) == 4 && match[2] == accountID && finding.Region == match[1] && finding.ResourceID == match[3]
	default:
		return false
	}
}

func securityAuthorityForRequest(request CollectionSecurityRequest) securityAuthority {
	return securityAuthority{
		Attempt: request.Attempt, CartographyVersion: "0.139.1", ConnectionID: request.ConnectionID.String(),
		CredentialExpiresAt: request.CredentialExpiresAt.Format(time.RFC3339), CursorLineage: request.CursorLineage,
		EnvironmentID: request.Scope.EnvironmentID().String(), IntegrationID: request.IntegrationID.String(), JobID: request.JobID.String(),
		ObservedAt: request.ObservedAt.Format(time.RFC3339), OrganizationID: request.Scope.OrganizationID().String(), Phase: request.Phase,
		ProwlerVersion: "5.39.1", RemainingBytes: request.RemainingBytes, RemainingEntities: request.RemainingEntities,
		RemainingRelationships: request.RemainingRelationships, SourceDigest: hex.EncodeToString(request.SourceDigest[:]),
		SubjectID: request.Subject.ID, SubjectKind: request.Subject.Kind, WorkspaceID: request.Scope.WorkspaceID().String(),
	}
}

func securityInput(request CollectionSecurityRequest, authority securityAuthority, credential []byte, privateHome string) ([]byte, securityProcessSpec, []byte, error) {
	environment := []string{
		"AWS_CONFIG_FILE=/dev/null", "AWS_DEFAULT_REGION=us-east-1", "AWS_EC2_METADATA_DISABLED=true",
		"AWS_REGION=us-east-1", "AWS_SDK_LOAD_CONFIG=0", "AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"BOTO_CONFIG=/dev/null", "HOME=" + privateHome, "LANG=C.UTF-8", "NO_PROXY=sts.us-east-1.amazonaws.com",
		"PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1", "TMPDIR=" + privateHome,
		"XDG_CONFIG_HOME=" + privateHome,
	}
	var document any
	var executable string
	var encoded []byte
	var quotedCredential []byte
	if request.Mode == SecurityModeCartographyAWS {
		executable = cartographySecurityExecutable
		document = cartographySecurityEnvelope{Authority: authority, ProtocolVersion: 1, Source: request.Source}
	} else {
		executable = prowlerSecurityExecutable
		encoded = make([]byte, base64.RawURLEncoding.EncodedLen(len(credential)))
		base64.RawURLEncoding.Encode(encoded, credential)
		quotedCredential = make([]byte, len(encoded)+2)
		quotedCredential[0], quotedCredential[len(quotedCredential)-1] = '"', '"'
		copy(quotedCredential[1:], encoded)
		document = prowlerSecurityEnvelope{Authority: authority, Credential: quotedCredential, ProtocolVersion: 1, Source: request.Source}
	}
	body, err := json.Marshal(document)
	clear(quotedCredential)
	if err != nil || len(body) < 2 || len(body) > maximumSecurityFrameBytes {
		return nil, securityProcessSpec{}, nil, ErrInvalid
	}
	framed := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(body)))
	copy(framed[4:], body)
	return framed, securityProcessSpec{Executable: executable, Arguments: []string{string(request.Mode)}, Environment: environment}, encoded, nil
}

func decodeSecurityResponse(output, authorityJSON []byte, digest [32]byte) (securityResponseEnvelope, bool) {
	length := int(binary.BigEndian.Uint32(output[:4]))
	if length != len(output)-4 || length < 2 || length > maximumSecurityFrameBytes {
		return securityResponseEnvelope{}, false
	}
	body := output[4:]
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response securityResponseEnvelope
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || response.ProtocolVersion != 1 || response.SourceDigest != hex.EncodeToString(digest[:]) || !bytes.Equal(response.Authority, authorityJSON) || !canonicalSecurityObject(response.Result) {
		return securityResponseEnvelope{}, false
	}
	canonical, err := json.Marshal(response)
	return response, err == nil && bytes.Equal(canonical, body)
}

func canonicalSecurityObject(raw []byte) bool {
	if len(raw) < 2 || len(raw) > maximumSecurityFrameBytes || raw[0] != '{' || raw[len(raw)-1] != '}' || !json.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF || document == nil {
		return false
	}
	canonical, err := json.Marshal(document)
	return err == nil && bytes.Equal(canonical, raw)
}

func exactUTCSecurityTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0 && value.Format(time.RFC3339) == value.Format("2006-01-02T15:04:05Z07:00")
}

func (runner *SecurityRunner) classifyProcessFailure(parent, bounded context.Context, cause error) error {
	if errors.Is(parent.Err(), context.Canceled) {
		return stableSecurityFailure(collection.FailureCancelled, time.Time{})
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) || errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return stableSecurityFailure(collection.FailureRetryable, time.Time{})
	}
	var processFailure *securityProcessError
	if errors.As(cause, &processFailure) {
		switch processFailure.ExitCode {
		case securityExitRateLimited:
			now := runner.clock().UTC()
			return stableSecurityFailure(collection.FailureRateLimited, now.Add(30*time.Second))
		case securityExitDenied:
			return stableSecurityFailure(collection.FailureDenied, time.Time{})
		case securityExitMalformed:
			return stableSecurityFailure(collection.FailureMalformed, time.Time{})
		case securityExitRetryable:
			return stableSecurityFailure(collection.FailureRetryable, time.Time{})
		}
	}
	return stableSecurityFailure(collection.FailureRetryable, time.Time{})
}

func stableSecurityContextFailure(err error) error {
	if errors.Is(err, context.Canceled) {
		return stableSecurityFailure(collection.FailureCancelled, time.Time{})
	}
	return stableSecurityFailure(collection.FailureRetryable, time.Time{})
}

func stableSecurityFailure(code collection.FailureCode, retryAt time.Time) error {
	failure, err := collection.NewFailure(code, retryAt)
	if err == nil {
		return failure
	}
	fallback, _ := collection.NewFailure(collection.FailureMalformed, time.Time{})
	return fallback
}

func nilSecurityProcess(value securityProcess) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

type boundedSecurityBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedSecurityBuffer) Write(payload []byte) (int, error) {
	if buffer == nil || len(payload) > buffer.limit-buffer.buffer.Len() {
		if buffer != nil {
			buffer.overflow = true
		}
		return 0, errors.New("security process output rejected")
	}
	return buffer.buffer.Write(payload)
}

type execSecurityProcess struct{}

func (*execSecurityProcess) Run(ctx context.Context, spec securityProcessSpec, input []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || spec.Executable == "" || len(spec.Arguments) != 1 || len(input) < 6 {
		return nil, &securityProcessError{ExitCode: securityExitMalformed}
	}
	command := exec.CommandContext(ctx, spec.Executable, spec.Arguments...)
	command.Env = append([]string(nil), spec.Environment...)
	command.Stdin = bytes.NewReader(input)
	stdout := &boundedSecurityBuffer{limit: maximumSecurityFrameBytes + 4}
	stderr := &boundedSecurityBuffer{limit: maximumSecurityStderrBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if err := command.Run(); err != nil {
		if stdout.overflow || stderr.overflow {
			return nil, &securityProcessError{ExitCode: securityExitMalformed}
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, &securityProcessError{ExitCode: exit.ExitCode()}
		}
		return nil, err
	}
	if stderr.buffer.Len() != 0 {
		return nil, &securityProcessError{ExitCode: securityExitMalformed}
	}
	return bytes.Clone(stdout.buffer.Bytes()), nil
}
