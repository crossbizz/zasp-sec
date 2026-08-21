package awsdiscovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"regexp"
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
	securityAccountPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	securityAccessKeyPattern    = regexp.MustCompile(`^(?:ASIA|AKIA)[A-Z0-9]{16}$`)
	securitySecretKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
	securitySessionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9/+=_-]+$`)
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
	Credential      string            `json:"credential"`
	ProtocolVersion int               `json:"protocol_version"`
	Source          json.RawMessage   `json:"source"`
}

type securityResponseEnvelope struct {
	Authority       json.RawMessage `json:"authority"`
	ProtocolVersion int             `json:"protocol_version"`
	Result          json.RawMessage `json:"result"`
	SourceDigest    string          `json:"source_digest"`
}

type prowlerCredentialDocument struct {
	AccessKeyID     string `json:"access_key_id"`
	ExpiresAt       string `json:"expires_at"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
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
	input, spec, encodedCredential, err := securityInput(request, authority, borrowedCredential)
	if err != nil {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	defer clear(input)
	bounded, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()
	output, err := runner.process.Run(bounded, spec, input)
	if err != nil || bounded.Err() != nil {
		return CollectionSecurityResult{}, runner.classifyProcessFailure(ctx, bounded, err)
	}
	if len(output) < 6 || len(output) > maximumSecurityFrameBytes+4 || len(credential) != 0 && bytes.Contains(output, credential) || encodedCredential != "" && bytes.Contains(output, []byte(encodedCredential)) || containsSecurityFragment(output, credentialFragments) {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	response, ok := decodeSecurityResponse(output, authorityJSON, request.SourceDigest)
	if !ok {
		return CollectionSecurityResult{}, stableSecurityFailure(collection.FailureMalformed, time.Time{})
	}
	return CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: bytes.Clone(response.Result)}, nil
}

func securityCredentialFragments(request CollectionSecurityRequest, credential []byte) ([][]byte, error) {
	if request.Mode == SecurityModeCartographyAWS {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(credential))
	decoder.DisallowUnknownFields()
	var document prowlerCredentialDocument
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF || !securityAccessKeyPattern.MatchString(document.AccessKeyID) || !securitySecretKeyPattern.MatchString(document.SecretAccessKey) || len(document.SessionToken) < 32 || len(document.SessionToken) > 4096 || !securitySessionTokenPattern.MatchString(document.SessionToken) || document.ExpiresAt != request.CredentialExpiresAt.Format(time.RFC3339) {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, credential) {
		return nil, ErrInvalid
	}
	return [][]byte{[]byte(document.AccessKeyID), []byte(document.SecretAccessKey), []byte(document.SessionToken)}, nil
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
	if request.Scope.Validate() != nil || request.IntegrationID.IsZero() || request.ConnectionID.IsZero() || request.JobID.IsZero() || request.Attempt < 1 || request.Attempt > 100 || request.CursorLineage < 1 || request.CursorLineage > 1_000_000 || request.Subject.Kind != "aws_account" || !securityAccountPattern.MatchString(request.Subject.ID) || request.RemainingBytes < 0 || request.RemainingBytes > 64*1024*1024 || request.RemainingEntities < 0 || request.RemainingEntities > 1_000 || request.RemainingRelationships < 0 || request.RemainingRelationships > 2_000 || request.SourceDigest == ([32]byte{}) || !exactUTCSecurityTime(request.ObservedAt) || !exactUTCSecurityTime(request.CredentialExpiresAt) || !request.CredentialExpiresAt.After(request.ObservedAt) || !canonicalSecurityObject(request.Source) {
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

func securityInput(request CollectionSecurityRequest, authority securityAuthority, credential []byte) ([]byte, securityProcessSpec, string, error) {
	environment := []string{"HOME=/tmp", "LANG=C.UTF-8", "PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1"}
	var document any
	var executable string
	encoded := ""
	if request.Mode == SecurityModeCartographyAWS {
		executable = cartographySecurityExecutable
		document = cartographySecurityEnvelope{Authority: authority, ProtocolVersion: 1, Source: request.Source}
	} else {
		executable = prowlerSecurityExecutable
		encoded = base64.RawURLEncoding.EncodeToString(credential)
		document = prowlerSecurityEnvelope{Authority: authority, Credential: encoded, ProtocolVersion: 1, Source: request.Source}
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) < 2 || len(body) > maximumSecurityFrameBytes {
		return nil, securityProcessSpec{}, "", ErrInvalid
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
