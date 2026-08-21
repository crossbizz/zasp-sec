package awsdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSecurityRunnerUsesExactProwlerProcessAuthorityAndClearsInput(t *testing.T) {
	request := securityRequestFixture(t, SecurityModeProwlerAWS)
	credential := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T00:15:00Z","secret_access_key":"ssssssssssssssssssssssssssssssssssssssss","session_token":"tttttttttttttttttttttttttttttttt"}`)
	process := &recordingSecurityProcess{}
	privateHome := ""
	process.respond = func(spec securityProcessSpec, input []byte) []byte {
		document := decodeSecurityFrameForTest(t, input)
		encoded, ok := document["credential"].(string)
		if !ok {
			t.Fatal("credential was not encoded into stdin")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || !bytes.Equal(decoded, credential) {
			t.Fatalf("credential = %q, decode error = %v", decoded, err)
		}
		environment := strings.Join(spec.Environment, "\n")
		if strings.Contains(environment, string(credential)) || !strings.Contains(environment, "AWS_CONFIG_FILE=/dev/null") || !strings.Contains(environment, "AWS_SHARED_CREDENTIALS_FILE=/dev/null") || !strings.Contains(environment, "AWS_EC2_METADATA_DISABLED=true") || !strings.Contains(environment, "NO_PROXY=sts.us-east-1.amazonaws.com") {
			t.Fatalf("environment leaked AWS authority: %#v", spec.Environment)
		}
		for _, entry := range spec.Environment {
			if strings.HasPrefix(entry, "HOME=") {
				privateHome = strings.TrimPrefix(entry, "HOME=")
				info, statErr := os.Stat(privateHome)
				if statErr != nil || info.Mode().Perm() != 0o700 {
					t.Fatalf("private HOME = %q, info = %#v, error = %v", entry, info, statErr)
				}
				return securityResponseFrameForTest(t, document, json.RawMessage(`{"findings":[],"version":"5.39.1"}`))
			}
		}
		t.Fatal("private HOME was not configured")
		return securityResponseFrameForTest(t, document, json.RawMessage(`{"findings":[],"version":"5.39.1"}`))
	}
	runner := newSecurityRunnerForTest(process, 5*time.Second, func() time.Time {
		return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	})

	result, err := runner.Collect(context.Background(), request, credential)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Mode != SecurityModeProwlerAWS || result.SourceDigest != request.SourceDigest || string(result.Result) != `{"findings":[],"version":"5.39.1"}` {
		t.Fatalf("result = %#v", result)
	}
	if len(process.specs) != 1 || process.specs[0].Executable != prowlerSecurityExecutable || len(process.specs[0].Arguments) != 1 || process.specs[0].Arguments[0] != "prowler-aws-v1" {
		t.Fatalf("process specs = %#v", process.specs)
	}
	if !bytes.Equal(credential, []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T00:15:00Z","secret_access_key":"ssssssssssssssssssssssssssssssssssssssss","session_token":"tttttttttttttttttttttttttttttttt"}`)) {
		t.Fatalf("caller credential was mutated: %q", credential)
	}
	if len(process.borrowed) != 1 || bytes.Count(process.borrowed[0], []byte{0}) != len(process.borrowed[0]) {
		t.Fatal("runner-owned stdin was not cleared")
	}
	if privateHome == "" {
		t.Fatal("private HOME was not observed")
	}
	if _, err := os.Stat(privateHome); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private HOME survived collection: %v", err)
	}
}

func TestSecurityRunnerUsesCredentialFreeCartographyProcess(t *testing.T) {
	request := securityRequestFixture(t, SecurityModeCartographyAWS)
	process := &recordingSecurityProcess{}
	process.respond = func(_ securityProcessSpec, input []byte) []byte {
		document := decodeSecurityFrameForTest(t, input)
		if _, exists := document["credential"]; exists {
			t.Fatal("Cartography request contains credential")
		}
		return securityResponseFrameForTest(t, document, json.RawMessage(`{"policies":[],"roles":[],"version":"0.139.1"}`))
	}
	runner := newSecurityRunnerForTest(process, 5*time.Second, time.Now)

	result, err := runner.Collect(context.Background(), request, nil)
	if err != nil || result.Mode != SecurityModeCartographyAWS {
		t.Fatalf("Collect() = %#v, %v", result, err)
	}
	if len(process.specs) != 1 || process.specs[0].Executable != cartographySecurityExecutable || process.specs[0].Arguments[0] != "cartography-aws-v1" {
		t.Fatalf("process specs = %#v", process.specs)
	}
}

func TestSecurityRunnerBindsSourceDigestAndOutputBudgets(t *testing.T) {
	validRole := json.RawMessage(`{"policies":[],"roles":[{"arn":"arn:aws:iam::123456789012:role/reader","name":"reader","trusted_role_arns":[]}],"version":"0.139.1"}`)
	trustedRoles := json.RawMessage(`{"policies":[],"roles":[{"arn":"arn:aws:iam::123456789012:role/a","name":"a","trusted_role_arns":["arn:aws:iam::123456789012:role/b"]},{"arn":"arn:aws:iam::123456789012:role/b","name":"b","trusted_role_arns":[]}],"version":"0.139.1"}`)
	for name, mutate := range map[string]func(*CollectionSecurityRequest) json.RawMessage{
		"source digest drift": func(request *CollectionSecurityRequest) json.RawMessage {
			request.Source = json.RawMessage(`{"account_id":"123456789012","managed_policies":{},"roles":[{}]}`)
			return validRole
		},
		"entity budget exhausted": func(request *CollectionSecurityRequest) json.RawMessage {
			request.RemainingEntities = 0
			return validRole
		},
		"relationship budget exhausted": func(request *CollectionSecurityRequest) json.RawMessage {
			request.RemainingRelationships = 0
			return trustedRoles
		},
		"byte budget exhausted": func(request *CollectionSecurityRequest) json.RawMessage {
			request.RemainingBytes = int64(len(validRole) - 1)
			return validRole
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := securityRequestFixture(t, SecurityModeCartographyAWS)
			response := mutate(&request)
			process := &recordingSecurityProcess{respond: func(_ securityProcessSpec, input []byte) []byte {
				return securityResponseFrameForTest(t, decodeSecurityFrameForTest(t, input), response)
			}}
			runner := newSecurityRunnerForTest(process, time.Second, time.Now)
			_, err := runner.Collect(context.Background(), request, nil)
			if securityFailureCode(err) != collection.FailureMalformed {
				t.Fatalf("Collect() error = %v", err)
			}
			if name == "source digest drift" && len(process.specs) != 0 {
				t.Fatalf("process calls = %d, want 0", len(process.specs))
			}
		})
	}
}

func TestSecurityRunnerFailsClosedForContextProcessAndOutputErrors(t *testing.T) {
	request := securityRequestFixture(t, SecurityModeProwlerAWS)
	credential := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T00:15:00Z","secret_access_key":"ssssssssssssssssssssssssssssssssssssssss","session_token":"tttttttttttttttttttttttttttttttt"}`)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	process := &recordingSecurityProcess{}
	runner := newSecurityRunnerForTest(process, time.Second, time.Now)
	if _, err := runner.Collect(cancelled, request, credential); securityFailureCode(err) != collection.FailureCancelled || len(process.specs) != 0 {
		t.Fatalf("cancelled Collect() error = %v, calls = %d", err, len(process.specs))
	}

	for name, test := range map[string]struct {
		processErr error
		respond    func(securityProcessSpec, []byte) []byte
		panic      bool
		want       collection.FailureCode
	}{
		"retryable exit": {processErr: &securityProcessError{ExitCode: securityExitRetryable}, want: collection.FailureRetryable},
		"rate limit":     {processErr: &securityProcessError{ExitCode: securityExitRateLimited}, want: collection.FailureRateLimited},
		"denied":         {processErr: &securityProcessError{ExitCode: securityExitDenied}, want: collection.FailureDenied},
		"malformed exit": {processErr: &securityProcessError{ExitCode: securityExitMalformed}, want: collection.FailureMalformed},
		"panic":          {panic: true, want: collection.FailureMalformed},
		"empty":          {respond: func(securityProcessSpec, []byte) []byte { return nil }, want: collection.FailureMalformed},
		"oversize": {respond: func(securityProcessSpec, []byte) []byte {
			return bytes.Repeat([]byte("x"), maximumSecurityFrameBytes+5)
		}, want: collection.FailureMalformed},
		"foreign scope": {
			respond: func(_ securityProcessSpec, input []byte) []byte {
				document := decodeSecurityFrameForTest(t, input)
				document["authority"].(map[string]any)["organization_id"] = "pid_99999999-9999-4999-8999-999999999999"
				return securityResponseFrameForTest(t, document, json.RawMessage(`{"findings":[],"version":"5.39.1"}`))
			},
			want: collection.FailureMalformed,
		},
		"secret output": {
			respond: func(_ securityProcessSpec, input []byte) []byte {
				document := decodeSecurityFrameForTest(t, input)
				return securityResponseFrameForTest(t, document, json.RawMessage(credential))
			},
			want: collection.FailureMalformed,
		},
		"secret fragment output": {
			respond: func(_ securityProcessSpec, input []byte) []byte {
				document := decodeSecurityFrameForTest(t, input)
				return securityResponseFrameForTest(t, document, json.RawMessage(`{"leak":"ssssssssssssssssssssssssssssssssssssssss"}`))
			},
			want: collection.FailureMalformed,
		},
		"wrong result schema": {
			respond: func(_ securityProcessSpec, input []byte) []byte {
				document := decodeSecurityFrameForTest(t, input)
				return securityResponseFrameForTest(t, document, json.RawMessage(`{}`))
			},
			want: collection.FailureMalformed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := &recordingSecurityProcess{err: test.processErr, respond: test.respond, panic: test.panic}
			bounded := newSecurityRunnerForTest(candidate, time.Second, func() time.Time {
				return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
			})
			_, err := bounded.Collect(context.Background(), request, credential)
			if got := securityFailureCode(err); got != test.want || strings.Contains(err.Error(), string(credential)) {
				t.Fatalf("Collect() error = %v, code = %q, want %q", err, got, test.want)
			}
		})
	}

	invalid := &recordingSecurityProcess{}
	malformedRunner := newSecurityRunnerForTest(invalid, time.Second, time.Now)
	if _, err := malformedRunner.Collect(context.Background(), request, []byte(`{"secret_access_key":"secret"}`)); securityFailureCode(err) != collection.FailureMalformed || len(invalid.specs) != 0 {
		t.Fatalf("malformed credential error = %v, process calls = %d", err, len(invalid.specs))
	}
}

func TestExecSecurityProcessBoundsOutputAndKillsCancelledProcessGroup(t *testing.T) {
	directory := t.TempDir()
	writeScript := func(name, source string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+source+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	process := &execSecurityProcess{}
	input := []byte("framed")
	oversized := writeScript("oversized", fmt.Sprintf("head -c %d /dev/zero", maximumSecurityFrameBytes+5))
	if output, err := process.Run(context.Background(), securityProcessSpec{Executable: oversized, Arguments: []string{"run"}, Environment: []string{"PATH=/usr/bin:/bin"}}, input); output != nil || securityProcessExitCode(err) != securityExitMalformed {
		t.Fatalf("oversized Run() = %d bytes, %v", len(output), err)
	}

	pidFile := filepath.Join(directory, "child.pid")
	blocking := writeScript("blocking", fmt.Sprintf("sleep 30 &\nchild=$!\nprintf '%%s' \"$child\" > %q\nwait \"$child\"", pidFile))
	ctx, cancel := context.WithCancel(context.Background())
	type processResult struct {
		output []byte
		err    error
	}
	done := make(chan processResult, 1)
	started := time.Now()
	go func() {
		output, err := process.Run(ctx, securityProcessSpec{Executable: blocking, Arguments: []string{"run"}, Environment: []string{"PATH=/usr/bin:/bin"}}, input)
		done <- processResult{output: output, err: err}
	}()
	var pidText []byte
	for time.Since(started) < 2*time.Second {
		pidText, _ = os.ReadFile(pidFile)
		if len(pidText) != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pidText) == 0 {
		cancel()
		t.Fatal("child process did not start")
	}
	cancel()
	select {
	case result := <-done:
		if result.err == nil || len(result.output) != 0 || time.Since(started) > 3*time.Second {
			t.Fatalf("cancelled Run() = %d bytes, %v, elapsed = %s", len(result.output), result.err, time.Since(started))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled process group did not stop")
	}
	pid, err := strconv.Atoi(string(pidText))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("child process %d survived cancellation: %v", pid, err)
	}
}

func securityProcessExitCode(err error) int {
	var failure *securityProcessError
	if errors.As(err, &failure) {
		return failure.ExitCode
	}
	return -1
}

type recordingSecurityProcess struct {
	specs    []securityProcessSpec
	borrowed [][]byte
	respond  func(securityProcessSpec, []byte) []byte
	err      error
	panic    bool
}

func (process *recordingSecurityProcess) Run(_ context.Context, spec securityProcessSpec, input []byte) ([]byte, error) {
	if process.panic {
		panic("process detail")
	}
	process.specs = append(process.specs, spec)
	process.borrowed = append(process.borrowed, input)
	if process.err != nil {
		return nil, process.err
	}
	if process.respond == nil {
		return nil, nil
	}
	return process.respond(spec, input), nil
}

func securityRequestFixture(t *testing.T, mode SecurityMode) CollectionSecurityRequest {
	t.Helper()
	mustID := func(value string) domain.ProductID {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(
		mustID("pid_00000001-0000-4000-8000-000000000001"),
		mustID("pid_00000002-0000-4000-8000-000000000002"),
		mustID("pid_00000003-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatal(err)
	}
	phase := "posture"
	source := json.RawMessage(`{"account_id":"123456789012","instances":[],"roles":[]}`)
	if mode == SecurityModeCartographyAWS {
		phase = "iam"
		source = json.RawMessage(`{"account_id":"123456789012","managed_policies":{},"roles":[]}`)
	}
	return CollectionSecurityRequest{
		Mode: mode, Scope: scope,
		IntegrationID: mustID("pid_00000004-0000-4000-8000-000000000004"),
		ConnectionID:  mustID("pid_00000005-0000-4000-8000-000000000005"),
		JobID:         mustID("pid_00000006-0000-4000-8000-000000000006"),
		Attempt:       1, CursorLineage: 3,
		Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"},
		Phase:   phase, ObservedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		CredentialExpiresAt: time.Date(2026, 8, 20, 0, 15, 0, 0, time.UTC),
		RemainingBytes:      1024, RemainingEntities: 10, RemainingRelationships: 20,
		SourceDigest: sha256.Sum256(source), Source: source,
	}
}

func decodeSecurityFrameForTest(t *testing.T, input []byte) map[string]any {
	t.Helper()
	if len(input) < 6 || int(binary.BigEndian.Uint32(input[:4])) != len(input)-4 {
		t.Fatalf("invalid input frame length: %d", len(input))
	}
	var document map[string]any
	if err := json.Unmarshal(input[4:], &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func securityResponseFrameForTest(t *testing.T, request map[string]any, result json.RawMessage) []byte {
	t.Helper()
	response := map[string]any{
		"authority":        request["authority"],
		"protocol_version": 1,
		"result":           result,
		"source_digest":    request["authority"].(map[string]any)["source_digest"],
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	framed := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(body)))
	copy(framed[4:], body)
	return framed
}

func securityFailureCode(err error) collection.FailureCode {
	var failure *collection.Failure
	if errors.As(err, &failure) {
		return failure.Code()
	}
	return ""
}
