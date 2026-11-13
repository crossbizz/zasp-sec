package awsdiscovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/localcloud"
)

func securityLocalSettings(environment, endpoint string) (localcloud.Settings, func(string) string) {
	getenv := func(name string) string {
		switch name {
		case localcloud.EnvironmentVariable:
			return environment
		case localcloud.EndpointVariable:
			return endpoint
		}
		return ""
	}
	settings, _ := localcloud.Load(getenv)
	return settings, getenv
}

// The posture analyzer is told about a local cloud emulator only when
// localcloud accepted it, which it never does in production.
func TestSecurityLocalEnvironmentIsEmptyOutsideDevelopmentEmulator(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, environment, endpoint string }{
		{"production", "production", ""},
		{"production with a refused endpoint", "production", "http://127.0.0.1:4566"},
		{"staging with a refused endpoint", "staging", "http://127.0.0.1:4566"},
		{"unset environment with a refused endpoint", "", "http://127.0.0.1:4566"},
		{"development without an endpoint", "development", ""},
		{"development with a public endpoint", "development", "http://8.8.8.8:4566"},
		{"development with a TLS endpoint", "development", "https://127.0.0.1:4566"},
	} {
		settings, getenv := securityLocalSettings(test.environment, test.endpoint)
		if extra := securityLocalEnvironment(settings, getenv); len(extra) != 0 {
			t.Fatalf("%s: extra environment = %q", test.name, extra)
		}
	}
	for _, environment := range []string{"development", "test"} {
		settings, getenv := securityLocalSettings(environment, "http://127.0.0.1:4566")
		extra := securityLocalEnvironment(settings, getenv)
		if len(extra) != 2 || extra[0] != "ZASP_LOCAL_CLOUD_ENDPOINT=http://127.0.0.1:4566" || extra[1] != "ZASP_ENVIRONMENT="+environment {
			t.Fatalf("%s: extra environment = %q", environment, extra)
		}
	}
	if settings, _ := securityLocalSettings("development", "http://127.0.0.1:4566"); securityLocalEnvironment(settings, nil) != nil {
		t.Fatal("a missing environment reader produced an emulator environment")
	}
}

func TestSecurityRunnerPassesEmulatorOnlyToPostureAnalyzer(t *testing.T) {
	credential := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T00:15:00Z","secret_access_key":"ssssssssssssssssssssssssssssssssssssssss","session_token":"tttttttttttttttttttttttttttttttt"}`)
	clock := func() time.Time { return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC) }
	run := func(mode SecurityMode, local []string) []string {
		t.Helper()
		process := &recordingSecurityProcess{}
		process.respond = func(_ securityProcessSpec, input []byte) []byte {
			result := json.RawMessage(`{"findings":[],"version":"5.39.1"}`)
			if mode == SecurityModeCartographyAWS {
				result = json.RawMessage(`{"policies":[],"roles":[],"version":"0.139.1"}`)
			}
			return securityResponseFrameForTest(t, decodeSecurityFrameForTest(t, input), result)
		}
		runner := newSecurityRunnerForTest(process, 5*time.Second, clock)
		runner.localEnvironment = local
		var borrowed []byte
		if mode == SecurityModeProwlerAWS {
			borrowed = credential
		}
		if _, err := runner.Collect(context.Background(), securityRequestFixture(t, mode), borrowed); err != nil {
			t.Fatalf("Collect(%s) error = %v", mode, err)
		}
		if len(process.specs) != 1 {
			t.Fatalf("process specs = %#v", process.specs)
		}
		return process.specs[0].Environment
	}
	hasLocal := func(environment []string) bool {
		for _, entry := range environment {
			if strings.HasPrefix(entry, "ZASP_") {
				return true
			}
		}
		return false
	}
	local := []string{"ZASP_LOCAL_CLOUD_ENDPOINT=http://127.0.0.1:4566", "ZASP_ENVIRONMENT=development"}

	// Production: a runner without an emulator passes no ZASP_ setting, so the
	// analyzer re-attests against the regional AWS STS endpoint.
	for _, mode := range []SecurityMode{SecurityModeProwlerAWS, SecurityModeCartographyAWS} {
		if environment := run(mode, nil); hasLocal(environment) {
			t.Fatalf("%s without an emulator received %q", mode, environment)
		}
	}
	// Emulator: only the posture analyzer, which calls STS, is told.
	if environment := run(SecurityModeProwlerAWS, local); !strings.Contains(strings.Join(environment, "\n"), strings.Join(local, "\n")) {
		t.Fatalf("posture analyzer environment = %q", environment)
	}
	if environment := run(SecurityModeCartographyAWS, local); hasLocal(environment) {
		t.Fatalf("graph analyzer received %q", environment)
	}
}

func TestNewSecurityRunnerHasNoEmulatorEnvironmentByDefault(t *testing.T) {
	if localcloud.Current().Enabled() {
		t.Skip("a local cloud endpoint is configured for this test process")
	}
	runner, err := NewSecurityRunner(time.Minute)
	if err != nil || len(runner.localEnvironment) != 0 {
		t.Fatalf("runner local environment = %q, %v", runner.localEnvironment, err)
	}
}

// The posture analyzer writes canonical JSON: object keys sorted. This is the
// exact encoding workers/security-python produces for a finding.
func TestSecurityResultAcceptsCanonicalPostureFindings(t *testing.T) {
	t.Parallel()
	request := securityRequestFixture(t, SecurityModeProwlerAWS)
	account := request.Subject.ID
	canonical := json.RawMessage(`{"findings":[` +
		`{"check_id":"ec2_instance_imdsv2_enabled","region":"us-east-1","resource_arn":"arn:aws:ec2:us-east-1:` + account + `:instance/i-0123456789abcdef0","resource_id":"i-0123456789abcdef0","severity":"high","status":"FAIL"},` +
		`{"check_id":"iam_role_administratoraccess_policy","region":"global","resource_arn":"arn:aws:iam::` + account + `:role/agents/orchestrator","resource_id":"orchestrator","severity":"high","status":"PASS"}` +
		`],"version":"5.39.1"}`)
	if !canonicalSecurityObject(canonical) {
		t.Fatal("fixture is not canonical JSON")
	}
	if !validSecurityResult(request, canonical) {
		t.Fatal("canonical posture findings were rejected")
	}
	unsorted := json.RawMessage(strings.ReplaceAll(string(canonical), `"region":"global","resource_arn":"arn:aws:iam::`+account+`:role/agents/orchestrator","resource_id":"orchestrator"`, `"resource_arn":"arn:aws:iam::`+account+`:role/agents/orchestrator","resource_id":"orchestrator","region":"global"`))
	if string(unsorted) == string(canonical) || validSecurityResult(request, unsorted) {
		t.Fatal("non-canonical posture findings were accepted")
	}
}
