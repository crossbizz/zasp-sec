package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestConfigurationCommandProcessEntry(t *testing.T) {
	if os.Getenv("ZASP_TEST_CONFIGURATION_COMMAND") == "1" {
		os.Args = []string{"agentsec-api", "--check-config"}
		main()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConfigurationCommandProcessEntry$")
	command.Env = []string{"ZASP_TEST_CONFIGURATION_COMMAND=1"}
	// This valid syntax fixture has runtime services disabled. Full production
	// construction refuses it, so a successful process proves the check returns
	// before dependency construction or normal server startup.
	for key, value := range fixtureRuntimeEnvironment() {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Equal(output, []byte(configurationCheckAccepted+"PASS\n")) {
		t.Fatal("configuration command process did not exit at the syntax boundary")
	}
}

func TestConfigurationCommandUsesCompleteLauncherConfiguration(t *testing.T) {
	cases := []struct {
		name     string
		values   map[string]string
		accepted bool
	}{
		{"base", fixtureRuntimeEnvironment(), true},
		{"audit", fixtureAuditExportEnvironment(), true},
		{"compliance", complianceAPIEnvironment(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			handled, err := runConfigurationCommand([]string{"--check-config"}, func(k string) (string, bool) { v, ok := tc.values[k]; return v, ok }, &output)
			if !handled || err != nil || output.String() != configurationCheckAccepted {
				t.Fatalf("handled=%t err=%v output=%q", handled, err, output.String())
			}
		})
	}
}

func TestConfigurationCommandRejectsInvalidAndPartialBundlesWithoutDisclosure(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]string)
	}{
		{"database", func(v map[string]string) { v["ZASP_POSTGRES_DSN"] = "credential-shaped-invalid-dsn" }},
		{"audit", func(v map[string]string) { v["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = "private-invalid-policy" }},
		{"runtime", func(v map[string]string) { v["ZASP_RUNTIME_SERVICES_ENABLED"] = "true" }},
		{"compliance", func(v map[string]string) { v["ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN"] = "private-invalid-role" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := fixtureRuntimeEnvironment()
			tc.change(values)
			var output bytes.Buffer
			handled, err := runConfigurationCommand([]string{"--check-config"}, func(k string) (string, bool) { v, ok := values[k]; return v, ok }, &output)
			if !handled || !errors.Is(err, errInvalidRuntimeConfig) || output.String() != configurationCheckRefused {
				t.Fatalf("handled=%t err=%v output=%q", handled, err, output.String())
			}
			for _, value := range values {
				if len(value) > 8 && strings.Contains(output.String(), value) {
					t.Fatal("configuration value disclosed")
				}
			}
		})
	}
}

func TestConfigurationCommandDispatchCannotStartServerOnUnknownArguments(t *testing.T) {
	for _, args := range [][]string{{"--unknown"}, {"--check-config", "extra"}, {"--check-config=1"}} {
		reads := 0
		var output bytes.Buffer
		handled, err := runConfigurationCommand(args, func(string) (string, bool) { reads++; return "", false }, &output)
		if !handled || !errors.Is(err, errInvalidRuntimeConfig) || reads != 0 || output.String() != configurationCheckUsage {
			t.Fatalf("handled=%t err=%v reads=%d output=%q", handled, err, reads, output.String())
		}
	}
	handled, err := runConfigurationCommand(nil, func(string) (string, bool) { t.Fatal("ordinary startup read environment early"); return "", false }, nil)
	if handled || err != nil {
		t.Fatalf("ordinary startup handled=%t err=%v", handled, err)
	}
}

func TestConfigurationCommandRefusesMissingInputsAndOutputFailures(t *testing.T) {
	var output bytes.Buffer
	handled, err := runConfigurationCommand([]string{"--check-config"}, nil, &output)
	if !handled || !errors.Is(err, errInvalidRuntimeConfig) || output.String() != configurationCheckRefused {
		t.Fatal("nil environment accepted")
	}
	values := fixtureRuntimeEnvironment()
	lookup := func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	for _, writer := range []io.Writer{nil, (*bytes.Buffer)(nil), configurationFailingWriter{}, configurationShortWriter{}} {
		handled, err = runConfigurationCommand([]string{"--check-config"}, lookup, writer)
		if !handled || !errors.Is(err, errOutputUnavailable) {
			t.Fatalf("handled=%t err=%v", handled, err)
		}
	}
}

type configurationFailingWriter struct{}

func (configurationFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("private writer failure")
}

type configurationShortWriter struct{}

func (configurationShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
