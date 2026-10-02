package main

import (
	"strings"
	"testing"
)

func globalControlEnvironment() map[string]string {
	return map[string]string{
		"ZASP_SECURITY_AGENT_GLOBAL_ENABLED":          "false",
		"ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION": "1",
		"ZASP_SECURITY_AGENT_GLOBAL_REQUEST_ID":       "pid_7f560001-0000-4000-8000-000000000001",
		"ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID":   "global-stop-test",
	}
}

// Permissive numeric parsing must not accept a different wire intent.
func TestGlobalExecutionControlRejectsNoncanonicalVersion(t *testing.T) {
	values := globalControlEnvironment()
	for _, value := range []string{"01", "", "0", "+1", "-1", " 1", "1 ", "1.0", "1e1", "9223372036854775807", "9223372036854775808"} {
		values["ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION"] = value
		if _, err := loadGlobalExecutionControlRequest(func(k string) string { return values[k] }); err == nil {
			t.Fatalf("accepted noncanonical expected version %q", value)
		}
	}
	for _, value := range []string{"1", "9223372036854775806"} {
		values["ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION"] = value
		got, err := loadGlobalExecutionControlRequest(func(k string) string { return values[k] })
		if err != nil || got.ExpectedVersion < 1 || got.Enabled {
			t.Fatalf("valid stop rejected: %+v %v", got, err)
		}
	}
}

func TestGlobalExecutionControlStrictRequest(t *testing.T) {
	for key, invalid := range map[string][]string{
		"ZASP_SECURITY_AGENT_GLOBAL_ENABLED":        {"", "TRUE", "False", "0", "1", " true"},
		"ZASP_SECURITY_AGENT_GLOBAL_REQUEST_ID":     {"", "7f560001-0000-4000-8000-000000000001", "pid_7F560001-0000-4000-8000-000000000001", "pid_7f560001-0000-1000-8000-000000000001", "pid_7f560001-0000-4000-7000-000000000001"},
		"ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID": {"", "has space", "x\t", "x\n", "x\x00", "x\x7f", "é", strings.Repeat("x", 129)},
	} {
		for _, value := range invalid {
			values := globalControlEnvironment()
			values[key] = value
			if _, err := loadGlobalExecutionControlRequest(func(k string) string { return values[k] }); err == nil {
				t.Fatalf("accepted %s=%q", key, value)
			}
		}
	}
	if _, err := loadGlobalExecutionControlRequest(nil); err == nil {
		t.Fatal("accepted nil environment")
	}
	values := globalControlEnvironment()
	values["ZASP_SECURITY_AGENT_GLOBAL_ENABLED"] = "true"
	values["ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID"] = strings.Repeat("!", 128)
	if got, err := loadGlobalExecutionControlRequest(func(k string) string { return values[k] }); err != nil || !got.Enabled {
		t.Fatal("valid enable rejected", err)
	}
}

func TestGlobalExecutionControlCommandArguments(t *testing.T) {
	for _, command := range []string{"security-agent-global-read", "security-agent-global-set"} {
		if isForwardMigration([]string{command}) {
			t.Fatal("operational command treated as migration")
		}
		for _, args := range [][]string{{command, "extra"}, {command, ""}} {
			if _, err := parseGlobalExecutionControlCommand(args, func(string) string { t.Fatal("extra arguments read environment"); return "" }); err == nil {
				t.Fatal("extra arguments accepted")
			}
		}
	}
	if got, err := parseGlobalExecutionControlCommand([]string{"security-agent-global-read"}, func(string) string { t.Fatal("read loaded mutation environment"); return "" }); err != nil || got != nil {
		t.Fatal("read rejected", err)
	}
	values := globalControlEnvironment()
	if got, err := parseGlobalExecutionControlCommand([]string{"security-agent-global-set"}, func(k string) string { return values[k] }); err != nil || got == nil || got.ExpectedVersion != 1 {
		t.Fatal("set rejected", err)
	}
}
